from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_detection_engine.analyzer import analyze_ssh_log
from security_detection_engine.correlation import (
    CorrelationEngine,
    CorrelationRule,
    CorrelationStep,
    load_correlation_rules_from_directory,
)
from security_detection_engine.detection import (
    Condition,
    DetectionEngine,
    load_rules_from_directory,
)
from security_detection_engine.models import EventSource, SecurityEvent, Severity

BASE = datetime(2024, 11, 16, 10, 0, 0, tzinfo=UTC)


def make_event(
    event_type: str,
    ip: str | None = "192.168.1.10",
    minutes: float = 0,
    **data,
) -> SecurityEvent:
    if ip is not None:
        data.setdefault("source_ip", ip)
    return SecurityEvent(
        timestamp=BASE + timedelta(minutes=minutes),
        source=EventSource.LINUX,
        event_type=event_type,
        host="server",
        data=data,
    )


def make_rule(
    rule_id: str = "CORR-001",
    steps: list | None = None,
    time_window_seconds: int = 300,
    group_by: list[str] | None = None,
    enabled: bool = True,
    severity: Severity = Severity.HIGH,
) -> CorrelationRule:
    return CorrelationRule(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        description=f"Description of {rule_id}",
        severity=severity,
        enabled=enabled,
        time_window_seconds=time_window_seconds,
        group_by=group_by or ["data.source_ip"],
        steps=steps
        or [
            CorrelationStep(event_type="ssh_authentication_failed"),
            CorrelationStep(event_type="ssh_authentication_success"),
        ],
    )


def failed(**kwargs) -> SecurityEvent:
    return make_event("ssh_authentication_failed", **kwargs)


def success(**kwargs) -> SecurityEvent:
    return make_event("ssh_authentication_success", **kwargs)


def test_sequence_detected():
    events = [failed(minutes=0), failed(minutes=1), success(minutes=2)]

    alerts = CorrelationEngine([make_rule()]).analyze_events(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "CORR-001"
    assert alert.rule_name == "Rule CORR-001"
    assert alert.severity is Severity.HIGH
    # Упорядоченная подпоследовательность: промежуточные события допустимы
    assert alert.event_ids == [events[0].event_id, events[2].event_id]
    assert alert.start_timestamp == events[0].timestamp
    assert alert.end_timestamp == events[2].timestamp
    assert alert.timestamp == events[2].timestamp
    assert alert.group_values == {"data.source_ip": "192.168.1.10"}


def test_wrong_order_not_detected():
    events = [success(minutes=0), failed(minutes=1)]

    assert CorrelationEngine([make_rule()]).analyze_events(events) == []


def test_time_window_exceeded_not_detected():
    events = [failed(minutes=0), success(minutes=10)]

    engine = CorrelationEngine([make_rule(time_window_seconds=300)])
    assert engine.analyze_events(events) == []


def test_different_ips_not_merged():
    events = [
        failed(ip="192.168.1.10", minutes=0),
        success(ip="10.0.0.5", minutes=1),
    ]

    assert CorrelationEngine([make_rule()]).analyze_events(events) == []


def test_missing_group_field_excludes_event():
    events = [failed(minutes=0), success(ip=None, minutes=1)]

    assert CorrelationEngine([make_rule()]).analyze_events(events) == []


def test_multiple_independent_sequences():
    events = [
        failed(minutes=0),
        success(minutes=1),
        failed(minutes=10),
        success(minutes=11),
    ]

    alerts = CorrelationEngine([make_rule()]).analyze_events(events)

    assert len(alerts) == 2
    assert alerts[0].correlation_id != alerts[1].correlation_id


def test_multiple_rules():
    first = make_rule(rule_id="CORR-001")
    second = make_rule(
        rule_id="CORR-002",
        steps=[
            CorrelationStep(event_type="ssh_authentication_failed"),
            CorrelationStep(event_type="ssh_authentication_failed"),
        ],
    )
    events = [failed(minutes=0), failed(minutes=1), success(minutes=2)]

    alerts = CorrelationEngine([first, second]).analyze_events(events)

    assert {alert.rule_id for alert in alerts} == {"CORR-001", "CORR-002"}


def test_disabled_rule_produces_no_alerts():
    rule = make_rule(enabled=False)
    events = [failed(minutes=0), success(minutes=1)]

    assert CorrelationEngine([rule]).analyze_events(events) == []


def test_missing_condition_field_prevents_match():
    step = CorrelationStep(
        event_type="ssh_authentication_failed",
        conditions=[Condition(field="data.username", operator="equals", value="root")],
    )
    rule = make_rule(
        steps=[step, CorrelationStep(event_type="ssh_authentication_success")]
    )
    events = [failed(minutes=0), success(minutes=1)]

    assert CorrelationEngine([rule]).analyze_events(events) == []


def test_step_conditions_applied():
    step = CorrelationStep(
        event_type="ssh_authentication_failed",
        conditions=[
            Condition(
                field="data.authentication_method", operator="equals", value="password"
            )
        ],
    )
    rule = make_rule(
        steps=[step, CorrelationStep(event_type="ssh_authentication_success")]
    )

    engine = CorrelationEngine([rule])
    matching = [
        failed(minutes=0, authentication_method="password"),
        success(minutes=1),
    ]
    not_matching = [
        failed(minutes=0, authentication_method="publickey"),
        success(minutes=1),
    ]

    assert len(engine.analyze_events(matching)) == 1
    assert engine.analyze_events(not_matching) == []


def test_same_timestamp_events_detected():
    events = [failed(minutes=0), success(minutes=0)]

    assert len(CorrelationEngine([make_rule()]).analyze_events(events)) == 1


def test_empty_input():
    assert CorrelationEngine([make_rule()]).analyze_events([]) == []


def test_unsorted_input_processed_chronologically():
    events = [success(minutes=2), failed(minutes=0)]

    assert len(CorrelationEngine([make_rule()]).analyze_events(events)) == 1


def test_window_restarts_from_latest_candidate():
    # Первый fail выходит за окно, но вторая пара fail+success успевает
    events = [
        failed(minutes=0),
        failed(minutes=6),
        success(minutes=7),
    ]

    engine = CorrelationEngine([make_rule(time_window_seconds=300)])
    alerts = engine.analyze_events(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == [events[1].event_id, events[2].event_id]


def test_integration_with_ssh_analyzer_and_detection(tmp_path: Path):
    rules_dir = (
        Path(__file__).parent.parent / "src" / "security_detection_engine" / "rules"
    )
    correlation_rules = load_correlation_rules_from_directory(rules_dir / "correlation")
    detection_rules = load_rules_from_directory(rules_dir)

    lines = []
    for i in range(3):
        lines.append(
            f"Nov 16 10:0{i}:32 server sshd[1234]: Failed password for root "
            "from 192.168.1.10 port 54321 ssh2"
        )
    lines.append(
        "Nov 16 10:05:00 server sshd[1234]: Accepted password for root "
        "from 192.168.1.10 port 54322 ssh2"
    )
    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events = analyze_ssh_log(log_file, year=2024, tz=UTC).events

    correlation_alerts = CorrelationEngine(correlation_rules).analyze_events(events)
    detection_alerts = DetectionEngine(detection_rules).analyze_events(events)

    assert len(correlation_alerts) == 1
    assert correlation_alerts[0].rule_id == "CORR-SSH-001"
    assert len(correlation_alerts[0].event_ids) == 4
    assert correlation_alerts[0].group_values == {"data.source_ip": "192.168.1.10"}
    assert len(detection_alerts) == 3


def test_group_by_does_not_merge_bool_and_int():
    # True == 1 в Python, но группировать их вместе нельзя
    rule = make_rule(group_by=["data.flag"])
    events = [failed(minutes=0, flag=True), success(minutes=1, flag=1)]

    assert CorrelationEngine([rule]).analyze_events(events) == []


def test_group_by_does_not_merge_int_and_float():
    # 1 == 1.0 в Python, но типы разные — группы разные
    rule = make_rule(group_by=["data.flag"])
    events = [failed(minutes=0, flag=1), success(minutes=1, flag=1.0)]

    assert CorrelationEngine([rule]).analyze_events(events) == []


def test_group_by_with_complex_value_excludes_event():
    # Сложные значения не поддерживаются: события исключаются без исключений
    rule = make_rule(group_by=["data.flag"])
    events = [failed(minutes=0, flag=["a", "b"]), success(minutes=1, flag=["a", "b"])]

    assert CorrelationEngine([rule]).analyze_events(events) == []


def test_same_timestamp_input_order_matters():
    # Политика: сортировка стабильна, равные timestamp сохраняют порядок входа
    engine = CorrelationEngine([make_rule()])

    ordered = [failed(minutes=0), success(minutes=0)]
    swapped = [success(minutes=0), failed(minutes=0)]

    assert len(engine.analyze_events(ordered)) == 1
    assert engine.analyze_events(swapped) == []


def test_greedy_search_misses_later_start_within_window():
    # Ограничение жадного поиска: кандидат, начатый с fail@0, выходит за окно
    # на success@6 и сбрасывается; последовательность (fail@4, success@6),
    # укладывающаяся в окно, не рассматривается
    events = [
        failed(minutes=0),
        failed(minutes=4),
        success(minutes=6),
    ]

    engine = CorrelationEngine([make_rule(time_window_seconds=300)])
    assert engine.analyze_events(events) == []


def test_alternative_sequence_detected_without_early_candidate():
    # Та же пара (fail@4, success@6) из test_greedy_search_misses_...
    # обнаруживается, если ранний fail@0 отсутствует: последовательность
    # валидна, но жадный поиск не находит её при наличии более раннего
    # кандидата, вышедшего за окно
    events = [
        failed(minutes=4),
        success(minutes=6),
    ]

    engine = CorrelationEngine([make_rule(time_window_seconds=300)])
    alerts = engine.analyze_events(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == [events[0].event_id, events[1].event_id]
    assert alerts[0].start_timestamp == events[0].timestamp
    assert alerts[0].end_timestamp == events[1].timestamp
