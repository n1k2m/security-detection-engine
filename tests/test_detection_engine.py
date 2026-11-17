from datetime import UTC, datetime
from pathlib import Path

from security_detection_engine.analyzer import analyze_ssh_log
from security_detection_engine.detection import (
    Condition,
    DetectionEngine,
    DetectionRule,
    load_rules_from_directory,
)
from security_detection_engine.models import EventSource, SecurityEvent, Severity


def make_event(event_type: str = "ssh_authentication_failed", **data) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(UTC),
        source=EventSource.LINUX,
        event_type=event_type,
        host="server",
        data=data,
    )


def make_rule(
    rule_id: str = "R-1",
    event_type: str = "ssh_authentication_failed",
    conditions: list[Condition] | None = None,
    enabled: bool = True,
    severity: Severity = Severity.LOW,
) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        description=f"Description of {rule_id}",
        severity=severity,
        event_type=event_type,
        conditions=conditions or [],
        enabled=enabled,
    )


def condition(field: str, operator: str, value) -> Condition:
    return Condition(field=field, operator=operator, value=value)


def test_matching_event_produces_alert():
    rule = make_rule()
    event = make_event()

    alerts = DetectionEngine([rule]).analyze_event(event)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "R-1"
    assert alert.rule_name == "Rule R-1"
    assert alert.description == "Description of R-1"
    assert alert.severity is Severity.LOW
    assert alert.event_id == event.event_id
    assert alert.timestamp == event.timestamp


def test_different_event_type_does_not_match():
    rule = make_rule()
    event = make_event(event_type="ssh_authentication_success")

    assert DetectionEngine([rule]).analyze_event(event) == []


def test_disabled_rule_produces_no_alerts():
    rule = make_rule(enabled=False)

    assert DetectionEngine([rule]).analyze_event(make_event()) == []


def test_missing_field_does_not_match():
    rule = make_rule(conditions=[condition("data.username", "equals", "root")])

    assert DetectionEngine([rule]).analyze_event(make_event()) == []


def test_equals_operator():
    rule = make_rule(conditions=[condition("data.username", "equals", "root")])

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event(username="root"))) == 1
    assert engine.analyze_event(make_event(username="admin")) == []


def test_not_equals_operator():
    rule = make_rule(conditions=[condition("data.username", "not_equals", "root")])

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event(username="admin"))) == 1
    assert engine.analyze_event(make_event(username="root")) == []


def test_contains_operator():
    rule = make_rule(
        conditions=[condition("data.authentication_method", "contains", "key")]
    )

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event(authentication_method="publickey"))) == 1
    assert engine.analyze_event(make_event(authentication_method="password")) == []


def test_contains_operator_on_list():
    rule = make_rule(conditions=[condition("data.tags", "contains", "ssh")])

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event(tags=["ssh", "auth"]))) == 1
    assert engine.analyze_event(make_event(tags=["web"])) == []


def test_contains_operator_with_incompatible_types():
    rule = make_rule(conditions=[condition("data.source_port", "contains", "22")])

    assert DetectionEngine([rule]).analyze_event(make_event(source_port=22)) == []


def test_greater_than_operator():
    rule = make_rule(conditions=[condition("data.source_port", "greater_than", 1024)])

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event(source_port=54321))) == 1
    assert engine.analyze_event(make_event(source_port=22)) == []


def test_less_than_operator():
    rule = make_rule(conditions=[condition("data.source_port", "less_than", 1024)])

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event(source_port=22))) == 1
    assert engine.analyze_event(make_event(source_port=54321)) == []


def test_comparison_with_incompatible_types_is_safe():
    rule = make_rule(conditions=[condition("data.username", "greater_than", 5)])

    assert DetectionEngine([rule]).analyze_event(make_event(username="root")) == []


def test_multiple_conditions_all_must_match():
    rule = make_rule(
        conditions=[
            condition("data.username", "equals", "root"),
            condition("data.authentication_method", "equals", "password"),
        ]
    )

    engine = DetectionEngine([rule])
    event = make_event(username="root", authentication_method="password")
    assert len(engine.analyze_event(event)) == 1
    assert engine.analyze_event(make_event(username="root")) == []


def test_multiple_rules_can_match_same_event():
    first = make_rule(rule_id="R-1")
    second = make_rule(rule_id="R-2", severity=Severity.HIGH)

    alerts = DetectionEngine([first, second]).analyze_event(make_event())

    assert [alert.rule_id for alert in alerts] == ["R-1", "R-2"]
    assert alerts[0].alert_id != alerts[1].alert_id


def test_analyze_events_collects_alerts_from_all_events():
    rule = make_rule()
    events = [
        make_event(),
        make_event(event_type="ssh_authentication_success"),
        make_event(),
    ]

    alerts = DetectionEngine([rule]).analyze_events(events)

    assert len(alerts) == 2
    assert alerts[0].event_id == events[0].event_id
    assert alerts[1].event_id == events[2].event_id


def test_end_to_end_with_ssh_analyzer_and_packaged_rule(tmp_path: Path):
    rules_dir = (
        Path(__file__).parent.parent / "src" / "security_detection_engine" / "rules"
    )
    rules = load_rules_from_directory(rules_dir)
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Nov 16 10:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2\n"
        "Nov 16 10:16:02 server sshd[1234]: Accepted password for admin "
        "from 192.168.1.10 port 54321 ssh2\n",
        encoding="utf-8",
    )

    events = analyze_ssh_log(log_file, year=2024, tz=UTC).events
    alerts = DetectionEngine(rules).analyze_events(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SSH-001"
    assert alerts[0].event_id == events[0].event_id


def test_greater_than_with_strings_does_not_match():
    rule = make_rule(conditions=[condition("data.username", "greater_than", "a")])

    assert DetectionEngine([rule]).analyze_event(make_event(username="z")) == []


def test_less_than_with_strings_does_not_match():
    rule = make_rule(conditions=[condition("data.username", "less_than", "z")])

    assert DetectionEngine([rule]).analyze_event(make_event(username="a")) == []


def test_greater_than_with_bool_does_not_match():
    rule = make_rule(conditions=[condition("data.flag", "greater_than", 0)])

    assert DetectionEngine([rule]).analyze_event(make_event(flag=True)) == []


def test_less_than_with_bool_does_not_match():
    rule = make_rule(conditions=[condition("data.source_port", "less_than", True)])

    assert DetectionEngine([rule]).analyze_event(make_event(source_port=22)) == []


def test_engine_accepts_rules_generator():
    rules = (make_rule(rule_id=f"R-{i}") for i in range(3))

    alerts = DetectionEngine(rules).analyze_event(make_event())

    assert len(alerts) == 3


def test_rule_without_conditions_matches_by_event_type():
    rule = make_rule()

    engine = DetectionEngine([rule])
    assert len(engine.analyze_event(make_event())) == 1
    assert engine.analyze_event(make_event(event_type="other_event")) == []
