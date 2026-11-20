from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from security_detection_engine.correlation import (
    CorrelationAlert,
    CorrelationRule,
    CorrelationStep,
)
from security_detection_engine.models import Severity


def make_rule_dict(**overrides) -> dict:
    fields = {
        "rule_id": "CORR-001",
        "name": "Failed then successful login",
        "description": "Failed logins followed by a successful one",
        "severity": "high",
        "time_window_seconds": 300,
        "group_by": ["data.source_ip"],
        "steps": [
            {"event_type": "ssh_authentication_failed"},
            {"event_type": "ssh_authentication_success"},
        ],
    }
    fields.update(overrides)
    return fields


def test_valid_rule_created():
    rule = CorrelationRule.model_validate(make_rule_dict())

    assert rule.rule_id == "CORR-001"
    assert rule.severity is Severity.HIGH
    assert rule.enabled is True
    assert rule.time_window_seconds == 300
    assert rule.group_by == ["data.source_ip"]
    assert len(rule.steps) == 2
    assert rule.steps[0].conditions == []


def test_step_with_conditions():
    rule = CorrelationRule.model_validate(
        make_rule_dict(
            steps=[
                {
                    "event_type": "ssh_authentication_failed",
                    "conditions": [
                        {
                            "field": "data.authentication_method",
                            "operator": "equals",
                            "value": "password",
                        }
                    ],
                },
                {"event_type": "ssh_authentication_success"},
            ]
        )
    )

    assert rule.steps[0].conditions[0].value == "password"


def test_single_step_rejected():
    with pytest.raises(ValidationError):
        CorrelationRule.model_validate(
            make_rule_dict(steps=[{"event_type": "ssh_authentication_failed"}])
        )


def test_non_positive_time_window_rejected():
    with pytest.raises(ValidationError):
        CorrelationRule.model_validate(make_rule_dict(time_window_seconds=0))

    with pytest.raises(ValidationError):
        CorrelationRule.model_validate(make_rule_dict(time_window_seconds=-10))


def test_empty_group_by_rejected():
    with pytest.raises(ValidationError):
        CorrelationRule.model_validate(make_rule_dict(group_by=[]))


def test_invalid_group_by_path_rejected():
    for bad_path in ("", "data..source_ip", ".data.source_ip", "data.source_ip."):
        with pytest.raises(ValidationError):
            CorrelationRule.model_validate(make_rule_dict(group_by=[bad_path]))


def test_empty_required_fields_rejected():
    with pytest.raises(ValidationError):
        CorrelationRule.model_validate(make_rule_dict(rule_id="  "))

    with pytest.raises(ValidationError):
        CorrelationStep(event_type="", conditions=[])


def test_unknown_operator_in_step_rejected():
    with pytest.raises(ValidationError):
        CorrelationRule.model_validate(
            make_rule_dict(
                steps=[
                    {
                        "event_type": "ssh_authentication_failed",
                        "conditions": [
                            {
                                "field": "data.username",
                                "operator": "regex",
                                "value": "root",
                            }
                        ],
                    },
                    {"event_type": "ssh_authentication_success"},
                ]
            )
        )


def test_alert_created_with_generated_id():
    start = datetime(2024, 11, 16, 10, 0, 0, tzinfo=UTC)
    end = datetime(2024, 11, 16, 10, 1, 0, tzinfo=UTC)
    kwargs = {
        "rule_id": "CORR-001",
        "rule_name": "Failed then successful login",
        "description": "Failed logins followed by a successful one",
        "severity": Severity.HIGH,
        "timestamp": end,
        "event_ids": [uuid4(), uuid4()],
        "start_timestamp": start,
        "end_timestamp": end,
        "group_values": {"data.source_ip": "192.168.1.10"},
    }
    first = CorrelationAlert(**kwargs)
    second = CorrelationAlert(**kwargs)

    assert isinstance(first.correlation_id, UUID)
    assert first.correlation_id != second.correlation_id


def make_alert_kwargs(**overrides) -> dict:
    start = datetime(2024, 11, 16, 10, 0, 0, tzinfo=UTC)
    end = datetime(2024, 11, 16, 10, 1, 0, tzinfo=UTC)
    fields = {
        "rule_id": "CORR-001",
        "rule_name": "Failed then successful login",
        "description": "Failed logins followed by a successful one",
        "severity": Severity.HIGH,
        "timestamp": end,
        "event_ids": [uuid4(), uuid4()],
        "start_timestamp": start,
        "end_timestamp": end,
        "group_values": {"data.source_ip": "192.168.1.10"},
    }
    fields.update(overrides)
    return fields


def test_alert_naive_timestamps_rejected():
    naive = datetime(2024, 11, 16, 10, 0, 0)

    with pytest.raises(ValidationError):
        CorrelationAlert(**make_alert_kwargs(start_timestamp=naive))

    with pytest.raises(ValidationError):
        CorrelationAlert(**make_alert_kwargs(end_timestamp=naive, timestamp=naive))

    with pytest.raises(ValidationError):
        CorrelationAlert(**make_alert_kwargs(timestamp=naive))


def test_alert_start_after_end_rejected():
    end = datetime(2024, 11, 16, 10, 1, 0, tzinfo=UTC)
    later = datetime(2024, 11, 16, 10, 2, 0, tzinfo=UTC)

    with pytest.raises(ValidationError, match="start_timestamp"):
        CorrelationAlert(
            **make_alert_kwargs(start_timestamp=later, end_timestamp=end, timestamp=end)
        )


def test_alert_timestamp_must_equal_end_timestamp():
    other = datetime(2024, 11, 16, 10, 5, 0, tzinfo=UTC)

    with pytest.raises(ValidationError, match="timestamp"):
        CorrelationAlert(**make_alert_kwargs(timestamp=other))


def test_alert_single_event_id_rejected():
    with pytest.raises(ValidationError):
        CorrelationAlert(**make_alert_kwargs(event_ids=[uuid4()]))
