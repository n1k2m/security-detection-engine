from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from security_detection_engine.detection import (
    Alert,
    Condition,
    DetectionRule,
    Operator,
)
from security_detection_engine.models import Severity


def make_rule_dict(**overrides) -> dict:
    fields = {
        "rule_id": "SSH-001",
        "name": "SSH Authentication Failure",
        "description": "Detects failed SSH authentication attempts",
        "severity": "low",
        "event_type": "ssh_authentication_failed",
        "conditions": [
            {
                "field": "data.authentication_method",
                "operator": "equals",
                "value": "password",
            }
        ],
    }
    fields.update(overrides)
    return fields


def test_valid_rule_created():
    rule = DetectionRule.model_validate(make_rule_dict())

    assert rule.rule_id == "SSH-001"
    assert rule.severity is Severity.LOW
    assert rule.enabled is True
    assert len(rule.conditions) == 1
    assert rule.conditions[0].operator is Operator.EQUALS


def test_rule_defaults():
    rule = DetectionRule(
        rule_id="R-1",
        name="Test",
        description="Test rule",
        severity=Severity.MEDIUM,
        event_type="test_event",
    )

    assert rule.conditions == []
    assert rule.enabled is True


def test_empty_required_fields_rejected():
    with pytest.raises(ValidationError):
        DetectionRule.model_validate(make_rule_dict(rule_id=""))

    with pytest.raises(ValidationError):
        DetectionRule.model_validate(make_rule_dict(name="   "))

    with pytest.raises(ValidationError):
        DetectionRule.model_validate(make_rule_dict(event_type=""))


def test_missing_required_fields_rejected():
    with pytest.raises(ValidationError):
        DetectionRule.model_validate({"rule_id": "R-1"})


def test_unknown_operator_rejected():
    with pytest.raises(ValidationError):
        Condition(field="data.username", operator="regex", value="root")


def test_invalid_condition_structure_rejected():
    with pytest.raises(ValidationError):
        DetectionRule.model_validate(
            make_rule_dict(conditions=[{"field": "data.username"}])
        )


def test_unknown_severity_rejected():
    with pytest.raises(ValidationError):
        DetectionRule.model_validate(make_rule_dict(severity="extreme"))


def test_alert_created_with_generated_id():
    first = Alert(
        rule_id="SSH-001",
        rule_name="SSH Authentication Failure",
        description="Detects failed SSH authentication attempts",
        severity=Severity.LOW,
        event_id=uuid4(),
        timestamp=datetime.now(UTC),
    )
    second = Alert(
        rule_id="SSH-001",
        rule_name="SSH Authentication Failure",
        description="Detects failed SSH authentication attempts",
        severity=Severity.LOW,
        event_id=uuid4(),
        timestamp=datetime.now(UTC),
    )

    assert isinstance(first.alert_id, UUID)
    assert first.alert_id != second.alert_id


def test_empty_condition_field_rejected():
    with pytest.raises(ValidationError):
        Condition(field="", operator="equals", value="x")

    with pytest.raises(ValidationError):
        Condition(field="   ", operator="equals", value="x")


def test_condition_field_whitespace_stripped():
    condition = Condition(field="  data.username  ", operator="equals", value="root")

    assert condition.field == "data.username"


def test_condition_field_with_empty_segments_rejected():
    for bad_path in ("data..username", ".data.username", "data.username."):
        with pytest.raises(ValidationError):
            Condition(field=bad_path, operator="equals", value="x")


def test_valid_condition_field_paths():
    for path in ("event_type", "data.username", "data.source_ip"):
        condition = Condition(field=path, operator="equals", value="x")
        assert condition.field == path
