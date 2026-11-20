from pathlib import Path

import pytest

from security_detection_engine.correlation import (
    CorrelationRule,
    load_correlation_rule,
    load_correlation_rules_from_directory,
)
from security_detection_engine.detection import RuleLoadError
from security_detection_engine.models import Severity

RULE_YAML = """
rule_id: CORR-001
name: Failed then successful login
description: Failed logins followed by a successful one
severity: high
time_window_seconds: 300

group_by:
  - data.source_ip

steps:
  - event_type: ssh_authentication_failed
    conditions:
      - field: data.authentication_method
        operator: equals
        value: password
  - event_type: ssh_authentication_success
"""

SECOND_RULE_YAML = """
rule_id: CORR-002
name: Two failures
description: Two failed logins in a row
severity: medium
time_window_seconds: 60

group_by:
  - data.source_ip

steps:
  - event_type: ssh_authentication_failed
  - event_type: ssh_authentication_failed
"""


def test_load_single_rule(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(RULE_YAML, encoding="utf-8")

    rule = load_correlation_rule(rule_file)

    assert isinstance(rule, CorrelationRule)
    assert rule.rule_id == "CORR-001"
    assert rule.severity is Severity.HIGH
    assert rule.time_window_seconds == 300
    assert rule.steps[0].conditions[0].value == "password"


def test_load_rules_from_directory(tmp_path: Path):
    (tmp_path / "first.yaml").write_text(RULE_YAML, encoding="utf-8")
    (tmp_path / "second.yml").write_text(SECOND_RULE_YAML, encoding="utf-8")

    rules = load_correlation_rules_from_directory(tmp_path)

    assert len(rules) == 2
    assert {rule.rule_id for rule in rules} == {"CORR-001", "CORR-002"}


def test_unsupported_file_extensions_are_skipped(tmp_path: Path):
    (tmp_path / "rule.yaml").write_text(RULE_YAML, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a rule", encoding="utf-8")

    assert len(load_correlation_rules_from_directory(tmp_path)) == 1


def test_invalid_yaml_raises_rule_load_error(tmp_path: Path):
    rule_file = tmp_path / "broken.yaml"
    rule_file.write_text("steps: [unclosed\n  bad: indent", encoding="utf-8")

    with pytest.raises(RuleLoadError, match="broken.yaml"):
        load_correlation_rule(rule_file)


def test_invalid_rule_fields_raise_rule_load_error(tmp_path: Path):
    rule_file = tmp_path / "invalid.yaml"
    rule_file.write_text(
        RULE_YAML.replace("operator: equals", "operator: regex"),
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="invalid.yaml"):
        load_correlation_rule(rule_file)


def test_missing_directory_raises_rule_load_error(tmp_path: Path):
    with pytest.raises(RuleLoadError, match="не найдена"):
        load_correlation_rules_from_directory(tmp_path / "missing")


def test_packaged_rule_loads():
    rules_dir = (
        Path(__file__).parent.parent
        / "src"
        / "security_detection_engine"
        / "rules"
        / "correlation"
    )

    rules = load_correlation_rules_from_directory(rules_dir)

    assert len(rules) == 1
    assert rules[0].rule_id == "CORR-SSH-001"
    assert [step.event_type for step in rules[0].steps] == [
        "ssh_authentication_failed",
        "ssh_authentication_failed",
        "ssh_authentication_failed",
        "ssh_authentication_success",
    ]
