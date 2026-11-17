from pathlib import Path

import pytest

from security_detection_engine.detection import (
    DetectionRule,
    Operator,
    RuleLoadError,
    load_rule,
    load_rules_from_directory,
)
from security_detection_engine.models import Severity

RULE_YAML = """
rule_id: SSH-001
name: SSH Authentication Failure
description: Detects failed SSH authentication attempts
severity: low
event_type: ssh_authentication_failed
enabled: true

conditions:
  - field: data.authentication_method
    operator: equals
    value: password
"""

SECOND_RULE_YAML = """
rule_id: SSH-002
name: SSH Root Login
description: Detects successful SSH logins as root
severity: high
event_type: ssh_authentication_success

conditions:
  - field: data.username
    operator: equals
    value: root
"""


def test_load_single_rule(tmp_path: Path):
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(RULE_YAML, encoding="utf-8")

    rule = load_rule(rule_file)

    assert isinstance(rule, DetectionRule)
    assert rule.rule_id == "SSH-001"
    assert rule.severity is Severity.LOW
    assert rule.conditions[0].operator is Operator.EQUALS


def test_load_rules_from_directory(tmp_path: Path):
    (tmp_path / "first.yaml").write_text(RULE_YAML, encoding="utf-8")
    (tmp_path / "second.yml").write_text(SECOND_RULE_YAML, encoding="utf-8")

    rules = load_rules_from_directory(tmp_path)

    assert len(rules) == 2
    assert {rule.rule_id for rule in rules} == {"SSH-001", "SSH-002"}


def test_unsupported_file_extensions_are_skipped(tmp_path: Path):
    (tmp_path / "rule.yaml").write_text(RULE_YAML, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a rule", encoding="utf-8")
    (tmp_path / "rule.json").write_text("{}", encoding="utf-8")

    rules = load_rules_from_directory(tmp_path)

    assert len(rules) == 1


def test_empty_directory_returns_empty_list(tmp_path: Path):
    assert load_rules_from_directory(tmp_path) == []


def test_missing_directory_raises_rule_load_error(tmp_path: Path):
    with pytest.raises(RuleLoadError, match="не найдена"):
        load_rules_from_directory(tmp_path / "missing")


def test_invalid_yaml_raises_rule_load_error(tmp_path: Path):
    rule_file = tmp_path / "broken.yaml"
    rule_file.write_text("rule_id: [unclosed\n  bad indent", encoding="utf-8")

    with pytest.raises(RuleLoadError, match="broken.yaml"):
        load_rule(rule_file)


def test_non_dict_yaml_raises_rule_load_error(tmp_path: Path):
    rule_file = tmp_path / "list.yaml"
    rule_file.write_text("- just\n- a\n- list\n", encoding="utf-8")

    with pytest.raises(RuleLoadError, match="list.yaml"):
        load_rule(rule_file)


def test_invalid_rule_fields_raise_rule_load_error(tmp_path: Path):
    rule_file = tmp_path / "invalid.yaml"
    rule_file.write_text(
        RULE_YAML.replace("operator: equals", "operator: regex"),
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="invalid.yaml"):
        load_rule(rule_file)


def test_missing_rule_file_raises_rule_load_error(tmp_path: Path):
    with pytest.raises(RuleLoadError):
        load_rule(tmp_path / "missing.yaml")
