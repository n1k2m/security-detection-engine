from pathlib import Path

import pytest

from security_detection_engine.detection import (
    Condition,
    DetectionEngine,
    DetectionRule,
)
from security_detection_engine.models import Severity
from security_detection_engine.windows import analyze_windows_log

NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"


def event_xml(
    event_id: str, timestamp: str = "2024-11-16T10:15:32.000000Z", data: str = ""
) -> str:
    return f"""
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>{event_id}</EventID>
      <TimeCreated SystemTime="{timestamp}"/>
      <Computer>DC-01</Computer>
    </System>
    <EventData>{data}</EventData>
  </Event>
"""


def write_log(path: Path, *events: str) -> Path:
    path.write_text(
        f'<Events xmlns="{NAMESPACE}">{"".join(events)}</Events>',
        encoding="utf-8",
    )
    return path


def test_mixed_log_counts(tmp_path: Path):
    log_file = write_log(
        tmp_path / "mixed.xml",
        event_xml("4624", data='<Data Name="TargetUserName">admin</Data>'),
        event_xml("4625", data='<Data Name="TargetUserName">root</Data>'),
        event_xml("4634"),  # неподдерживаемый Event ID
        event_xml("4624", timestamp="broken"),  # некорректный timestamp
    )

    result = analyze_windows_log(log_file)

    assert result.total_events == 4
    assert result.parsed_events == 2
    assert result.unsupported_events == 1
    assert result.invalid_events == 1
    assert (
        result.total_events
        == result.parsed_events + result.unsupported_events + result.invalid_events
    )


def test_events_content(tmp_path: Path):
    log_file = write_log(
        tmp_path / "logon.xml",
        event_xml("4624", data='<Data Name="TargetUserName">admin</Data>'),
        event_xml("4625", data='<Data Name="TargetUserName">root</Data>'),
    )

    result = analyze_windows_log(log_file)

    assert len(result.events) == 2
    assert result.events[0].event_type == "windows_logon_success"
    assert result.events[0].host == "DC-01"
    assert result.events[1].event_type == "windows_logon_failed"
    assert result.events[1].data["TargetUserName"] == "root"


def test_empty_events_file(tmp_path: Path):
    log_file = write_log(tmp_path / "empty.xml")

    result = analyze_windows_log(log_file)

    assert result.events == []
    assert result.total_events == 0


def test_missing_file_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        analyze_windows_log(tmp_path / "missing.xml")


def test_corrupted_xml_raises_value_error(tmp_path: Path):
    log_file = tmp_path / "broken.xml"
    log_file.write_text("<Events><Event>", encoding="utf-8")

    with pytest.raises(ValueError, match="broken.xml"):
        analyze_windows_log(log_file)


def test_integration_with_detection_engine(tmp_path: Path):
    log_file = write_log(
        tmp_path / "detect.xml",
        event_xml("4624", data='<Data Name="TargetUserName">admin</Data>'),
        event_xml("4625", data='<Data Name="TargetUserName">admin</Data>'),
    )
    rule = DetectionRule(
        rule_id="WIN-001",
        name="Failed logon for admin",
        description="Detects failed Windows logons for the admin account",
        severity=Severity.MEDIUM,
        event_type="windows_logon_failed",
        conditions=[
            Condition(field="data.TargetUserName", operator="equals", value="admin")
        ],
    )

    result = analyze_windows_log(log_file)
    alerts = DetectionEngine([rule]).analyze_events(result.events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "WIN-001"
    assert alerts[0].event_id == result.events[1].event_id
