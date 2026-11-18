from datetime import UTC, datetime

from security_detection_engine.models import EventSource, Severity
from security_detection_engine.windows import (
    WindowsEventRecord,
    normalize_windows_record,
)


def make_record(event_id: int, **overrides) -> WindowsEventRecord:
    fields = {
        "event_id": event_id,
        "timestamp": datetime(2024, 11, 16, 10, 15, 32, tzinfo=UTC),
        "computer": "DC-01",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_data": {"TargetUserName": "admin", "LogonType": "10"},
    }
    fields.update(overrides)
    return WindowsEventRecord(**fields)


def test_logon_success_normalized():
    event = normalize_windows_record(make_record(4624))

    assert event.event_type == "windows_logon_success"
    assert event.severity is None
    assert event.source is EventSource.WINDOWS


def test_logon_failure_normalized():
    event = normalize_windows_record(make_record(4625))

    assert event.event_type == "windows_logon_failed"
    assert event.severity is Severity.LOW
    assert event.source is EventSource.WINDOWS


def test_computer_becomes_host_and_timestamp_preserved():
    record = make_record(4624)

    event = normalize_windows_record(record)

    assert event.host == "DC-01"
    assert event.timestamp == record.timestamp


def test_event_id_and_data_preserved():
    event = normalize_windows_record(make_record(4625))

    assert event.data["event_id"] == 4625
    assert event.data["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event.data["TargetUserName"] == "admin"
    assert event.data["LogonType"] == "10"
