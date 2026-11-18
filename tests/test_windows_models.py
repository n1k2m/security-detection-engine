from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from security_detection_engine.windows import WindowsEventRecord


def make_record(**overrides) -> WindowsEventRecord:
    fields = {
        "event_id": 4624,
        "timestamp": datetime.now(UTC),
        "computer": "DC-01",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_data": {"TargetUserName": "admin"},
    }
    fields.update(overrides)
    return WindowsEventRecord(**fields)


def test_valid_record():
    record = make_record()

    assert record.event_id == 4624
    assert record.computer == "DC-01"
    assert record.event_data == {"TargetUserName": "admin"}


def test_optional_fields_default():
    record = WindowsEventRecord(event_id=4625, timestamp=datetime.now(UTC))

    assert record.computer is None
    assert record.provider is None
    assert record.event_data == {}


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        make_record(timestamp=datetime(2024, 5, 1, 12, 30))


def test_invalid_event_id_rejected():
    with pytest.raises(ValidationError):
        make_record(event_id=0)

    with pytest.raises(ValidationError):
        make_record(event_id="not-a-number")
