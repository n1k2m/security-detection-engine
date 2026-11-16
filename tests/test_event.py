from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from security_detection_engine.models import EventSource, SecurityEvent, Severity


def make_event(**overrides) -> SecurityEvent:
    fields = {
        "timestamp": datetime.now(UTC),
        "source": EventSource.LINUX,
        "event_type": "authentication_failure",
    }
    fields.update(overrides)
    return SecurityEvent(**fields)


def test_create_valid_event():
    event = make_event(
        severity=Severity.MEDIUM,
        host="web-server-01",
        data={"username": "root", "attempts": 5},
    )

    assert isinstance(event.event_id, UUID)
    assert event.source is EventSource.LINUX
    assert event.severity is Severity.MEDIUM
    assert event.host == "web-server-01"
    assert event.data == {"username": "root", "attempts": 5}


def test_event_id_generated_automatically():
    first = make_event()
    second = make_event()

    assert isinstance(first.event_id, UUID)
    assert first.event_id != second.event_id


def test_event_id_can_be_provided_explicitly():
    explicit_id = UUID("12345678-1234-5678-1234-567812345678")
    event = make_event(event_id=explicit_id)

    assert event.event_id == explicit_id


def test_timestamp_preserved_with_timezone():
    tz = timezone(timedelta(hours=3))
    moment = datetime(2024, 5, 1, 12, 30, tzinfo=tz)
    event = make_event(timestamp=moment)

    assert event.timestamp == moment
    assert event.timestamp.utcoffset() == timedelta(hours=3)


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        make_event(timestamp=datetime(2024, 5, 1, 12, 30))


def test_severity_and_host_optional_by_default():
    event = make_event()

    assert event.severity is None
    assert event.host is None
    assert event.data == {}


def test_missing_required_fields_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent()


def test_empty_event_type_rejected():
    with pytest.raises(ValidationError):
        make_event(event_type="")

    with pytest.raises(ValidationError):
        make_event(event_type="   ")


def test_unknown_source_rejected():
    with pytest.raises(ValidationError):
        make_event(source="mainframe")


def test_unknown_severity_rejected():
    with pytest.raises(ValidationError):
        make_event(severity="extreme")


def test_source_accepts_string_value():
    event = make_event(source="windows")

    assert event.source is EventSource.WINDOWS


def test_host_whitespace_stripped():
    event = make_event(host="  dc-01  ")

    assert event.host == "dc-01"

def test_data_is_not_shared_between_events():
    first = make_event()
    second = make_event()

    first.data["username"] = "root"

    assert second.data == {}