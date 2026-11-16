from datetime import UTC

from security_detection_engine.models import EventSource, Severity
from security_detection_engine.normalization import normalize_ssh_record
from security_detection_engine.parsers import parse_ssh_auth_line

YEAR = 2024
TZ = UTC


def make_record(line: str):
    result = parse_ssh_auth_line(line, year=YEAR, tz=TZ)
    assert result.record is not None
    return result.record


def test_failed_login_becomes_security_event():
    record = make_record(
        "Nov 16 10:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2"
    )

    event = normalize_ssh_record(record)

    assert event.event_type == "ssh_authentication_failed"
    assert event.severity is Severity.LOW
    assert event.source is EventSource.LINUX
    assert event.host == "server"
    assert event.timestamp == record.timestamp
    assert event.event_id is not None


def test_successful_login_becomes_security_event():
    record = make_record(
        "Nov 16 10:18:22 server sshd[1234]: Accepted publickey for admin "
        "from 192.168.1.10 port 54321 ssh2"
    )

    event = normalize_ssh_record(record)

    assert event.event_type == "ssh_authentication_success"
    assert event.severity is None
    assert event.source is EventSource.LINUX
    assert event.host == "server"
    assert event.timestamp == record.timestamp
    assert event.data == {
        "username": "admin",
        "source_ip": "192.168.1.10",
        "source_port": 54321,
        "authentication_method": "publickey",
        "process_id": 1234,
        "invalid_user": False,
    }


def test_event_data_contains_extracted_fields():
    record = make_record(
        "Nov 16 10:17:11 server sshd[1234]: Failed password for invalid user "
        "test from 192.168.1.10 port 54321 ssh2"
    )

    event = normalize_ssh_record(record)

    assert event.data == {
        "username": "test",
        "source_ip": "192.168.1.10",
        "source_port": 54321,
        "authentication_method": "password",
        "process_id": 1234,
        "invalid_user": True,
    }
