from datetime import UTC, datetime

from security_detection_engine.models import EventSource, SecurityEvent
from security_detection_engine.network import (
    NetworkPacketRecord,
    normalize_network_record,
)


def make_record(**overrides) -> NetworkPacketRecord:
    fields = {
        "timestamp": datetime(2024, 5, 1, 12, 30, tzinfo=UTC),
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "protocol": "tcp",
        "source_port": 54321,
        "destination_port": 22,
        "packet_size": 60,
        "tcp_flags": "S",
    }
    fields.update(overrides)
    return NetworkPacketRecord(**fields)


def test_record_becomes_security_event():
    event = normalize_network_record(make_record())

    assert isinstance(event, SecurityEvent)
    assert event.event_id is not None


def test_event_source_is_network():
    event = normalize_network_record(make_record())

    assert event.source is EventSource.NETWORK


def test_event_type_and_optional_fields():
    event = normalize_network_record(make_record())

    assert event.event_type == "network_packet_observed"
    assert event.severity is None
    assert event.host is None


def test_all_fields_copied_to_data():
    event = normalize_network_record(make_record())

    assert event.data == {
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "protocol": "tcp",
        "source_port": 54321,
        "destination_port": 22,
        "packet_size": 60,
        "tcp_flags": "S",
    }


def test_timestamp_preserved():
    record = make_record()

    event = normalize_network_record(record)

    assert event.timestamp == record.timestamp
