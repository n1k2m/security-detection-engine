from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from security_detection_engine.network import NetworkPacketRecord


def make_record(**overrides) -> NetworkPacketRecord:
    fields = {
        "timestamp": datetime.now(UTC),
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


def test_valid_tcp_record():
    record = make_record()

    assert record.protocol == "tcp"
    assert record.source_port == 54321
    assert record.tcp_flags == "S"


def test_valid_udp_record():
    record = make_record(protocol="udp", destination_port=53, tcp_flags=None)

    assert record.protocol == "udp"
    assert record.tcp_flags is None


def test_invalid_ipv4_rejected():
    with pytest.raises(ValidationError):
        make_record(source_ip="999.999.999.999")

    with pytest.raises(ValidationError):
        make_record(destination_ip="not-an-ip")


def test_ipv6_rejected():
    with pytest.raises(ValidationError):
        make_record(source_ip="2001:db8::1")


def test_invalid_port_rejected():
    with pytest.raises(ValidationError):
        make_record(source_port=0)

    with pytest.raises(ValidationError):
        make_record(destination_port=65536)


def test_ports_may_be_absent():
    record = make_record(protocol="icmp", source_port=None, destination_port=None)

    assert record.source_port is None
    assert record.destination_port is None


def test_negative_packet_size_rejected():
    with pytest.raises(ValidationError):
        make_record(packet_size=-1)


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        make_record(timestamp=datetime(2024, 5, 1, 12, 30))


def test_empty_protocol_rejected():
    with pytest.raises(ValidationError):
        make_record(protocol="")

    with pytest.raises(ValidationError):
        make_record(protocol="   ")
