from datetime import UTC

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from security_detection_engine.network import parse_packet


def test_tcp_packet_parsed():
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(
        sport=54321, dport=22, flags="S"
    )

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "tcp"
    assert record.source_ip == "192.168.1.10"
    assert record.destination_ip == "10.0.0.5"
    assert record.source_port == 54321
    assert record.destination_port == 22
    assert record.tcp_flags == "S"
    assert record.packet_size == len(packet)
    assert record.timestamp.tzinfo is not None
    assert record.timestamp.utcoffset() == UTC.utcoffset(None)


def test_udp_packet_parsed():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53)

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "udp"
    assert record.source_port == 12345
    assert record.destination_port == 53
    assert record.tcp_flags is None


def test_icmp_packet_parsed():
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / ICMP()

    record = parse_packet(packet)

    assert record is not None
    assert record.protocol == "icmp"
    assert record.source_port is None
    assert record.destination_port is None
    assert record.tcp_flags is None


def test_packet_without_ipv4_returns_none():
    packet = Ether() / ARP(pdst="192.168.1.1")

    assert parse_packet(packet) is None


def test_ipv4_with_unsupported_transport_returns_none():
    packet = IP(src="192.168.1.10", dst="10.0.0.5", proto=2)

    assert parse_packet(packet) is None


def test_missing_timestamp_returns_none():
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / TCP()
    packet.time = None

    assert parse_packet(packet) is None


def test_invalid_timestamp_returns_none():
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / TCP()
    packet.time = "not-a-timestamp"

    assert parse_packet(packet) is None


def test_invalid_port_returns_none():
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54321, dport=0)

    assert parse_packet(packet) is None


def test_extreme_timestamp_returns_none():
    # 10**20 секунд выходит за диапазон datetime и вызывает OverflowError
    packet = IP(src="192.168.1.10", dst="10.0.0.5") / TCP()
    packet.time = 10**20

    assert parse_packet(packet) is None
