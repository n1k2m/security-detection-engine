from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import wrpcap

from security_detection_engine.detection import (
    Condition,
    DetectionEngine,
    DetectionRule,
)
from security_detection_engine.models import Severity
from security_detection_engine.network import analyze_pcap


def write_pcap(path: Path, packets: list):
    wrpcap(str(path), packets)


def test_mixed_pcap_counts(tmp_path: Path):
    pcap_file = tmp_path / "mixed.pcap"
    write_pcap(
        pcap_file,
        [
            IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54321, dport=22),
            IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53),
            IP(src="192.168.1.10", dst="10.0.0.5") / ICMP(),
            IP(src="192.168.1.10", dst="10.0.0.5", proto=2),  # IGMP
            IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54321, dport=0),
        ],
    )

    result = analyze_pcap(pcap_file)

    assert result.total_packets == 5
    assert result.parsed_packets == 3
    assert result.unsupported_packets == 1
    assert result.invalid_packets == 1
    assert (
        result.total_packets
        == result.parsed_packets + result.unsupported_packets + result.invalid_packets
    )


def test_events_created_for_parsed_packets(tmp_path: Path):
    pcap_file = tmp_path / "events.pcap"
    write_pcap(
        pcap_file,
        [
            IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54321, dport=22),
            IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53),
        ],
    )

    result = analyze_pcap(pcap_file)

    assert len(result.events) == result.parsed_packets == 2
    assert result.events[0].event_type == "network_packet_observed"
    assert result.events[0].data["protocol"] == "tcp"
    assert result.events[1].data["protocol"] == "udp"


def test_empty_pcap(tmp_path: Path):
    pcap_file = tmp_path / "empty.pcap"
    write_pcap(pcap_file, [])

    result = analyze_pcap(pcap_file)

    assert result.events == []
    assert result.total_packets == 0
    assert result.parsed_packets == 0
    assert result.unsupported_packets == 0
    assert result.invalid_packets == 0


def test_missing_file_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        analyze_pcap(tmp_path / "missing.pcap")


def test_integration_with_detection_engine(tmp_path: Path):
    pcap_file = tmp_path / "detect.pcap"
    write_pcap(
        pcap_file,
        [
            IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54321, dport=22),
            IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=54322, dport=8080),
        ],
    )
    rule = DetectionRule(
        rule_id="NET-001",
        name="Connection to non-standard port",
        description="Detects TCP connections to ports above 1024",
        severity=Severity.MEDIUM,
        event_type="network_packet_observed",
        conditions=[
            Condition(
                field="data.destination_port",
                operator="greater_than",
                value=1024,
            )
        ],
    )

    result = analyze_pcap(pcap_file)
    alerts = DetectionEngine([rule]).analyze_events(result.events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "NET-001"
    assert alerts[0].severity is Severity.MEDIUM
    assert alerts[0].event_id == result.events[1].event_id
