from dataclasses import dataclass, field
from pathlib import Path

from security_detection_engine.models import SecurityEvent
from security_detection_engine.network.normalizer import normalize_network_record
from security_detection_engine.network.parser import is_supported_packet, parse_packet
from security_detection_engine.network.reader import read_pcap


@dataclass
class NetworkAnalysisResult:
    """Итог анализа PCAP-файла: события и статистика пакетов."""

    events: list[SecurityEvent] = field(default_factory=list)
    total_packets: int = 0
    parsed_packets: int = 0
    unsupported_packets: int = 0
    invalid_packets: int = 0


def analyze_pcap(path: str | Path) -> NetworkAnalysisResult:
    """Анализирует PCAP-файл и возвращает нормализованные сетевые события.

    Один некорректный пакет не прерывает анализ остальных.
    Ошибки открытия и чтения файла передаются вызывающему коду.
    """
    result = NetworkAnalysisResult()
    for packet in read_pcap(path):
        result.total_packets += 1
        if not is_supported_packet(packet):
            result.unsupported_packets += 1
            continue
        record = parse_packet(packet)
        if record is None:
            result.invalid_packets += 1
            continue
        result.parsed_packets += 1
        result.events.append(normalize_network_record(record))
    return result
