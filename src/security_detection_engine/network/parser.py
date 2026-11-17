from datetime import UTC, datetime

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet

from security_detection_engine.network.models import NetworkPacketRecord


def is_supported_packet(packet: Packet) -> bool:
    """Проверяет, содержит ли пакет поддерживаемые IPv4/TCP/UDP/ICMP данные."""
    return packet.haslayer(IP) and (
        packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)
    )


def parse_packet(packet: Packet) -> NetworkPacketRecord | None:
    """Извлекает сетевые метаданные из пакета Scapy.

    Возвращает None для пакетов без поддерживаемого содержимого
    и для пакетов с некорректными данными.
    """
    if not is_supported_packet(packet):
        return None

    ip = packet[IP]
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)

    try:
        timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)

        if tcp is not None:
            protocol = "tcp"
            source_port = tcp.sport
            destination_port = tcp.dport
            tcp_flags = str(tcp.flags)
        elif udp is not None:
            protocol = "udp"
            source_port = udp.sport
            destination_port = udp.dport
            tcp_flags = None
        else:
            protocol = "icmp"
            source_port = None
            destination_port = None
            tcp_flags = None

        return NetworkPacketRecord(
            timestamp=timestamp,
            source_ip=ip.src,
            destination_ip=ip.dst,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            packet_size=len(packet),
            tcp_flags=tcp_flags,
        )
    except (ValueError, TypeError, OverflowError, OSError):
        # Некорректный timestamp, порты или адреса — пакет пропускается
        return None
