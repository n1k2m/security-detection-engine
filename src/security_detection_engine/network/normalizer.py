from security_detection_engine.models import EventSource, SecurityEvent
from security_detection_engine.network.models import NetworkPacketRecord


def normalize_network_record(record: NetworkPacketRecord) -> SecurityEvent:
    """Преобразует запись сетевого пакета в SecurityEvent."""
    return SecurityEvent(
        timestamp=record.timestamp,
        source=EventSource.NETWORK,
        event_type="network_packet_observed",
        severity=None,
        host=None,
        data={
            "source_ip": record.source_ip,
            "destination_ip": record.destination_ip,
            "protocol": record.protocol,
            "source_port": record.source_port,
            "destination_port": record.destination_port,
            "packet_size": record.packet_size,
            "tcp_flags": record.tcp_flags,
        },
    )
