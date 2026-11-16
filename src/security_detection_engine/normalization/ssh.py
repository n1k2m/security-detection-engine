from security_detection_engine.models import EventSource, SecurityEvent, Severity
from security_detection_engine.parsers import SshAuthRecord


def normalize_ssh_record(record: SshAuthRecord) -> SecurityEvent:
    """Преобразует запись SSH-аутентификации в SecurityEvent."""
    if record.success:
        event_type = "ssh_authentication_success"
        severity = None
    else:
        event_type = "ssh_authentication_failed"
        severity = Severity.LOW

    return SecurityEvent(
        timestamp=record.timestamp,
        source=EventSource.LINUX,
        event_type=event_type,
        severity=severity,
        host=record.hostname,
        data={
            "username": record.username,
            "source_ip": record.source_ip,
            "source_port": record.source_port,
            "authentication_method": record.authentication_method,
            "process_id": record.process_id,
            "invalid_user": record.invalid_user,
        },
    )
