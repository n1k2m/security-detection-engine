import ipaddress
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class NetworkPacketRecord(BaseModel):
    """Промежуточная модель сетевого пакета, извлечённого из PCAP."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str = Field(min_length=1)
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    packet_size: int = Field(ge=0)
    tcp_flags: str | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp должен содержать информацию о часовом поясе")
        return value

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def ip_must_be_valid_ipv4(cls, value: str) -> str:
        # IPv4Address отклоняет и некорректные адреса, и IPv6
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError(f"некорректный IPv4-адрес: {value}") from None
        return value

    @field_validator("protocol")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("значение не должно быть пустой строкой")
        return value
