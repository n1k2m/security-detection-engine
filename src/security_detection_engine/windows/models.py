from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class WindowsEventRecord(BaseModel):
    """Промежуточная модель события Windows Event Log, извлечённого из XML."""

    event_id: int = Field(gt=0)
    timestamp: datetime
    computer: str | None = None
    provider: str | None = None
    event_data: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp должен содержать информацию о часовом поясе")
        return value
