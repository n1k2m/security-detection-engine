from dataclasses import dataclass, field
from pathlib import Path

from security_detection_engine.models import SecurityEvent
from security_detection_engine.windows.normalizer import normalize_windows_record
from security_detection_engine.windows.parser import ParseStatus, parse_event
from security_detection_engine.windows.reader import read_events


@dataclass
class WindowsAnalysisResult:
    """Итог анализа XML-экспорта Windows Event Log."""

    events: list[SecurityEvent] = field(default_factory=list)
    total_events: int = 0
    parsed_events: int = 0
    unsupported_events: int = 0
    invalid_events: int = 0


def analyze_windows_log(path: str | Path) -> WindowsAnalysisResult:
    """Анализирует XML-файл с событиями Windows Event Log.

    Неподдерживаемые и повреждённые события не прерывают обработку,
    а учитываются в статистике результата. Ошибки чтения файла
    передаются вызывающему коду.
    """
    result = WindowsAnalysisResult()
    for element in read_events(path):
        result.total_events += 1
        parsed = parse_event(element)
        if parsed.status is ParseStatus.PARSED and parsed.record is not None:
            result.parsed_events += 1
            result.events.append(normalize_windows_record(parsed.record))
        elif parsed.status is ParseStatus.UNSUPPORTED:
            result.unsupported_events += 1
        else:
            result.invalid_events += 1
    return result
