from dataclasses import dataclass, field
from datetime import tzinfo
from pathlib import Path

from security_detection_engine.collectors import read_log_lines
from security_detection_engine.models import SecurityEvent
from security_detection_engine.normalization import normalize_ssh_record
from security_detection_engine.parsers import ParseStatus, parse_ssh_auth_line


@dataclass
class LogAnalysisResult:
    """Итог анализа лог-файла: события и статистика пропущенных строк."""

    events: list[SecurityEvent] = field(default_factory=list)
    unsupported_lines: int = 0
    invalid_lines: int = 0


def analyze_ssh_log(path: str | Path, *, year: int, tz: tzinfo) -> LogAnalysisResult:
    """Анализирует файл Linux auth log и возвращает события SSH-аутентификации.

    Неподдерживаемые и некорректные строки не прерывают обработку,
    а учитываются в статистике результата.
    """
    result = LogAnalysisResult()
    for line in read_log_lines(path):
        parsed = parse_ssh_auth_line(line, year=year, tz=tz)
        if parsed.status is ParseStatus.PARSED and parsed.record is not None:
            result.events.append(normalize_ssh_record(parsed.record))
        elif parsed.status is ParseStatus.INVALID:
            result.invalid_lines += 1
        else:
            result.unsupported_lines += 1
    return result
