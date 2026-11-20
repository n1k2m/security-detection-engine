from pathlib import Path

from security_detection_engine.correlation.models import CorrelationRule
from security_detection_engine.detection.loader import (
    load_rule_directory,
    load_rule_file,
)


def load_correlation_rule(path: str | Path) -> CorrelationRule:
    """Загружает одно корреляционное правило из YAML-файла."""
    return load_rule_file(Path(path), CorrelationRule)


def load_correlation_rules_from_directory(
    directory: str | Path,
) -> list[CorrelationRule]:
    """Загружает все YAML-правила корреляции из директории.

    Файлы с другими расширениями игнорируются.
    """
    return load_rule_directory(Path(directory), CorrelationRule)
