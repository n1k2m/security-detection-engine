from pathlib import Path

import yaml
from pydantic import ValidationError

from security_detection_engine.detection.models import DetectionRule

_SUPPORTED_SUFFIXES = (".yaml", ".yml")


class RuleLoadError(Exception):
    """Ошибка загрузки или валидации YAML-правила."""


def load_rule(path: str | Path) -> DetectionRule:
    """Загружает одно правило обнаружения из YAML-файла."""
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleLoadError(f"не удалось прочитать файл правила {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"некорректный YAML в файле {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuleLoadError(f"файл {path} не содержит описание правила")

    try:
        return DetectionRule.model_validate(raw)
    except ValidationError as exc:
        raise RuleLoadError(f"некорректное правило в файле {path}: {exc}") from exc


def load_rules_from_directory(directory: str | Path) -> list[DetectionRule]:
    """Загружает все YAML-правила из директории.

    Файлы с другими расширениями игнорируются.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise RuleLoadError(f"директория правил не найдена: {directory}")

    rules = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in _SUPPORTED_SUFFIXES:
            rules.append(load_rule(path))
    return rules
