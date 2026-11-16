from collections.abc import Iterator
from pathlib import Path


def read_log_lines(path: str | Path) -> Iterator[str]:
    """Читает лог-файл построчно, не загружая его целиком в память.

    Повреждённые байты заменяются символом U+FFFD, чтобы ошибки
    декодирования не прерывали обработку файла.
    """
    with open(path, encoding="utf-8", errors="replace") as file:
        for line in file:
            yield line.rstrip("\r\n")
