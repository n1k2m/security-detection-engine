from collections.abc import Iterator
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError, iterparse


def read_events(path: str | Path) -> Iterator[Element]:
    """Читает элементы Event из XML-экспорта Windows Event Log.

    Файл обрабатывается последовательно, без загрузки целиком в память:
    обработанные элементы Event удаляются из родительского элемента, чтобы
    корень не накапливал их при разборе большого файла. Пространства имён
    игнорируются — элементы сопоставляются по локальному имени. Отсутствующий
    файл приводит к FileNotFoundError, повреждённый XML — к ValueError
    с указанием пути.
    """
    try:
        parents: list[Element] = []
        for action, element in iterparse(path, events=("start", "end")):
            if action == "start":
                parents.append(element)
                continue
            parents.pop()
            if _local_name(element.tag) == "Event":
                yield element
                if parents:
                    parents[-1].remove(element)
    except ParseError as exc:
        raise ValueError(f"некорректный XML в файле {path}: {exc}") from exc


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
