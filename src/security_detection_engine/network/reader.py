from collections.abc import Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapReader


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """Читает пакеты из PCAP-файла последовательно, не загружая его в память.

    Отсутствующий файл приводит к FileNotFoundError, повреждённый файл —
    к ValueError с указанием пути.
    """
    try:
        reader = PcapReader(str(path))
    except Scapy_Exception as exc:
        raise ValueError(f"не удалось открыть PCAP-файл {path}: {exc}") from exc
    try:
        yield from reader
    except (Scapy_Exception, OSError) as exc:
        raise ValueError(f"ошибка чтения PCAP-файла {path}: {exc}") from exc
    finally:
        reader.close()
