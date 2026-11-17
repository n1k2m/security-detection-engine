from pathlib import Path

import pytest
from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import wrpcap

from security_detection_engine.network import read_pcap


def test_reads_existing_pcap(tmp_path: Path):
    pcap_file = tmp_path / "one.pcap"
    wrpcap(str(pcap_file), IP(src="192.168.1.10", dst="10.0.0.5") / TCP())

    packets = list(read_pcap(pcap_file))

    assert len(packets) == 1
    assert packets[0].haslayer(TCP)


def test_reads_multiple_packets(tmp_path: Path):
    pcap_file = tmp_path / "multi.pcap"
    wrpcap(
        str(pcap_file),
        [
            IP(src="192.168.1.10", dst="10.0.0.5") / TCP(dport=22),
            IP(src="192.168.1.10", dst="10.0.0.5") / UDP(dport=53),
            IP(src="192.168.1.10", dst="10.0.0.5") / ICMP(),
        ],
    )

    packets = list(read_pcap(pcap_file))

    assert len(packets) == 3


def test_missing_file_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        list(read_pcap(tmp_path / "missing.pcap"))


def test_file_handle_closed_after_iteration(tmp_path: Path):
    pcap_file = tmp_path / "close.pcap"
    wrpcap(str(pcap_file), IP() / TCP())

    packets = read_pcap(pcap_file)
    next(packets)
    packets.close()

    # Windows не даёт удалить файл с открытым дескриптором
    pcap_file.unlink()
    assert not pcap_file.exists()


def test_corrupted_file_raises_value_error(tmp_path: Path):
    pcap_file = tmp_path / "broken.pcap"
    pcap_file.write_bytes(b"this is definitely not a pcap file")

    with pytest.raises(ValueError, match="broken.pcap"):
        list(read_pcap(pcap_file))


def test_truncated_packet_data_does_not_crash(tmp_path: Path):
    pcap_file = tmp_path / "truncated.pcap"
    wrpcap(str(pcap_file), IP(src="192.168.1.10", dst="10.0.0.5") / TCP(dport=22))
    data = pcap_file.read_bytes()
    # Корректный заголовок PCAP, но данные пакета обрезаны
    pcap_file.write_bytes(data[: len(data) - 10])

    packets = list(read_pcap(pcap_file))

    assert len(packets) == 1


class _BrokenReader:
    """Заглушка PcapReader, выбрасывающая ошибку при чтении."""

    instances: list = []

    def __init__(self, path: str):
        self.closed = False
        _BrokenReader.instances.append(self)

    def __iter__(self):
        raise Scapy_Exception("broken packet data")

    def close(self):
        self.closed = True


def test_reader_closed_on_read_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _BrokenReader.instances.clear()
    monkeypatch.setattr(
        "security_detection_engine.network.reader.PcapReader", _BrokenReader
    )
    target = tmp_path / "broken.pcap"
    target.write_bytes(b"dummy")

    with pytest.raises(ValueError, match="broken.pcap"):
        list(read_pcap(target))

    assert _BrokenReader.instances[0].closed is True


def test_reader_closed_on_oserror_during_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = False

    class FakePcapReader:
        def __init__(self, path: str) -> None:
            pass

        def __iter__(self):
            raise OSError("simulated read error")

        def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(
        "security_detection_engine.network.reader.PcapReader",
        FakePcapReader,
    )

    with pytest.raises(ValueError, match="ошибка чтения PCAP-файла"):
        list(read_pcap("test.pcap"))

    assert closed
