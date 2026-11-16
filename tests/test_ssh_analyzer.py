from datetime import UTC
from pathlib import Path

import pytest

from security_detection_engine.analyzer import analyze_ssh_log
from security_detection_engine.parsers import ParseResult, ParseStatus

YEAR = 2024
TZ = UTC

FAILED_LINE = (
    "Nov 16 10:15:32 server sshd[1234]: Failed password for root "
    "from 192.168.1.10 port 54321 ssh2"
)
ACCEPTED_LINE = (
    "Nov 16 10:16:02 server sshd[1234]: Accepted publickey for admin "
    "from 192.168.1.10 port 54321 ssh2"
)
UNSUPPORTED_LINE = (
    "Nov 16 10:20:00 server sshd[1234]: pam_unix(sshd:session): "
    "session opened for user admin"
)
INVALID_LINE = "Nov 16 10:15:32 server sshd[1234]: Failed password for root from"


def test_empty_file_produces_empty_result(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    result = analyze_ssh_log(log_file, year=YEAR, tz=TZ)

    assert result.events == []
    assert result.unsupported_lines == 0
    assert result.invalid_lines == 0


def test_missing_file_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        analyze_ssh_log(tmp_path / "missing.log", year=YEAR, tz=TZ)


def test_multiple_lines_are_classified(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join([FAILED_LINE, ACCEPTED_LINE, UNSUPPORTED_LINE, INVALID_LINE]) + "\n",
        encoding="utf-8",
    )

    result = analyze_ssh_log(log_file, year=YEAR, tz=TZ)

    assert len(result.events) == 2
    assert result.events[0].event_type == "ssh_authentication_failed"
    assert result.events[1].event_type == "ssh_authentication_success"
    assert result.unsupported_lines == 1
    assert result.invalid_lines == 1


def test_file_with_corrupted_bytes_does_not_crash(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(FAILED_LINE.encode() + b"\n" + b"\xff\xfe broken\n")

    result = analyze_ssh_log(log_file, year=YEAR, tz=TZ)

    assert len(result.events) == 1
    assert result.unsupported_lines == 1
    assert result.invalid_lines == 0


def test_inconsistent_parse_result_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # PARSED без record — неконсистентный результат парсера
    monkeypatch.setattr(
        "security_detection_engine.analyzer.parse_ssh_auth_line",
        lambda line, *, year, tz: ParseResult(ParseStatus.PARSED, record=None),
    )
    log_file = tmp_path / "auth.log"
    log_file.write_text(FAILED_LINE + "\n", encoding="utf-8")

    result = analyze_ssh_log(log_file, year=YEAR, tz=TZ)

    assert result.events == []
    assert result.unsupported_lines == 1
    assert result.invalid_lines == 0
