from pathlib import Path

import pytest

from security_detection_engine.collectors import read_log_lines


def test_reads_lines_without_newline_characters(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("line one\nline two\nline three\n", encoding="utf-8")

    lines = list(read_log_lines(log_file))

    assert lines == ["line one", "line two", "line three"]


def test_missing_file_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        list(read_log_lines(tmp_path / "missing.log"))


def test_invalid_bytes_are_replaced(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"valid line\ninvalid \xff\xfe bytes\n")

    lines = list(read_log_lines(log_file))

    assert len(lines) == 2
    assert lines[0] == "valid line"
    assert "�" in lines[1]


def test_crlf_line_endings_are_stripped(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"first\r\nsecond\r\n")

    assert list(read_log_lines(log_file)) == ["first", "second"]
