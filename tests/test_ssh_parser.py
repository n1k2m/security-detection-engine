from datetime import UTC, datetime, timedelta, timezone

from security_detection_engine.parsers import ParseStatus, parse_ssh_auth_line

YEAR = 2024
TZ = UTC


def parse(line: str):
    return parse_ssh_auth_line(line, year=YEAR, tz=TZ)


def test_failed_password_parsed():
    result = parse(
        "Nov 16 10:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2"
    )

    assert result.status is ParseStatus.PARSED
    record = result.record
    assert record.success is False
    assert record.authentication_method == "password"
    assert record.invalid_user is False


def test_accepted_password_parsed():
    result = parse(
        "Nov 16 10:16:02 server sshd[1234]: Accepted password for admin "
        "from 192.168.1.10 port 54321 ssh2"
    )

    assert result.status is ParseStatus.PARSED
    record = result.record
    assert record.success is True
    assert record.authentication_method == "password"


def test_accepted_publickey_parsed():
    result = parse(
        "Nov 16 10:18:22 server sshd[1234]: Accepted publickey for admin "
        "from 192.168.1.10 port 54321 ssh2"
    )

    record = result.record
    assert result.status is ParseStatus.PARSED
    assert record.success is True
    assert record.authentication_method == "publickey"


def test_failed_password_for_invalid_user():
    result = parse(
        "Nov 16 10:17:11 server sshd[1234]: Failed password for invalid user "
        "test from 192.168.1.10 port 54321 ssh2"
    )

    record = result.record
    assert result.status is ParseStatus.PARSED
    assert record.success is False
    assert record.username == "test"
    assert record.invalid_user is True


def test_username_ip_and_port_extracted():
    result = parse(
        "Dec 1 08:00:00 host sshd[42]: Accepted password for alice "
        "from 10.0.0.5 port 2222 ssh2"
    )

    record = result.record
    assert record.username == "alice"
    assert record.source_ip == "10.0.0.5"
    assert record.source_port == 2222


def test_pid_and_hostname_extracted():
    result = parse(
        "Nov 16 10:15:32 web-server-01 sshd[9876]: Accepted password for admin "
        "from 192.168.1.10 port 54321 ssh2"
    )

    record = result.record
    assert record.process_id == 9876
    assert record.hostname == "web-server-01"


def test_timestamp_uses_given_year_and_timezone():
    tz = timezone(timedelta(hours=3))
    result = parse_ssh_auth_line(
        "Nov 16 10:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2",
        year=2023,
        tz=tz,
    )

    assert result.record.timestamp == datetime(2023, 11, 16, 10, 15, 32, tzinfo=tz)


def test_other_authentication_method_extracted():
    result = parse(
        "Nov 16 10:19:00 server sshd[1234]: Accepted keyboard-interactive/pam "
        "for admin from 192.168.1.10 port 54321 ssh2"
    )

    record = result.record
    assert result.status is ParseStatus.PARSED
    assert record.authentication_method == "keyboard-interactive/pam"


def test_unsupported_sshd_message():
    result = parse(
        "Nov 16 10:20:00 server sshd[1234]: pam_unix(sshd:session): "
        "session opened for user admin"
    )

    assert result.status is ParseStatus.UNSUPPORTED
    assert result.record is None


def test_non_sshd_line_is_unsupported():
    result = parse(
        "Nov 16 10:20:00 server CRON[555]: pam_unix(cron:session): "
        "session opened for user root"
    )

    assert result.status is ParseStatus.UNSUPPORTED


def test_random_text_is_unsupported():
    assert parse("this is not a syslog line at all").status is ParseStatus.UNSUPPORTED
    assert parse("").status is ParseStatus.UNSUPPORTED


def test_truncated_auth_line_is_invalid():
    result = parse("Nov 16 10:15:32 server sshd[1234]: Failed password for root from")

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_unknown_month_is_invalid():
    result = parse(
        "Xyz 16 10:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2"
    )

    assert result.status is ParseStatus.INVALID


def make_auth_line(
    ip: str = "192.168.1.10",
    port: int = 54321,
    pid: int = 1234,
    suffix: str = " ssh2",
    action: str = "Accepted",
) -> str:
    return (
        f"Nov 16 10:15:32 server sshd[{pid}]: {action} password for admin "
        f"from {ip} port {port}{suffix}"
    )


def test_ipv6_address_parsed():
    result = parse(make_auth_line(ip="2001:db8::1"))

    assert result.status is ParseStatus.PARSED
    assert result.record is not None
    assert result.record.source_ip == "2001:db8::1"


def test_minimal_port_allowed():
    result = parse(make_auth_line(port=1))

    assert result.status is ParseStatus.PARSED
    assert result.record.source_port == 1


def test_maximal_port_allowed():
    result = parse(make_auth_line(port=65535))

    assert result.status is ParseStatus.PARSED
    assert result.record.source_port == 65535


def test_publickey_with_fingerprint_suffix():
    result = parse(
        "Nov 16 10:15:32 server sshd[1234]: Accepted publickey for admin "
        "from 192.168.1.10 port 54321 ssh2: ED25519 SHA256:AbCdEf123456"
    )

    assert result.status is ParseStatus.PARSED
    record = result.record
    assert record is not None
    assert record.success is True
    assert record.authentication_method == "publickey"
    assert record.username == "admin"
    assert record.source_ip == "192.168.1.10"
    assert record.source_port == 54321


def test_line_without_ssh_suffix_parsed():
    result = parse(make_auth_line(suffix=""))

    assert result.status is ParseStatus.PARSED
    assert result.record is not None


def test_invalid_ipv4_rejected():
    result = parse(make_auth_line(ip="999.999.999.999"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_non_ip_string_rejected():
    result = parse(make_auth_line(ip="not-an-ip"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_zero_port_rejected():
    result = parse(make_auth_line(port=0))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_port_above_maximum_rejected():
    result = parse(make_auth_line(port=65536))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_non_numeric_port_rejected():
    result = parse(
        "Nov 16 10:15:32 server sshd[1234]: Accepted password for admin "
        "from 192.168.1.10 port lots ssh2"
    )

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_zero_pid_rejected():
    result = parse(make_auth_line(pid=0))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_trailing_garbage_after_port_rejected():
    result = parse(make_auth_line(suffix=" ssh2 unexpected trailing text"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_arbitrary_text_after_port_rejected():
    result = parse(make_auth_line(suffix=" GARBAGE"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_invalid_day_rejected():
    result = parse(
        "Nov 42 10:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2"
    )

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_invalid_hour_rejected():
    result = parse(
        "Nov 16 25:15:32 server sshd[1234]: Failed password for root "
        "from 192.168.1.10 port 54321 ssh2"
    )

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_rsa_fingerprint_suffix_parsed():
    result = parse(
        "Nov 16 10:15:32 server sshd[1234]: Accepted publickey for admin "
        "from 192.168.1.10 port 54321 ssh2: RSA SHA256:xYz789"
    )

    assert result.status is ParseStatus.PARSED
    assert result.record is not None
    assert result.record.authentication_method == "publickey"


def test_fingerprint_with_garbage_words_rejected():
    result = parse(make_auth_line(suffix=" ssh2: garbage garbage"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_fingerprint_without_sha256_prefix_rejected():
    result = parse(make_auth_line(suffix=" ssh2: ED25519 abc123"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None
