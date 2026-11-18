from datetime import UTC, datetime
from xml.etree.ElementTree import fromstring

from security_detection_engine.windows import ParseStatus, parse_event

NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

EVENT_TEMPLATE = """
<Event xmlns="{ns}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>DC-01</Computer>
  </System>
  {event_data}
</Event>
"""

LOGON_DATA = """
  <EventData>
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0x3e7</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.10</Data>
    <Data Name="IpPort">54321</Data>
    <Data Name="WorkstationName">WS-07</Data>
    <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="LogonProcessName">User32</Data>
  </EventData>
"""

FAILURE_DATA = """
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC000006A</Data>
    <Data Name="SubStatus">0xC0000064</Data>
    <Data Name="FailureReason">%%2313</Data>
  </EventData>
"""


def make_event(
    event_id="4624", timestamp="2024-11-16T10:15:32.123456Z", event_data=LOGON_DATA
):
    xml = EVENT_TEMPLATE.format(
        ns=NAMESPACE,
        event_id=event_id,
        timestamp=timestamp,
        event_data=event_data,
    )
    return fromstring(xml)


def test_event_4624_parsed():
    result = parse_event(make_event())

    assert result.status is ParseStatus.PARSED
    record = result.record
    assert record is not None
    assert record.event_id == 4624
    assert record.computer == "DC-01"
    assert record.provider == "Microsoft-Windows-Security-Auditing"


def test_event_4625_parsed_with_failure_fields():
    result = parse_event(make_event(event_id="4625", event_data=FAILURE_DATA))

    assert result.status is ParseStatus.PARSED
    record = result.record
    assert record.event_id == 4625
    assert record.event_data["Status"] == "0xC000006A"
    assert record.event_data["SubStatus"] == "0xC0000064"
    assert record.event_data["FailureReason"] == "%%2313"


def test_event_data_extracted_by_name_attribute():
    result = parse_event(make_event())

    data = result.record.event_data
    assert data["TargetUserName"] == "admin"
    assert data["TargetDomainName"] == "CORP"
    assert data["LogonType"] == "10"
    assert data["IpAddress"] == "192.168.1.10"
    assert data["IpPort"] == "54321"
    assert data["SubjectUserName"] == "SYSTEM"
    assert data["AuthenticationPackageName"] == "Negotiate"
    assert data["LogonProcessName"] == "User32"


def test_timestamp_parsed_as_timezone_aware():
    result = parse_event(make_event())

    timestamp = result.record.timestamp
    assert timestamp == datetime(2024, 11, 16, 10, 15, 32, 123456, tzinfo=UTC)


def test_missing_optional_event_data_fields():
    result = parse_event(
        make_event(
            event_data='<EventData><Data Name="TargetUserName">bob</Data></EventData>'
        )
    )

    assert result.status is ParseStatus.PARSED
    assert result.record.event_data == {"TargetUserName": "bob"}


def test_missing_event_data_element_still_parsed():
    result = parse_event(make_event(event_data=""))

    assert result.status is ParseStatus.PARSED
    assert result.record.event_data == {}


def test_unsupported_event_id():
    result = parse_event(make_event(event_id="4634"))

    assert result.status is ParseStatus.UNSUPPORTED
    assert result.record is None


def test_missing_event_id_is_invalid():
    xml = EVENT_TEMPLATE.format(
        ns=NAMESPACE,
        event_id="4624",
        timestamp="2024-11-16T10:15:32Z",
        event_data="",
    ).replace("    <EventID>4624</EventID>\n", "")

    result = parse_event(fromstring(xml))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_non_numeric_event_id_is_invalid():
    result = parse_event(make_event(event_id="unknown"))

    assert result.status is ParseStatus.INVALID


def test_invalid_timestamp_is_invalid():
    result = parse_event(make_event(timestamp="not-a-timestamp"))

    assert result.status is ParseStatus.INVALID
    assert result.record is None


def test_naive_timestamp_is_invalid():
    result = parse_event(make_event(timestamp="2024-11-16T10:15:32"))

    assert result.status is ParseStatus.INVALID


def test_missing_time_created_is_invalid():
    xml = EVENT_TEMPLATE.format(
        ns=NAMESPACE,
        event_id="4624",
        timestamp="2024-11-16T10:15:32Z",
        event_data="",
    ).replace('    <TimeCreated SystemTime="2024-11-16T10:15:32Z"/>\n', "")

    assert parse_event(fromstring(xml)).status is ParseStatus.INVALID
