from pathlib import Path

import pytest

from security_detection_engine.windows import read_events

NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

EVENT_XML = """
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2024-11-16T10:15:32.123456Z"/>
      <Computer>DC-01</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">admin</Data>
    </EventData>
  </Event>
"""


def test_reads_events_with_namespace(tmp_path: Path):
    xml_file = tmp_path / "events.xml"
    xml_file.write_text(
        f'<Events xmlns="{NAMESPACE}">{EVENT_XML}</Events>', encoding="utf-8"
    )

    events = list(read_events(xml_file))

    assert len(events) == 1


def test_reads_events_without_namespace(tmp_path: Path):
    xml_file = tmp_path / "events.xml"
    xml_file.write_text(f"<Events>{EVENT_XML}</Events>", encoding="utf-8")

    assert len(list(read_events(xml_file))) == 1


def test_reads_multiple_events(tmp_path: Path):
    xml_file = tmp_path / "events.xml"
    xml_file.write_text(
        f'<Events xmlns="{NAMESPACE}">{EVENT_XML}{EVENT_XML}{EVENT_XML}</Events>',
        encoding="utf-8",
    )

    assert len(list(read_events(xml_file))) == 3


def test_empty_events_root_returns_nothing(tmp_path: Path):
    xml_file = tmp_path / "empty.xml"
    xml_file.write_text(f'<Events xmlns="{NAMESPACE}"></Events>', encoding="utf-8")

    assert list(read_events(xml_file)) == []


def test_missing_file_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        list(read_events(tmp_path / "missing.xml"))


def test_corrupted_xml_raises_value_error(tmp_path: Path):
    xml_file = tmp_path / "broken.xml"
    xml_file.write_text("<Events><Event><System><EventID>4624", encoding="utf-8")

    with pytest.raises(ValueError, match="broken.xml"):
        list(read_events(xml_file))


def test_empty_file_raises_value_error(tmp_path: Path):
    xml_file = tmp_path / "empty.xml"
    xml_file.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="empty.xml"):
        list(read_events(xml_file))


def test_processed_events_removed_from_parent(tmp_path: Path):
    import gc
    import weakref

    xml_file = tmp_path / "events.xml"
    xml_file.write_text(
        f'<Events xmlns="{NAMESPACE}">{EVENT_XML * 5}</Events>', encoding="utf-8"
    )

    refs = []
    for element in read_events(xml_file):
        # Содержимое Event должно быть доступно потребителю целиком
        assert len(list(element)) > 0
        refs.append(weakref.ref(element))
    del element
    gc.collect()

    # Если бы Event оставался в родителе, корень удерживал бы его в памяти
    assert all(ref() is None for ref in refs)
