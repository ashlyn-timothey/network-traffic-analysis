import ast
from contextlib import contextmanager
from pathlib import Path

from network_traffic_analysis.dashboard_components import (
    render_count_rows,
    render_investigation_cards,
    render_labeled_fields,
    render_timeline_cards,
)


class RecordingStreamlit:
    def __init__(self):
        self.events = []

    @contextmanager
    def container(self, **kwargs):
        self.events.append(("container", kwargs))
        yield self

    def columns(self, spec):
        count = spec if isinstance(spec, int) else len(spec)
        self.events.append(("columns", count))
        return [self] * count

    def text(self, value):
        self.events.append(("text", str(value)))

    def caption(self, value):
        self.events.append(("caption", str(value)))

    def metric(self, label, value):
        self.events.append(("metric", str(label), str(value)))

    def __getattr__(self, name):
        if name in {"table", "dataframe", "write"}:
            raise AssertionError(f"pandas-dependent rendering called: {name}")
        raise AttributeError(name)


def test_count_rows_render_labels_and_values_with_native_components():
    ui = RecordingStreamlit()

    render_count_rows(ui, [("TCP", 12), ("UDP", 3)], "Packets")

    assert ("text", "TCP") in ui.events
    assert ("text", "UDP") in ui.events
    assert ("metric", "Packets", "12") in ui.events
    assert ("metric", "Packets", "3") in ui.events
    assert ui.events.count(("container", {"border": True})) == 2


def test_labeled_fields_wrap_across_native_column_rows():
    ui = RecordingStreamlit()

    render_labeled_fields(
        ui,
        [("Capture", "sample.pcap"), ("Packets", 10), ("Status", "Open"), ("ID", "abc")],
        columns_per_row=3,
    )

    assert ("caption", "Capture") in ui.events
    assert ("text", "sample.pcap") in ui.events
    assert ("caption", "ID") in ui.events
    assert ("text", "abc") in ui.events
    assert ui.events.count(("container", {"border": True})) == 2


def test_investigation_cards_preserve_list_fields():
    ui = RecordingStreamlit()
    investigation = {
        "id": "test-id",
        "name": "Case one",
        "status": "In Progress",
        "capture_filename": "traffic.pcapng",
        "packet_count": 8,
        "uploaded_at": "2026-11-08T10:00:00+00:00",
        "created_at": "2026-11-08T10:01:00+00:00",
        "updated_at": "2026-11-08T10:02:00+00:00",
    }

    render_investigation_cards(
        ui, [investigation], include_upload_time=True, include_id=True
    )

    assert ("text", "Case one") in ui.events
    assert ("metric", "Status", "In Progress") in ui.events
    assert ("text", "Capture: traffic.pcapng") in ui.events
    assert ("caption", "Upload received (UTC)") in ui.events
    assert ("text", "2026-11-08T10:00:00+00:00") in ui.events
    assert ("caption", "Investigation ID: test-id") in ui.events


def test_timeline_cards_preserve_packet_and_address_evidence():
    ui = RecordingStreamlit()
    event = {
        "timestamp": 1_700_000_000.0,
        "packet_number": 17,
        "finding_type": "possible_icmp_sweep",
        "severity": "medium",
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.5",
    }

    render_timeline_cards(ui, [event], lambda _: "capture time")

    assert ("metric", "Capture time (UTC)", "capture time") in ui.events
    assert ("text", "Packet: 17") in ui.events
    assert ("text", "possible_icmp_sweep") in ui.events
    assert ("metric", "Severity", "medium") in ui.events
    assert ("text", "Source IP: 192.0.2.1") in ui.events
    assert ("text", "Destination IP: 198.51.100.5") in ui.events


def test_app_avoids_streamlit_dataframe_table_and_write_dispatch():
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    forbidden = {"table", "dataframe", "write"}

    calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "st"
        and node.func.attr in forbidden
    ]

    assert calls == []
