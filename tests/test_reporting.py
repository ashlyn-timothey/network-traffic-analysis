import copy
import sqlite3
import uuid
from io import BytesIO

import pytest
from pypdf import PdfReader

from network_traffic_analysis.investigations import InvestigationStore
from network_traffic_analysis.reporting import (
    ReportGenerationError,
    generate_investigation_report,
    report_filename,
)


@pytest.fixture
def store(tmp_path):
    repository = InvestigationStore(tmp_path / "investigations.sqlite3")
    repository.initialize()
    return repository


def report_data(*, findings=None):
    return {
        "packets": 4,
        "duration_s": 3.0,
        "capture_first_timestamp": 1_700_000_000.0,
        "capture_last_timestamp": 1_700_000_003.0,
        "protocols": {"TCP": 3, "ARP": 1},
        "top_talkers": [("192.0.2.10", 3)],
        "top_dns_queries": [],
        "malformed_packets": 0,
        "skipped_non_ethernet": 0,
        "findings": findings
        if findings is not None
        else [
            {
                "type": "repeated_connection_attempts",
                "severity": "medium",
                "confidence": "low",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "timestamp": 1_700_000_001.0,
                "first_seen": 1_700_000_001.0,
                "last_seen": 1_700_000_003.0,
                "packet_count": 3,
                "reason": "Repeated TCP SYN packets to destination port 443.",
                "recommendations": ["Review packet outcomes and expected service use."],
                "evidence": [
                    {
                        "packet_number": 2,
                        "timestamp": 1_700_000_001.0,
                        "source_ip": "192.0.2.10",
                        "destination_ip": "198.51.100.20",
                        "destination_port": 443,
                        "tcp_flags": 2,
                        "payload": "SECRET_RAW_PAYLOAD_SENTINEL",
                    },
                    {
                        "packet_number": 4,
                        "timestamp": 1_700_000_003.0,
                        "source_ip": "192.0.2.10",
                        "destination_ip": "198.51.100.20",
                        "destination_port": 443,
                        "tcp_flags": 2,
                    },
                ],
            }
        ],
    }


def create_investigation(store, name="SOC Review", findings=None):
    return store.create_investigation(
        name,
        "capture.pcap",
        report_data(findings=findings),
        uploaded_at="2026-11-08T12:00:00+00:00",
    )


def read_pdf(pdf_bytes):
    assert pdf_bytes.startswith(b"%PDF-")
    reader = PdfReader(BytesIO(pdf_bytes), strict=True)
    assert not reader.is_encrypted
    assert len(reader.pages) >= 1
    text = " ".join(
        " ".join((page.extract_text() or "").split()) for page in reader.pages
    )
    assert "Page 1" in text
    return reader, text


def test_generates_valid_pdf_for_saved_investigation(store):
    investigation_id = create_investigation(store)
    investigation = store.get_investigation(investigation_id)

    reader, text = read_pdf(generate_investigation_report(investigation))

    assert len(reader.pages) >= 2
    for section in (
        "Network Security Investigation Report",
        "Executive summary",
        "Investigation details",
        "Detection findings",
        "Packet evidence",
        "Investigation timeline",
        "Analyst notes and conclusion",
        "Analyst conclusion not provided.",
        "Limitations and disclaimer",
    ):
        assert section in text
    assert investigation_id in text
    assert "SOC Review" in text
    assert "capture.pcap" in text
    assert "Repeated TCP SYN packets" in text


def test_generates_pdf_when_no_findings(store):
    investigation_id = create_investigation(store, findings=[])

    _, text = read_pdf(
        generate_investigation_report(store.get_investigation(investigation_id))
    )

    assert "No findings were recorded for this investigation." in text
    assert "Finding count" in text
    assert "0" in text
    assert "No timestamped packet evidence is available" in text


def test_groups_multiple_findings_by_severity(store):
    first = report_data()["findings"][0]
    findings = [
        first,
        {
            **copy.deepcopy(first),
            "type": "vertical_syn_scan",
            "severity": "high",
            "confidence": "high",
            "reason": "High-priority scan indicator.",
            "packet_count": 1,
        },
        {
            **copy.deepcopy(first),
            "type": "possible_icmp_sweep",
            "severity": "low",
            "confidence": "medium",
            "reason": "Possible ICMP echo sweep.",
            "packet_count": 2,
        },
    ]
    investigation_id = create_investigation(store, findings=findings)

    _, text = read_pdf(
        generate_investigation_report(store.get_investigation(investigation_id))
    )

    assert "[HIGH]" in text
    assert "[MEDIUM]" in text
    assert "[LOW]" in text
    assert "High-priority scan indicator." in text
    assert "Possible ICMP echo sweep." in text


def test_missing_and_invalid_timestamps_and_evidence_are_safe():
    malformed = {
        "id": str(uuid.uuid4()),
        "name": "Malformed <case>",
        "analysis_summary": {"protocols": {"TCP": 1}},
        "findings": [
            {
                "type": "vertical_syn_scan",
                "severity": "medium",
                "confidence": "low",
                "reason": "Stored text <script> must be escaped.",
                "packet_count": 2,
                "evidence": [
                    {"packet_number": 0, "timestamp": "not a timestamp"},
                    {
                        "packet_number": 1,
                        "timestamp": float("inf"),
                        "payload": "SECRET_INVALID_EVIDENCE_PAYLOAD",
                    },
                    {"packet_number": 2, "timestamp": 1_700_000_001.0},
                    "not an evidence object",
                ],
            }
        ],
        "timeline": [
            {"packet_number": 1, "timestamp": None, "finding_type": "fake"},
            {"packet_number": 2, "timestamp": float("nan")},
        ],
    }

    _, text = read_pdf(generate_investigation_report(malformed))

    assert "Not recorded" in text
    assert "not a timestamp" not in text
    assert "SECRET_INVALID_EVIDENCE_PAYLOAD" not in text
    assert "script" in text
    assert "No timestamped packet evidence is available" in text


def test_long_notes_and_finding_descriptions_flow_across_pages(store):
    long_finding = report_data()["findings"][0]
    long_finding["reason"] = "Long evidence-based explanation. " * 900
    investigation_id = create_investigation(store, findings=[long_finding])
    store.update_notes(investigation_id, "Long analyst note. " * 2500)

    reader, text = read_pdf(
        generate_investigation_report(store.get_investigation(investigation_id))
    )

    assert len(reader.pages) >= 4
    assert text.count("Page ") >= len(reader.pages)
    assert "Long evidence-based explanation." in text
    assert "Long analyst note." in text


def test_missing_optional_investigation_fields_and_empty_data():
    _, text = read_pdf(generate_investigation_report({"findings": []}))

    assert "Investigation name not recorded" in text
    assert "Capture filename" in text
    assert "Not recorded" in text
    assert "Analyst conclusion not provided." in text

    empty_reader, empty_text = read_pdf(generate_investigation_report({}))
    assert len(empty_reader.pages) >= 1
    assert "No findings were recorded" in empty_text


def test_long_names_addresses_and_capture_paths_wrap_without_leaking_directories():
    investigation = {
        "id": str(uuid.uuid4()),
        "name": "Investigation " + "LongName" * 20,
        "capture_filename": r"C:\private\captures\capture-" + "x" * 180 + ".pcap",
        "analysis_summary": {"protocols": {"TCP": 1}},
        "findings": [
            {
                "type": "repeated_connection_attempts",
                "severity": "low",
                "confidence": "low",
                "source_ip": "2001:db8:" + "a" * 32,
                "destination_ip": "198.51.100." + "9" * 30,
                "timestamp": 1.0,
                "packet_count": 1,
                "reason": "Long address rendering.",
                "evidence": [],
            }
        ],
    }

    reader, text = read_pdf(generate_investigation_report(investigation))

    assert len(reader.pages) >= 2
    assert "private" not in text
    assert "captures" not in text
    assert "capture-" in text
    assert "LongName" in text
    assert "2001:db8:" in text


def test_unicode_text_is_rendered_in_pdf():
    investigation = {
        "id": str(uuid.uuid4()),
        "name": "Café – Δοκιμή",
        "analyst_notes": "Résumé: vérifié; naïve façade; π-network.",
        "analysis_summary": {"protocols": {"TCP": 1}},
        "findings": [],
    }

    _, text = read_pdf(generate_investigation_report(investigation))

    assert "Café" in text
    assert "[U+0394][U+03BF][U+03BA][U+03B9][U+03BC][U+03AE]" in text
    assert "Résumé" in text
    assert "π-network" in text


def test_payloads_and_untrusted_markup_are_not_exposed(store):
    investigation_id = create_investigation(store)
    investigation = store.get_investigation(investigation_id)
    investigation["findings"][0]["raw_packet_payload"] = "SECRET_RAW_FINDING"

    _, text = read_pdf(generate_investigation_report(investigation))

    assert "SECRET_RAW_PAYLOAD_SENTINEL" not in text
    assert "SECRET_RAW_FINDING" not in text
    assert "SECRET" not in text
    assert "payload" not in text.lower()


def test_pdf_includes_persisted_analyst_assessments_and_activity(store):
    investigation_id = create_investigation(store)
    finding = store.get_investigation(investigation_id)["findings"][0]
    store.update_conclusion(
        investigation_id,
        "Expected client retries were confirmed; no incident was identified.",
    )
    store.update_finding_assessment(
        investigation_id,
        finding["finding_id"],
        "False Positive",
        "The destination service was unavailable during the capture.",
    )
    store.update_evidence_review(investigation_id, finding["finding_id"], 0, True)
    store.record_pdf_report_generated(investigation_id)

    _, text = read_pdf(
        generate_investigation_report(store.get_investigation(investigation_id))
    )

    for expected in (
        "Analyst conclusion",
        "Expected client retries were confirmed",
        "False Positive",
        "The destination service was unavailable",
        "Review status",
        "Reviewed",
        "Investigation activity history",
        "Finding disposition changed",
        "Evidence review changed",
        "PDF report generated",
    ):
        assert expected in text
    assert "SECRET_RAW_PAYLOAD_SENTINEL" not in text


def test_report_generation_does_not_change_database(store):
    investigation_id = create_investigation(store)

    with sqlite3.connect(store.database_path) as connection:
        before = {
            "investigations": connection.execute(
                "SELECT * FROM investigations ORDER BY id"
            ).fetchall(),
            "findings": connection.execute(
                "SELECT * FROM findings ORDER BY id"
            ).fetchall(),
            "version": connection.execute("PRAGMA user_version").fetchone()[0],
        }

    generate_investigation_report(store.get_investigation(investigation_id))

    with sqlite3.connect(store.database_path) as connection:
        after = {
            "investigations": connection.execute(
                "SELECT * FROM investigations ORDER BY id"
            ).fetchall(),
            "findings": connection.execute(
                "SELECT * FROM findings ORDER BY id"
            ).fetchall(),
            "version": connection.execute("PRAGMA user_version").fetchone()[0],
        }
    assert after == before


def test_selected_investigation_id_controls_export_contents(store):
    create_investigation(store, "First investigation")
    second_id = create_investigation(store, "Second investigation")
    selected = store.get_investigation(second_id)

    _, text = read_pdf(generate_investigation_report(selected))

    assert "Second investigation" in text
    assert "First investigation" not in text
    assert second_id in report_filename(selected["id"])
    assert report_filename(selected["id"]).endswith(".pdf")


def test_invalid_or_missing_id_cannot_be_used_for_download_name():
    with pytest.raises(ReportGenerationError, match="ID is missing or invalid"):
        report_filename(r"..\secret")
