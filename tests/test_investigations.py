import sqlite3
import uuid

import pytest

from network_traffic_analysis.investigations import (
    DuplicateInvestigation,
    FINDING_DISPOSITIONS,
    MAX_CONCLUSION_LENGTH,
    INVESTIGATION_STATUSES,
    FindingNotFound,
    InvestigationNotFound,
    InvestigationStore,
    InvestigationStoreError,
)


@pytest.fixture
def database_path(tmp_path):
    return tmp_path / "investigations.sqlite3"


@pytest.fixture
def store(database_path):
    repository = InvestigationStore(database_path)
    repository.initialize()
    return repository


def sample_report():
    return {
        "packets": 4,
        "duration_s": 3.0,
        "capture_first_timestamp": 1_700_000_000.0,
        "capture_last_timestamp": 1_700_000_003.0,
        "protocols": {"TCP": 4},
        "top_talkers": [("192.0.2.10", 4)],
        "top_dns_queries": [],
        "malformed_packets": 0,
        "skipped_non_ethernet": 0,
        "threshold": 15,
        "detection_thresholds": {
            "icmp_sweep_hosts": 10,
            "dns_query_volume": 100,
            "repeated_syn_attempts": 20,
        },
        "findings": [
            {
                "type": "repeated_connection_attempts",
                "severity": "low",
                "confidence": "low",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "timestamp": 1_700_000_001.0,
                "first_seen": 1_700_000_001.0,
                "last_seen": 1_700_000_003.0,
                "packet_count": 3,
                "reason": "Repeated TCP SYN packets.",
                "recommendations": ["Review packet outcomes."],
                "evidence": [
                    {
                        "packet_number": 4,
                        "timestamp": 1_700_000_003.0,
                        "source_ip": "192.0.2.10",
                        "destination_ip": "198.51.100.20",
                        "destination_port": 443,
                        "tcp_flags": 2,
                        "payload": "must not be persisted",
                    },
                    {
                        "packet_number": 2,
                        "timestamp": 1_700_000_001.0,
                        "source_ip": "192.0.2.10",
                        "destination_ip": "198.51.100.20",
                        "destination_port": 443,
                        "tcp_flags": 2,
                    },
                ],
                "destination_port": 443,
                "raw_packet_payload": "must not be persisted",
            }
        ],
    }


def create_sample(store, name="Test investigation"):
    return store.create_investigation(
        name,
        "sample.pcap",
        sample_report(),
        uploaded_at="2026-11-08T01:00:00+00:00",
    )


def test_database_initialization_creates_expected_schema(store, database_path):
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(investigations)")
        }

    assert {"investigations", "findings"}.issubset(tables)
    assert store.list_investigations() == []
    assert "updated_at" in columns
    assert "analyst_conclusion" in columns


def test_create_and_list_investigation(store):
    investigation_id = create_sample(store, "  Port review  ")

    investigations = store.list_investigations()

    assert len(investigations) == 1
    assert investigations[0]["id"] == investigation_id
    assert investigations[0]["name"] == "Port review"
    assert investigations[0]["capture_filename"] == "sample.pcap"
    assert investigations[0]["uploaded_at"] == "2026-11-08T01:00:00+00:00"
    assert investigations[0]["packet_count"] == 4
    assert investigations[0]["status"] == "Open"


def test_saves_and_retrieves_structured_findings_without_packet_payloads(store):
    investigation_id = create_sample(store)

    investigation = store.get_investigation(investigation_id)
    finding = investigation["findings"][0]

    assert finding["type"] == "repeated_connection_attempts"
    assert finding["severity"] == "low"
    assert finding["packet_count"] == 3
    assert finding["evidence"][0]["packet_number"] == 4
    assert finding["recommendations"] == ["Review packet outcomes."]
    assert finding["destination_port"] == 443
    assert "raw" not in finding
    assert "payload" not in finding
    assert "payload" not in finding["evidence"][0]
    assert investigation["analysis_summary"]["protocols"] == {"TCP": 4}


def test_update_status_accepts_only_supported_values(store):
    investigation_id = create_sample(store)

    for status in INVESTIGATION_STATUSES:
        store.update_status(investigation_id, status)
        assert store.get_investigation(investigation_id)["status"] == status

    with pytest.raises(ValueError, match="status must be one of"):
        store.update_status(investigation_id, "Closed")


def test_save_and_retrieve_notes(store):
    investigation_id = create_sample(store)
    notes = "Check expected service downtime with the owner."

    store.update_notes(investigation_id, notes)

    assert store.get_investigation(investigation_id)["analyst_notes"] == notes
    assert store.get_investigation(investigation_id)["updated_at"]


def test_status_and_notes_advance_updated_at(store, monkeypatch):
    investigation_id = create_sample(store)
    monkeypatch.setattr(
        "network_traffic_analysis.investigations.utc_now",
        lambda: "2026-11-08T02:00:00+00:00",
    )

    store.update_status(investigation_id, "In Progress")
    store.update_notes(investigation_id, "Reviewed by analyst.")

    investigation = store.get_investigation(investigation_id)
    assert investigation["updated_at"] == "2026-11-08T02:00:00+00:00"
    assert investigation["status"] == "In Progress"
    assert investigation["analyst_notes"] == "Reviewed by analyst."


def test_delete_investigation_cascades_findings(store):
    investigation_id = create_sample(store)
    finding_id = store.get_investigation(investigation_id)["findings"][0]["finding_id"]
    store.update_evidence_review(investigation_id, finding_id, 0, True)

    store.delete_investigation(investigation_id)

    assert store.list_investigations() == []
    with pytest.raises(InvestigationNotFound):
        store.get_investigation(investigation_id)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM activity_history").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM evidence_reviews").fetchone()[0] == 0


@pytest.mark.parametrize("operation", ["get", "status", "notes", "delete"])
def test_invalid_investigation_ids_are_rejected(store, operation):
    invalid_id = "not-a-uuid"

    with pytest.raises(ValueError, match="valid UUID"):
        if operation == "get":
            store.get_investigation(invalid_id)
        elif operation == "status":
            store.update_status(invalid_id, "Open")
        elif operation == "notes":
            store.update_notes(invalid_id, "notes")
        else:
            store.delete_investigation(invalid_id)


def test_valid_but_missing_id_raises_not_found(store):
    missing_id = str(uuid.uuid4())

    with pytest.raises(InvestigationNotFound):
        store.get_investigation(missing_id)


def test_data_persists_after_reopening_database(database_path):
    first_store = InvestigationStore(database_path)
    first_store.initialize()
    investigation_id = create_sample(first_store)

    reopened_store = InvestigationStore(database_path)
    reopened_store.initialize()

    assert reopened_store.get_investigation(investigation_id)["name"] == (
        "Test investigation"
    )
    assert len(reopened_store.get_investigation(investigation_id)["findings"]) == 1


def test_timeline_orders_only_real_packet_evidence(store):
    investigation_id = create_sample(store)

    timeline = store.get_investigation(investigation_id)["timeline"]

    assert [event["packet_number"] for event in timeline] == [2, 4]
    assert [event["timestamp"] for event in timeline] == [
        1_700_000_001.0,
        1_700_000_003.0,
    ]
    assert all(
        event["finding_type"] == "repeated_connection_attempts"
        and event["severity"] == "low"
        and event["source_ip"] == "192.0.2.10"
        and event["destination_ip"] == "198.51.100.20"
        for event in timeline
    )
    assert store.get_investigation(investigation_id)["analysis_summary"][
        "capture_first_timestamp"
    ] == 1_700_000_000.0


def test_timeline_skips_missing_or_invalid_packet_timestamps():
    from network_traffic_analysis.investigations import build_timeline

    events = build_timeline(
        {
            "findings": [
                {
                    "type": "sample",
                    "severity": "low",
                    "evidence": [
                        {"packet_number": 1, "timestamp": None},
                        {"packet_number": 2, "timestamp": float("nan")},
                        {"packet_number": 3, "timestamp": 1.5},
                        {"packet_number": True, "timestamp": 0.5},
                    ],
                }
            ]
        }
    )

    assert [(event["packet_number"], event["timestamp"]) for event in events] == [
        (3, 1.5)
    ]


def test_rejects_empty_name_and_invalid_report(store):
    with pytest.raises(ValueError, match="name must not be empty"):
        store.create_investigation("  ", "sample.pcap", sample_report())

    with pytest.raises(ValueError, match="valid packet count"):
        store.create_investigation(
            "Invalid report", "sample.pcap", {"packets": "many", "findings": []}
        )


def test_corrupt_database_is_reported_without_replacing_it(tmp_path):
    database_path = tmp_path / "corrupt.sqlite3"
    original_bytes = b"not a sqlite database"
    database_path.write_bytes(original_bytes)
    repository = InvestigationStore(database_path)

    with pytest.raises(InvestigationStoreError, match="Could not initialize"):
        repository.initialize()

    assert database_path.read_bytes() == original_bytes


def test_legacy_schema_migrates_without_losing_investigations(tmp_path):
    database_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                capture_filename TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                analysis_summary_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                analyst_notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL
                    REFERENCES investigations(id) ON DELETE CASCADE,
                finding_index INTEGER NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                timestamp REAL NOT NULL,
                first_seen REAL,
                last_seen REAL,
                packet_count INTEGER NOT NULL,
                reason TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            INSERT INTO investigations VALUES (
                '00000000-0000-4000-8000-000000000001', 'Legacy case', 'old.pcap',
                '2026-11-08T01:00:00+00:00',
                '2026-11-08T01:00:01+00:00', 4, '{"protocols":{"TCP":4}}',
                'In Progress', 'preserve these notes'
            );
            INSERT INTO findings VALUES (
                1, '00000000-0000-4000-8000-000000000001', 0,
                'legacy_finding', 'low', 'low', '192.0.2.1', '198.51.100.1',
                1.0, 1.0, 1.0, 1, 'preserve this finding', '[]',
                '[{"packet_number":1,"timestamp":1.0}]', '{}'
            );
            """
        )

    repository = InvestigationStore(database_path)
    repository.initialize()

    investigation = repository.list_investigations()[0]
    assert investigation["id"] == "00000000-0000-4000-8000-000000000001"
    assert investigation["name"] == "Legacy case"
    assert investigation["analyst_notes"] == "preserve these notes"
    assert investigation["updated_at"] == investigation["created_at"]
    migrated = repository.get_investigation(investigation["id"])
    assert migrated["findings"][0]["reason"] == "preserve this finding"
    assert migrated["timeline"][0]["packet_number"] == 1
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_newer_database_version_is_rejected_without_modification(tmp_path):
    database_path = tmp_path / "future.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE preserved (value TEXT)")
        connection.execute("INSERT INTO preserved VALUES ('keep')")
        connection.execute("PRAGMA user_version = 99")

    with pytest.raises(InvestigationStoreError, match="newer than supported"):
        InvestigationStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 99
        assert connection.execute("SELECT value FROM preserved").fetchone()[0] == "keep"
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'investigations'"
        ).fetchone() is None


def test_incompatible_unversioned_database_is_left_unchanged(tmp_path):
    database_path = tmp_path / "incompatible.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE investigations (id TEXT)")

    with pytest.raises(InvestigationStoreError, match="incomplete"):
        InvestigationStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name = 'findings'"
        ).fetchone() is None


def test_failed_finding_save_rolls_back_investigation_and_prior_findings(store):
    report = sample_report()
    report["findings"].append({"type": "incomplete"})

    with pytest.raises(ValueError, match="invalid finding"):
        store.create_investigation("Atomic save", "sample.pcap", report)

    assert store.list_investigations() == []
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 0


def test_duplicate_capture_or_submission_is_rejected(store):
    digest = "a" * 64
    investigation_id = store.create_investigation(
        "Same capture", "sample.pcap", sample_report(),
        capture_sha256=digest, request_key="submission-1",
    )

    with pytest.raises(DuplicateInvestigation) as duplicate_capture:
        store.create_investigation(
            "Same capture", "renamed.pcap", sample_report(),
            capture_sha256=digest, request_key="submission-2",
        )
    assert duplicate_capture.value.investigation_id == investigation_id

    with pytest.raises(DuplicateInvestigation) as duplicate_submission:
        store.create_investigation(
            "Different name", "sample.pcap", sample_report(),
            capture_sha256="b" * 64, request_key="submission-1",
        )
    assert duplicate_submission.value.investigation_id == investigation_id
    assert len(store.list_investigations()) == 1


def test_upload_filename_is_reduced_to_basename_and_summary_is_allowlisted(store):
    report = sample_report()
    report["raw_capture"] = b"must not be persisted"

    investigation_id = store.create_investigation(
        "Safe fields", r"C:\private\captures\sample.pcap", report
    )
    saved = store.get_investigation(investigation_id)

    assert saved["capture_filename"] == "sample.pcap"
    assert "raw_capture" not in saved["analysis_summary"]


def test_invalid_finding_evidence_timestamp_is_rejected_atomically(store):
    report = sample_report()
    report["findings"][0]["evidence"][0]["timestamp"] = float("nan")

    with pytest.raises(ValueError, match="timestamp must be finite"):
        store.create_investigation("Invalid timestamp", "sample.pcap", report)

    assert store.list_investigations() == []


def test_corrupt_json_is_reported_as_a_database_error(store):
    investigation_id = create_sample(store)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE investigations SET analysis_summary_json = ? WHERE id = ?",
            ("{invalid json", investigation_id),
        )

    with pytest.raises(InvestigationStoreError, match="invalid structured data"):
        store.get_investigation(investigation_id)


def test_analyst_conclusion_is_validated_persisted_and_updated(store):
    investigation_id = create_sample(store)

    assert store.get_investigation(investigation_id)["analyst_conclusion"] == ""
    conclusion = "The observed retries align with an expected service outage.\nNo incident confirmed."
    store.update_conclusion(investigation_id, conclusion)
    assert store.get_investigation(investigation_id)["analyst_conclusion"] == conclusion

    reopened = InvestigationStore(store.database_path)
    reopened.initialize()
    assert reopened.get_investigation(investigation_id)["analyst_conclusion"] == conclusion

    updated = "Further evidence supports expected client retry behavior."
    reopened.update_conclusion(investigation_id, updated)
    assert store.get_investigation(investigation_id)["analyst_conclusion"] == updated

    with pytest.raises(ValueError, match="at most"):
        store.update_conclusion(
            investigation_id, "x" * (MAX_CONCLUSION_LENGTH + 1)
        )
    with pytest.raises(ValueError, match="must be text"):
        store.update_conclusion(investigation_id, None)


def test_finding_disposition_and_reasoning_are_separate_from_detection(store):
    investigation_id = create_sample(store)
    original = store.get_investigation(investigation_id)["findings"][0]
    finding_id = original["finding_id"]

    store.update_finding_assessment(
        investigation_id,
        finding_id,
        "False Positive",
        "Expected service retries confirmed by the service owner.",
    )
    reviewed = store.get_investigation(investigation_id)["findings"][0]
    assert reviewed["analyst_disposition"] == "False Positive"
    assert reviewed["analyst_reasoning"] == (
        "Expected service retries confirmed by the service owner."
    )
    assert reviewed["reviewed_at"]
    for field in ("type", "severity", "confidence", "reason", "evidence"):
        assert reviewed[field] == original[field]

    store.update_finding_assessment(
        investigation_id, finding_id, "Inconclusive", "Awaiting endpoint logs."
    )
    updated = store.get_investigation(investigation_id)["findings"][0]
    assert updated["analyst_disposition"] == "Inconclusive"
    assert updated["analyst_reasoning"] == "Awaiting endpoint logs."

    with pytest.raises(ValueError, match="disposition must be one of"):
        store.update_finding_assessment(investigation_id, finding_id, "Malicious")
    with pytest.raises(ValueError, match="at most"):
        store.update_finding_assessment(
            investigation_id, finding_id, "True Positive", "x" * 4001
        )
    with pytest.raises(FindingNotFound):
        store.update_finding_assessment(
            investigation_id, 99999, FINDING_DISPOSITIONS[0]
        )


def test_evidence_review_status_persists_without_changing_packet_metadata(store):
    investigation_id = create_sample(store)
    original = store.get_investigation(investigation_id)["findings"][0]
    finding_id = original["finding_id"]

    assert [item["review_status"] for item in original["evidence"]] == [
        "Not Reviewed",
        "Not Reviewed",
    ]
    store.update_evidence_review(investigation_id, finding_id, 0, True)

    reopened = InvestigationStore(store.database_path)
    reopened.initialize()
    reviewed = reopened.get_investigation(investigation_id)["findings"][0]
    assert reviewed["evidence"][0]["review_status"] == "Reviewed"
    assert reviewed["evidence"][0]["reviewed_at"]
    assert reviewed["evidence"][1]["review_status"] == "Not Reviewed"
    assert {
        key: value
        for key, value in reviewed["evidence"][0].items()
        if key not in {"review_status", "reviewed_at"}
    } == {
        key: value
        for key, value in original["evidence"][0].items()
        if key not in {"review_status", "reviewed_at"}
    }

    reopened.update_evidence_review(investigation_id, finding_id, 0, False)
    assert (
        reopened.get_investigation(investigation_id)["findings"][0]["evidence"][0][
            "review_status"
        ]
        == "Not Reviewed"
    )
    with pytest.raises(ValueError, match="missing or malformed"):
        store.update_evidence_review(investigation_id, finding_id, 9, True)


def test_activity_history_records_actions_in_chronological_order(store):
    investigation_id = create_sample(store)
    finding_id = store.get_investigation(investigation_id)["findings"][0]["finding_id"]

    store.update_status(investigation_id, "In Progress")
    store.update_notes(investigation_id, "Checked service ownership.")
    store.update_conclusion(investigation_id, "No incident confirmed.")
    store.update_finding_assessment(
        investigation_id, finding_id, "False Positive", "Expected retries."
    )
    store.update_evidence_review(investigation_id, finding_id, 0, True)
    store.record_pdf_report_generated(investigation_id)

    activity = store.get_investigation(investigation_id)["activity_history"]
    event_types = [event["event_type"] for event in activity]
    assert event_types == [
        "investigation_created",
        "status_changed",
        "notes_updated",
        "conclusion_updated",
        "finding_disposition_changed",
        "evidence_review_changed",
        "pdf_report_generated",
    ]
    timestamps = [event["timestamp"] for event in activity]
    assert timestamps == sorted(timestamps)
    assert activity[4]["finding_id"] == finding_id
    assert "Expected retries" not in " ".join(event["message"] for event in activity)
    assert activity[-1]["message"] == "PDF investigation report generated."


def test_packet_evidence_is_capped_and_reports_omitted_count(store):
    report = sample_report()
    report["findings"][0]["evidence"] = [
        {
            "packet_number": index + 1,
            "timestamp": 1_700_000_000.0 + index,
            "source_ip": "192.0.2.10",
            "payload": "must not be persisted",
        }
        for index in range(30)
    ]
    investigation_id = store.create_investigation(
        "Bounded evidence", "sample.pcap", report
    )

    finding = store.get_investigation(investigation_id)["findings"][0]
    assert len(finding["evidence"]) == 25
    assert finding["evidence_truncated"] == 5
    assert all("payload" not in item for item in finding["evidence"])


def test_failed_activity_insert_rolls_back_corresponding_update(store):
    investigation_id = create_sample(store)
    before = store.get_investigation(investigation_id)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_conclusion_activity
            BEFORE INSERT ON activity_history
            WHEN NEW.event_type = 'conclusion_updated'
            BEGIN
                SELECT RAISE(ABORT, 'test activity failure');
            END
            """
        )

    with pytest.raises(InvestigationStoreError, match="test activity failure"):
        store.update_conclusion(investigation_id, "must roll back")

    after = store.get_investigation(investigation_id)
    assert after["analyst_conclusion"] == before["analyst_conclusion"] == ""
    assert after["updated_at"] == before["updated_at"]
    assert [event["event_type"] for event in after["activity_history"]] == [
        "investigation_created"
    ]


def test_malformed_stored_evidence_is_reported_without_hiding_investigation(store):
    investigation_id = create_sample(store)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE findings SET evidence_json = ? WHERE investigation_id = ?",
            ("{invalid json", investigation_id),
        )

    saved = store.get_investigation(investigation_id)
    finding = saved["findings"][0]
    assert finding["evidence"] == []
    assert "malformed" in finding["evidence_error"]
    assert saved["timeline"] == []
    with pytest.raises(InvestigationStoreError, match="malformed and unavailable"):
        store.update_evidence_review(investigation_id, finding["finding_id"], 0, True)


def test_version_one_migration_preserves_existing_investigation_data(tmp_path):
    database_path = tmp_path / "version-one.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE investigations (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, capture_filename TEXT NOT NULL,
                uploaded_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                packet_count INTEGER NOT NULL, analysis_summary_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open', analyst_notes TEXT NOT NULL DEFAULT '',
                capture_sha256 TEXT, request_key TEXT
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                finding_index INTEGER NOT NULL, finding_type TEXT NOT NULL,
                severity TEXT NOT NULL, confidence TEXT NOT NULL, source_ip TEXT,
                destination_ip TEXT, timestamp REAL NOT NULL, first_seen REAL,
                last_seen REAL, packet_count INTEGER NOT NULL, reason TEXT NOT NULL,
                recommendations_json TEXT NOT NULL, evidence_json TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            INSERT INTO investigations VALUES (
                '00000000-0000-4000-8000-000000000001', 'Version one case',
                'old.pcap', '2026-11-08T01:00:00+00:00',
                '2026-11-08T01:00:01+00:00', '2026-11-08T01:00:02+00:00',
                4, '{"protocols":{"TCP":4}}', 'In Progress',
                'preserve version one notes', NULL, NULL
            );
            INSERT INTO findings VALUES (
                7, '00000000-0000-4000-8000-000000000001', 0,
                'legacy_finding', 'low', 'low', '192.0.2.1', '198.51.100.1',
                1.0, 1.0, 1.0, 1, 'preserve detection', '[]',
                '[{"packet_number":1,"timestamp":1.0}]', '{}'
            );
            PRAGMA user_version = 1;
            """
        )

    repository = InvestigationStore(database_path)
    repository.initialize()
    migrated = repository.get_investigation(
        "00000000-0000-4000-8000-000000000001"
    )
    assert migrated["analyst_notes"] == "preserve version one notes"
    assert migrated["analyst_conclusion"] == ""
    assert migrated["findings"][0]["finding_id"] == 7
    assert migrated["findings"][0]["reason"] == "preserve detection"
    assert migrated["findings"][0]["analyst_disposition"] == "Needs Review"
    assert migrated["activity_history"] == []
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_failed_schema_migration_rolls_back_all_changes(tmp_path, monkeypatch):
    database_path = tmp_path / "migration-rollback.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE investigations (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, capture_filename TEXT NOT NULL,
                uploaded_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                packet_count INTEGER NOT NULL, analysis_summary_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open', analyst_notes TEXT NOT NULL DEFAULT '',
                capture_sha256 TEXT, request_key TEXT
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                finding_index INTEGER NOT NULL, finding_type TEXT NOT NULL,
                severity TEXT NOT NULL, confidence TEXT NOT NULL, source_ip TEXT,
                destination_ip TEXT, timestamp REAL NOT NULL, first_seen REAL,
                last_seen REAL, packet_count INTEGER NOT NULL, reason TEXT NOT NULL,
                recommendations_json TEXT NOT NULL, evidence_json TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            PRAGMA user_version = 1;
            """
        )
    original_migration = InvestigationStore._migrate_version_one

    def fail_after_schema_change(connection):
        original_migration(connection)
        raise RuntimeError("forced migration failure")

    monkeypatch.setattr(
        InvestigationStore,
        "_migrate_version_one",
        staticmethod(fail_after_schema_change),
    )
    with pytest.raises(RuntimeError, match="forced migration failure"):
        InvestigationStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        investigation_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(investigations)")
        }
        finding_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(findings)")
        }
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "analyst_conclusion" not in investigation_columns
    assert "analyst_disposition" not in finding_columns
    assert "activity_history" not in tables
    assert "evidence_reviews" not in tables
