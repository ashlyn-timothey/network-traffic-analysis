"""Local SQLite storage for investigation metadata and structured findings."""

import json
import math
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

DEFAULT_DATABASE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "investigations.sqlite3"
)
INVESTIGATION_STATUSES = ("Open", "In Progress", "Resolved")
FINDING_DISPOSITIONS = (
    "Needs Review",
    "True Positive",
    "False Positive",
    "Inconclusive",
)
MAX_CONCLUSION_LENGTH = 10_000
MAX_FINDING_REASONING_LENGTH = 4_000
MAX_ANALYST_NOTES_LENGTH = 20_000
MAX_EVIDENCE_PER_FINDING = 25
SCHEMA_VERSION = 2
_INVESTIGATION_COLUMNS = {
    "id",
    "name",
    "capture_filename",
    "uploaded_at",
    "created_at",
    "updated_at",
    "packet_count",
    "analysis_summary_json",
    "status",
    "analyst_notes",
    "capture_sha256",
    "request_key",
    "analyst_conclusion",
}
_FINDING_COLUMNS = {
    "id",
    "investigation_id",
    "finding_index",
    "finding_type",
    "severity",
    "confidence",
    "source_ip",
    "destination_ip",
    "timestamp",
    "first_seen",
    "last_seen",
    "packet_count",
    "reason",
    "recommendations_json",
    "evidence_json",
    "details_json",
    "analyst_disposition",
    "analyst_reasoning",
    "reviewed_at",
}
_ACTIVITY_TYPES = {
    "investigation_created",
    "status_changed",
    "notes_updated",
    "conclusion_updated",
    "finding_review_updated",
    "finding_disposition_changed",
    "evidence_review_changed",
    "pdf_report_generated",
}
_EVIDENCE_FIELDS = {
    "packet_number",
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "mac_address",
    "tcp_flags",
    "dns_name",
}
_FINDING_DETAILS_FIELDS = {
    "distinct_ports",
    "distinct_hosts",
    "destination_port",
    "tcp_flags",
    "ip",
    "macs",
    "evidence_truncated",
}


class InvestigationStoreError(RuntimeError):
    """Raised when the local investigation database cannot be used safely."""


class InvestigationNotFound(LookupError):
    """Raised when a valid investigation ID does not exist."""


class FindingNotFound(LookupError):
    """Raised when a finding does not belong to the requested investigation."""


class DuplicateInvestigation(LookupError):
    """Raised when the same capture/name or submission has already been saved."""

    def __init__(self, investigation_id: str):
        super().__init__(f"duplicate investigation already exists: {investigation_id}")
        self.investigation_id = investigation_id


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class InvestigationStore:
    """SQLite repository; opens short-lived connections and never stores payloads."""

    def __init__(self, database_path: str | Path = DEFAULT_DATABASE_PATH):
        self.database_path = Path(database_path)

    def initialize(self) -> None:
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version > SCHEMA_VERSION:
                    raise InvestigationStoreError(
                        f"Database schema version {version} is newer than "
                        f"supported version {SCHEMA_VERSION}."
                    )
                if version == 0:
                    self._migrate_version_zero(connection)
                    version = 1
                if version == 1:
                    self._validate_schema(connection)
                    self._migrate_version_one(connection)
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                self._validate_schema(connection)
                self._validate_version_two_schema(connection)
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS findings_investigation_idx
                    ON findings(investigation_id, finding_index)
                    """
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS investigations_request_key_idx
                    ON investigations(request_key) WHERE request_key IS NOT NULL
                    """
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS investigations_capture_name_idx
                    ON investigations(capture_sha256, name)
                    WHERE capture_sha256 IS NOT NULL
                    """
                )
        except InvestigationStoreError:
            raise
        except (OSError, sqlite3.DatabaseError) as exc:
            raise InvestigationStoreError(
                f"Could not initialize investigation database "
                f"'{self.database_path}': {exc}"
            ) from exc

    @staticmethod
    def _migrate_version_zero(connection: sqlite3.Connection) -> None:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
        expected = {"investigations", "findings"}
        if not tables:
            connection.execute(
                """
                CREATE TABLE investigations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL CHECK(length(trim(name)) > 0),
                    capture_filename TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    packet_count INTEGER NOT NULL CHECK(packet_count >= 0),
                    analysis_summary_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open'
                        CHECK(status IN ('Open', 'In Progress', 'Resolved')),
                    analyst_notes TEXT NOT NULL DEFAULT '',
                    capture_sha256 TEXT,
                    request_key TEXT
                )
                """
            )
            connection.execute(
                """
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
                    packet_count INTEGER NOT NULL CHECK(packet_count >= 0),
                    reason TEXT NOT NULL,
                    recommendations_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    UNIQUE(investigation_id, finding_index)
                )
                """
            )
            return
        if not expected.issubset(tables):
            raise InvestigationStoreError(
                "Unversioned database has an incomplete investigation schema; "
                "it was left unchanged."
            )
        InvestigationStore._validate_schema(connection, legacy=True)

        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(investigations)")
        }
        if "updated_at" not in columns:
            connection.execute(
                "ALTER TABLE investigations ADD COLUMN updated_at TEXT"
            )
            connection.execute(
                "UPDATE investigations SET updated_at = created_at "
                "WHERE updated_at IS NULL"
            )
        if "capture_sha256" not in columns:
            connection.execute(
                "ALTER TABLE investigations ADD COLUMN capture_sha256 TEXT"
            )
        if "request_key" not in columns:
            connection.execute(
                "ALTER TABLE investigations ADD COLUMN request_key TEXT"
            )

    @staticmethod
    def _migrate_version_one(connection: sqlite3.Connection) -> None:
        connection.execute(
            "ALTER TABLE investigations ADD COLUMN analyst_conclusion "
            "TEXT NOT NULL DEFAULT '' CHECK(length(analyst_conclusion) <= 10000)"
        )
        connection.execute(
            "ALTER TABLE findings ADD COLUMN analyst_disposition "
            "TEXT NOT NULL DEFAULT 'Needs Review' CHECK(analyst_disposition IN "
            "('Needs Review', 'True Positive', 'False Positive', 'Inconclusive'))"
        )
        connection.execute(
            "ALTER TABLE findings ADD COLUMN analyst_reasoning "
            "TEXT NOT NULL DEFAULT '' CHECK(length(analyst_reasoning) <= 4000)"
        )
        connection.execute(
            "ALTER TABLE findings ADD COLUMN reviewed_at TEXT"
        )
        connection.execute(
            """
            CREATE TABLE evidence_reviews (
                finding_id INTEGER NOT NULL
                    REFERENCES findings(id) ON DELETE CASCADE,
                evidence_index INTEGER NOT NULL CHECK(evidence_index >= 0),
                reviewed INTEGER NOT NULL CHECK(reviewed IN (0, 1)),
                reviewed_at TEXT,
                PRIMARY KEY (finding_id, evidence_index)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE activity_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL
                    REFERENCES investigations(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL CHECK(event_type IN (
                    'investigation_created', 'status_changed', 'notes_updated',
                    'conclusion_updated', 'finding_review_updated',
                    'finding_disposition_changed', 'evidence_review_changed',
                    'pdf_report_generated'
                )),
                occurred_at TEXT NOT NULL,
                finding_id INTEGER
                    REFERENCES findings(id) ON DELETE SET NULL,
                message TEXT NOT NULL CHECK(length(message) <= 240)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX activity_investigation_chronology_idx
            ON activity_history(investigation_id, occurred_at, id)
            """
        )

    @staticmethod
    def _validate_schema(
        connection: sqlite3.Connection, *, legacy: bool = False
    ) -> None:
        required_investigation_columns = _INVESTIGATION_COLUMNS - (
            {"analyst_conclusion", "updated_at", "capture_sha256", "request_key"}
            if legacy
            else {"analyst_conclusion"}
        )
        required_finding_columns = _FINDING_COLUMNS - {
            "analyst_disposition",
            "analyst_reasoning",
            "reviewed_at",
        }
        for table, required in (
            ("investigations", required_investigation_columns),
            ("findings", required_finding_columns),
        ):
            columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            }
            if not required.issubset(columns):
                raise InvestigationStoreError(
                    f"Database table '{table}' is incompatible; it was left unchanged."
                )

        if legacy:
            invalid_status = connection.execute(
                "SELECT 1 FROM investigations WHERE status NOT IN (?, ?, ?) LIMIT 1",
                INVESTIGATION_STATUSES,
            ).fetchone()
            if invalid_status:
                raise InvestigationStoreError(
                    "Database contains an unsupported investigation status; "
                    "it was left unchanged."
                )

    @staticmethod
    def _validate_version_two_schema(connection: sqlite3.Connection) -> None:
        for table, required in (
            ("investigations", _INVESTIGATION_COLUMNS),
            ("findings", _FINDING_COLUMNS),
            ("evidence_reviews", {"finding_id", "evidence_index", "reviewed", "reviewed_at"}),
            (
                "activity_history",
                {"id", "investigation_id", "event_type", "occurred_at", "finding_id", "message"},
            ),
        ):
            columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            }
            if not required.issubset(columns):
                raise InvestigationStoreError(
                    f"Database table '{table}' is incompatible; it was left unchanged."
                )

    def create_investigation(
        self,
        name: str,
        capture_filename: str,
        report: dict[str, Any],
        uploaded_at: str | None = None,
        *,
        capture_sha256: str | None = None,
        request_key: str | None = None,
    ) -> str:
        if not isinstance(name, str):
            raise ValueError("investigation name must be text")
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("investigation name must not be empty")
        if len(clean_name) > 200:
            raise ValueError("investigation name must be at most 200 characters")
        if not isinstance(capture_filename, str) or not capture_filename.strip():
            raise ValueError("capture filename must not be empty")
        safe_filename = Path(capture_filename.replace("\\", "/")).name
        if safe_filename in {"", ".", ".."}:
            raise ValueError("capture filename must not be empty")
        if not isinstance(report, dict):
            raise ValueError("analysis report must be an object")
        packet_count = report.get("packets")
        if (
            not isinstance(packet_count, int)
            or isinstance(packet_count, bool)
            or packet_count < 0
        ):
            raise ValueError("analysis report must contain a valid packet count")
        _validate_optional_key(request_key, "request key", 128)
        if capture_sha256 is not None and (
            not isinstance(capture_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", capture_sha256)
        ):
            raise ValueError(
                "capture SHA-256 must be 64 lowercase hexadecimal characters"
            )

        investigation_id = str(uuid.uuid4())
        created_at = utc_now()
        uploaded_at = _normalize_uploaded_at(
            created_at if uploaded_at is None else uploaded_at
        )
        summary = _safe_analysis_summary(report)
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError("analysis report findings must be a list")

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                duplicate = None
                if request_key is not None:
                    duplicate = connection.execute(
                        "SELECT id FROM investigations WHERE request_key = ?",
                        (request_key,),
                    ).fetchone()
                if duplicate is None and capture_sha256 is not None:
                    duplicate = connection.execute(
                        """
                        SELECT id FROM investigations
                        WHERE capture_sha256 = ? AND name = ?
                        """,
                        (capture_sha256, clean_name),
                    ).fetchone()
                if duplicate is not None:
                    raise DuplicateInvestigation(duplicate["id"])

                connection.execute(
                    """
                    INSERT INTO investigations (
                        id, name, capture_filename, uploaded_at, created_at,
                        updated_at, packet_count, analysis_summary_json, status,
                        capture_sha256, request_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
                    """,
                    (
                        investigation_id,
                        clean_name,
                        safe_filename,
                        uploaded_at,
                        created_at,
                        created_at,
                        packet_count,
                        _json_dump(summary),
                        capture_sha256,
                        request_key,
                    ),
                )
                for index, finding in enumerate(findings):
                    _validate_finding(finding)
                    details = {
                        key: value
                        for key, value in finding.items()
                        if key in _FINDING_DETAILS_FIELDS
                    }
                    details = _validate_finding_details(details)
                    stored_evidence = finding["evidence"][:MAX_EVIDENCE_PER_FINDING]
                    safe_evidence = [
                        _safe_packet_evidence(packet) for packet in stored_evidence
                    ]
                    omitted_evidence = max(
                        len(finding["evidence"]) - MAX_EVIDENCE_PER_FINDING,
                        details.get("evidence_truncated", 0),
                    )
                    if omitted_evidence:
                        details["evidence_truncated"] = omitted_evidence
                    connection.execute(
                        """
                        INSERT INTO findings (
                            investigation_id, finding_index, finding_type,
                            severity, confidence, source_ip, destination_ip,
                            timestamp, first_seen, last_seen, packet_count,
                            reason, recommendations_json, evidence_json,
                            details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            investigation_id,
                            index,
                            finding["type"],
                            finding["severity"],
                            finding["confidence"],
                            finding.get("source_ip"),
                            finding.get("destination_ip"),
                            finding["timestamp"],
                            finding.get("first_seen"),
                            finding.get("last_seen"),
                            finding["packet_count"],
                            finding["reason"],
                            _json_dump(finding.get("recommendations", [])),
                            _json_dump(
                                safe_evidence
                            ),
                            _json_dump(details),
                        ),
                    )
                _record_activity(
                    connection,
                    investigation_id,
                    "investigation_created",
                    "Investigation created.",
                    occurred_at=created_at,
                )
        except DuplicateInvestigation:
            raise
        except (OSError, sqlite3.DatabaseError) as exc:
            raise InvestigationStoreError(
                f"Could not save investigation: {exc}"
            ) from exc
        return investigation_id

    def list_investigations(self) -> list[dict[str, Any]]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT id, name, capture_filename, uploaded_at, created_at,
                           updated_at, packet_count, status, analyst_notes,
                           analyst_conclusion
                    FROM investigations
                    ORDER BY created_at DESC, id
                    """
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not list investigations: {exc}"
            ) from exc
        return [dict(row) for row in rows]

    def get_investigation(self, investigation_id: str) -> dict[str, Any]:
        clean_id = _validate_id(investigation_id)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT id, name, capture_filename, uploaded_at, created_at,
                           updated_at, packet_count, analysis_summary_json, status,
                           analyst_notes, analyst_conclusion
                    FROM investigations WHERE id = ?
                    """,
                    (clean_id,),
                ).fetchone()
                if row is None:
                    raise InvestigationNotFound("investigation was not found")
                findings = connection.execute(
                    """
                    SELECT id, finding_type, severity, confidence, source_ip,
                           destination_ip, timestamp, first_seen, last_seen,
                           packet_count, reason, recommendations_json,
                           evidence_json, details_json, analyst_disposition,
                           analyst_reasoning, reviewed_at
                    FROM findings
                    WHERE investigation_id = ?
                    ORDER BY finding_index
                    """,
                    (clean_id,),
                ).fetchall()
                evidence_reviews = connection.execute(
                    """
                    SELECT evidence_reviews.finding_id,
                           evidence_reviews.evidence_index,
                           evidence_reviews.reviewed,
                           evidence_reviews.reviewed_at
                    FROM evidence_reviews
                    JOIN findings ON findings.id = evidence_reviews.finding_id
                    WHERE findings.investigation_id = ?
                    """,
                    (clean_id,),
                ).fetchall()
                activity = connection.execute(
                    """
                    SELECT id, event_type, occurred_at, finding_id, message
                    FROM activity_history
                    WHERE investigation_id = ?
                    ORDER BY occurred_at, id
                    """,
                    (clean_id,),
                ).fetchall()
        except InvestigationNotFound:
            raise
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not retrieve investigation: {exc}"
            ) from exc

        try:
            result = dict(row)
            result["analysis_summary"] = _json_load(
                result.pop("analysis_summary_json")
            )
            if not isinstance(result["analysis_summary"], dict):
                raise ValueError("analysis summary must be an object")
            review_map: dict[int, dict[int, dict[str, Any]]] = {}
            for review in evidence_reviews:
                review_map.setdefault(review["finding_id"], {})[
                    review["evidence_index"]
                ] = {
                    "reviewed": review["reviewed"],
                    "reviewed_at": review["reviewed_at"],
                }
            result["findings"] = [
                _finding_from_row(finding, review_map.get(finding["id"], {}))
                for finding in findings
            ]
            result["activity_history"] = [
                _activity_from_row(event) for event in activity
            ]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise InvestigationStoreError(
                f"Investigation contains invalid structured data: {exc}"
            ) from exc
        result["timeline"] = build_timeline(result)
        return result

    def update_status(self, investigation_id: str, status: str) -> None:
        clean_id = _validate_id(investigation_id)
        if status not in INVESTIGATION_STATUSES:
            raise ValueError(f"status must be one of {', '.join(INVESTIGATION_STATUSES)}")
        self._update_field(clean_id, "status", status)

    def update_notes(self, investigation_id: str, notes: str) -> None:
        clean_id = _validate_id(investigation_id)
        if not isinstance(notes, str):
            raise ValueError("analyst notes must be text")
        self._update_field(
            clean_id,
            "analyst_notes",
            notes,
            max_length=MAX_ANALYST_NOTES_LENGTH,
        )

    def update_conclusion(self, investigation_id: str, conclusion: str) -> None:
        clean_id = _validate_id(investigation_id)
        if not isinstance(conclusion, str):
            raise ValueError("analyst conclusion must be text")
        if len(conclusion) > MAX_CONCLUSION_LENGTH:
            raise ValueError(
                f"analyst conclusion must be at most {MAX_CONCLUSION_LENGTH} characters"
            )
        self._update_field(clean_id, "analyst_conclusion", conclusion)

    def update_finding_assessment(
        self,
        investigation_id: str,
        finding_id: int,
        disposition: str,
        reasoning: str = "",
    ) -> None:
        clean_id = _validate_id(investigation_id)
        if not isinstance(finding_id, int) or isinstance(finding_id, bool) or finding_id < 1:
            raise ValueError("finding ID must be a positive integer")
        if disposition not in FINDING_DISPOSITIONS:
            raise ValueError(
                f"disposition must be one of {', '.join(FINDING_DISPOSITIONS)}"
            )
        if not isinstance(reasoning, str):
            raise ValueError("analyst reasoning must be text")
        if len(reasoning) > MAX_FINDING_REASONING_LENGTH:
            raise ValueError(
                "analyst reasoning must be at most "
                f"{MAX_FINDING_REASONING_LENGTH} characters"
            )

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT analyst_disposition, analyst_reasoning, reviewed_at
                    FROM findings
                    WHERE id = ? AND investigation_id = ?
                    """,
                    (finding_id, clean_id),
                ).fetchone()
                if row is None:
                    raise FindingNotFound("finding was not found")
                if (
                    row["analyst_disposition"] == disposition
                    and row["analyst_reasoning"] == reasoning
                    and row["reviewed_at"] is not None
                ):
                    return

                occurred_at = utc_now()
                changed_disposition = row["analyst_disposition"] != disposition
                connection.execute(
                    """
                    UPDATE findings
                    SET analyst_disposition = ?, analyst_reasoning = ?,
                        reviewed_at = ?
                    WHERE id = ? AND investigation_id = ?
                    """,
                    (disposition, reasoning, occurred_at, finding_id, clean_id),
                )
                connection.execute(
                    "UPDATE investigations SET updated_at = ? WHERE id = ?",
                    (occurred_at, clean_id),
                )
                event_type = (
                    "finding_disposition_changed"
                    if changed_disposition
                    else "finding_review_updated"
                )
                message = (
                    f"Finding {finding_id} disposition changed to {disposition}."
                    if changed_disposition
                    else f"Finding {finding_id} assessment updated."
                )
                _record_activity(
                    connection,
                    clean_id,
                    event_type,
                    message,
                    finding_id=finding_id,
                    occurred_at=occurred_at,
                )
        except FindingNotFound:
            raise
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not update finding assessment: {exc}"
            ) from exc

    def update_evidence_review(
        self,
        investigation_id: str,
        finding_id: int,
        evidence_index: int,
        reviewed: bool,
    ) -> None:
        clean_id = _validate_id(investigation_id)
        if not isinstance(finding_id, int) or isinstance(finding_id, bool) or finding_id < 1:
            raise ValueError("finding ID must be a positive integer")
        if (
            not isinstance(evidence_index, int)
            or isinstance(evidence_index, bool)
            or evidence_index < 0
        ):
            raise ValueError("evidence index must be a non-negative integer")
        if not isinstance(reviewed, bool):
            raise ValueError("evidence review status must be a boolean")

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT evidence_json FROM findings
                    WHERE id = ? AND investigation_id = ?
                    """,
                    (finding_id, clean_id),
                ).fetchone()
                if row is None:
                    raise FindingNotFound("finding was not found")
                try:
                    evidence_items = _json_load(row["evidence_json"])
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise InvestigationStoreError(
                        "Stored packet evidence is malformed and unavailable."
                    ) from exc
                if (
                    not isinstance(evidence_items, list)
                    or evidence_index >= len(evidence_items)
                    or not isinstance(evidence_items[evidence_index], dict)
                ):
                    raise ValueError("evidence item is missing or malformed")
                safe_evidence = _safe_packet_evidence(
                    evidence_items[evidence_index]
                )
                packet_number = safe_evidence.get("packet_number")

                existing = connection.execute(
                    """
                    SELECT reviewed FROM evidence_reviews
                    WHERE finding_id = ? AND evidence_index = ?
                    """,
                    (finding_id, evidence_index),
                ).fetchone()
                if existing is None and not reviewed:
                    return
                if existing is not None and bool(existing["reviewed"]) == reviewed:
                    return

                occurred_at = utc_now()
                connection.execute(
                    """
                    INSERT INTO evidence_reviews (
                        finding_id, evidence_index, reviewed, reviewed_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(finding_id, evidence_index) DO UPDATE SET
                        reviewed = excluded.reviewed,
                        reviewed_at = excluded.reviewed_at
                    """,
                    (
                        finding_id,
                        evidence_index,
                        int(reviewed),
                        occurred_at if reviewed else None,
                    ),
                )
                connection.execute(
                    "UPDATE investigations SET updated_at = ? WHERE id = ?",
                    (occurred_at, clean_id),
                )
                status = "Reviewed" if reviewed else "Not Reviewed"
                _record_activity(
                    connection,
                    clean_id,
                    "evidence_review_changed",
                    f"Evidence packet {packet_number or 'unknown'} for finding "
                    f"{finding_id} marked {status}.",
                    finding_id=finding_id,
                    occurred_at=occurred_at,
                )
        except (FindingNotFound, InvestigationStoreError, ValueError):
            raise
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not update evidence review status: {exc}"
            ) from exc

    def record_pdf_report_generated(self, investigation_id: str) -> None:
        clean_id = _validate_id(investigation_id)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                exists = connection.execute(
                    "SELECT 1 FROM investigations WHERE id = ?", (clean_id,)
                ).fetchone()
                if exists is None:
                    raise InvestigationNotFound("investigation was not found")
                _record_activity(
                    connection,
                    clean_id,
                    "pdf_report_generated",
                    "PDF investigation report generated.",
                )
        except InvestigationNotFound:
            raise
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not record report generation: {exc}"
            ) from exc

    def delete_investigation(self, investigation_id: str) -> None:
        clean_id = _validate_id(investigation_id)
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "DELETE FROM investigations WHERE id = ?", (clean_id,)
                )
                if cursor.rowcount == 0:
                    raise InvestigationNotFound("investigation was not found")
        except InvestigationNotFound:
            raise
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not delete investigation: {exc}"
            ) from exc

    def _update_field(
        self,
        investigation_id: str,
        field: str,
        value: str,
        *,
        max_length: int | None = None,
    ) -> None:
        field_events = {
            "status": ("status_changed", f"Investigation status changed to {value}."),
            "analyst_notes": ("notes_updated", "Analyst notes updated."),
            "analyst_conclusion": (
                "conclusion_updated",
                "Analyst conclusion updated.",
            ),
        }
        if field not in field_events:
            raise ValueError("unsupported investigation field")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    f"SELECT {field} FROM investigations WHERE id = ?",
                    (investigation_id,),
                ).fetchone()
                if current is None:
                    raise InvestigationNotFound("investigation was not found")
                if current[field] == value:
                    return
                if max_length is not None and len(value) > max_length:
                    raise ValueError(
                        f"analyst notes must be at most {max_length} characters"
                    )
                occurred_at = utc_now()
                cursor = connection.execute(
                    f"UPDATE investigations SET {field} = ?, updated_at = ? "
                    "WHERE id = ?",
                    (value, occurred_at, investigation_id),
                )
                if cursor.rowcount == 0:
                    raise InvestigationNotFound("investigation was not found")
                event_type, message = field_events[field]
                _record_activity(
                    connection,
                    investigation_id,
                    event_type,
                    message,
                    occurred_at=occurred_at,
                )
        except InvestigationNotFound:
            raise
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not update investigation: {exc}"
            ) from exc

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        try:
            connection = sqlite3.connect(self.database_path, timeout=5)
        except sqlite3.DatabaseError as exc:
            raise InvestigationStoreError(
                f"Could not open investigation database '{self.database_path}': {exc}"
            ) from exc
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def build_timeline(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    """Build timestamped events only from packet evidence already in findings."""
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, int, float]] = set()
    findings = investigation.get("findings", [])
    if not isinstance(findings, (list, tuple)):
        return events
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_type = finding.get("type")
        severity = finding.get("severity")
        evidence_items = finding.get("evidence", [])
        if (
            not isinstance(finding_type, str)
            or not isinstance(severity, str)
            or not isinstance(evidence_items, (list, tuple))
        ):
            continue
        for evidence in evidence_items:
            if not isinstance(evidence, dict):
                continue
            packet_number = evidence.get("packet_number")
            timestamp = evidence.get("timestamp")
            if (
                not isinstance(packet_number, int)
                or isinstance(packet_number, bool)
                or packet_number < 1
                or not _is_finite_number(timestamp)
            ):
                continue
            key = (finding_type, packet_number, float(timestamp))
            if key in seen:
                continue
            seen.add(key)
            source_ip = evidence.get("source_ip", finding.get("source_ip"))
            destination_ip = evidence.get(
                "destination_ip", finding.get("destination_ip")
            )
            events.append(
                {
                    "timestamp": float(timestamp),
                    "packet_number": packet_number,
                    "finding_type": finding_type,
                    "source_ip": source_ip if isinstance(source_ip, str) else None,
                    "destination_ip": (
                        destination_ip if isinstance(destination_ip, str) else None
                    ),
                    "severity": severity,
                }
            )
    return sorted(
        events,
        key=lambda event: (
            event["timestamp"],
            event["packet_number"],
            event["finding_type"],
        ),
    )


def _validate_id(investigation_id: str) -> str:
    if not isinstance(investigation_id, str):
        raise ValueError("investigation ID must be a UUID string")
    try:
        parsed_id = uuid.UUID(investigation_id)
    except (ValueError, AttributeError) as exc:
        raise ValueError("investigation ID must be a valid UUID") from exc
    if str(parsed_id) != investigation_id.lower():
        raise ValueError("investigation ID must be a canonical UUID")
    return str(parsed_id)


def _validate_finding(finding: Any) -> None:
    required = {
        "type",
        "severity",
        "confidence",
        "timestamp",
        "packet_count",
        "reason",
        "evidence",
    }
    if not isinstance(finding, dict) or not required.issubset(finding):
        raise ValueError("analysis report contains an invalid finding")
    if not isinstance(finding["type"], str) or not finding["type"].strip():
        raise ValueError("finding type must be non-empty text")
    if not isinstance(finding["severity"], str) or finding[
        "severity"
    ] not in {"informational", "low", "medium", "high"}:
        raise ValueError("finding severity is invalid")
    if not isinstance(finding["confidence"], str) or finding[
        "confidence"
    ] not in {"low", "medium", "high"}:
        raise ValueError("finding confidence is invalid")
    if not _is_finite_number(finding["timestamp"]):
        raise ValueError("finding timestamp must be finite")
    if (
        not isinstance(finding["packet_count"], int)
        or isinstance(finding["packet_count"], bool)
        or finding["packet_count"] < 0
    ):
        raise ValueError("finding packet count must be a non-negative integer")
    if not isinstance(finding["reason"], str):
        raise ValueError("finding reason must be text")
    if not isinstance(finding["evidence"], list):
        raise ValueError("finding evidence must be a list")
    for key in ("first_seen", "last_seen"):
        if finding.get(key) is not None and not _is_finite_number(finding[key]):
            raise ValueError(f"finding {key} timestamp must be finite")
    recommendations = finding.get("recommendations", [])
    if not isinstance(recommendations, (list, tuple)) or not all(
        isinstance(item, str) for item in recommendations
    ):
        raise ValueError("finding recommendations must be a list of text")
    for key in ("source_ip", "destination_ip"):
        if finding.get(key) is not None and not isinstance(finding[key], str):
            raise ValueError(f"finding {key} must be text or null")


def _safe_packet_evidence(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, dict):
        raise ValueError("packet evidence entries must be objects")
    safe = {key: value for key, value in packet.items() if key in _EVIDENCE_FIELDS}
    packet_number = safe.get("packet_number")
    if (
        packet_number is not None
        and (
            not isinstance(packet_number, int)
            or isinstance(packet_number, bool)
            or packet_number < 1
        )
    ):
        raise ValueError("evidence packet number must be a positive integer")
    if safe.get("timestamp") is not None and not _is_finite_number(
        safe["timestamp"]
    ):
        raise ValueError("evidence timestamp must be finite")
    text_limits = {
        "source_ip": 128,
        "destination_ip": 128,
        "mac_address": 64,
        "dns_name": 255,
    }
    for key, maximum in text_limits.items():
        if safe.get(key) is not None and not isinstance(safe[key], str):
            raise ValueError(f"evidence {key} must be text or null")
        if safe.get(key) is not None and (
            len(safe[key]) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in safe[key])
        ):
            raise ValueError(f"evidence {key} is too long or contains control characters")
    for key, maximum in (("destination_port", 65535), ("tcp_flags", 255)):
        if key in safe and (
            not isinstance(safe[key], int)
            or isinstance(safe[key], bool)
            or not 0 <= safe[key] <= maximum
        ):
            raise ValueError(f"evidence {key} must be an integer from 0 to {maximum}")
    return safe


def _safe_analysis_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("duration_s", "capture_first_timestamp", "capture_last_timestamp"):
        if key in report:
            value = report[key]
            if value is not None and not _is_finite_number(value):
                raise ValueError(f"analysis report {key} must be finite")
            summary[key] = value
    for key in ("skipped_non_ethernet", "malformed_packets", "threshold"):
        if key in report:
            value = report[key]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"analysis report {key} must be a non-negative integer")
            summary[key] = value

    protocols = report.get("protocols", {})
    if not isinstance(protocols, dict) or not all(
        isinstance(name, str)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
        for name, count in protocols.items()
    ):
        raise ValueError("analysis report protocols are invalid")
    summary["protocols"] = protocols

    for key in ("top_talkers", "top_dns_queries"):
        pairs = report.get(key, [])
        if not isinstance(pairs, (list, tuple)):
            raise ValueError(f"analysis report {key} must be a list")
        safe_pairs = []
        for pair in pairs:
            if (
                not isinstance(pair, (list, tuple))
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not isinstance(pair[1], int)
                or isinstance(pair[1], bool)
                or pair[1] < 0
            ):
                raise ValueError(f"analysis report {key} entries are invalid")
            safe_pairs.append((pair[0], pair[1]))
        summary[key] = safe_pairs

    thresholds = report.get("detection_thresholds", {})
    if not isinstance(thresholds, dict) or not all(
        isinstance(name, str)
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
        for name, value in thresholds.items()
    ):
        raise ValueError("analysis report detection thresholds are invalid")
    summary["detection_thresholds"] = thresholds
    return summary


def _validate_finding_details(details: dict[str, Any]) -> dict[str, Any]:
    for key in ("distinct_ports", "distinct_hosts", "evidence_truncated"):
        if key in details and (
            not isinstance(details[key], int)
            or isinstance(details[key], bool)
            or details[key] < 0
        ):
            raise ValueError(f"finding {key} must be a non-negative integer")
    if "destination_port" in details and (
        not isinstance(details["destination_port"], int)
        or isinstance(details["destination_port"], bool)
        or not 0 <= details["destination_port"] <= 65535
    ):
        raise ValueError("finding destination_port is invalid")
    if "tcp_flags" in details and (
        not isinstance(details["tcp_flags"], int)
        or isinstance(details["tcp_flags"], bool)
        or not 0 <= details["tcp_flags"] <= 255
    ):
        raise ValueError("finding tcp_flags is invalid")
    if "ip" in details and not isinstance(details["ip"], str):
        raise ValueError("finding ip must be text")
    if "macs" in details and (
        not isinstance(details["macs"], (list, tuple))
        or not all(isinstance(value, str) for value in details["macs"])
    ):
        raise ValueError("finding macs must be a list of text")
    return details


def _validate_optional_key(value: str | None, label: str, max_length: int) -> None:
    if value is not None and (
        not isinstance(value, str) or not value.strip() or len(value) > max_length
    ):
        raise ValueError(f"{label} must be non-empty text up to {max_length} characters")


def _is_finite_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _normalize_uploaded_at(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("upload timestamp must be ISO-8601 text")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("upload timestamp must be ISO-8601 text") from exc
    if timestamp.tzinfo is None:
        raise ValueError("upload timestamp must include a timezone")
    return timestamp.astimezone(timezone.utc).isoformat()


def _record_activity(
    connection: sqlite3.Connection,
    investigation_id: str,
    event_type: str,
    message: str,
    *,
    finding_id: int | None = None,
    occurred_at: str | None = None,
) -> None:
    if event_type not in _ACTIVITY_TYPES:
        raise ValueError("unsupported activity event type")
    if not isinstance(message, str) or len(message) > 240:
        raise ValueError("activity message must be text up to 240 characters")
    connection.execute(
        """
        INSERT INTO activity_history (
            investigation_id, event_type, occurred_at, finding_id, message
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (investigation_id, event_type, occurred_at or utc_now(), finding_id, message),
    )


def _activity_from_row(row: sqlite3.Row) -> dict[str, Any]:
    event_type = row["event_type"]
    occurred_at = row["occurred_at"]
    message = row["message"]
    malformed = (
        event_type not in _ACTIVITY_TYPES
        or not isinstance(occurred_at, str)
        or not isinstance(message, str)
    )
    return {
        "id": row["id"],
        "event_type": event_type if isinstance(event_type, str) else "unknown",
        "timestamp": occurred_at if isinstance(occurred_at, str) else None,
        "finding_id": row["finding_id"],
        "message": (
            "Activity record is malformed and unavailable." if malformed else message
        ),
    }


def _finding_from_row(
    row: sqlite3.Row,
    evidence_reviews: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    recommendations = _json_load(row["recommendations_json"])
    details = _json_load(row["details_json"])
    if not isinstance(recommendations, list):
        raise ValueError("finding recommendations must be a list")
    if not isinstance(details, dict):
        raise ValueError("finding details must be an object")

    details = {
        key: value for key, value in details.items() if key in _FINDING_DETAILS_FIELDS
    }
    _validate_finding_details(details)
    evidence_error = None
    try:
        stored_evidence = _json_load(row["evidence_json"])
    except (json.JSONDecodeError, TypeError, ValueError):
        stored_evidence = None
        evidence_error = "Stored packet evidence is malformed and unavailable."
    evidence_truncated = max(
        len(stored_evidence) - MAX_EVIDENCE_PER_FINDING,
        details.get("evidence_truncated", 0),
    ) if isinstance(stored_evidence, list) else details.get("evidence_truncated", 0)
    if not isinstance(stored_evidence, list):
        evidence = []
        if evidence_error is None:
            evidence_error = "Stored packet evidence is missing or malformed."
    else:
        evidence = []
        for index, item in enumerate(stored_evidence[:MAX_EVIDENCE_PER_FINDING]):
            try:
                safe_item = _safe_packet_evidence(item)
            except ValueError:
                evidence_error = (
                    "One or more stored packet evidence entries are malformed."
                )
                continue
            safe_item["evidence_index"] = index
            review = (evidence_reviews or {}).get(index, {})
            safe_item["review_status"] = (
                "Reviewed" if review.get("reviewed") else "Not Reviewed"
            )
            safe_item["reviewed_at"] = review.get("reviewed_at")
            evidence.append(safe_item)
        if not evidence and evidence_error is None:
            evidence_error = "No packet evidence was retained for this finding."

    disposition = row["analyst_disposition"]
    assessment_error = None
    if disposition not in FINDING_DISPOSITIONS:
        disposition = "Needs Review"
        assessment_error = "Stored analyst disposition is malformed."
    reasoning = row["analyst_reasoning"]
    if not isinstance(reasoning, str):
        reasoning = ""
        assessment_error = "Stored analyst assessment is malformed."
    result = {
        "finding_id": row["id"],
        "type": row["finding_type"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "timestamp": row["timestamp"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "packet_count": row["packet_count"],
        "reason": row["reason"],
        "recommendations": recommendations,
        "evidence": evidence,
        "evidence_error": evidence_error,
        "analyst_disposition": disposition,
        "analyst_reasoning": reasoning,
        "reviewed_at": row["reviewed_at"],
        "assessment_error": assessment_error,
    }
    result.update(details)
    if evidence_truncated:
        result["evidence_truncated"] = evidence_truncated
    return result


def _json_dump(value: Any) -> str:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _json_load(value: str) -> Any:
    return json.loads(value)
