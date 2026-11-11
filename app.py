"""Local Streamlit dashboard for packet analysis and investigations."""

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from network_traffic_analysis import CaptureError, DetectionThresholds, analyze_bytes
from network_traffic_analysis.dashboard_components import (
    render_count_rows,
    render_investigation_cards,
    render_labeled_fields,
    render_timeline_cards,
)
from network_traffic_analysis.investigations import (
    DEFAULT_DATABASE_PATH,
    DuplicateInvestigation,
    FINDING_DISPOSITIONS,
    MAX_ANALYST_NOTES_LENGTH,
    MAX_CONCLUSION_LENGTH,
    MAX_FINDING_REASONING_LENGTH,
    INVESTIGATION_STATUSES,
    FindingNotFound,
    InvestigationNotFound,
    InvestigationStore,
    InvestigationStoreError,
)
from network_traffic_analysis.reporting import (
    ReportGenerationError,
    generate_investigation_report,
    report_filename,
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ACTIVITY_DISPLAY = 100
SEVERITIES = ("informational", "low", "medium", "high")
DATABASE_PATH = Path(
    os.environ.get("NTA_DATABASE_PATH", str(DEFAULT_DATABASE_PATH))
).expanduser()

st.set_page_config(page_title="Network Threat Investigation", layout="wide")
st.title("Network Threat Detection & Investigation")
st.caption(
    "Local-first PCAP/PCAPNG analysis. Findings are triage hypotheses, not "
    "proof of malicious activity."
)

store = InvestigationStore(DATABASE_PATH)
try:
    store.initialize()
except InvestigationStoreError as exc:
    st.error(f"Investigation storage is unavailable: {exc}")
    st.stop()

st.caption(f"Local database: `{DATABASE_PATH}`")
section = st.radio(
    "Workspace section",
    ("Overview", "New Analysis", "Investigations", "Investigation Details"),
    horizontal=True,
    label_visibility="collapsed",
    key="workspace_section",
)


def _utc_timestamp(value):
    if value is None:
        return "Not available"
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OverflowError, OSError, TypeError, ValueError):
        return "Not available"


def _app_timestamp(value):
    if not isinstance(value, str):
        return "Not available"
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return "Invalid stored timestamp"
    if timestamp.tzinfo is None:
        return "Invalid stored timestamp"
    return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _render_findings(findings, key_prefix):
    if not findings:
        st.info("No findings were produced for this analysis.")
        return
    selected_severities = st.multiselect(
        "Filter by severity",
        options=SEVERITIES,
        default=list(SEVERITIES),
        key=f"{key_prefix}_severity_filter",
    )
    visible_findings = [
        finding
        for finding in findings
        if finding.get("severity") in selected_severities
    ]
    for index, finding in enumerate(visible_findings, start=1):
        with st.expander(
            f"{index}. [{finding['severity'].upper()} / "
            f"{finding['confidence']} confidence] {finding['type']}"
        ):
            st.text(finding["reason"])
            render_labeled_fields(
                st,
                [
                    ("Source IP", finding.get("source_ip")),
                    ("Destination IP", finding.get("destination_ip")),
                    ("First seen (UTC)", _utc_timestamp(finding.get("first_seen"))),
                    ("Last seen (UTC)", _utc_timestamp(finding.get("last_seen"))),
                    ("Packet count", finding.get("packet_count")),
                ],
            )
            st.markdown("**Recommended investigation steps**")
            for recommendation in finding.get("recommendations", []):
                st.markdown(f"- {recommendation}")
            if finding.get("evidence_truncated"):
                st.caption(
                    f"Showing {len(finding['evidence'])} evidence packets; "
                    f"{finding['evidence_truncated']} additional packets are "
                    "represented in the count and time range."
                )
            st.json(finding.get("evidence", []))
    if not visible_findings:
        st.info("No findings match the selected severity filter.")


def _render_analysis(report):
    st.subheader("Capture overview")
    packet_col, duration_col, malformed_col = st.columns(3)
    packet_col.metric("Packets", report["packets"])
    duration_col.metric("Duration (seconds)", report["duration_s"])
    malformed_col.metric("Malformed packets skipped", report["malformed_packets"])

    if report["skipped_non_ethernet"]:
        st.info(
            f"{report['skipped_non_ethernet']} non-Ethernet packet(s) were skipped."
        )
    if report["malformed_packets"]:
        st.warning(
            "Some frames had incomplete or invalid protocol headers and were "
            "excluded from protocol analysis."
        )

    left_col, right_col = st.columns(2)
    with left_col:
        st.subheader("Protocol statistics")
        if report["protocols"]:
            render_count_rows(st, report["protocols"].items(), "Packets")
        else:
            st.info("No supported protocol packets were found.")

        st.subheader("Top source IP addresses")
        if report["top_talkers"]:
            render_count_rows(st, report["top_talkers"], "Packets")
        else:
            st.info("No IPv4 source addresses were found.")

    with right_col:
        st.subheader("Top DNS queries")
        if report["top_dns_queries"]:
            render_count_rows(st, report["top_dns_queries"], "Count")
        else:
            st.info("No supported UDP/53 DNS queries were found.")
    st.subheader("Security findings")
    _render_findings(report["findings"], "new_analysis")


def _open_investigation(investigation_id):
    st.session_state["selected_investigation_id"] = investigation_id
    st.session_state["workspace_section"] = "Investigation Details"


def _render_investigation_list():
    investigations = store.list_investigations()
    st.subheader("Saved investigations")
    if not investigations:
        st.info("No investigations have been saved yet.")
        return
    render_investigation_cards(
        st,
        investigations,
        include_upload_time=True,
        include_id=True,
    )
    choices = {f"{item['name']} — {item['status']} — {item['id']}": item["id"] for item in investigations}
    selected_label = st.selectbox("Select investigation", list(choices))
    st.button(
        "Open selected investigation",
        on_click=_open_investigation,
        args=(choices[selected_label],),
    )


def _render_finding_reviews(findings, investigation_id):
    if not findings:
        st.info("No security findings were recorded for this investigation.")
        return
    for finding in findings:
        finding_id = finding.get("finding_id")
        disposition = finding.get("analyst_disposition", "Needs Review")
        severity = str(finding.get("severity", "not recorded")).upper()
        with st.expander(
            f"[{severity}] {finding.get('type', 'Finding')} — {disposition}"
        ):
            st.caption(
                "Automated detection. Its original description, severity, confidence, "
                "and evidence are unchanged by analyst review."
            )
            st.text(finding.get("reason", "No detection explanation was recorded."))
            render_labeled_fields(
                st,
                [
                    ("Finding ID", finding_id),
                    ("Confidence", finding.get("confidence")),
                    ("Source IP", finding.get("source_ip")),
                    ("Destination IP", finding.get("destination_ip")),
                    ("Packet count", finding.get("packet_count")),
                    ("Analyst disposition", disposition),
                    ("Reviewed (UTC)", _app_timestamp(finding.get("reviewed_at"))),
                ],
            )
            if finding.get("assessment_error"):
                st.warning(finding["assessment_error"])
            with st.form(f"finding_assessment_form_{investigation_id}_{finding_id}"):
                new_disposition = st.selectbox(
                    "Analyst disposition",
                    FINDING_DISPOSITIONS,
                    index=(
                        FINDING_DISPOSITIONS.index(disposition)
                        if disposition in FINDING_DISPOSITIONS
                        else 0
                    ),
                    key=f"finding_disposition_{investigation_id}_{finding_id}",
                )
                reasoning = st.text_area(
                    "Analyst reasoning (optional)",
                    value=finding.get("analyst_reasoning", ""),
                    max_chars=MAX_FINDING_REASONING_LENGTH,
                    height=100,
                    key=f"finding_reasoning_{investigation_id}_{finding_id}",
                )
                save_assessment = st.form_submit_button("Save finding assessment")
            if save_assessment:
                try:
                    store.update_finding_assessment(
                        investigation_id, finding_id, new_disposition, reasoning
                    )
                except (
                    FindingNotFound,
                    InvestigationNotFound,
                    InvestigationStoreError,
                    ValueError,
                ) as exc:
                    st.error(f"Could not save finding assessment: {exc}")
                else:
                    st.success("Finding assessment saved.")
                    st.rerun()


def _render_evidence_reviews(findings, investigation_id):
    available_evidence = 0
    for finding in findings:
        finding_id = finding.get("finding_id")
        evidence_items = finding.get("evidence", [])
        if finding.get("evidence_truncated"):
            st.caption(
                f"Finding {finding_id}: showing {len(evidence_items)} bounded "
                f"evidence records; {finding['evidence_truncated']} additional "
                "records are not individually listed."
            )
        if finding.get("evidence_error"):
            st.warning(
                f"Finding {finding_id}: {finding['evidence_error']} "
                "Unavailable evidence cannot be reviewed."
            )
        for index, evidence in enumerate(evidence_items):
            if not isinstance(evidence, dict):
                st.warning(
                    f"Finding {finding_id}, evidence {index + 1} is malformed "
                    "and unavailable."
                )
                continue
            evidence_index = evidence.get("evidence_index", index)
            if (
                not isinstance(evidence_index, int)
                or isinstance(evidence_index, bool)
                or evidence_index < 0
            ):
                st.warning(
                    f"Finding {finding_id}, evidence {index + 1} has an invalid "
                    "stored index and cannot be reviewed."
                )
                continue
            available_evidence += 1
            reviewed = evidence.get("review_status") == "Reviewed"
            status = "Reviewed" if reviewed else "Not Reviewed"
            with st.container(border=True):
                st.markdown(
                    f"**Finding {finding_id} · Packet "
                    f"{evidence.get('packet_number', 'Not recorded')}**"
                )
                render_labeled_fields(
                    st,
                    [
                        ("Capture timestamp (UTC)", _utc_timestamp(evidence.get("timestamp"))),
                        ("Source IP", evidence.get("source_ip")),
                        ("Destination IP", evidence.get("destination_ip")),
                        ("Destination port", evidence.get("destination_port")),
                        ("MAC address", evidence.get("mac_address")),
                        ("TCP flags", evidence.get("tcp_flags")),
                        ("DNS name", evidence.get("dns_name")),
                        ("Review status", status),
                    ],
                    columns_per_row=3,
                )
                if evidence.get("reviewed_at"):
                    st.caption(
                        f"Last marked Reviewed: {_app_timestamp(evidence['reviewed_at'])}"
                    )
                if st.button(
                    "Mark Not Reviewed" if reviewed else "Mark Reviewed",
                    key=(
                        f"evidence_review_{investigation_id}_{finding_id}_"
                        f"{evidence_index}"
                    ),
                ):
                    try:
                        store.update_evidence_review(
                            investigation_id, finding_id, evidence_index, not reviewed
                        )
                    except (
                        FindingNotFound,
                        InvestigationNotFound,
                        InvestigationStoreError,
                        ValueError,
                    ) as exc:
                        st.error(f"Could not update evidence review status: {exc}")
                    else:
                        st.rerun()
    if not available_evidence and not any(
        finding.get("evidence_error") for finding in findings
    ):
        st.info("No packet evidence was retained for this investigation.")


def _render_activity_history(events):
    if not events:
        st.info("No investigation activity has been recorded.")
        return
    visible_events = events[-MAX_ACTIVITY_DISPLAY:]
    if len(events) > len(visible_events):
        st.caption(
            f"Showing the latest {len(visible_events)} of {len(events)} "
            "activity records."
        )
    for event in visible_events:
        with st.container(border=True):
            timestamp_column, detail_column = st.columns([1, 3])
            timestamp_column.caption(_app_timestamp(event.get("timestamp")))
            title = str(event.get("event_type", "activity")).replace("_", " ").title()
            detail_column.markdown(f"**{title}**")
            detail_column.text(event.get("message", "Activity record unavailable."))
            if event.get("finding_id") is not None:
                detail_column.caption(f"Finding ID: {event['finding_id']}")


if section == "Overview":
    st.subheader("Overview")
    try:
        investigations = store.list_investigations()
    except InvestigationStoreError as exc:
        st.error(f"Could not load investigations: {exc}")
    else:
        open_count = sum(item["status"] == "Open" for item in investigations)
        in_progress_count = sum(
            item["status"] == "In Progress" for item in investigations
        )
        resolved_count = sum(item["status"] == "Resolved" for item in investigations)
        first, second, third = st.columns(3)
        first.metric("Open", open_count)
        second.metric("In Progress", in_progress_count)
        third.metric("Resolved", resolved_count)
        st.caption(
            "These totals come from saved investigations. Analyze a capture in "
            "New Analysis, then explicitly save it to create an investigation."
        )
        if investigations:
            render_investigation_cards(
                st,
                investigations[:10],
            )

elif section == "New Analysis":
    st.subheader("New Analysis")
    with st.sidebar:
        st.subheader("Detection thresholds")
        scan_threshold = st.number_input(
            "Distinct TCP ports/hosts for SYN scan",
            min_value=1,
            value=15,
            step=1,
        )
        icmp_threshold = st.number_input(
            "ICMP echo destination hosts", min_value=1, value=10, step=1
        )
        dns_threshold = st.number_input(
            "Extractable DNS queries per source", min_value=1, value=100, step=10
        )
        repeated_syn_threshold = st.number_input(
            "TCP SYN attempts to same destination port",
            min_value=1,
            value=20,
            step=1,
        )

    uploaded_capture = st.file_uploader(
        "Upload an authorized capture",
        type=["pcap", "pcapng"],
        help="Processing stays local. Maximum size: 50 MB.",
        key="new_analysis_upload",
    )
    current_fingerprint = None
    if uploaded_capture is not None:
        capture_data = uploaded_capture.getvalue()
        if len(capture_data) > MAX_UPLOAD_BYTES:
            st.error("Capture exceeds the 50 MB upload limit.")
        else:
            current_fingerprint = hashlib.sha256(capture_data).hexdigest()
            if (
                st.session_state.get("analysis_fingerprint")
                != current_fingerprint
            ):
                st.session_state.pop("analysis_report", None)
                st.session_state.pop("analysis_request_key", None)
                st.session_state["analysis_fingerprint"] = current_fingerprint
                st.session_state["analysis_uploaded_at"] = datetime.now(
                    timezone.utc
                ).isoformat(timespec="seconds")
            if st.button("Analyze capture"):
                try:
                    report = analyze_bytes(
                        capture_data,
                        source=uploaded_capture.name,
                        threshold=scan_threshold,
                        detection_thresholds=DetectionThresholds(
                            icmp_sweep_hosts=icmp_threshold,
                            dns_query_volume=dns_threshold,
                            repeated_syn_attempts=repeated_syn_threshold,
                        ),
                    )
                except (CaptureError, OSError, ValueError) as exc:
                    st.error(f"Could not analyse this capture: {exc}")
                else:
                    st.session_state["analysis_report"] = report
                    st.session_state["analysis_filename"] = uploaded_capture.name
                    st.session_state["analysis_request_key"] = uuid.uuid4().hex

    report = st.session_state.get("analysis_report")
    if report is not None:
        _render_analysis(report)
        st.divider()
        st.subheader("Save investigation")
        with st.form("save_investigation_form"):
            investigation_name = st.text_input(
                "Investigation name", max_chars=200
            )
            save_investigation = st.form_submit_button("Save investigation")
        if save_investigation:
            try:
                investigation_id = store.create_investigation(
                    investigation_name,
                    st.session_state["analysis_filename"],
                    report,
                    uploaded_at=st.session_state["analysis_uploaded_at"],
                    capture_sha256=st.session_state["analysis_fingerprint"],
                    request_key=st.session_state["analysis_request_key"],
                )
            except DuplicateInvestigation as exc:
                st.warning(
                    "This capture and investigation name were already saved "
                    f"(investigation ID: {exc.investigation_id}). Open it from "
                    "Investigations instead of creating a duplicate."
                )
            except (ValueError, InvestigationStoreError) as exc:
                st.error(f"Could not save investigation: {exc}")
            else:
                st.session_state["selected_investigation_id"] = investigation_id
                st.success(
                    f"Investigation saved with ID {investigation_id}. "
                    "Open it from Investigations."
                )

elif section == "Investigations":
    st.subheader("Investigations")
    try:
        _render_investigation_list()
    except InvestigationStoreError as exc:
        st.error(f"Could not load investigations: {exc}")

elif section == "Investigation Details":
    st.subheader("Investigation Details")
    try:
        investigations = store.list_investigations()
    except InvestigationStoreError as exc:
        st.error(f"Could not load investigations: {exc}")
        investigations = []

    if not investigations:
        st.info("Save an analyzed capture before opening investigation details.")
    else:
        valid_ids = {item["id"] for item in investigations}
        selected_id = st.session_state.get("selected_investigation_id")
        if selected_id not in valid_ids:
            selected_id = None
        selected_label = st.selectbox(
            "Investigation",
            options=[item["id"] for item in investigations],
            index=(
                [item["id"] for item in investigations].index(selected_id)
                if selected_id
                else 0
            ),
            format_func=lambda value: next(
                f"{item['name']} — {item['status']}"
                for item in investigations
                if item["id"] == value
            ),
        )
        st.session_state["selected_investigation_id"] = selected_label
        try:
            investigation = store.get_investigation(selected_label)
        except (InvestigationNotFound, InvestigationStoreError, ValueError) as exc:
            st.error(f"Could not open investigation: {exc}")
        else:
            st.subheader("1. Investigation Overview")
            st.markdown(f"### {investigation['name']}")
            render_labeled_fields(
                st,
                [
                    ("Status", investigation["status"]),
                    ("Capture", investigation["capture_filename"]),
                    ("Packets", investigation["packet_count"]),
                    ("Capture received (UTC)", investigation["uploaded_at"]),
                    ("Investigation created (UTC)", investigation["created_at"]),
                    ("Investigation updated (UTC)", investigation["updated_at"]),
                ],
            )
            summary = investigation["analysis_summary"]
            st.markdown("**Capture timestamps (from packets, UTC)**")
            render_labeled_fields(
                st,
                [
                    (
                        "First captured packet",
                        _utc_timestamp(summary.get("capture_first_timestamp")),
                    ),
                    (
                        "Last captured packet",
                        _utc_timestamp(summary.get("capture_last_timestamp")),
                    ),
                ],
            )

            with st.form(f"status_form_{selected_label}"):
                new_status = st.selectbox(
                    "Status",
                    INVESTIGATION_STATUSES,
                    index=INVESTIGATION_STATUSES.index(investigation["status"]),
                    key=f"status_{selected_label}",
                )
                save_status = st.form_submit_button("Update status")
            if save_status:
                try:
                    store.update_status(selected_label, new_status)
                except (ValueError, InvestigationNotFound, InvestigationStoreError) as exc:
                    st.error(f"Could not update status: {exc}")
                else:
                    st.success("Investigation status updated.")
                    st.rerun()

            st.markdown("**Saved analysis summary**")
            render_labeled_fields(
                st,
                [
                    ("Duration (seconds)", summary.get("duration_s")),
                    ("Malformed packets skipped", summary.get("malformed_packets")),
                    ("Non-Ethernet packets skipped", summary.get("skipped_non_ethernet")),
                ],
            )
            st.markdown("**Protocols**")
            if summary.get("protocols"):
                render_count_rows(st, summary["protocols"].items(), "Packets")
            else:
                st.info("No supported protocol packets were found.")
            st.markdown("**Top source IPs**")
            if summary.get("top_talkers"):
                render_count_rows(st, summary["top_talkers"], "Packets")
            else:
                st.info("No IPv4 source addresses were found.")
            st.markdown("**Top DNS queries**")
            if summary.get("top_dns_queries"):
                render_count_rows(st, summary["top_dns_queries"], "Count")
            else:
                st.info("No supported UDP/53 DNS queries were found.")

            st.subheader("2. Analyst Conclusion")
            st.caption(
                "Record your final assessment. This field is analyst-authored and "
                "is never generated from automated detections."
            )
            with st.form(f"conclusion_form_{selected_label}"):
                conclusion = st.text_area(
                    "Analyst conclusion",
                    value=investigation.get("analyst_conclusion", ""),
                    max_chars=MAX_CONCLUSION_LENGTH,
                    height=180,
                )
                save_conclusion = st.form_submit_button("Save conclusion")
            if save_conclusion:
                try:
                    store.update_conclusion(selected_label, conclusion)
                except (ValueError, InvestigationNotFound, InvestigationStoreError) as exc:
                    st.error(f"Could not save analyst conclusion: {exc}")
                else:
                    st.success("Analyst conclusion saved.")
                    st.rerun()

            st.subheader("3. Security Findings")
            st.caption(
                "Automated detections are unchanged. Record a separate analyst "
                "disposition and optional reasoning for each finding."
            )
            _render_finding_reviews(investigation["findings"], selected_label)

            st.subheader("4. Evidence Review")
            st.caption(
                "Review bounded packet metadata only; raw packet payloads are not stored."
            )
            _render_evidence_reviews(investigation["findings"], selected_label)

            st.subheader("5. Investigation Timeline")
            st.caption(
                "Timeline entries below are derived from packet evidence. "
                "Capture timestamps are separate from app upload and investigation "
                "creation times shown above."
            )
            if investigation["timeline"]:
                render_timeline_cards(
                    st, investigation["timeline"], _utc_timestamp
                )
            else:
                st.info("No timestamped packet evidence is available for a timeline.")

            st.subheader("6. Activity History")
            _render_activity_history(investigation.get("activity_history", []))

            st.subheader("7. Analyst Notes")
            with st.form(f"notes_form_{selected_label}"):
                notes = st.text_area(
                    "Analyst notes",
                    value=investigation["analyst_notes"],
                    height=160,
                )
                st.caption(
                    f"{len(notes):,} / {MAX_ANALYST_NOTES_LENGTH:,} characters"
                )
                save_notes = st.form_submit_button("Save notes")
            if save_notes:
                try:
                    store.update_notes(selected_label, notes)
                except (ValueError, InvestigationNotFound, InvestigationStoreError) as exc:
                    st.error(f"Could not save notes: {exc}")
                else:
                    st.success("Analyst notes saved.")
                    st.rerun()

            st.subheader("8. PDF Report")
            if st.button(
                "Generate PDF Report",
                key=f"generate_report_{selected_label}",
            ):
                st.session_state.pop("generated_investigation_pdf", None)
                try:
                    report_data = store.get_investigation(selected_label)
                    if report_data["id"] != selected_label:
                        raise ReportGenerationError(
                            "Selected investigation changed; reopen it and retry."
                        )
                    generate_investigation_report(report_data)
                    store.record_pdf_report_generated(selected_label)
                    report_data = store.get_investigation(selected_label)
                    pdf_bytes = generate_investigation_report(report_data)
                    st.session_state["generated_investigation_pdf"] = {
                        "investigation_id": selected_label,
                        "updated_at": report_data.get("updated_at"),
                        "filename": report_filename(selected_label),
                        "bytes": pdf_bytes,
                    }
                    st.rerun()
                except (
                    InvestigationNotFound,
                    InvestigationStoreError,
                    ReportGenerationError,
                    ValueError,
                ) as exc:
                    st.error(f"Could not generate the PDF report: {exc}")

            generated_report = st.session_state.get("generated_investigation_pdf")
            if (
                isinstance(generated_report, dict)
                and generated_report.get("investigation_id") == selected_label
                and generated_report.get("updated_at") == investigation.get("updated_at")
                and isinstance(generated_report.get("bytes"), bytes)
            ):
                st.download_button(
                    "Download PDF report",
                    data=generated_report["bytes"],
                    file_name=generated_report["filename"],
                    mime="application/pdf",
                    key=f"download_report_{selected_label}_{investigation.get('updated_at')}",
                )

            st.subheader("Delete investigation")
            confirm_delete = st.checkbox(
                "I understand this permanently deletes the investigation and its findings.",
                key=f"confirm_delete_{selected_label}",
            )
            if st.button(
                "Delete investigation",
                disabled=not confirm_delete,
                type="secondary",
            ):
                try:
                    store.delete_investigation(selected_label)
                except (InvestigationNotFound, ValueError, InvestigationStoreError) as exc:
                    st.error(f"Could not delete investigation: {exc}")
                else:
                    st.session_state.pop("selected_investigation_id", None)
                    st.success("Investigation deleted.")
                    st.rerun()
