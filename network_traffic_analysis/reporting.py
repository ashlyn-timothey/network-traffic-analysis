"""Generate local, evidence-based PDF reports from saved investigations."""

import io
import math
import unicodedata
import uuid
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Mapping

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class ReportGenerationError(RuntimeError):
    """Raised when an investigation cannot be rendered as a PDF report."""


_NAVY = colors.HexColor("#15324B")
_BLUE = colors.HexColor("#236B8E")
_PALE_BLUE = colors.HexColor("#EAF2F6")
_PALE_GRAY = colors.HexColor("#F3F5F7")
_BORDER = colors.HexColor("#CCD5DC")
_SEVERITIES = ("high", "medium", "low", "informational")
_MAX_EVIDENCE_PER_FINDING = 25
_MAX_ACTIVITY_EVENTS = 100
_SAFE_EVIDENCE_FIELDS = {
    "packet_number",
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "mac_address",
    "tcp_flags",
    "dns_name",
}
_PROTOCOL_BY_FINDING = {
    "vertical_syn_scan": "TCP",
    "horizontal_syn_sweep": "TCP",
    "repeated_connection_attempts": "TCP",
    "unusual_tcp_flag_combination": "TCP",
    "possible_icmp_sweep": "ICMP",
    "high_dns_query_volume": "UDP/DNS",
    "arp_ip_claimed_by_multiple_macs": "ARP",
}


def report_filename(investigation_id: Any) -> str:
    """Return a path-safe download filename bound to a canonical UUID."""
    identifier = _canonical_uuid(investigation_id)
    return f"investigation_report_{identifier}.pdf"


def generate_investigation_report(investigation: Mapping[str, Any]) -> bytes:
    """Build a multipage PDF using only the supplied persisted investigation."""
    if not isinstance(investigation, Mapping):
        raise ReportGenerationError("Investigation data must be an object.")
    try:
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=22 * mm,
            bottomMargin=18 * mm,
            title="Network Security Investigation Report",
            author="Network Traffic Analysis",
            subject="Saved network security investigation",
        )
        styles = _make_styles()
        _register_unicode_fonts()
        story = _build_story(investigation, styles)
        document.build(
            story,
            onFirstPage=_draw_page_chrome,
            onLaterPages=_draw_page_chrome,
        )
        content = buffer.getvalue()
        if not content.startswith(b"%PDF-") or not content.rstrip().endswith(
            b"%%EOF"
        ):
            raise ReportGenerationError("PDF output did not pass its format check.")
        return content
    except ReportGenerationError:
        raise
    except Exception as exc:
        raise ReportGenerationError(
            f"Could not generate the investigation PDF: {exc}"
        ) from exc


def _register_unicode_fonts() -> None:
    font_dir = Path(__import__("reportlab").__path__[0]) / "fonts"
    regular_path = font_dir / "Vera.ttf"
    bold_path = font_dir / "VeraBd.ttf"
    if not regular_path.is_file() or not bold_path.is_file():
        raise ReportGenerationError("The bundled Unicode report fonts are unavailable.")
    if "NTA-Vera" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("NTA-Vera", str(regular_path)))
        pdfmetrics.registerFont(TTFont("NTA-Vera-Bold", str(bold_path)))
        pdfmetrics.registerFontFamily(
            "NTA-Vera",
            normal="NTA-Vera",
            bold="NTA-Vera-Bold",
            italic="NTA-Vera",
            boldItalic="NTA-Vera-Bold",
        )


def _make_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "NTACoverTitle",
            parent=base["Title"],
            fontName="NTA-Vera-Bold",
            fontSize=24,
            leading=30,
            textColor=_NAVY,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "cover_subtitle": ParagraphStyle(
            "NTACoverSubtitle",
            parent=base["Normal"],
            fontName="NTA-Vera",
            fontSize=13,
            leading=18,
            textColor=_BLUE,
            alignment=TA_CENTER,
            spaceAfter=20,
        ),
        "section": ParagraphStyle(
            "NTASection",
            parent=base["Heading1"],
            fontName="NTA-Vera-Bold",
            fontSize=16,
            leading=21,
            textColor=_NAVY,
            spaceBefore=8,
            spaceAfter=9,
            keepWithNext=True,
        ),
        "subsection": ParagraphStyle(
            "NTASubsection",
            parent=base["Heading2"],
            fontName="NTA-Vera-Bold",
            fontSize=11,
            leading=15,
            textColor=_BLUE,
            spaceBefore=8,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "NTABody",
            parent=base["BodyText"],
            fontName="NTA-Vera",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#263746"),
            spaceAfter=5,
            splitLongWords=1,
        ),
        "small": ParagraphStyle(
            "NTASmall",
            parent=base["BodyText"],
            fontName="NTA-Vera",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#263746"),
            splitLongWords=1,
        ),
        "label": ParagraphStyle(
            "NTALabel",
            parent=base["BodyText"],
            fontName="NTA-Vera-Bold",
            fontSize=8,
            leading=11,
            textColor=_NAVY,
            splitLongWords=1,
        ),
        "note": ParagraphStyle(
            "NTANote",
            parent=base["BodyText"],
            fontName="NTA-Vera",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#263746"),
            leftIndent=8,
            rightIndent=8,
            borderColor=_BORDER,
            borderWidth=0.5,
            borderPadding=8,
            splitLongWords=1,
        ),
        "center_small": ParagraphStyle(
            "NTACenterSmall",
            parent=base["BodyText"],
            fontName="NTA-Vera",
            fontSize=8,
            leading=11,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#526473"),
        ),
        "table_header": ParagraphStyle(
            "NTATableHeader",
            parent=base["BodyText"],
            fontName="NTA-Vera-Bold",
            fontSize=7.5,
            leading=10,
            textColor=colors.white,
            splitLongWords=1,
        ),
    }


def _build_story(
    investigation: Mapping[str, Any], styles: Mapping[str, ParagraphStyle]
) -> list[Any]:
    summary = _mapping(investigation.get("analysis_summary"))
    findings = [
        _mapping(item)
        for item in _sequence(investigation.get("findings"))
        if isinstance(item, Mapping)
    ]
    events = _valid_timeline(investigation.get("timeline"))
    activity = _valid_activity(investigation.get("activity_history"))
    protocols = _protocols(summary.get("protocols"))
    severity_counts = Counter(
        _severity(item.get("severity")) for item in findings
    )
    story: list[Any] = []

    story.extend(
        [
            Spacer(1, 25 * mm),
            Paragraph("Network Security Investigation Report", styles["cover_title"]),
            Paragraph(_text(investigation.get("name"), "Investigation name not recorded"), styles["cover_subtitle"]),
            _section_heading("Report information", styles),
            _key_value_table(
                [
                    ("Investigation ID", _text(investigation.get("id"), "Not recorded", 64)),
                    ("Capture filename", _safe_capture_name(investigation.get("capture_filename"))),
                    ("Report generated (UTC)", _format_app_timestamp(_utc_now().isoformat())),
                    ("Investigation created (UTC)", _format_app_timestamp(investigation.get("created_at"))),
                    ("Last updated (UTC)", _format_app_timestamp(investigation.get("updated_at"))),
                    ("Current status", _text(investigation.get("status"), "Not recorded")),
                ],
                styles,
            ),
            Spacer(1, 8 * mm),
            Paragraph(
                "This report reflects saved investigation data. Detection findings "
                "are triage indicators and do not, on their own, establish malicious activity.",
                styles["center_small"],
            ),
            PageBreak(),
            _section_heading("Executive summary", styles),
            Paragraph(
                f"The saved analysis records {_integer(summary.get('packets', investigation.get('packet_count')))} "
                f"packets and {_integer(len(findings))} detection finding(s). "
                "These heuristic results require analyst validation and are not a determination "
                "that an incident occurred.",
                styles["body"],
            ),
            _section_heading("Findings by severity", styles, level=2),
            _simple_table(
                [["Severity", "Finding count"]]
                + [[level.title(), str(severity_counts.get(level, 0))] for level in _SEVERITIES],
                [115 * mm, 55 * mm],
                styles,
            ),
            _section_heading("Protocol distribution", styles, level=2),
        ]
    )
    if protocols:
        story.append(
            _simple_table(
                [["Protocol", "Packets"]]
                + [[name, str(count)] for name, count in protocols],
                [115 * mm, 55 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("Protocol distribution not recorded.", styles["body"]))

    story.extend(
        [
            _section_heading("Investigation details", styles),
            _key_value_table(
                [
                    ("Capture filename", _safe_capture_name(investigation.get("capture_filename"))),
                    ("Packets analyzed", _integer(summary.get("packets", investigation.get("packet_count")))),
                    ("Capture duration (seconds)", _number(summary.get("duration_s"))),
                    ("Malformed packets skipped", _integer(summary.get("malformed_packets"))),
                    ("Non-Ethernet packets skipped", _integer(summary.get("skipped_non_ethernet"))),
                    ("First capture packet (UTC)", _format_epoch(summary.get("capture_first_timestamp"))),
                    ("Last capture packet (UTC)", _format_epoch(summary.get("capture_last_timestamp"))),
                ],
                styles,
            ),
            _section_heading("Protocol statistics", styles, level=2),
        ]
    )
    if protocols:
        story.append(
            _simple_table(
                [["Protocol", "Packet count"]]
                + [[name, str(count)] for name, count in protocols],
                [115 * mm, 55 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("No protocol statistics are available.", styles["body"]))

    addresses = _addresses(findings)
    story.append(_section_heading("Relevant IP addresses", styles, level=2))
    if addresses:
        story.append(
            _simple_table(
                [["Role", "Address"]] + [[role, address] for role, address in addresses],
                [45 * mm, 125 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("No source or destination IP addresses were recorded.", styles["body"]))

    story.append(_section_heading("Detection findings", styles))
    if findings:
        for index, finding in enumerate(findings, 1):
            story.extend(_finding_story(index, finding, styles))
    else:
        story.append(Paragraph("No findings were recorded for this investigation.", styles["body"]))

    story.append(_section_heading("Investigation activity history", styles))
    story.append(
        Paragraph(
            "The following records document saved investigation actions. "
            "Analyst assessments are separate from the automated detection findings above.",
            styles["body"],
        )
    )
    if activity:
        visible_activity = activity[-_MAX_ACTIVITY_EVENTS:]
        if len(activity) > len(visible_activity):
            story.append(
                Paragraph(
                    f"Showing the latest {len(visible_activity)} of "
                    f"{len(activity)} activity records.",
                    styles["small"],
                )
            )
        story.append(
            _simple_table(
                [["Timestamp (UTC)", "Event", "Finding", "Activity"]]
                + [
                    [
                        _format_app_timestamp(event.get("timestamp")),
                        _activity_label(event.get("event_type")),
                        _integer(event.get("finding_id"))
                        if event.get("finding_id") is not None
                        else "—",
                        _text(event.get("message"), "Activity record unavailable.", 240),
                    ]
                    for event in visible_activity
                ],
                [38 * mm, 36 * mm, 20 * mm, 80 * mm],
                styles,
                compact=True,
            )
        )
    else:
        story.append(Paragraph("No investigation activity has been recorded.", styles["body"]))

    story.append(_section_heading("Investigation timeline", styles))
    story.append(
        Paragraph(
            "Timeline timestamps below are capture events derived from stored packet evidence. "
            "Investigation creation and update timestamps are application metadata, shown separately "
            "on the cover.",
            styles["body"],
        )
    )
    if events:
        story.append(
            _simple_table(
                [["Capture time (UTC)", "Packet", "Detection", "Severity", "Source", "Destination"]]
                + [
                    [
                        _format_epoch(event.get("timestamp")),
                        _packet_number(event.get("packet_number")),
                        _text(event.get("finding_type"), "Not recorded", 160),
                        _severity(event.get("severity")).title(),
                        _text(event.get("source_ip"), "Not recorded", 128),
                        _text(event.get("destination_ip"), "Not recorded", 128),
                    ]
                    for event in events
                ],
                [36 * mm, 13 * mm, 36 * mm, 20 * mm, 32 * mm, 33 * mm],
                styles,
                compact=True,
            )
        )
    else:
        story.append(Paragraph("No timestamped packet evidence is available for a timeline.", styles["body"]))

    story.extend(
        [
            _section_heading("Analyst notes and conclusion", styles),
            _section_heading("Saved analyst notes", styles, level=2),
            _paragraph(_text(investigation.get("analyst_notes"), "No analyst notes recorded."), styles["note"]),
            _section_heading("Analyst conclusion", styles, level=2),
            _paragraph(
                _text(
                    investigation.get("analyst_conclusion"),
                    "Analyst conclusion not provided.",
                    10_000,
                ),
                styles["note"],
            ),
            Paragraph(
                "This is the analyst's assessment and is not generated automatically "
                "from detection results.",
                styles["small"],
            ),
            _section_heading("Limitations and disclaimer", styles),
            Paragraph(
                "Detection rules are heuristic and require analyst validation; false positives are possible. "
                "The parser currently summarizes supported Ethernet, IPv4, TCP, UDP, ICMP, ARP, VLAN-tagged "
                "frames, and extractable unencrypted UDP/53 DNS fields. It does not provide IPv6 analysis, "
                "stream reassembly, encrypted-DNS visibility, or complete protocol decoding. This report "
                "reflects only information retained in the saved investigation; bounded evidence may omit "
                "additional packets represented by finding counts and timestamps.",
                styles["body"],
            ),
        ]
    )
    return story


def _finding_story(
    index: int, finding: Mapping[str, Any], styles: Mapping[str, ParagraphStyle]
) -> list[Any]:
    finding_type = _text(finding.get("type"), "Finding type not recorded", 160)
    severity = _severity(finding.get("severity"))
    heading = Paragraph(
        f"{index}. [{escape(severity.upper())}] {_escape_text(finding_type)}",
        styles["subsection"],
    )
    details = [
        ("Finding ID", _integer(finding.get("finding_id"))),
        ("Confidence", _text(finding.get("confidence"), "Not recorded")),
        ("Source IP", _text(finding.get("source_ip"), "Not recorded", 128)),
        ("Destination IP", _text(finding.get("destination_ip"), "Not recorded", 128)),
        ("Protocol", _protocol_for_finding(finding_type)),
        ("First observed (UTC)", _format_epoch(finding.get("first_seen"))),
        ("Last observed (UTC)", _format_epoch(finding.get("last_seen"))),
        ("Packet count", _integer(finding.get("packet_count"))),
        (
            "Analyst disposition",
            _text(finding.get("analyst_disposition"), "Needs Review", 32),
        ),
        ("Assessment reviewed (UTC)", _format_app_timestamp(finding.get("reviewed_at"))),
    ]
    if finding.get("assessment_error"):
        details.append(("Assessment data", "Malformed stored analyst assessment"))
    story: list[Any] = [
        heading,
        _key_value_table(details, styles, compact=True),
        _section_heading("Detection explanation", styles, level=3),
        _paragraph(
            _text(finding.get("reason"), "No detection explanation was recorded."),
            styles["body"],
        ),
        _section_heading("Analyst reasoning", styles, level=3),
        _paragraph(
            _text(finding.get("analyst_reasoning"), "No analyst reasoning recorded.", 4_000),
            styles["note"],
        ),
    ]
    recommendations = [
        _text(value, "")
        for value in _sequence(finding.get("recommendations"))
        if isinstance(value, str) and value
    ]
    story.append(_section_heading("Recommended investigation steps", styles, level=3))
    if recommendations:
        story.extend(
            _paragraph(f"• {_escape_text(item)}", styles["body"])
            for item in recommendations
        )
    else:
        story.append(Paragraph("No recommendations were recorded.", styles["body"]))

    evidence = [
        _safe_evidence(item)
        for item in _sequence(finding.get("evidence"))
        if isinstance(item, Mapping)
    ][: _MAX_EVIDENCE_PER_FINDING]
    story.append(_section_heading("Packet evidence", styles, level=3))
    if evidence:
        table_data = [
            [
                "Packet",
                "Timestamp (UTC)",
                "Source",
                "Destination",
                "Review status",
                "Protocol / packet metadata",
            ]
        ]
        for packet in evidence:
            review_status = packet.get("review_status")
            if review_status not in {"Reviewed", "Not Reviewed"}:
                review_status = "Not available"
            table_data.append(
                [
                    _packet_number(packet.get("packet_number")),
                    _format_epoch(packet.get("timestamp")),
                    _text(packet.get("source_ip"), "Not recorded", 128),
                    _text(packet.get("destination_ip"), "Not recorded", 128),
                    review_status,
                    _evidence_metadata(packet, finding_type),
                ]
            )
        story.append(
            _simple_table(
                table_data,
                [12 * mm, 30 * mm, 32 * mm, 32 * mm, 21 * mm, 47 * mm],
                styles,
                compact=True,
            )
        )
        reported_omitted = _nonnegative_int(finding.get("evidence_truncated"))
        extra_count = max(
            reported_omitted,
            _nonnegative_int(finding.get("packet_count")) - len(evidence),
        )
        if extra_count:
            story.append(
                Paragraph(
                    f"{extra_count} additional packet(s) are represented by the finding count "
                    "and time range but are not individually listed.",
                    styles["small"],
                )
            )
    else:
        evidence_error = _text(
            finding.get("evidence_error"),
            "Structured packet evidence is unavailable.",
            160,
        )
        story.append(Paragraph(_escape_text(evidence_error), styles["body"]))
    story.append(Spacer(1, 4 * mm))
    return story


def _draw_page_chrome(canvas: Any, document: Any) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
    canvas.setFont("NTA-Vera", 7.5)
    canvas.setFillColor(colors.HexColor("#526473"))
    canvas.drawString(18 * mm, height - 11 * mm, "NETWORK SECURITY INVESTIGATION")
    canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
    canvas.drawString(18 * mm, 8 * mm, "Local investigation report - heuristic findings")
    canvas.drawRightString(width - 18 * mm, 8 * mm, f"Page {document.page}")
    canvas.restoreState()


def _section_heading(
    text: str, styles: Mapping[str, ParagraphStyle], level: int = 1
) -> Paragraph:
    style = styles["section"] if level == 1 else styles["subsection"]
    return Paragraph(_escape_text(text), style)


def _key_value_table(
    rows: list[tuple[str, Any]],
    styles: Mapping[str, ParagraphStyle],
    *,
    compact: bool = False,
) -> Table:
    label_style = styles["small"] if compact else styles["label"]
    value_style = styles["small"] if compact else styles["body"]
    data = [
        [
            Paragraph(_escape_text(label), label_style),
            _paragraph(_text(value, "Not recorded"), value_style),
        ]
        for label, value in rows
    ]
    widths = [48 * mm, 122 * mm]
    table = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=0)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), _PALE_BLUE),
                ("BACKGROUND", (1, 0), (1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, _BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4 if compact else 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4 if compact else 6),
            ]
        )
    )
    return table


def _simple_table(
    data: list[list[Any]],
    widths: list[float],
    styles: Mapping[str, ParagraphStyle],
    *,
    compact: bool = False,
) -> Table:
    style = styles["small"] if compact else styles["body"]
    cells = []
    for row_index, row in enumerate(data):
        cell_style = styles["table_header"] if row_index == 0 else style
        cells.append([Paragraph(_escape_text(value), cell_style) for value in row])
    table = Table(
        cells,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "NTA-Vera-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PALE_GRAY]),
                ("GRID", (0, 0), (-1, -1), 0.35, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _paragraph(value: str, style: ParagraphStyle) -> Paragraph:
    normalized = _normalize_text(value).replace("\r\n", "\n").replace("\r", "\n")
    return Paragraph(_escape_text(normalized).replace("\n", "<br/>"), style)


def _escape_text(value: Any) -> str:
    return escape(_normalize_text(str(value)), quote=True)


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    font = pdfmetrics.getFont("NTA-Vera")
    supported_glyphs = font.face.charWidths
    clean = []
    for char in normalized:
        if char in "\n\t":
            clean.append(char)
        elif unicodedata.category(char) in {"Cc", "Cs"}:
            continue
        elif ord(char) in supported_glyphs:
            clean.append(char)
        else:
            clean.append(f"[U+{ord(char):04X}]")
    return "".join(clean)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _text(value: Any, fallback: str, max_length: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    normalized = _normalize_text(value.strip())
    if max_length is not None and len(normalized) > max_length:
        return normalized[:max_length] + " ... [truncated]"
    return normalized


def _safe_capture_name(value: Any) -> str:
    if not isinstance(value, str):
        return "Not recorded"
    name = _text(value.replace("\\", "/").rsplit("/", 1)[-1], "Not recorded")
    if name in {"", ".", ".."}:
        return "Not recorded"
    if len(name) > 255:
        return name[:255] + " ... [truncated]"
    return name


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ReportGenerationError("Investigation ID is missing or invalid.")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ReportGenerationError("Investigation ID is missing or invalid.") from exc
    if str(parsed) != value.lower():
        raise ReportGenerationError("Investigation ID is missing or invalid.")
    return str(parsed)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_app_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "Not recorded"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return "Not recorded (invalid timestamp)"
    if parsed.tzinfo is None:
        return "Not recorded (timezone missing)"
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_epoch(value: Any) -> str:
    if not _finite_number(value):
        return "Not recorded"
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OverflowError, OSError, TypeError, ValueError):
        return "Not recorded"


def _finite_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _integer(value: Any) -> str:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return "Not recorded"
    return f"{value:,}"


def _nonnegative_int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return 0
    return value


def _number(value: Any) -> str:
    if not _finite_number(value):
        return "Not recorded"
    return f"{value:,.3f}"


def _packet_number(value: Any) -> str:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        return "Not recorded"
    return str(value)


def _severity(value: Any) -> str:
    if isinstance(value, str) and value.lower() in _SEVERITIES:
        return value.lower()
    return "not recorded"


def _protocols(value: Any) -> list[tuple[str, int]]:
    if not isinstance(value, Mapping):
        return []
    return [
        (_text(name, "Not recorded", 128), count)
        for name, count in sorted(value.items(), key=lambda item: str(item[0]).casefold())
        if isinstance(name, str)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
    ]


def _addresses(findings: list[Mapping[str, Any]]) -> list[tuple[str, str]]:
    found = {
        (role, _text(value.strip(), "Not recorded", 128))
        for finding in findings
        for role, key in (("Source", "source_ip"), ("Destination", "destination_ip"))
        if isinstance((value := finding.get(key)), str) and value.strip()
    }
    return sorted(found, key=lambda pair: (pair[0], pair[1]))


def _valid_timeline(value: Any) -> list[Mapping[str, Any]]:
    events = [
        event
        for event in _sequence(value)
        if isinstance(event, Mapping)
        and _finite_number(event.get("timestamp"))
        and isinstance(event.get("packet_number"), int)
        and not isinstance(event.get("packet_number"), bool)
        and event.get("packet_number") > 0
    ]
    return sorted(
        events,
        key=lambda event: (
            float(event["timestamp"]),
            event["packet_number"],
            _text(event.get("finding_type"), ""),
        ),
    )


def _valid_activity(value: Any) -> list[Mapping[str, Any]]:
    events = [
        event
        for event in _sequence(value)
        if isinstance(event, Mapping)
    ]
    return sorted(
        events,
        key=lambda event: (
            event.get("timestamp")
            if isinstance(event.get("timestamp"), str)
            else "",
            event.get("id")
            if isinstance(event.get("id"), int)
            and not isinstance(event.get("id"), bool)
            else 0,
        ),
    )


def _activity_label(value: Any) -> str:
    labels = {
        "investigation_created": "Investigation created",
        "status_changed": "Status changed",
        "notes_updated": "Notes updated",
        "conclusion_updated": "Conclusion updated",
        "finding_review_updated": "Finding assessment updated",
        "finding_disposition_changed": "Finding disposition changed",
        "evidence_review_changed": "Evidence review changed",
        "pdf_report_generated": "PDF report generated",
    }
    if not isinstance(value, str):
        return "Malformed activity event"
    return labels.get(value, "Malformed activity event")


def _safe_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in _SAFE_EVIDENCE_FIELDS if key in value}


def _protocol_for_finding(finding_type: str) -> str:
    return _PROTOCOL_BY_FINDING.get(finding_type, "Not recorded")


def _evidence_metadata(evidence: Mapping[str, Any], finding_type: str) -> str:
    values = [f"Protocol: {_protocol_for_finding(finding_type)}"]
    if "destination_port" in evidence and _valid_integer(
        evidence["destination_port"], 0, 65535
    ):
        values.append(f"Destination port: {evidence['destination_port']}")
    if "tcp_flags" in evidence and _valid_integer(evidence["tcp_flags"], 0, 255):
        values.append(f"TCP flags: 0x{evidence['tcp_flags']:02x}")
    mac = evidence.get("mac_address")
    if isinstance(mac, str):
        values.append(f"MAC: {_text(mac, '', 64)}")
    dns_name = evidence.get("dns_name")
    if isinstance(dns_name, str):
        values.append(f"DNS query: {_text(dns_name, '', 255)}")
    return "; ".join(values)


def _valid_integer(value: Any, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )
