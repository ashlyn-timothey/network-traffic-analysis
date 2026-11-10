#!/usr/bin/env python3
"""Backwards-compatible command-line interface for the packet analysis engine."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from network_traffic_analysis.analysis import analyse, parse_dns_qname  # noqa: E402
from network_traffic_analysis.capture import (  # noqa: E402
    LINKTYPE_ETHERNET,
    PCAP_MAGICS,
    PCAPNG_SHB,
    CaptureError,
    read_packets,
)
from network_traffic_analysis.models import DetectionThresholds  # noqa: E402

__all__ = [
    "LINKTYPE_ETHERNET",
    "PCAP_MAGICS",
    "PCAPNG_SHB",
    "CaptureError",
    "DetectionThresholds",
    "analyse",
    "main",
    "parse_dns_qname",
    "read_packets",
    "render",
]


def render(report):
    out = [
        f"File: {report['file']}",
        f"Packets: {report['packets']}  Duration: {report['duration_s']}s",
    ]
    if report["skipped_non_ethernet"]:
        out.append(
            f"Skipped (non-Ethernet link type): {report['skipped_non_ethernet']}"
        )
    if report.get("malformed_packets"):
        out.append(f"Malformed packets skipped: {report['malformed_packets']}")
    out.append(
        "Protocols: "
        + ", ".join(f"{key}={value}" for key, value in report["protocols"].items())
    )
    out.append(
        "Top talkers: "
        + ", ".join(f"{ip} ({count})" for ip, count in report["top_talkers"])
    )
    out.append(
        "Top DNS queries: "
        + (
            ", ".join(f"{name} ({count})" for name, count in report["top_dns_queries"])
            or "none"
        )
    )
    out.append(f"\nFindings (scan threshold = {report['threshold']}):")
    if not report["findings"]:
        out.append("  none")
    for finding in report["findings"]:
        out.append(
            "  [!] "
            + f"{finding['type']} severity={finding['severity']} "
            + f"confidence={finding['confidence']} "
            + f"packets={finding['packet_count']} "
            + f"source_ip={finding['source_ip']} "
            + f"destination_ip={finding['destination_ip']}"
        )
        out.append(f"      reason={finding['reason']}")
        out.append(
            "      recommendations="
            + " | ".join(finding["recommendations"])
        )
        out.append(
            "      details="
            + ", ".join(
                f"{key}={value}"
                for key, value in finding.items()
                if key
                not in {
                    "type",
                    "severity",
                    "confidence",
                    "source_ip",
                    "destination_ip",
                    "timestamp",
                    "first_seen",
                    "last_seen",
                    "packet_count",
                    "reason",
                    "evidence",
                    "recommendations",
                }
            )
        )
    out.append(
        "\nThese are heuristics: confirm every finding in Wireshark before reporting it."
    )
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Triage a pcap/pcapng capture.")
    parser.add_argument("capture")
    parser.add_argument(
        "--threshold",
        type=int,
        default=15,
        help="distinct ports/hosts before a SYN pattern is flagged (default 15)",
    )
    parser.add_argument(
        "--icmp-sweep-threshold",
        type=int,
        default=10,
        help="distinct ICMP echo destinations before a sweep is flagged",
    )
    parser.add_argument(
        "--dns-volume-threshold",
        type=int,
        default=100,
        help="extractable UDP/53 queries per source before volume is flagged",
    )
    parser.add_argument(
        "--repeated-syn-threshold",
        type=int,
        default=20,
        help="TCP SYN attempts to one destination/port before flagging",
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)
    try:
        thresholds = DetectionThresholds(
            icmp_sweep_hosts=args.icmp_sweep_threshold,
            dns_query_volume=args.dns_volume_threshold,
            repeated_syn_attempts=args.repeated_syn_threshold,
        )
        report = analyse(
            args.capture,
            args.threshold,
            detection_thresholds=thresholds,
        )
    except (OSError, CaptureError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
