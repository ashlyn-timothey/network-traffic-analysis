import json
import struct

import pytest

from network_traffic_analysis import (
    CaptureError,
    DetectionThresholds,
    analyze_bytes,
)
from test_pcap_summary import (
    MAC_A,
    MAC_B,
    MAC_C,
    arp_reply,
    eth,
    ipv4,
    dns_frame,
    ps,
    tcp_frame,
    write_pcap,
    write_pcapng,
)


def icmp_frame(src, dst, icmp_type=8, code=0):
    icmp = struct.pack("!BBHI", icmp_type, code, 0, 1)
    return eth(MAC_B, MAC_A, 0x0800, ipv4(src, dst, 1, icmp))


@pytest.mark.parametrize(
    ("writer", "expected_timestamp"),
    [(write_pcap, 1000), (write_pcapng, 0)],
)
def test_scan_finding_has_structured_evidence(
    tmp_path, writer, expected_timestamp
):
    frames = [
        tcp_frame("10.0.0.9", "10.0.0.5", port, 0x02)
        for port in range(20, 36)
    ]
    capture_path = tmp_path / "structured-scan.capture"
    writer(str(capture_path), frames)

    report = analyze_bytes(capture_path.read_bytes(), source="upload.pcap")
    finding = next(
        item for item in report["findings"] if item["type"] == "vertical_syn_scan"
    )

    assert finding["source_ip"] == "10.0.0.9"
    assert finding["destination_ip"] == "10.0.0.5"
    assert finding["timestamp"] == expected_timestamp
    assert "16 distinct TCP ports" in finding["reason"]
    assert finding["evidence"][0] == {
        "packet_number": 1,
        "timestamp": expected_timestamp,
        "source_ip": "10.0.0.9",
        "destination_ip": "10.0.0.5",
        "destination_port": 20,
        "tcp_flags": 0x02,
    }


def test_arp_conflict_has_claim_evidence(tmp_path):
    capture_path = tmp_path / "arp.pcap"
    write_pcap(
        str(capture_path),
        [arp_reply("10.0.0.1", MAC_A), arp_reply("10.0.0.1", MAC_C)],
    )

    finding = analyze_bytes(capture_path.read_bytes())["findings"][0]

    assert finding["type"] == "arp_ip_claimed_by_multiple_macs"
    assert finding["source_ip"] == "10.0.0.1"
    assert finding["destination_ip"] is None
    assert finding["timestamp"] == 1001
    assert len(finding["evidence"]) == 2
    assert {item["mac_address"] for item in finding["evidence"]} == {
        "02:00:00:00:00:0a",
        "02:00:00:00:00:0c",
    }


def test_horizontal_sweep_exposes_host_evidence(tmp_path):
    capture_path = tmp_path / "sweep.pcap"
    write_pcap(
        str(capture_path),
        [
            tcp_frame("10.0.0.9", f"10.0.1.{host}", 22, 0x02)
            for host in range(1, 16)
        ],
    )

    finding = next(
        item
        for item in analyze_bytes(capture_path.read_bytes())["findings"]
        if item["type"] == "horizontal_syn_sweep"
    )

    assert finding["source_ip"] == "10.0.0.9"
    assert finding["destination_ip"] is None
    assert finding["distinct_hosts"] == 15
    assert len(finding["evidence"]) == 15


def test_rejects_truncated_pcap_record():
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1000, 0, 10, 10) + b"short"

    with pytest.raises(CaptureError, match="truncated PCAP packet data"):
        analyze_bytes(header + record)


def test_rejects_invalid_pcapng_block_trailer(tmp_path):
    capture_path = tmp_path / "empty.pcapng"
    write_pcapng(str(capture_path), [])
    capture = bytearray(capture_path.read_bytes())
    capture[44:48] = struct.pack("<I", 24)

    with pytest.raises(CaptureError, match="does not match trailing length"):
        analyze_bytes(bytes(capture))


def test_counts_malformed_ethernet_ipv4_frames(tmp_path):
    capture_path = tmp_path / "short-ip.pcap"
    frame = eth(MAC_B, MAC_A, 0x0800, b"\x45\x00\x00\x14\x00\x00")
    write_pcap(str(capture_path), [frame])

    report = analyze_bytes(capture_path.read_bytes())

    assert report["packets"] == 1
    assert report["malformed_packets"] == 1
    assert report["protocols"] == {}


@pytest.mark.parametrize("threshold", [0, -1, True, 1.5])
def test_rejects_invalid_scan_threshold(threshold):
    with pytest.raises(ValueError, match="positive integer"):
        analyze_bytes(b"not a capture", threshold=threshold)


def test_bounds_finding_evidence_and_reports_truncation(tmp_path):
    capture_path = tmp_path / "large-scan.pcap"
    write_pcap(
        str(capture_path),
        [
            tcp_frame("10.0.0.9", "10.0.0.5", port, 0x02)
            for port in range(1, 41)
        ],
    )

    finding = analyze_bytes(capture_path.read_bytes())["findings"][0]

    assert len(finding["evidence"]) == 25
    assert finding["evidence_truncated"] == 15


def test_icmp_echo_sweep_threshold_and_negative_case(tmp_path):
    destinations = [f"10.0.1.{host}" for host in range(1, 11)]
    negative_path = tmp_path / "icmp-below.pcap"
    positive_path = tmp_path / "icmp-at-threshold.pcap"
    write_pcap(str(negative_path), [icmp_frame("10.0.0.9", ip) for ip in destinations[:9]])
    write_pcap(str(positive_path), [icmp_frame("10.0.0.9", ip) for ip in destinations])

    negative = analyze_bytes(negative_path.read_bytes())
    positive = analyze_bytes(positive_path.read_bytes())
    finding = next(
        item for item in positive["findings"] if item["type"] == "possible_icmp_sweep"
    )

    assert not any(item["type"] == "possible_icmp_sweep" for item in negative["findings"])
    assert finding["severity"] == "low"
    assert finding["confidence"] == "low"
    assert finding["packet_count"] == 10
    assert finding["first_seen"] == 1000
    assert finding["last_seen"] == 1009
    assert len(finding["evidence"]) == 10


def test_icmp_echo_reply_does_not_count_as_sweep(tmp_path):
    capture_path = tmp_path / "icmp-replies.pcap"
    write_pcap(
        str(capture_path),
        [icmp_frame("10.0.0.9", f"10.0.1.{host}", icmp_type=0) for host in range(1, 12)],
    )

    report = analyze_bytes(capture_path.read_bytes())

    assert not any(item["type"] == "possible_icmp_sweep" for item in report["findings"])


def test_dns_volume_threshold_has_bounded_evidence(tmp_path):
    below_path = tmp_path / "dns-below.pcap"
    at_path = tmp_path / "dns-at.pcap"
    write_pcap(str(below_path), [dns_frame("example.test") for _ in range(99)])
    write_pcap(str(at_path), [dns_frame("example.test") for _ in range(100)])

    below = analyze_bytes(below_path.read_bytes())
    at = analyze_bytes(at_path.read_bytes())
    finding = next(
        item for item in at["findings"] if item["type"] == "high_dns_query_volume"
    )

    assert not any(item["type"] == "high_dns_query_volume" for item in below["findings"])
    assert finding["packet_count"] == 100
    assert finding["first_seen"] == 1000
    assert finding["last_seen"] == 1099
    assert len(finding["evidence"]) == 25
    assert finding["evidence_truncated"] == 75
    assert finding["confidence"] == "low"
    assert finding["evidence"][0]["dns_name"] == "example.test"


def test_dns_threshold_is_configurable_and_invalid_values_rejected(tmp_path):
    capture_path = tmp_path / "dns-configured.pcap"
    write_pcap(str(capture_path), [dns_frame("example.test") for _ in range(3)])

    report = analyze_bytes(
        capture_path.read_bytes(),
        detection_thresholds=DetectionThresholds(dns_query_volume=3),
    )
    with pytest.raises(ValueError, match="dns_query_volume"):
        DetectionThresholds(dns_query_volume=0)

    assert any(item["type"] == "high_dns_query_volume" for item in report["findings"])


def test_dns_responses_are_not_counted_as_queries(tmp_path):
    capture_path = tmp_path / "dns-responses.pcap"
    write_pcap(
        str(capture_path),
        [dns_frame("example.test", response=True) for _ in range(100)],
    )

    report = analyze_bytes(capture_path.read_bytes())

    assert report["top_dns_queries"] == []
    assert not any(item["type"] == "high_dns_query_volume" for item in report["findings"])


def test_icmp_sweep_threshold_is_configurable(tmp_path):
    capture_path = tmp_path / "icmp-configured.pcap"
    write_pcap(
        str(capture_path),
        [icmp_frame("10.0.0.9", f"10.0.1.{host}") for host in range(1, 4)],
    )

    report = analyze_bytes(
        capture_path.read_bytes(),
        detection_thresholds=DetectionThresholds(icmp_sweep_hosts=3),
    )

    assert any(item["type"] == "possible_icmp_sweep" for item in report["findings"])


def test_repeated_connection_attempts_count_duplicates_once_per_finding(tmp_path):
    capture_path = tmp_path / "repeated-syn.pcap"
    write_pcap(
        str(capture_path),
        [tcp_frame("10.0.0.9", "10.0.0.5", 443, 0x02) for _ in range(20)],
    )

    report = analyze_bytes(capture_path.read_bytes())
    matches = [
        item
        for item in report["findings"]
        if item["type"] == "repeated_connection_attempts"
    ]

    assert len(matches) == 1
    assert matches[0]["packet_count"] == 20
    assert matches[0]["first_seen"] == 1000
    assert matches[0]["last_seen"] == 1019
    assert len(matches[0]["evidence"]) == 20


def test_repeated_connection_attempt_threshold_boundary(tmp_path):
    below_path = tmp_path / "repeated-below.pcap"
    at_path = tmp_path / "repeated-at.pcap"
    packets = [tcp_frame("10.0.0.9", "10.0.0.5", 443, 0x02) for _ in range(20)]
    write_pcap(str(below_path), packets[:19])
    write_pcap(str(at_path), packets)

    below = analyze_bytes(below_path.read_bytes())
    at = analyze_bytes(at_path.read_bytes())

    assert not any(item["type"] == "repeated_connection_attempts" for item in below["findings"])
    assert any(item["type"] == "repeated_connection_attempts" for item in at["findings"])


def test_repeated_syn_threshold_is_configurable(tmp_path):
    capture_path = tmp_path / "repeated-configured.pcap"
    write_pcap(
        str(capture_path),
        [tcp_frame("10.0.0.9", "10.0.0.5", 443, 0x02) for _ in range(3)],
    )

    report = analyze_bytes(
        capture_path.read_bytes(),
        detection_thresholds=DetectionThresholds(repeated_syn_attempts=3),
    )

    assert any(
        item["type"] == "repeated_connection_attempts"
        for item in report["findings"]
    )


def test_unusual_tcp_flags_report_header_evidence_not_syn_ack(tmp_path):
    capture_path = tmp_path / "unusual-flags.pcap"
    frames = [
        tcp_frame("10.0.0.9", "10.0.0.5", 80, 0x03),
        tcp_frame("10.0.0.9", "10.0.0.5", 443, 0x12),
    ]
    write_pcap(str(capture_path), frames)

    report = analyze_bytes(capture_path.read_bytes())
    matches = [
        item
        for item in report["findings"]
        if item["type"] == "unusual_tcp_flag_combination"
    ]

    assert len(matches) == 1
    assert matches[0]["severity"] == "informational"
    assert matches[0]["confidence"] == "medium"
    assert matches[0]["packet_count"] == 1
    assert matches[0]["evidence"][0]["tcp_flags"] == 0x03


def test_new_findings_have_severity_confidence_and_recommendations(tmp_path):
    capture_path = tmp_path / "icmp-metadata.pcap"
    write_pcap(
        str(capture_path),
        [icmp_frame("10.0.0.9", f"10.0.1.{host}") for host in range(1, 11)],
    )

    finding = next(
        item
        for item in analyze_bytes(capture_path.read_bytes())["findings"]
        if item["type"] == "possible_icmp_sweep"
    )

    assert finding["severity"] in {"informational", "low", "medium", "high"}
    assert finding["confidence"] in {"low", "medium", "high"}
    assert finding["source_ip"] == "10.0.0.9"
    assert finding["destination_ip"] is None
    assert finding["reason"]
    assert finding["first_seen"] <= finding["last_seen"]
    assert finding["packet_count"] >= len(finding["evidence"])
    assert finding["recommendations"]


def test_cli_accepts_new_threshold_options_and_keeps_json_output(tmp_path, capsys):
    capture_path = tmp_path / "cli-repeated-syn.pcap"
    write_pcap(
        str(capture_path),
        [tcp_frame("10.0.0.9", "10.0.0.5", 443, 0x02) for _ in range(3)],
    )

    exit_code = ps.main(
        [
            str(capture_path),
            "--repeated-syn-threshold",
            "3",
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    finding = next(
        item
        for item in report["findings"]
        if item["type"] == "repeated_connection_attempts"
    )
    assert finding["packet_count"] == 3
