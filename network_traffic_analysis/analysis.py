"""Packet decoding and capture-level aggregation."""

import socket
import struct
from collections import Counter, defaultdict
from os import PathLike, fspath
from pathlib import Path

from .capture import LINKTYPE_ETHERNET, iter_capture_packets
from .detections import detect_findings
from .models import DetectionThresholds, EvidenceStats, PacketEvidence

VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}


def analyse(
    path: str | PathLike,
    threshold: int = 15,
    *,
    detection_thresholds: DetectionThresholds | None = None,
) -> dict:
    """Analyse a PCAP/PCAPNG path and return the legacy-compatible report shape."""
    path_text = fspath(path)
    return analyze_bytes(
        Path(path).read_bytes(),
        source=path_text,
        threshold=threshold,
        detection_thresholds=detection_thresholds,
    )


def analyze_bytes(
    data: bytes,
    source: str = "<upload>",
    threshold: int = 15,
    *,
    detection_thresholds: DetectionThresholds | None = None,
) -> dict:
    """Analyse capture bytes, suitable for local in-memory uploads."""
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    thresholds = detection_thresholds or DetectionThresholds()

    protocols: Counter = Counter()
    talkers: Counter = Counter()
    syn_ports: dict = defaultdict(lambda: defaultdict(dict))
    syn_packets: dict = defaultdict(EvidenceStats)
    repeated_syn: dict = defaultdict(EvidenceStats)
    arp_claims: dict = defaultdict(lambda: defaultdict(EvidenceStats))
    icmp_echo: dict = defaultdict(lambda: defaultdict(EvidenceStats))
    dns_queries: dict = defaultdict(EvidenceStats)
    unusual_tcp_flags: dict = defaultdict(EvidenceStats)
    dns_names: Counter = Counter()
    first_timestamp = None
    last_timestamp = None
    total = skipped = malformed = 0

    for packet in iter_capture_packets(data):
        total += 1
        first_timestamp = (
            packet.timestamp
            if first_timestamp is None
            else min(first_timestamp, packet.timestamp)
        )
        last_timestamp = (
            packet.timestamp
            if last_timestamp is None
            else max(last_timestamp, packet.timestamp)
        )

        if packet.linktype != LINKTYPE_ETHERNET:
            skipped += 1
            continue
        if len(packet.raw) < 14:
            malformed += 1
            continue

        ethertype, offset = struct.unpack("!H", packet.raw[12:14])[0], 14
        while ethertype in VLAN_ETHERTYPES:
            if len(packet.raw) < offset + 4:
                malformed += 1
                break
            ethertype = struct.unpack("!H", packet.raw[offset + 2 : offset + 4])[0]
            offset += 4
        else:
            if ethertype == 0x0806:
                if len(packet.raw) < offset + 28:
                    malformed += 1
                    continue
                hardware_type, protocol_type = struct.unpack(
                    "!HH", packet.raw[offset : offset + 4]
                )
                hardware_len, protocol_len, operation = struct.unpack(
                    "!BBH", packet.raw[offset + 4 : offset + 8]
                )
                if (
                    hardware_type != 1
                    or protocol_type != 0x0800
                    or hardware_len != 6
                    or protocol_len != 4
                ):
                    malformed += 1
                    continue
                protocols["ARP"] += 1
                if operation == 2:
                    mac = ":".join(
                        f"{byte:02x}" for byte in packet.raw[offset + 8 : offset + 14]
                    )
                    ip_address = socket.inet_ntoa(
                        packet.raw[offset + 14 : offset + 18]
                    )
                    arp_claims[ip_address][mac].add(
                        PacketEvidence(
                            packet.number,
                            packet.timestamp,
                            source_ip=ip_address,
                            mac_address=mac,
                        )
                    )
            elif ethertype == 0x0800:
                if len(packet.raw) < offset + 20:
                    malformed += 1
                    continue
                version = packet.raw[offset] >> 4
                header_len = (packet.raw[offset] & 0x0F) * 4
                if (
                    version != 4
                    or header_len < 20
                    or len(packet.raw) < offset + header_len
                ):
                    malformed += 1
                    continue
                total_len = struct.unpack("!H", packet.raw[offset + 2 : offset + 4])[0]
                if total_len < header_len:
                    malformed += 1
                    continue

                ip_protocol = packet.raw[offset + 9]
                source_ip = socket.inet_ntoa(packet.raw[offset + 12 : offset + 16])
                destination_ip = socket.inet_ntoa(
                    packet.raw[offset + 16 : offset + 20]
                )
                talkers[source_ip] += 1
                fragment = struct.unpack(
                    "!H", packet.raw[offset + 6 : offset + 8]
                )[0]
                fragment_offset = fragment & 0x1FFF
                transport_offset = offset + header_len
                packet_end = min(offset + total_len, len(packet.raw))

                if fragment_offset:
                    protocols[f"IP/{ip_protocol}"] += 1
                    continue
                if ip_protocol == 6:
                    if packet_end < transport_offset + 20:
                        malformed += 1
                        continue
                    tcp_header_len = (packet.raw[transport_offset + 12] >> 4) * 4
                    if tcp_header_len < 20 or tcp_header_len > total_len - header_len:
                        malformed += 1
                        continue
                    protocols["TCP"] += 1
                    destination_port = struct.unpack(
                        "!H", packet.raw[transport_offset + 2 : transport_offset + 4]
                    )[0]
                    flags = packet.raw[transport_offset + 13]
                    evidence = PacketEvidence(
                        packet.number,
                        packet.timestamp,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        tcp_flags=flags,
                    )
                    if flags & 0x12 == 0x02:
                        syn_ports[source_ip][destination_ip].setdefault(
                            destination_port, EvidenceStats()
                        ).add(evidence)
                        syn_packets[(source_ip, destination_ip)].add(evidence)
                        repeated_syn[
                            (source_ip, destination_ip, destination_port)
                        ].add(evidence)
                    if flags & 0x02 and flags & (0x01 | 0x04):
                        unusual_tcp_flags[
                            (source_ip, destination_ip, destination_port, flags)
                        ].add(evidence)
                elif ip_protocol == 17:
                    if packet_end < transport_offset + 8:
                        malformed += 1
                        continue
                    udp_len = struct.unpack(
                        "!H", packet.raw[transport_offset + 4 : transport_offset + 6]
                    )[0]
                    if udp_len < 8:
                        malformed += 1
                        continue
                    protocols["UDP"] += 1
                    destination_port = struct.unpack(
                        "!H", packet.raw[transport_offset + 2 : transport_offset + 4]
                    )[0]
                    if destination_port == 53:
                        dns_start = transport_offset + 8
                        dns_end = min(transport_offset + udp_len, packet_end)
                        name = parse_dns_qname(packet.raw[dns_start:dns_end])
                        if name:
                            dns_names[name] += 1
                            dns_queries[source_ip].add(
                                PacketEvidence(
                                    packet.number,
                                    packet.timestamp,
                                    source_ip=source_ip,
                                    destination_ip=destination_ip,
                                    destination_port=destination_port,
                                    dns_name=name,
                                )
                            )
                elif ip_protocol == 1:
                    if packet_end < transport_offset + 4:
                        malformed += 1
                        continue
                    protocols["ICMP"] += 1
                    if packet_end >= transport_offset + 8:
                        icmp_type, icmp_code = packet.raw[
                            transport_offset : transport_offset + 2
                        ]
                        if icmp_type == 8 and icmp_code == 0:
                            icmp_echo[source_ip][destination_ip].add(
                                PacketEvidence(
                                    packet.number,
                                    packet.timestamp,
                                    source_ip=source_ip,
                                    destination_ip=destination_ip,
                                )
                            )
                else:
                    protocols[f"IP/{ip_protocol}"] += 1
            else:
                protocols[f"ethertype 0x{ethertype:04x}"] += 1
            continue

        # The VLAN loop broke because a tag was truncated.
        continue

    findings = detect_findings(
        syn_ports,
        syn_packets,
        repeated_syn,
        arp_claims,
        icmp_echo,
        dns_queries,
        unusual_tcp_flags,
        threshold,
        thresholds.icmp_sweep_hosts,
        thresholds.dns_query_volume,
        thresholds.repeated_syn_attempts,
    )
    return {
        "file": source,
        "packets": total,
        "skipped_non_ethernet": skipped,
        "malformed_packets": malformed,
        "duration_s": round(last_timestamp - first_timestamp, 3)
        if first_timestamp is not None and last_timestamp is not None
        else 0,
        "capture_first_timestamp": first_timestamp,
        "capture_last_timestamp": last_timestamp,
        "protocols": dict(protocols.most_common()),
        "top_talkers": talkers.most_common(5),
        "top_dns_queries": dns_names.most_common(5),
        "findings": findings,
        "threshold": threshold,
        "detection_thresholds": {
            "icmp_sweep_hosts": thresholds.icmp_sweep_hosts,
            "dns_query_volume": thresholds.dns_query_volume,
            "repeated_syn_attempts": thresholds.repeated_syn_attempts,
        },
    }


def parse_dns_qname(payload: bytes) -> str | None:
    """Return the first uncompressed question name from a DNS query, if present."""
    if len(payload) < 13 or payload[2] & 0x80:
        return None
    question_count = struct.unpack("!H", payload[4:6])[0]
    if question_count == 0:
        return None

    labels = []
    position = 12
    while position < len(payload):
        length = payload[position]
        if length == 0:
            return ".".join(labels).lower() or None
        if length > 63 or length & 0xC0 or position + 1 + length > len(payload):
            return None
        labels.append(payload[position + 1 : position + 1 + length].decode("ascii", "replace"))
        position += 1 + length
    return None
