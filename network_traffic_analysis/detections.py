"""Deterministic, explainable packet-level detection heuristics."""

from collections.abc import Mapping

from .models import EvidenceStats, Finding


def detect_findings(
    syn_ports: Mapping[str, Mapping[str, Mapping[int, EvidenceStats]]],
    syn_packets: Mapping[str, Mapping[str, EvidenceStats]],
    repeated_syn: Mapping[tuple[str, str, int], EvidenceStats],
    arp_claims: Mapping[str, Mapping[str, EvidenceStats]],
    icmp_echo: Mapping[str, Mapping[str, EvidenceStats]],
    dns_queries: Mapping[str, EvidenceStats],
    unusual_tcp_flags: Mapping[tuple[str, str, int, int], EvidenceStats],
    scan_threshold: int,
    icmp_sweep_threshold: int,
    dns_volume_threshold: int,
    repeated_syn_threshold: int,
) -> list[dict]:
    findings: list[Finding] = []

    for source_ip, targets in syn_ports.items():
        for destination_ip, ports in targets.items():
            if len(ports) >= scan_threshold:
                stats = _merge([syn_packets[(source_ip, destination_ip)]])
                findings.append(
                    Finding(
                        type="vertical_syn_scan",
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        timestamp=stats.first_seen or 0,
                        first_seen=stats.first_seen,
                        last_seen=stats.last_seen,
                        packet_count=stats.packet_count,
                        severity="medium",
                        confidence="medium",
                        reason=(
                            f"Observed SYN packets to {len(ports)} distinct TCP "
                            f"ports (threshold: {scan_threshold}). This capture-wide "
                            "pattern may also result from authorized scanning or "
                            "monitoring; it does not prove malicious activity."
                        ),
                        evidence=stats.evidence,
                        recommendations=(
                            "Check the source owner and authorization for scanning.",
                            "Review destination-port outcomes and the surrounding time window.",
                            "Compare with an approved scanner and normal-traffic baseline.",
                        ),
                        details={"distinct_ports": len(ports)},
                    )
                )

        if len(targets) >= scan_threshold:
            stats = _merge(
                syn_packets[(source_ip, destination_ip)]
                for destination_ip in targets
            )
            findings.append(
                Finding(
                    type="horizontal_syn_sweep",
                    source_ip=source_ip,
                    destination_ip=None,
                    timestamp=stats.first_seen or 0,
                    first_seen=stats.first_seen,
                    last_seen=stats.last_seen,
                    packet_count=stats.packet_count,
                    severity="medium",
                    confidence="medium",
                    reason=(
                        f"Observed SYN packets to {len(targets)} distinct IPv4 "
                        f"hosts (threshold: {scan_threshold}). This capture-wide "
                        "pattern may also result from authorized scanning or "
                        "monitoring; it does not prove malicious activity."
                    ),
                    evidence=stats.evidence,
                    recommendations=(
                        "Check whether the source is an authorized discovery or monitoring system.",
                        "Review the target set and packet outcomes in the capture.",
                        "Compare with an approved scanner and normal-traffic baseline.",
                    ),
                    details={"distinct_hosts": len(targets)},
                )
            )

    for (source_ip, destination_ip, destination_port), stats in repeated_syn.items():
        if stats.packet_count >= repeated_syn_threshold:
            findings.append(
                Finding(
                    type="repeated_connection_attempts",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    timestamp=stats.first_seen or 0,
                    first_seen=stats.first_seen,
                    last_seen=stats.last_seen,
                    packet_count=stats.packet_count,
                    severity="low",
                    confidence="low",
                    reason=(
                        f"Observed {stats.packet_count} TCP SYN packets from this "
                        f"source to destination port {destination_port} "
                        f"(threshold: {repeated_syn_threshold}). Retransmissions, "
                        "retries, and capture duplication can produce this pattern."
                    ),
                    evidence=stats.evidence,
                    recommendations=(
                        "Inspect SYN/SYN-ACK/RST responses and the interval between attempts.",
                        "Check whether retries match expected client behavior or a service outage.",
                        "Correlate with endpoint or firewall logs before escalation.",
                    ),
                    details={"destination_port": destination_port},
                )
            )

    for source_ip, destinations in icmp_echo.items():
        if len(destinations) >= icmp_sweep_threshold:
            stats = _merge(destinations.values())
            findings.append(
                Finding(
                    type="possible_icmp_sweep",
                    source_ip=source_ip,
                    destination_ip=None,
                    timestamp=stats.first_seen or 0,
                    first_seen=stats.first_seen,
                    last_seen=stats.last_seen,
                    packet_count=stats.packet_count,
                    severity="low",
                    confidence="low",
                    reason=(
                        f"Observed ICMP echo requests to {len(destinations)} "
                        f"distinct IPv4 destinations (threshold: "
                        f"{icmp_sweep_threshold}). Host discovery and monitoring "
                        "can produce the same pattern."
                    ),
                    evidence=stats.evidence,
                    recommendations=(
                        "Verify that the source is authorized to perform reachability checks.",
                        "Review destination addresses and replies in the capture.",
                        "Compare the observed rate with the network's normal monitoring baseline.",
                    ),
                    details={"distinct_hosts": len(destinations)},
                )
            )

    for source_ip, stats in dns_queries.items():
        if stats.packet_count >= dns_volume_threshold:
            findings.append(
                Finding(
                    type="high_dns_query_volume",
                    source_ip=source_ip,
                    destination_ip=None,
                    timestamp=stats.first_seen or 0,
                    first_seen=stats.first_seen,
                    last_seen=stats.last_seen,
                    packet_count=stats.packet_count,
                    severity="low",
                    confidence="low",
                    reason=(
                        f"Observed {stats.packet_count} extractable UDP/53 DNS "
                        f"queries from this source (threshold: "
                        f"{dns_volume_threshold}). Busy clients, resolvers, "
                        "retries, or long captures may naturally exceed this limit."
                    ),
                    evidence=stats.evidence,
                    recommendations=(
                        "Review query rate over a known time window and identify the source role.",
                        "Inspect queried names and response codes with a DNS-aware analyzer.",
                        "Compare with a normal baseline; this rule alone does not indicate tunneling.",
                    ),
                )
            )

    for ip_address, mac_claims in arp_claims.items():
        if len(mac_claims) > 1:
            stats = _merge(mac_claims.values())
            first_claims = sorted(
                (value.evidence[0] for value in mac_claims.values() if value.evidence),
                key=lambda item: item.packet_number,
            )
            findings.append(
                Finding(
                    type="arp_ip_claimed_by_multiple_macs",
                    source_ip=ip_address,
                    destination_ip=None,
                    timestamp=first_claims[1].timestamp,
                    first_seen=stats.first_seen,
                    last_seen=stats.last_seen,
                    packet_count=stats.packet_count,
                    severity="medium",
                    confidence="low",
                    reason=(
                        f"ARP replies claimed sender IP {ip_address} from "
                        f"{len(mac_claims)} distinct MAC addresses. Failover, "
                        "address reassignment, or virtualization can also explain this."
                    ),
                    evidence=stats.evidence,
                    recommendations=(
                        "Check switch, DHCP, and endpoint records for the claimed IP and MAC addresses.",
                        "Compare against an authorized baseline and the timing of network changes.",
                        "Validate the ARP state from a trusted host before concluding spoofing.",
                    ),
                    details={"ip": ip_address, "macs": sorted(mac_claims)},
                )
            )

    for (source_ip, destination_ip, destination_port, flags), stats in unusual_tcp_flags.items():
        flag_names = []
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x04:
            flag_names.append("RST")
        findings.append(
            Finding(
                type="unusual_tcp_flag_combination",
                source_ip=source_ip,
                destination_ip=destination_ip,
                timestamp=stats.first_seen or 0,
                first_seen=stats.first_seen,
                last_seen=stats.last_seen,
                packet_count=stats.packet_count,
                severity="informational",
                confidence="medium",
                reason=(
                    f"Observed TCP {'+'.join(flag_names)} flags together. "
                    "This is unusual but can be generated by diagnostic tools, "
                    "malformed traffic, or middleboxes; it is not proof of an attack."
                ),
                evidence=stats.evidence,
                recommendations=(
                    "Verify the packet flags and capture integrity in a packet analyzer.",
                    "Check the source application and whether a network diagnostic tool was running.",
                ),
                details={"destination_port": destination_port, "tcp_flags": flags},
            )
        )

    return [finding.as_dict() for finding in findings]


def _merge(values) -> EvidenceStats:
    merged = EvidenceStats()
    for value in values:
        merged.merge(value)
    return merged
