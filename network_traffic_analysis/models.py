"""Small data models shared by capture processing and detection rules."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    linktype: int
    raw: bytes
    number: int


@dataclass(frozen=True)
class DetectionThresholds:
    icmp_sweep_hosts: int = 10
    dns_query_volume: int = 100
    repeated_syn_attempts: int = 20

    def __post_init__(self) -> None:
        for name, value in (
            ("icmp_sweep_hosts", self.icmp_sweep_hosts),
            ("dns_query_volume", self.dns_query_volume),
            ("repeated_syn_attempts", self.repeated_syn_attempts),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class PacketEvidence:
    packet_number: int
    timestamp: float
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    mac_address: str | None = None
    tcp_flags: int | None = None
    dns_name: str | None = None

    def as_dict(self) -> dict:
        return {
            key: value
            for key, value in {
                "packet_number": self.packet_number,
                "timestamp": self.timestamp,
                "source_ip": self.source_ip,
                "destination_ip": self.destination_ip,
                "destination_port": self.destination_port,
                "mac_address": self.mac_address,
                "tcp_flags": self.tcp_flags,
                "dns_name": self.dns_name,
            }.items()
            if value is not None
        }


@dataclass
class EvidenceStats:
    """Aggregate event counts/times while retaining bounded packet examples."""

    evidence_limit: int = 25
    packet_count: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    evidence: list[PacketEvidence] = field(default_factory=list)

    def add(self, evidence: PacketEvidence) -> None:
        self.packet_count += 1
        self.first_seen = (
            evidence.timestamp
            if self.first_seen is None
            else min(self.first_seen, evidence.timestamp)
        )
        self.last_seen = (
            evidence.timestamp
            if self.last_seen is None
            else max(self.last_seen, evidence.timestamp)
        )
        if len(self.evidence) < self.evidence_limit:
            self.evidence.append(evidence)

    def merge(self, other: "EvidenceStats") -> None:
        self.packet_count += other.packet_count
        if other.first_seen is not None:
            self.first_seen = (
                other.first_seen
                if self.first_seen is None
                else min(self.first_seen, other.first_seen)
            )
        if other.last_seen is not None:
            self.last_seen = (
                other.last_seen
                if self.last_seen is None
                else max(self.last_seen, other.last_seen)
            )
        remaining = self.evidence_limit - len(self.evidence)
        if remaining > 0:
            self.evidence.extend(other.evidence[:remaining])


@dataclass(frozen=True)
class Finding:
    type: str
    source_ip: str | None
    destination_ip: str | None
    timestamp: float
    reason: str
    evidence: list[PacketEvidence] = field(default_factory=list)
    severity: str = "low"
    confidence: str = "low"
    first_seen: float | None = None
    last_seen: float | None = None
    packet_count: int | None = None
    recommendations: tuple[str, ...] = ()
    details: dict = field(default_factory=dict)
    evidence_limit: int = 25

    def as_dict(self) -> dict:
        evidence = self.evidence[: self.evidence_limit]
        timestamps = [item.timestamp for item in self.evidence]
        result = {
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "timestamp": self.timestamp,
            "first_seen": self.first_seen
            if self.first_seen is not None
            else min(timestamps, default=self.timestamp),
            "last_seen": self.last_seen
            if self.last_seen is not None
            else max(timestamps, default=self.timestamp),
            "packet_count": self.packet_count
            if self.packet_count is not None
            else len(self.evidence),
            "reason": self.reason,
            "evidence": [item.as_dict() for item in evidence],
            "recommendations": list(self.recommendations),
            **self.details,
        }
        omitted = max(
            (self.packet_count or 0) - len(evidence),
            len(self.evidence) - self.evidence_limit,
        )
        if omitted:
            result["evidence_truncated"] = omitted

        # Retain the original finding keys used by the CLI and existing callers.
        if self.type in {"vertical_syn_scan", "horizontal_syn_sweep"}:
            result["source"] = self.source_ip
            if self.destination_ip is not None:
                result["target"] = self.destination_ip
        return result
