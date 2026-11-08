#!/usr/bin/env python3
"""pcap_summary: standard-library-only triage of packet captures.

Reads classic .pcap and .pcapng files (Ethernet link type) and reports:
  * overview: packets, duration, protocol counts, top talkers
  * possible SYN scans (vertical: many ports on one host; horizontal: many hosts)
  * possible ARP spoofing (one IP address claimed by more than one MAC)
  * most queried DNS names

Use it only on captures you created or are allowed to analyse.
Usage: python tools/pcap_summary.py capture.pcapng [--threshold 15] [--json]
"""
import argparse
import json
import socket
import struct
import sys
from collections import Counter, defaultdict

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1


def read_packets(path):
    """Yield (timestamp, linktype, raw_bytes) for every packet in the file."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] in PCAP_MAGICS:
        yield from _read_pcap(data)
    elif data[:4] == PCAPNG_SHB:
        yield from _read_pcapng(data)
    else:
        raise ValueError("not a pcap or pcapng file")


def _read_pcap(data):
    endian, unit = PCAP_MAGICS[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        yield sec + frac * unit, linktype, data[pos:pos + incl]
        pos += incl


def _read_pcapng(data):
    endian = "<"
    linktypes = []
    tsresol = []
    pos = 0
    while pos + 12 <= len(data):
        if data[pos:pos + 4] == PCAPNG_SHB:
            endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes, tsresol = [], []
        btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
        if blen < 12:
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1:  # Interface Description Block
            linktypes.append(struct.unpack(endian + "H", body[:2])[0])
            tsresol.append(_ts_unit(body, endian))
        elif btype == 6:  # Enhanced Packet Block
            iface, hi, lo, cap, _orig = struct.unpack(endian + "IIIII", body[:20])
            ts = ((hi << 32) | lo) * (tsresol[iface] if iface < len(tsresol) else 1e-6)
            link = linktypes[iface] if iface < len(linktypes) else LINKTYPE_ETHERNET
            yield ts, link, body[20:20 + cap]
        pos += blen


def _ts_unit(idb_body, endian):
    """Read the if_tsresol option (code 9); default is microseconds."""
    pos = 8
    while pos + 4 <= len(idb_body):
        code, length = struct.unpack(endian + "HH", idb_body[pos:pos + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = idb_body[pos + 4]
            return 10.0 ** -(v & 0x7F) if not v & 0x80 else 2.0 ** -(v & 0x7F)
        pos += 4 + ((length + 3) & ~3)
    return 1e-6


def parse_dns_qname(payload):
    """Return the first query name of a DNS query message, or None."""
    if len(payload) < 13 or payload[2] & 0x80:  # QR bit set means response
        return None
    labels, pos = [], 12
    while pos < len(payload):
        n = payload[pos]
        if n == 0:
            return ".".join(labels).lower() or None
        if n & 0xC0 or pos + 1 + n > len(payload):
            return None
        labels.append(payload[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return None


def analyse(path, threshold=15):
    proto = Counter()
    talkers = Counter()
    syn_ports = defaultdict(lambda: defaultdict(set))   # src -> dst -> {ports}
    arp_macs = defaultdict(set)                          # ip -> {macs}
    dns_names = Counter()
    first = last = None
    total = skipped = 0

    for ts, link, raw in read_packets(path):
        total += 1
        first = ts if first is None else first
        last = ts
        if link != LINKTYPE_ETHERNET or len(raw) < 14:
            skipped += 1
            continue
        etype, off = struct.unpack("!H", raw[12:14])[0], 14
        if etype == 0x8100 and len(raw) >= 18:  # 802.1Q VLAN tag
            etype, off = struct.unpack("!H", raw[16:18])[0], 18

        if etype == 0x0806 and len(raw) >= off + 28:
            proto["ARP"] += 1
            op = struct.unpack("!H", raw[off + 6:off + 8])[0]
            if op == 2:  # ARP reply: sender claims "spa is at sha"
                mac = ":".join(f"{b:02x}" for b in raw[off + 8:off + 14])
                arp_macs[socket.inet_ntoa(raw[off + 14:off + 18])].add(mac)
        elif etype == 0x0800 and len(raw) >= off + 20:
            ihl = (raw[off] & 0x0F) * 4
            ip_proto = raw[off + 9]
            src = socket.inet_ntoa(raw[off + 12:off + 16])
            dst = socket.inet_ntoa(raw[off + 16:off + 20])
            talkers[src] += 1
            l4 = off + ihl
            if ip_proto == 6 and len(raw) >= l4 + 14:
                proto["TCP"] += 1
                dport = struct.unpack("!H", raw[l4 + 2:l4 + 4])[0]
                flags = raw[l4 + 13]
                if flags & 0x12 == 0x02:  # SYN set, ACK not set
                    syn_ports[src][dst].add(dport)
            elif ip_proto == 17 and len(raw) >= l4 + 8:
                proto["UDP"] += 1
                dport = struct.unpack("!H", raw[l4 + 2:l4 + 4])[0]
                if dport == 53:
                    name = parse_dns_qname(raw[l4 + 8:])
                    if name:
                        dns_names[name] += 1
            elif ip_proto == 1:
                proto["ICMP"] += 1
            else:
                proto[f"IP/{ip_proto}"] += 1
        else:
            proto[f"ethertype 0x{etype:04x}"] += 1

    findings = []
    for src, targets in syn_ports.items():
        for dst, ports in targets.items():
            if len(ports) >= threshold:
                findings.append({"type": "vertical_syn_scan", "source": src,
                                 "target": dst, "distinct_ports": len(ports)})
        hosts = [d for d, p in targets.items() if p]
        if len(hosts) >= threshold:
            findings.append({"type": "horizontal_syn_sweep", "source": src,
                             "distinct_hosts": len(hosts)})
    for ip, macs in arp_macs.items():
        if len(macs) > 1:
            findings.append({"type": "arp_ip_claimed_by_multiple_macs",
                             "ip": ip, "macs": sorted(macs)})

    return {
        "file": path, "packets": total, "skipped_non_ethernet": skipped,
        "duration_s": round((last - first), 3) if first is not None else 0,
        "protocols": dict(proto.most_common()),
        "top_talkers": talkers.most_common(5),
        "top_dns_queries": dns_names.most_common(5),
        "findings": findings, "threshold": threshold,
    }


def render(report):
    out = [f"File: {report['file']}",
           f"Packets: {report['packets']}  Duration: {report['duration_s']}s"]
    if report["skipped_non_ethernet"]:
        out.append(f"Skipped (non-Ethernet link type): {report['skipped_non_ethernet']}")
    out.append("Protocols: " + ", ".join(f"{k}={v}" for k, v in report["protocols"].items()))
    out.append("Top talkers: " + ", ".join(f"{ip} ({n})" for ip, n in report["top_talkers"]))
    out.append("Top DNS queries: " + (", ".join(f"{n} ({c})" for n, c in report["top_dns_queries"]) or "none"))
    out.append(f"\nFindings (scan threshold = {report['threshold']}):")
    if not report["findings"]:
        out.append("  none")
    for f in report["findings"]:
        out.append("  [!] " + ", ".join(f"{k}={v}" for k, v in f.items()))
    out.append("\nThese are heuristics: confirm every finding in Wireshark before reporting it.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Triage a pcap/pcapng capture.")
    ap.add_argument("capture")
    ap.add_argument("--threshold", type=int, default=15,
                    help="distinct ports/hosts before a SYN pattern is flagged (default 15)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args(argv)
    try:
        report = analyse(args.capture, args.threshold)
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
