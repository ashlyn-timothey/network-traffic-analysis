import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import pcap_summary as ps  # noqa: E402

MAC_A, MAC_B, MAC_C = b"\x02\x00\x00\x00\x00\x0a", b"\x02\x00\x00\x00\x00\x0b", b"\x02\x00\x00\x00\x00\x0c"


def ip4(addr):
    return socket.inet_aton(addr)


def eth(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, ip4(src), ip4(dst))
    return header + payload


def tcp(sport, dport, flags):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 1024, 0, 0)


def tcp_frame(src, dst, dport, flags):
    return eth(MAC_B, MAC_A, 0x0800, ipv4(src, dst, 6, tcp(40000, dport, flags)))


def dns_frame(name, response=False):
    flags = 0x8180 if response else 0x0100
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    dns = struct.pack("!HHHHHH", 1, flags, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 5353, 53, 8 + len(dns), 0) + dns
    return eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.9", "10.0.0.2", 17, udp))


def arp_reply(ip, mac):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac + ip4(ip) + MAC_B + ip4("10.0.0.5")
    return eth(MAC_B, mac, 0x0806, body)


def write_pcap(path, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            fh.write(struct.pack("<IIII", 1000 + i, 0, len(f), len(f)) + f)


def write_pcapng(path, frames):
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    out = shb + idb
    for i, f in enumerate(frames):
        pad = (-len(f)) % 4
        total = 32 + len(f) + pad
        out += struct.pack("<IIIIIII", 6, total, 0, 0, 1000000 * i, len(f), len(f))
        out += f + b"\x00" * pad + struct.pack("<I", total)
    with open(path, "wb") as fh:
        fh.write(out)


class AnalyseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_both(self, frames, **kw):
        """Analyse the same frames as classic pcap and as pcapng."""
        reports = []
        for name, writer in (("a.pcap", write_pcap), ("a.pcapng", write_pcapng)):
            path = os.path.join(self.tmp.name, name)
            writer(path, frames)
            reports.append(ps.analyse(path, **kw))
        return reports

    def test_vertical_syn_scan_detected(self):
        frames = [tcp_frame("10.0.0.9", "10.0.0.5", p, 0x02) for p in range(1, 31)]
        for report in self.run_both(frames):
            kinds = [f["type"] for f in report["findings"]]
            self.assertIn("vertical_syn_scan", kinds)
            finding = report["findings"][0]
            self.assertEqual((finding["source"], finding["target"], finding["distinct_ports"]),
                             ("10.0.0.9", "10.0.0.5", 30))

    def test_below_threshold_is_not_flagged(self):
        frames = [tcp_frame("10.0.0.9", "10.0.0.5", p, 0x02) for p in range(1, 6)]
        for report in self.run_both(frames):
            self.assertEqual(report["findings"], [])

    def test_syn_ack_is_not_counted_as_scan(self):
        frames = [tcp_frame("10.0.0.5", "10.0.0.9", p, 0x12) for p in range(1, 40)]
        for report in self.run_both(frames):
            self.assertEqual(report["findings"], [])

    def test_horizontal_sweep_detected(self):
        frames = [tcp_frame("10.0.0.9", f"10.0.1.{i}", 22, 0x02) for i in range(1, 21)]
        for report in self.run_both(frames):
            self.assertIn("horizontal_syn_sweep", [f["type"] for f in report["findings"]])

    def test_arp_conflict_detected(self):
        frames = [arp_reply("10.0.0.1", MAC_A), arp_reply("10.0.0.1", MAC_C)]
        for report in self.run_both(frames):
            finding = report["findings"][0]
            self.assertEqual(finding["type"], "arp_ip_claimed_by_multiple_macs")
            self.assertEqual(finding["ip"], "10.0.0.1")
            self.assertEqual(len(finding["macs"]), 2)

    def test_consistent_arp_is_not_flagged(self):
        frames = [arp_reply("10.0.0.1", MAC_A), arp_reply("10.0.0.1", MAC_A)]
        for report in self.run_both(frames):
            self.assertEqual(report["findings"], [])

    def test_dns_queries_counted_and_responses_ignored(self):
        frames = [dns_frame("Example.com"), dns_frame("example.com"),
                  dns_frame("other.org"), dns_frame("example.com", response=True)]
        for report in self.run_both(frames):
            self.assertEqual(report["top_dns_queries"][0], ("example.com", 2))
            self.assertEqual(dict(report["top_dns_queries"])["other.org"], 1)

    def test_summary_counts(self):
        frames = [tcp_frame("10.0.0.9", "10.0.0.5", 80, 0x02), dns_frame("a.test")]
        for report in self.run_both(frames):
            self.assertEqual(report["packets"], 2)
            self.assertEqual(report["protocols"]["TCP"], 1)
            self.assertEqual(report["protocols"]["UDP"], 1)

    def test_rejects_non_capture_file(self):
        path = os.path.join(self.tmp.name, "junk.bin")
        with open(path, "wb") as fh:
            fh.write(b"not a capture")
        self.assertEqual(ps.main([path]), 2)


if __name__ == "__main__":
    unittest.main()
