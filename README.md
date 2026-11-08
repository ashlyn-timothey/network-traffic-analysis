# Network Traffic Analysis

[![ci](https://github.com/ashlyn-timothey/network-traffic-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/ashlyn-timothey/network-traffic-analysis/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![license](https://img.shields.io/badge/license-MIT-blue)

Packet-level investigations written like SOC triage reports: each case
reproduces an activity in an isolated lab, analyses it in Wireshark, maps it to
MITRE ATT&CK, and ends with detection and mitigation ideas. A small
standard-library Python tool automates the first-pass triage.

*Français :* analyses de trafic réseau (Wireshark) dans un laboratoire isolé :
scan de ports, ARP spoofing, DNS, HTTP en clair vs TLS. Chaque cas est mappé sur
MITRE ATT&CK avec pistes de détection et de remédiation.

## Cases

| # | Case | ATT&CK | Status |
|---|---|---|---|
| 01 | [TCP SYN port scan](cases/01-port-scan.md) | T1046 | 🚧 |
| 02 | [ARP spoofing](cases/02-arp-spoofing.md) | T1557.002 | 🚧 |
| 03 | [DNS activity](cases/03-dns-activity.md) | T1071.004 | 🚧 |
| 04 | [Cleartext HTTP vs TLS](cases/04-cleartext-vs-tls.md) | T1040 | 🚧 |
| 05 | [Public exercise write-up](cases/05-public-traffic-exercise.md) | varies | 🚧 |

## Triage tool

`tools/pcap_summary.py` reads `.pcap` and `.pcapng` files (Ethernet) with no
third-party dependencies and reports protocol counts, top talkers, top DNS
queries, possible SYN scans and ARP IP-to-MAC conflicts.

```bash
python tools/pcap_summary.py captures/01-port-scan.pcap
python tools/pcap_summary.py captures/02-arp-spoofing.pcap --threshold 20 --json
python -m unittest discover -s tests -v   # 9 tests on synthetic captures
```

Example output on a synthetic scan:

```text
Packets: 103  Duration: 102.0s
Protocols: TCP=100, ARP=2, UDP=1
Findings (scan threshold = 15):
  [!] type=vertical_syn_scan, source=10.0.0.9, target=10.0.0.5, distinct_ports=100
  [!] type=arp_ip_claimed_by_multiple_macs, ip=10.0.0.1, macs=[...]
```

The results are heuristics for triage, not verdicts: every finding is confirmed
in Wireshark before it goes into a report.

## Repository layout

```text
cases/      one write-up per investigation (template in cases/_template.md)
captures/   the .pcap files the write-ups refer to
docs/       lab setup and a Wireshark filter cheat sheet
tools/      pcap_summary.py (triage script)
tests/      unit tests using synthetic captures
```

## Lab

All traffic is generated between VMs on an isolated virtual network that I own;
see [docs/lab-setup.md](docs/lab-setup.md). Nothing here is aimed at third-party
systems.

## Limitations

- The tool parses Ethernet and IPv4 only (no IPv6, no Linux "cooked" captures).
- Detections are simple thresholds; real environments need tuning for false

  positives (scanners, monitoring, VRRP/HSRP failover).

## License

[MIT](LICENSE)
