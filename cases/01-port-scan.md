# Case 01 · TCP SYN port scan

| | |
|---|---|
| **Status** | Draft (replace every `TODO` with your own findings before publishing) |
| **Capture** | `captures/01-port-scan.pcap` |
| **MITRE ATT&CK** | T1046 Network Service Discovery |
| **Tools** | nmap, Wireshark, `tools/pcap_summary.py` |

## Scenario

From `attacker` (192.168.56.20) scan `victim` (192.168.56.10) in the isolated lab.

## How the traffic was generated

```bash
# on the victim: start capture
sudo tcpdump -i <interface> -w 01-port-scan.pcap
# on the attacker:
sudo nmap -sS -p 1-1000 192.168.56.10
```

## What I expected to see

A SYN scan sends a SYN to each port and never completes the handshake. Open
ports should answer SYN-ACK, closed ports RST. (Write your own prediction here.)

## Analysis

Filters: `tcp.flags.syn == 1 && tcp.flags.ack == 0`, `tcp.flags.reset == 1`,
`tcp.flags.syn == 1 && tcp.flags.ack == 1`. Also **Statistics → Conversations**
and an **I/O Graph**.

- TODO: how many SYN packets, from which source, in what time window
- TODO: which ports answered SYN-ACK (open) and what the scanner did next
- TODO: how many RST replies (closed ports)
- TODO: run `python tools/pcap_summary.py captures/01-port-scan.pcap` and paste the finding

![SYN filter](img/01-syn-filter.png)

## Indicators

- TODO: one source, hundreds of different destination ports, within seconds
- TODO: no completed handshakes / data transfer after the scan

## Detection ideas

- Threshold on distinct destination ports per source per minute (this repo's

  `pcap_summary.py` uses that idea).

- Starting point for an IDS rule (test it in your lab; tune thresholds):

  `alert tcp any any -> $HOME_NET any (msg:"Possible SYN scan"; flags:S; threshold: type both, track by_src, count 20, seconds 5; sid:1000001; rev:1;)`

- False positives: vulnerability scanners, monitoring systems, load balancers.

## Mitigation

Default-deny firewall rules, closing unused services, rate limiting, and IDS
alerting on scan behaviour.

## What I learned / limits

- TODO
