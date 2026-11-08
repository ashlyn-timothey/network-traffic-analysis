# Case 02 · ARP spoofing (man-in-the-middle)

| | |
|---|---|
| **Status** | Draft (replace every `TODO` with your own findings before publishing) |
| **Capture** | `captures/02-arp-spoofing.pcap` |
| **MITRE ATT&CK** | T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning |
| **Tools** | arpspoof (dsniff) or bettercap, Wireshark, `tools/pcap_summary.py` |

## Scenario

In the isolated lab, `attacker` tells `victim` that the gateway's IP belongs to
the attacker's MAC address. Use a third VM or the host-only gateway address as
the "gateway".

## How the traffic was generated

```bash
# on the attacker (isolated lab only)
sudo arpspoof -i <interface> -t 192.168.56.10 192.168.56.1
```

Also capture a **clean baseline** of normal ARP traffic first, to compare.

## What I expected to see

Repeated unsolicited ARP replies. (Write your own prediction here.)

## Analysis

Filters: `arp`, `arp.opcode == 2`, `arp.duplicate-address-detected`.
Check **Analyze → Expert Information**.

- TODO: the IP claimed by two different MAC addresses (list both MACs)
- TODO: how often the spoofed replies repeat (interval)
- TODO: compare with your baseline capture
- TODO: run `python tools/pcap_summary.py` and note whether it flags the conflict

![ARP replies](img/02-arp-replies.png)

## Indicators

- TODO: one IP mapped to two MACs; gratuitous or unsolicited replies at a steady rate

## Detection ideas

- Monitor ARP tables for IP-to-MAC changes (arpwatch, switch logs).
- Alert on one IP claimed by multiple MACs. False positives: failover pairs

  (VRRP/HSRP), NIC teaming, VM migration.

## Mitigation

Dynamic ARP Inspection with DHCP snooping, port security, 802.1X, network
segmentation, and encrypted protocols (TLS, SSH) so intercepted traffic is
useless.

## What I learned / limits

- TODO
