# Lab setup

All attack traffic in this repository is generated **inside an isolated virtual
network that you own**. Never run scans or spoofing tools against a home network
shared with other people, a school or work network, or anything on the internet.

## Machines

| VM | Role | Suggested image |
|---|---|---|
| `victim` | Target server | Ubuntu Server (SSH + a web server installed) |
| `attacker` | Generates the traffic | Kali Linux (or Ubuntu + nmap + dsniff) |

Use VirtualBox, VMware, or UTM. Two VMs and 2-4 GB RAM each is enough.

## Network

1. Put both VMs on a **Host-only** or **Internal Network** adapter (for example

   `lab-net`). Disable any Bridged adapter, otherwise your test traffic can leave
   the lab.

2. Give them static addresses, for example `victim` = `192.168.56.10` and

   `attacker` = `192.168.56.20`.

3. Check isolation: from `victim`, `ping 8.8.8.8` should fail.
4. Take a VM snapshot before each experiment so you can restore a clean state.

## Capturing

Pick one:

- **On the host with Wireshark:** capture on the VirtualBox Host-Only adapter.
- **Inside a VM with tcpdump:**

  `sudo tcpdump -i <interface> -w case01.pcap` (stop with Ctrl+C).

Save captures into `captures/` with the case number in the name, e.g.
`01-port-scan.pcap`. Classic `.pcap` and `.pcapng` both work with
`tools/pcap_summary.py`. Keep files small (a few MB).

## Safety checklist

- [ ] Only the lab adapter is active; no Bridged adapter
- [ ] Targets are VMs you own
- [ ] No real passwords, tokens or personal data appear in any capture
- [ ] Screenshots are cropped to what the case needs
