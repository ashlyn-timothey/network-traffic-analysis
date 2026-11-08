# Wireshark display filter cheat sheet

Display filters go in the bar at the top of Wireshark. (Capture filters use a
different syntax, BPF, e.g. `host 192.168.56.10 and tcp port 80`.)

## General

| Goal | Filter |
|---|---|
| One host (either direction) | `ip.addr == 192.168.56.10` |
| From / to a host | `ip.src == 192.168.56.20` / `ip.dst == 192.168.56.10` |
| A port | `tcp.port == 80` or `udp.port == 53` |
| Hide noise | `!(arp \|\| dns \|\| mdns)` |
| Text inside packets | `frame contains "password"` |

## TCP behaviour

| Goal | Filter |
|---|---|
| SYN packets (connection attempts / SYN scan) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYN-ACK (open port answers) | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| Resets (closed ports answer) | `tcp.flags.reset == 1` |
| Retransmissions | `tcp.analysis.retransmission` |

## ARP, DNS, HTTP, TLS

| Goal | Filter |
|---|---|
| All ARP / replies only | `arp` / `arp.opcode == 2` |
| Duplicate address warnings | `arp.duplicate-address-detected` |
| DNS queries only | `dns.flags.response == 0` |
| A specific DNS name | `dns.qry.name contains "example"` |
| HTTP POST requests | `http.request.method == "POST"` |
| TLS ClientHello | `tls.handshake.type == 1` |
| Server name (SNI) | `tls.handshake.extensions_server_name` |

## Menus worth knowing

- **Statistics → Conversations / Endpoints:** who talked to whom, how much.
- **Statistics → Protocol Hierarchy:** what the traffic is made of.
- **Statistics → I/O Graphs:** spikes in traffic over time (scans show as bursts).
- **Analyze → Follow → TCP Stream:** reassemble one conversation.
- **Analyze → Expert Information:** Wireshark's own warnings (duplicate IPs, resets).
