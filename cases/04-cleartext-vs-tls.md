# Case 04 · Cleartext HTTP credentials vs TLS

| | |
|---|---|
| **Status** | Draft (replace every `TODO` with your own findings before publishing) |
| **Capture** | `captures/04-http-vs-tls.pcap` |
| **MITRE ATT&CK** | T1040 Network Sniffing |
| **Tools** | Wireshark, python/curl |

## Scenario

Show why sniffing is dangerous on cleartext protocols and what TLS changes. Use
only **fake credentials** on VMs you own.

## How the traffic was generated

```bash
# on victim: a tiny web server that accepts a POST (any simple app works)
python3 -m http.server 8080
# on attacker: send a login-shaped request with FAKE credentials
curl -s -X POST -d "user=demo&password=NotARealPassword" http://192.168.56.10:8080/login
# then a TLS request for comparison
curl -s https://example.org -o /dev/null
```

## Analysis

Filters: `http.request.method == "POST"`, `tls.handshake.type == 1`,
`tls.handshake.extensions_server_name`. Use **Follow → TCP Stream**.

- TODO: where the fake credentials are visible in the HTTP stream
- TODO: what is still visible in the TLS capture (SNI, certificate, sizes, timing) and what is not (request content)
- TODO: the TLS version and cipher suite negotiated

![HTTP stream](img/04-http-follow-stream.png)
![TLS handshake](img/04-tls-clienthello.png)

## Indicators

- TODO: credentials or tokens in plain text on ports 80/8080/21/23/110

## Detection ideas

Alert on cleartext authentication protocols crossing the network; inventory
legacy services (FTP, Telnet, HTTP basic auth).

## Mitigation

TLS everywhere with HSTS, disable legacy cleartext services, use SSH/SFTP,
and segment management networks.

## What I learned / limits

- TODO
