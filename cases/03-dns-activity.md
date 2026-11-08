# Case 03 · DNS: normal lookups and what suspicious looks like

| | |
|---|---|
| **Status** | Draft (replace every `TODO` with your own findings before publishing) |
| **Capture** | `captures/03-dns.pcap` |
| **MITRE ATT&CK** | T1071.004 Application Layer Protocol: DNS (for the suspicious patterns) |
| **Tools** | Wireshark, `tools/pcap_summary.py` |

## Scenario

Capture the DNS lookups made by **your own computer** for a few minutes of
ordinary browsing (close private tabs and sensitive apps first), then study the
structure of DNS and describe which patterns would look suspicious.

## How the traffic was generated

```bash
nslookup example.com
dig +short A example.org
dig AAAA example.net
```

## Analysis

Filters: `dns`, `dns.flags.response == 0`, `dns.qry.name contains "example"`,
`dns.qry.type == 28` (AAAA).

- TODO: record types seen (A, AAAA, HTTPS, PTR) and what each is for
- TODO: query/response pairing, response times, any NXDOMAIN
- TODO: the DNS server your machine uses and over which port/protocol
- TODO: run `python tools/pcap_summary.py` and compare "top DNS queries"

![DNS queries](img/03-dns-queries.png)

## Indicators of suspicious DNS (reference, not observed here)

- Very long or high-entropy subdomains, many unique subdomains of one domain
- High query volume to a single rare domain, TXT-heavy traffic
- Frequent NXDOMAIN responses (possible domain-generation algorithms)

## Detection ideas

Log DNS at the resolver; alert on query-length and unique-subdomain thresholds;
use threat-intel blocklists.

## Mitigation

Controlled recursive resolvers, DNS filtering, blocking direct outbound DNS,
and monitoring DoH use where policy requires it.

## What I learned / limits

- TODO
