# Analysis Notes – Trickbot PCAP

## Initial DNS Observations

- The infected host (`192.168.1.216`) made several suspicious DNS A queries.
- All queries were directed to the local DNS server (`192.168.1.2`).
- Repeated attempts to resolve the following domains:

  - `spoonwatch-dc.spoonwatch.net`
  - `wpad.spoonwatch.net`
  - `wpad.localdomain`
  - `spoonwatch.net`

- The use of `wpad.` domains may suggest WPAD-based abuse or misconfigured name resolution.
- The domains are not commonly seen in benign enterprise networks and may be used as part of the malware’s command-and-control (C2) infrastructure or lateral movement.
- We used the following display filter in Wireshark to extract these queries:
  dns.qry.type == 1 && dns.flags.response == 0

- Below is a screenshot showing the suspicious DNS A queries initiated by the infected host:
![Suspicious DNS Queries](../screenshots/suspicious_dns_queries.png)

---

## Next Steps

- Inspect HTTP requests (GET/POST) from the infected host.
- Identify any payload delivery or outbound data exfiltration attempts.

