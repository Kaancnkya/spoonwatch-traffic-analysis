# 📝 Analysis Notes – Spoonwatch Traffic PCAP

This file contains Wireshark filters, investigation notes, IP analysis, and protocol breakdown during the investigation of the 2022-01-07 Trickbot malware infection.

---

## 📌 Wireshark Filters Used

- `http.request.method == "POST"`
- `dns`
- `ip.addr == 192.168.1.50`
- `tcp.stream eq 5`

---

## 🧠 Investigation Focus

- Identify infected host machine and behavior
- Extract IOCs: domains, IPs, user-agent, hashes
- Spot C2 communication and malware delivery patterns
