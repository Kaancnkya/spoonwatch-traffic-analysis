# Indicators of Compromise (IOCs)

## Domains (from DNS queries)
- `spoonwatch-dc.spoonwatch.net`
- `wpad.spoonwatch.net`
- `wpad.localdomain`
- `spoonwatch.net`

## IP Addresses
- `2.56.57.108` – Destination of malicious HTTP POST requests
- `192.168.1.216` – Infected host
- `192.168.1.2` – Internal DNS server

## Malicious URLs
- `http://2.56.57.108/osk/1.jpg`
- `http://2.56.57.108/osk/2.jpg`
- `http://2.56.57.108/osk/3.jpg`
- `http://2.56.57.108/osk/4.jpg`
- `http://2.56.57.108/osk/5.jpg`
- `http://2.56.57.108/osk/6.jpg`
- `http://2.56.57.108/osk/7.jpg`
- `http://2.56.57.108/osk/main.php`

## SHA256 Hashes
All the following files share the same hash and were flagged as malicious:

| File(s)              | SHA256                                                              | Detection                          |
|----------------------|----------------------------------------------------------------------|-------------------------------------|
| main.php, 1.jpg–7.jpg| `7b8ab07521c24e8ec610611e7e15d2fd39336166db6509885b8500d2a2bbfb14`   | Win.Malware.Agent-7761700-0 (ClamAV) |

## 🗂Notes
- `.exe` files extracted from the PCAP were **not** flagged as malicious.
- `.jpg` files and `main.php` had **identical hashes**, indicating a masquerading tactic (see MITRE ATT&CK T1036.003).

## Detection Rules (Snort)

We created the following Snort rules to detect Trickbot-related activity observed in the PCAP.

```snort
alert tcp $HOME_NET any -> 2.56.57.108 80 (msg:"[Trickbot] Possible C2 Communication to known malicious IP"; flow:established,to_server; content:"POST"; http_method; content:"/osk/"; http_uri; sid:100001; rev:1;)
alert tcp $HOME_NET any -> 2.56.57.108 80 (msg:"[Trickbot] Possible POST to C2 Command Endpoint (/main.php)"; flow:established,to_server; content:"POST"; http_method; content:"/main.php"; http_uri; sid:100002; rev:1;)
```
These rules can be used to detect communication between the infected host and the command-and-control (C2) server involved in this attack.
