# Spoonwatch Trickbot Traffic Analysis

This project provides an in-depth network traffic analysis of a simulated Trickbot malware infection. The analysis was conducted using a PCAP file from malware-traffic-analysis.net, focusing on forensic investigation, indicator extraction, and detection rule creation.


## 📁 Case Overview

This analysis is based on a Trickbot infection simulation captured within a controlled LAN segment. It replicates typical malware behavior observed in enterprise environments.

**Network Environment:**
- **LAN Range:** 192.168.1.0/24  
- **Domain:** spoonwatch.net  
- **Domain Controller:** 192.168.1.9 (SPOONWATCH-DC)  
- **Default Gateway:** 192.168.1.1  
- **Broadcast Address:** 192.168.1.255  


## 🎯 Objectives

- Identify the infected host and summarize key events
- Extract detailed host and user-level information
- Analyze the infection chain and malware behavior
- Enumerate all indicators of compromise (IPs, domains, URLs, hashes)
- Write and test Snort/Suricata detection rules
- Produce a structured incident report


## 🗂️ Project Structure

```
spoonwatch-traffic-analysis/
├── analysis_notes.md # Wireshark filters and investigation notes
├── ioc_report.md # Indicators of compromise (IP, domain, hash)
├── incident_report.md
├── rules/ # Snort/Suricata detection rules
├── screenshots/ # Wireshark and alert screenshots
└── pcap/ # Original PCAP capture (manually added)
```
[📝 Incident Report](./incident_report.md) – Executive summary, host details, and IOC summary


## 🛠️ Tools Used

- Wireshark  
- VirusTotal  
- Snort IDS  
- MITRE ATT&CK Framework  


## 🔑 Key Findings

- Infected host initiated multiple HTTP POST requests to suspicious external IPs
- Payload masquerading observed in `.jpg` and `.php` file uploads
- Shared SHA256 hash across malicious files indicates payload reuse
- Detection rules were successfully written and tested using Snort
- Techniques mapped to MITRE ATT&CK (e.g., **T1036.003 - Masquerading**)


## 📦 PCAP File Access

Due to size and licensing limitations, the original PCAP file is not included in this repository.  
You can download it directly from the official source:

🔗 [malware-traffic-analysis.net – 2022-01-07 Trickbot Infection](https://www.malware-traffic-analysis.net/2022/01/07/index.html)

> After downloading, place the `.pcap` file inside the `/pcap` directory as shown above.


## 🔍 References

- https://www.malware-traffic-analysis.net/2022/01/07/index.html  
- https://attack.mitre.org/techniques/T1036/003/  
- https://snort.org  


## 📘 License

This project is intended for **educational and cybersecurity portfolio** purposes only.
