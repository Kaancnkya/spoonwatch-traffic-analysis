# Spoonwatch Trickbot Traffic Analysis

This project provides an in-depth network traffic analysis of a simulated Trickbot malware infection. The analysis was conducted using a PCAP file from malware-traffic-analysis.net, focusing on forensic investigation, indicator extraction, and detection rule creation.

## Case Overview

This project analyzes a PCAP file based on a malware infection simulation provided by [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2022/01/07/index.html). The scenario replicates Trickbot activity within a controlled LAN segment.

### 🖥️ Environment

- **LAN Range:** 192.168.1.0/24  
- **Domain:** spoonwatch.net  
- **Domain Controller:** 192.168.1.9 (SPOONWATCH-DC)  
- **Default Gateway:** 192.168.1.1  
- **Broadcast Address:** 192.168.1.255  

## Objective

This project investigates a simulated Trickbot malware infection through PCAP and IDS data analysis. Based on the given scenario and alerts, the objectives are:

- Identify the infected host and summarize what happened  
- Extract host and user-level details from the network traffic  
- Understand the infection chain and malware behavior  
- Enumerate all indicators of compromise (domains, IPs, URLs, hashes)  
- Propose Snort/Suricata detection rules  
- Report findings in a structured incident report

## Project Structure
spoonwatch-traffic-analysis/
├── analysis_notes.md - Wireshark filters and investigation notes
├── ioc_report.md - Indicators of compromise (IP, domain, hash)
├── rules/ - Snort/Suricata detection rules
├── screenshots/ - Wireshark and alert screenshots
└── pcap/ - Original PCAP capture (to be added manually) 

## Tools Used

- Wireshark
- VirusTotal
- Snort IDS
- MITRE ATT&CK Framework

## Key Findings

- Infected host initiated multiple HTTP POST requests to suspicious external IPs
- Malicious executable delivered via encrypted sessions
- DNS activity observed for C2-related domains
- Detection rules applicable for signature-based IDS systems

## References

- https://www.malware-traffic-analysis.net/2022/01/07/index.html
- https://attack.mitre.org/techniques/T1059/001/
- https://snort.org

## License

This project is intended for educational and cybersecurity portfolio purposes only.
