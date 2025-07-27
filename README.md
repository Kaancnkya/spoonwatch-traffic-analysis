# Spoonwatch Trickbot Traffic Analysis

This project provides an in-depth network traffic analysis of a simulated Trickbot malware infection. The analysis was conducted using a PCAP file from malware-traffic-analysis.net, focusing on forensic investigation, indicator extraction, and detection rule creation.

## Objective

- Understand the infection chain of Trickbot malware
- Identify indicators of compromise (IOCs)
- Extract key forensic evidence using Wireshark
- Propose detection rules and recommendations for mitigation

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
