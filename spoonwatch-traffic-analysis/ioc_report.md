# Indicators of Compromise (IOCs)

## Domains (from DNS queries)
- spoonwatch-dc.spoonwatch.net
- wpad.spoonwatch.net
- wpad.localdomain
- spoonwatch.net

## IP Addresses
- `2.56.57.108` - Destination of malicious HTTP POST requests

## Malicious Files (Hash-based IOCs)

- `main.php`  
- `1.jpg` to `7.jpg`

These files all share the same SHA256 hash and were flagged by VirusTotal:

- **SHA256**: `7b8ab07521c24e8ec610611e7e15d2fd39336166db6509885b8500d2a2bbfb14`
- **VirusTotal Detection**: `Win.Malware.Agent-7761700-0` by ClamAV and other vendors


## URLs
- `http://2.56.57.108/osk/1.jpg`
- `http://2.56.57.108/osk/2.jpg`
- `http://2.56.57.108/osk/3.jpg`
- `http://2.56.57.108/osk/4.jpg`
- `http://2.56.57.108/osk/5.jpg`
- `http://2.56.57.108/osk/6.jpg`
- `http://2.56.57.108/osk/7.jpg`
- `http://2.56.57.108/osk/main.php`

## User-Agent Strings
