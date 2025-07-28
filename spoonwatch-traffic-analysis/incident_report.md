# 📝 Incident Report – Trickbot Infection (Spoonwatch Network)

## 1. Executive Summary

On **January 7, 2022**, a host within the **Spoonwatch corporate network** (`192.168.1.216`) was observed communicating with a known malicious external server (`2.56.57.108`).  
The infected host initiated multiple HTTP POST requests, uploading disguised payloads and interacting with a command-and-control (C2) endpoint.  
The activity is consistent with a **Trickbot malware infection** and exhibits signs of **masquerading** and possible **data exfiltration**.

---

## 2. Host Details

| Field           | Value                                             |
|----------------|---------------------------------------------------|
| Date           | January 7, 2022                                   |
| Victim IP      | 192.168.1.216                                     |
| Hostname       | DESKTOP-GXNYNO2                                   |
| MAC Address    | 9c:5c:8e:32:58:f9                                  |
| User Account   | Possibly `IEUser` (inferred from file path)       |
| C2 Server (IP) | 2.56.57.108                                       |

---

## 3. Indicators of Compromise (IOCs)

### 3.1 IP Addresses

- `192.168.1.216` – Infected Host  
- `2.56.57.108` – Remote C2 Server  
- `192.168.1.2` – Internal DNS Server  

### 3.2 Domains Queried

- `spoonwatch-dc.spoonwatch.net`  
- `wpad.spoonwatch.net`  
- `wpad.localdomain`  
- `spoonwatch.net`  

### 3.3 URLs Accessed

- `http://2.56.57.108/osk/1.jpg`  
- `http://2.56.57.108/osk/2.jpg`  
- `http://2.56.57.108/osk/3.jpg`  
- `http://2.56.57.108/osk/4.jpg`  
- `http://2.56.57.108/osk/5.jpg`  
- `http://2.56.57.108/osk/6.jpg`  
- `http://2.56.57.108/osk/7.jpg`  
- `http://2.56.57.108/osk/main.php`  

### 3.4 File Hashes

- **SHA256**: `7b8ab07521c24e8ec610611e7e15d2fd39336166db6509885b8500d2a2bbfb14`  
- **Files**: `main.php`, `1.jpg` to `7.jpg`  
- **Detection**: `Win.Malware.Agent-7761700-0` (ClamAV and others)

---

📌 *This report was generated based on PCAP traffic analysis and correlating IDS alerts.*

