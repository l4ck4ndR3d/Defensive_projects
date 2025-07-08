# 🧠 Mini SOC Project – KoiStealer Detection using Splunk & Suricata

> 🚨 Simulating a real-world Security Operations Center (SOC) to detect and investigate malware using Splunk and Suricata.

---

## 📘 Project Overview

This project simulates a threat hunting scenario where malware communication (specifically **KoiStealer**) is detected and investigated using logs from **Suricata IDS** and visualized through **Splunk**.

The main objective is to perform hands-on SOC analysis using real network traffic (PCAP), identify indicators of compromise (IOCs), and map the detection to **MITRE ATT&CK** techniques.

---

## 🔧 Tools & Technologies Used

- **Splunk** – Dockerized instance (SIEM platform)
- **Suricata** – Open-source IDS/IPS to analyze PCAP
- **VirusTotal / Hybrid Analysis / ThreatFox** – Threat intelligence enrichment
- **Wireshark** – Packet inspection
- **Windows 11** – Host and container environment

---

## 📦 Dataset

- `2025-06-21-Koi-Loader-Koi-Stealer-infection-traffic.pcap`
- **Link** - https://www.malware-traffic-analysis.net/2025/06/21/index.html
- Simulated a malware infection and C2 callback involving KoiStealer

---

## 📌 Key Features

✅ Suricata rule-based alert generation  
✅ Log parsing and investigation in Splunk using SPL  
✅ IOC extraction and enrichment using public threat intel  
✅ MITRE ATT&CK mapping to techniques like:
- T1105 – Ingress Tool Transfer
- T1071 – Application Layer Protocol
- T1059 – Command and Scripting Interpreter

✅ Actionable response and containment plan

---

## 🔍 Detection Flow

1. Suricata processes the PCAP and generates alerts
2. Alerts ingested into Splunk via log forwarding
3. Suspicious HTTP traffic detected:
   - `/index.php?id=&subid=...`
   - `/sempstrywork.php`
4. Detected alert:
   - `ET MALWARE Win32/Koi Stealer CnC Checkin (GET)`
5. MITRE ATT&CK technique mapped: `T1105` (C2 traffic)
6. IOC confirmed using VirusTotal, Hybrid Analysis, ThreatFox

---

## 🧪 SPL Queries Used

```spl
index=suricata "http.http_method"=GET "alert.signature"="ET MALWARE Win32/Koi Stealer CnC Checkin (GET)"
| table http.url src_ip dest_ip alert.severity alert.signature

index=suricata "http.url"="/sempstrywork.php"
| table src_ip dest_ip alert.signature
```
## 🚨 Incident Summary

 1. Target: 10.6.21.101 (internal host)
 2. Attacker IP: 89.36.231.26
 3. Malware: KoiStealer
 4. IOC: http://89.36.231.26/sempstrywork.php
 5. Severity: High
 6. SHA256: 84577db0b164c06ef9628a94eb693150dc2101332ed526f4d431ddb56b3a7c4c


# ✍️ Author
Bala Mahendar
Cybersecurity | SOC Analyst in Training
