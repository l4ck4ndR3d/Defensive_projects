🕵️‍♂️Building a Threat Detection and Response System using Splunk with Real-World Logs & SOAR Automation

#### Topic :  “CyberHunt: SOC Simulation with Multi-Source Logs & SOAR”

```
Project Objective:

To simulate a Security Operations Center (SOC) environment by ingesting multiple log sources (HTTP, Linux audit logs, Suricata IDS, Firewall logs), performing threat detection with Splunk, building dashboards, and automating incident response actions using SOAR.


https://www.paloaltonetworks.com/cyberpedia/what-is-soar

```

| Category            | Tools/Components                                                                               |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| SIEM                | Splunk (Free or Enterprise Trial)                                                              |
| OS                  | Ubuntu (as log forwarder and host)                                                             |
| Log Sources         | Suricata, Apache/Nginx (HTTP), Linux audit logs, Palo Alto Firewall logs (simulated), DNS logs |
| Log Forwarding      | Splunk Universal Forwarder                                                                     |
| Automation          | Splunk SOAR (Phantom) or Mocked Actions                                                        |
| Threat Intelligence | VirusTotal, Abuse.ch (optional)                                                                |
## 🔍 **Project Workflow (High-Level)**

1. **Log Collection and Ingestion**
    - Install Splunk on Ubuntu or VM
    - Use Universal Forwarder to send Linux audit logs
    - Simulate HTTP requests using web server (Apache/Nginx)
    - Generate Suricata alerts using PCAPs
    - Simulate firewall logs (JSON or syslog format from Palo Alto)
        
2. **Log Parsing and Field Extraction**:
    - Manually extract fields (using `rex`, `spath`)
    - Use props.conf + transforms.conf (if advanced)
    - Tag sourcetypes correctly (e.g., `suricata`, `linux_secure`, `http_access`, `firewall_logs`)
        
3. **Threat Hunting & Investigation**:
    - Run SPL queries to detect:
        - SSH brute-force attempts
        - Suspicious HTTP URLs or User Agents
        - C2 communication in Suricata
        - Blocked outbound firewall connections
    - Use MITRE ATT&CK framework for mapping

4. **Dashboards & Visualizations**:
    - Build 2–3 dashboards:
        - SSH Login Activity
        - HTTP Access Dashboard
        - Suricata Alerts Overview
        - MITRE Technique Heatmap (if lookup is available)

5. **Alerts & Automation (SOAR)**:
    - Create alerts in Splunk (e.g., brute-force SSH login)
    - Send alert to SOAR platform or simulate response
        - Auto-email security team
        - Run script to isolate host (simulated)
        - Block IP via firewall rule (mocked)

6. **Reporting**:
    - Document alert triage, response playbooks, dashboard screenshots
    - Incident summaries with IOC, timeline, severity, and response actions
        

---
## 📁 **Deliverables**:

- Splunk dashboards (exported or screenshots)
- Alert configurations and example triggers
- SOAR playbook or mock scripts
- Documentation/report (PDF or blog-style)

---
## ⭐ Sample Use Cases to Implement

|Use Case|Detection Method|Response Action|
|---|---|---|
|SSH Brute Force|Failed logins from same IP|Auto-block IP or alert|
|Malware Callback (Suricata)|Suspicious HTTP C2 alert|Notify via SOAR|
|Abnormal HTTP User-Agent|Regex match on UA|Flag for review|
|DNS Tunneling|High-frequency DNS logs|Alert SOC analyst|
|Unauthorized File Access|Audit log `chmod`, `scp`|Raise incident|

## 🧠 Bonus Enhancements
- Integrate with **MITRE ATT&CK Navigator**
- Use **lookup tables** for IP reputation (ThreatFox, Abuse.ch)
- Export logs and parse them offline (for portable demos)
