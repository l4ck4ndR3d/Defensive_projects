# 🛡 AI-Enhanced SOC Automation using No-Code SOAR

## 📌 Project Objective
To design and implement an autonomous Security Operations Center (SOC) pipeline using low-code/no-code SOAR platforms (e.g., Shuffle) that:
   - Ingests alerts from IDS/SIEM.
   - Uses AI/LLM models for threat summarization and MITRE ATT&CK mapping.
   - Automates real-time responses such as blocking malicious IPs, quarantining endpoints, and redirecting attackers to honeypots.
   - Maintains full incident documentation for digital forensics and reporting.

## 🚀 Features
- Alert Ingestion from IDS/SIEM via APIs.
- Threat Intelligence Enrichment (VirusTotal, AbuseIPDB).
- AI Summarization of incidents using LLaMA or GPT APIs.
- Automated Incident Response:
        1. Firewall blocking.
        2. Endpoint isolation.
        3. Honeypot redirection.
- Case Management via TheHive integration.
- Real-Time Dashboards with Kibana/Grafana.
- No Heavy Coding — built entirely using SOAR workflows.

# 🧰 Tools and Techniques 
| Component           | Tool/Service                | Purpose                               | Free Tier? |
| ------------------- | --------------------------- | ------------------------------------- | ---------- |
| **IDS/SIEM**        | Wazuh / Security Onion      | Generate alerts from network traffic  | ✅          |
| **SOAR**            | Shuffle SOAR                | Low-code incident response automation | ✅          |
| **Threat Intel**    | VirusTotal API, AbuseIPDB   | IP/domain reputation checks           | ✅          |
| **AI Engine**       | LLaMA (Ollama) / OpenAI API | Summarize and classify threats        | ✅          |
| **Honeypot**        | Cowrie / Dionaea            | Attacker redirection & capture        | ✅          |
| **Dashboard**       | Kibana / Grafana            | Real-time incident visualization      | ✅          |
| **Case Management** | TheHive                     | Store and track incidents             | ✅          |

# 📂 Architecture
```
    A[Network Devices/Endpoints] --> B[Wazuh/Security Onion IDS]
    B --> C[Shuffle SOAR]
    C --> D[Threat Intel APIs]
    C --> E[AI Summarizer - LLaMA/GPT]
    C --> F[Firewall API - Block IP]
    C --> G[Cowrie Honeypot Redirect]
    C --> H[TheHive Case Management]
    C --> I[Slack/Teams SOC Alerts]
    C --> J[Kibana/Grafana Dashboards]
```
# Day to Day Facing : 
## Day - 1:
Downloaded the windows 10 and imported in vbox 
After importing in vbox , installed splunk UF for forwarding the logs to my host Mint on port of 9997
created inputs.conf (C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf)
```
[default]
host = win10-vm

[WinEventLog:Security]
disabled = 0

[WinEventLog:System]
disabled = 0

[WinEventLog:Application]
disabled = 0
```

and restarted as C:\Program Files\SplunkUniversalForwarded\bin\splunk.exe restart 

cmds like 
```
C:\Program Files\SplunkUniversalForwarded\bin\splunk.exe  add forward-server <HOST-IP>:<PORT> -auth Username:Password

```


installed splunk on linux mint using docker 
cmds like 
```
Building :
docker pull splunk/splunk:latest
Running :
docker run -d --name splunk -p 8000:8000 -p 8088:8088 -p 9997:9997 -e SPLUNK_GENERAL_TERMS="--accept-sgt-current-at-splunk-com" -e SPLUNK_START_ARGS="--accept-license" -e SPLUNK_PASSWORD='PASSWORD'   splunk/splunk:latest
```

Runs on http://localhost:8000
<img width="1857" height="976" alt="splunk-1" src="https://github.com/user-attachments/assets/80093da8-581d-4c4f-91fa-34798e26baec" />

## Day - 2:

Flow of networking from kali and windows 10 vm , host linux mint 
  - Kali ↔ Windows over Internal Network (isolated) for attacks.
  - Windows ↔ Host over Host-only for Splunk UF log delivery.
  - No direct Kali ↔ Host at all — totally air-gapped from host.

### Steps 
```
Step 1 — Fix VirtualBox Network Settings
Windows 10 VM
    NIC 1: Host-only Adapter
        Name: vboxnet0 (or your host-only network)
        Purpose: Send logs to host Splunk UF.
    NIC 2: Internal Network
        Name: net (create it in VirtualBox if it doesn’t exist).
        Purpose: Kali ↔ Windows attacks/testing.

Kali VM
    NIC 1: Internal Network
        Name: net (must be exactly the same name as Windows NIC 2).
```
```
Step 2 — Assign Static IPs
On Windows 10
Host-only Adapter:
    IP: 192.168.xx.xx
    Subnet mask: 255.255.255.0
    No default gateway.

Internal Adapter (AttackNet):
    IP: 10.10.xx.xx
    Subnet mask: 255.255.255.0
    No default gateway.
```
---

**End Result :**
- Kali (10.10.xx.xx) <----> Windows (10.10.xx.xx)  -- Attack/Test
- Windows (192.168.xx.xx) <----> Host (192.168.xx.xx) -- Logs to Splunk
- No Kali <---//---> Host direct path
