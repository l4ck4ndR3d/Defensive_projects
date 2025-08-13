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

On Kali: (Check Connectivity)
Assign static IP:
   sudo ip addr add 10.10.xx.xx/24 dev eth0
   sudo ip link set eth0 up
```
```
Step 3 — Check Connectivity

From Kali:
ping 10.10.xx.xx   # Should reach Windows internal NIC

From Windows:
ping 10.10.xx.xx   # Should reach Kali
ping 192.168.xx.xx  # Should reach host
```
---
**End Result :**
- Kali (10.10.xx.xx) <----> Windows (10.10.xx.xx)  -- Attack/Test
- Windows (192.168.xx.xx) <----> Host (192.168.xx.xx) -- Logs to Splunk
- No Kali <---//---> Host direct path



---


# Upcoming plans 

2️⃣ Introduce IDS to Catch Attacks

Since you want something like IDS → SOAR, you need an Intrusion Detection System that sends alerts to Splunk.

Common choices:
    Suricata (good JSON logs, easy Splunk parsing)
    Snort (classic, but needs more tuning)

💡 You’d install IDS on Windows or Kali depending on design:
    If on Kali → it detects outbound attacks
    If on Windows → it detects incoming attacks
    If on host Mint → it passively sniffs VM traffic

For isolated lab, easiest is:
    Install Suricata on Windows 10 (to detect Kali attacks).
    Configure Suricata EVE JSON output → Splunk UF → Splunk.

3️⃣ Prepare Splunk to Parse IDS Logs

Create a props.conf + inputs.conf on UF for Suricata logs:

# inputs.conf
[monitor://C:\Program Files\Suricata\log\eve.json]
disabled = false
sourcetype = suricata:eve
index = ids

# props.conf (on indexer/Splunk Docker)
[suricata:eve]
INDEXED_EXTRACTIONS = json
KV_MODE = json
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ
TIME_PREFIX = "timestamp":\s*"

4️⃣ Generate & Capture an Attack

From Kali:
nmap -sS 10.10.xx.xx

From Windows Suricata logs → Splunk should now see IDS alerts.
5️⃣ Link Splunk to SOAR (Shuffle)

Once Splunk has both Windows logs + IDS alerts:
    Create a Webhook or HEC (HTTP Event Collector) in Splunk.
    In Shuffle, use:
        Trigger: Splunk Search → Alert → Webhook
        Apps: Splunk, Email, Slack, Microsoft Teams
        Actions: Send alert, disable user, isolate endpoint, etc.

Example Shuffle flow:

Suricata Alert → Splunk Alert → Shuffle Trigger → Email SOC Team

6️⃣ Build End-to-End Lab Test

Full cycle:
    Kali attacks Windows (Internal Network)
    Windows Suricata detects attack
    Suricata log → Splunk UF → Splunk
    Splunk scheduled search matches rule
    Splunk alert webhook triggers Shuffle
    Shuffle playbook executes response (email/disable account)

7️⃣ Optional but Recommended
    Add Sysmon on Windows for deep process/file monitoring
    Create Splunk dashboards for:
        Attack timeline
        IDS alert trends
        System security logs
If you want, I can give you the exact Suricata + UF + Splunk config so your lab will start detecting Kali attacks right after setup. That would make your next step plug-and-play.
