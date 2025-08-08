# 🛡 AI-Enhanced SOC Automation using No-Code SOAR

## 📌 Project Objective
To design and implement an autonomous Security Operations Center (SOC) pipeline using low-code/no-code SOAR platforms (e.g., Shuffle) that:
   - Ingests alerts from IDS/SIEM (Wazuh/Security Onion).
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
# 📅 Implementation Steps
Week 1 – Setup
    Deploy Wazuh Cloud or Security Onion.
    Configure Suricata/Zeek for traffic monitoring.
    Generate sample alerts (e.g., Nmap scans, brute force).

Week 2 – SOAR Integration
    Create a Shuffle SOAR account.
    Connect Wazuh API to Shuffle (Alert ingestion).
    Test a simple playbook: Alert → Slack notification.

Week 3 – AI + Threat Intel
    Connect Shuffle to VirusTotal API & AbuseIPDB.
    Integrate AI summarization via OpenAI API or Ollama.
    Configure decision nodes:
        If severity ≥ 8 → Block IP + Notify SOC.
        If severity < 8 → Only notify SOC.

Week 4 – Full Automation
    Integrate Firewall API for blocking malicious IPs.
    Set up Cowrie Honeypot for attacker redirection.
    Configure TheHive for ticket creation.
    Build Kibana Dashboard for visualizing alerts and responses.


# 📜 Future Improvements
    Add malware sandbox (Cuckoo) integration.
    Build self-learning AI model for rule generation.
    Automate phishing email investigation workflows.
