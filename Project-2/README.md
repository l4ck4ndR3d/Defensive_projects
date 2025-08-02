# 🛡️ Wazuh + Shuffle SOAR Automation Stack (2023–2025 Dataset Based) [In-development]

## 📌 Overview

This project demonstrates a **free, Docker-based security monitoring and response system** using:
- **Wazuh** (SIEM & IDS)
- **n8n** (Open-source SOAR)
- **Elasticsearch & Kibana** (Log analytics)
- **Public cybersecurity datasets (2023–2025)** for simulation

All components are deployed using Docker Compose on an **isolated Docker network** to maintain a controlled, secure environment.

---

## 🧠 Why This Stack?

Modern security teams need scalable and **automated** threat detection and response. Commercial SOAR solutions are expensive. This stack uses **only free and open-source** tools, fully containerized, and allows easy customization.

---

## 📦 Tech Stack

| Component         | Description                                      |
|------------------|--------------------------------------------------|
| **Wazuh**         | Open-source SIEM, IDS and log collector         |
| **n8n**       | SOAR platform to build automation playbooks     |
| **Elasticsearch** | Log indexing and search backend                 |
| **Kibana**        | Web UI for Elasticsearch dashboards             |
| **Docker Compose**| Container orchestration                         |

---

```
                            +-------------------------+
                            |     Public Datasets     |
                            |   (UNB, MITRE, etc.)    |
                            +-----------+-------------+
                                        |
                                        v
+-----------+       +--------------+        +-------------------+
| Ingestion | ----> |   Wazuh      | -----> | Elasticsearch     |
| Scripts   |       |   Manager    |        | + Kibana Dashboard|
+-----------+       +--------------+        +-------------------+
                                        |
                                        v
                                 +--------------+
                                 |       n8n     |
                                 |   SOAR Engine |
                                 +------+--------+
                                        |
          +-----------------------------+----------------------------+
          |                             |                            |
   +-------------+         +-----------------------+        +-------------------+
   | Cortex/VT   |         | Custom Python Scripts |        | Slack/Firewall API|
   +-------------+         +-----------------------+        +-------------------+

```
---

### 🌐 Docker Network Flow

All services are on a custom Docker bridge network (wazuh_net) to ensure isolation.
`docker network create --driver bridge wazuh_net`
