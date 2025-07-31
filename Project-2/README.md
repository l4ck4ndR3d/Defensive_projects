## Cyborg C2: A Realistic, Containerized Adversary Simulation Framework

### 🧠 Concepts

Build a containerized, modular Command & Control (C2) simulation framework that replicates real-world adversary behavior, inspired by tools like Cobalt Strike, Mythic, and Sliver, but built for training, detection engineering, and research, not real attacks.

---

### 🞋 Goal

1. Simulate real-world APT techniques (MITRE ATT&CK) inside isolated Kali VMs and networks.
2. Use Docker containers to spin up attack stages (e.g., phishing server, lateral movement toolkits).
3. Use VirtualBox (or Vagrant) to launch vulnerable machines and blue team defenders (e.g., ELK stack, Suricata).
4. Create an automated attack-emulation lab for testing EDRs, SIEMs, and SOC response playbooks.

---

### 🔁 Data Flow Summary:

- Kali VM (in VirtualBox) is the main attacker, issuing commands or payloads.
- The Docker C2 (e.g., Mythic or a custom Flask-based C2) manages communications with deployed payloads.
- Multiple Attack Containers simulate malware stages (e.g., phishing, privilege escalation).
- Defender Containers (IDS, loggers) inspect traffic, generate alerts, and provide telemetry.

---

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
---

### How are IP's are assigned 
```
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

    Enable Host-Only Adapter

    Assign adapter to vboxnet0 or your custom host-only adapter

    Set Kali static IP: 192.168.100.50

Edit /etc/network/interfaces or use:

sudo ip addr add 192.168.100.50/24 dev eth1
sudo ip link set dev eth1 up
```
