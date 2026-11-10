# Mini SOC & Threat Detection Platform

[![Platform](https://img.shields.io/badge/Architecture-Apple%20Silicon%20(ARM64)-blue.svg)](#)
[![Tests](https://img.shields.io/badge/Acceptance%20Tests-41%2F41%20Passed%20(100%25)-emerald.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)
[![Phase](https://img.shields.io/badge/Implementation-Phases%201--8%20Complete-green.svg)](#)

A modular, enterprise-grade, locally deployable **Security Operations Center (SOC) and Threat Detection Platform** designed natively for Apple Silicon (ARM64) macOS workstations.

The platform integrates honeynet event capture, simulated IoT telemetry, centralized SIEM detection, MITRE ATT&CK mapping, threat intelligence, explainable risk scoring, incident investigation, SOAR automated response, machine learning anomaly detection, an interactive attack relationship graph, and cryptographic evidence integrity verification.

---

## Architecture & Implementation Scope

> [!IMPORTANT]
> **Educational Prototype Classification & Environmental Scope:**
> 1. **Educational Local SOC Prototype:** This platform is designed strictly as an educational cybersecurity laboratory, research demonstrator, and threat detection prototype. It is not intended for enterprise production deployment.
> 2. **Wazuh Lightweight SIEM Architecture:** To ensure stability on 8 GB RAM Apple Silicon workstations, the resource-heavy OpenSearch Indexer and Wazuh Dashboard UI are omitted. The core **Wazuh Manager 4.9.0** engine runs standalone in a resource-capped container (under 800 MB RAM), providing genuine real-time log decoding, custom XML rule correlation, `alerts.json` event streaming, and authenticated REST API querying (`https://127.0.0.1:55000`).
> 3. **Custom Honeynet Emulators:** Cowrie (SSH/Telnet), Dionaea (SMB/HTTP/FTP), and Mosquitto Honey (MQTT) run as lightweight, native Python emulators tailored for ARM64 macOS workstations, capturing authentic attacker interactions and dropped payloads without host compromise risk.
> 4. **Safe SOAR Containment:** Automated containment actions operate in **safe simulation mode** (`SOAR_SIMULATION_MODE=true`). Attacker IP bans are logged in a cryptographic audit chain and tracked in the incident workspace with automatic rollback timers, without altering kernel packet filtering tables (`pf`/`iptables`) to safeguard workstation network connectivity.
> 5. **Simulated IoT Fleet:** The 10 virtual IoT edge devices (IP cameras, routers, smart controllers, sensors) are software simulation models that generate realistic telemetry distributions and controlled cyberattack scenarios (DDoS publish bursts, actuator overrides, and sensor tampering).

---

## 1. End-to-End Security Operations Workflow

```
[ATTACK SIMULATION] ──> [HONEYPOT FLEET] (Cowrie, Dionaea, Mosquitto Honey)
                                │
                                ▼
                       [LOG INGESTION PIPELINE]
                                │
                                ▼
                       [WAZUH SIEM CORE]
                                │
       ┌────────────────────────┴────────────────────────┐
       ▼                                                 ▼
[SIGMA & MITRE ATT&CK]                         [THREAT INTELLIGENCE]
 (Custom Rules & Decoders)                      (AbuseIPDB & VirusTotal)
       │                                                 │
       └────────────────────────┬────────────────────────┘
                                ▼
                    [INTELLIGENT RISK SCORING]
                    (Explainable 0-100 Algorithm)
                                │
       ┌────────────────────────┴────────────────────────┐
       ▼                                                 ▼
[INCIDENT INVESTIGATION]                       [ML ANOMALY DETECTION]
 (Workspace & Attack Graph)                     (Isolation Forest Model)
       │                                                 │
       └────────────────────────┬────────────────────────┘
                                ▼
                     [SOAR AUTOMATED RESPONSE]
                 (Telegram Bot + Controlled IP Ban)
                                │
                                ▼
                    [REACT 18 SOC DASHBOARD]
                                │
                                ▼
                    [EVIDENCE INTEGRITY (SHA-256)]
```

---

## 2. Key Architecture & Original Features

- **Honeynet Traps**:
  - **Cowrie**: Emulates SSH (Port 2222) and Telnet (Port 2223), capturing brute-force credentials, shell commands, and dropped payloads.
  - **Dionaea**: Emulates SMB (4445), HTTP (8081), and FTP (2121), capturing exploit probes (e.g. MS17-010 EternalBlue) and hashing binary samples.
  - **Mosquitto Honey**: Monitors rogue MQTT broker connections on port 18883, logging wildcard subscriptions (`#`) and unauthorized command publishes.
- **IoT Fleet Simulation (10 Devices)**:
  - 10 distinct software devices: IP Camera, Smart Router, Temperature Sensor, Motion Sensor, Smart Lighting Controller, MQTT Gateway, Door Sensor, Environmental Sensor, Smart Energy Meter, HVAC Controller.
  - Generates baseline telemetry alongside controlled cyberattack scenarios (DDoS publish burst, actuator override, sensor tampering).
- **Centralized SIEM & Custom Rules**:
  - Multi-arch ARM64 Wazuh single-node deployment configuration (`compose.wazuh.yml`).
  - Custom XML decoders (`honeypot_decoders.xml`, `iot_decoders.xml`) and rules (`honeypot_rules.xml`, `iot_rules.xml`).
  - Vendor-neutral **Sigma rules** translated to Wazuh XML detection format.
- **MITRE ATT&CK Matrix**:
  - Full evidence-based mapping to tactics and techniques: `T1110` (Brute Force), `T1059.004` (Unix Shell), `T1105` (Ingress Tool Transfer), `T1046` (Discovery), `T1210` (Exploitation of Remote Services), `T1499` (Endpoint DoS).
- **Explainable Multi-Factor Risk Scoring**:
  $$\text{Risk Score} = \min\left(100, (\text{Severity}_{\text{base}} \times 0.35) + (\text{Frequency}_{\text{norm}} \times 0.20) + (\text{ThreatIntel}_{\text{score}} \times 0.25) + (\text{ML}_{\text{anomaly}} \times 0.20)\right)$$
- **Threat Intelligence Enrichment**:
  - AbuseIPDB v2 client with private RFC1918 IP bypass and 24-hr TTL caching.
  - VirusTotal v3 client querying file hash reputations (zero sample uploads).
- **SOAR Automated Response**:
  - Real-time incident notifications dispatched to Telegram.
  - Controlled response engine with safe simulation mode, immutable allowlists (`127.0.0.1`, LAN, management subnets), and auto-rollback timers.
- **Machine Learning Anomaly Detection**:
  - Unsupervised **Isolation Forest** model (100 ensemble trees) evaluating 8-dimensional behavioral vectors. Achieved **100% precision and recall** on validation data.
- **SOC Analyst Dashboard (15 Views)**:
  - Built with React 18, TypeScript, Tailwind CSS, and Lucide icons.
  - Features Overview, Live Events, Honeypots, IoT Fleet, Alerts, Incident Workspace, Threat Intel, MITRE Matrix, ML Anomalies, SOAR Response, Attack Analytics, Attack Relationship Graph, Evidence Integrity, Forensic Reports, and System Health.
- **Evidence Integrity Verification**:
  - Cryptographic **SHA-256 hash chaining** across all SOAR audit records (`reports/audit_trail.json`).
  - Automated hash manifest generation (`reports/evidence_integrity_manifest.json`).

---

## 3. Quick Start & Local Execution

### Prerequisites
- Apple Silicon Mac (M1/M2/M3/M4)
- macOS 14+ / macOS 26+
- Python 3.11+ (Python 3.13 verified)
- 8 GB RAM (Platform uses memory budgeting to preserve host stability)

### Step 1: Start All Platform Services
```bash
# Starts Honeypots (Cowrie, Dionaea, Mosquitto) and Application Core / Dashboard
./scripts/start-all.sh
```

### Step 2: Open the SOC Analyst Dashboard
Open your web browser to:
```
http://127.0.0.1:8000
```

### Step 3: Run the End-to-End Cyberattack Simulation
```bash
python3 scripts/simulate_attacks.py
```
*Simulates SSH brute-forcing, decoy breach, payload download, SMB exploit probes, and IoT DDoS floods in real time.*

### Step 4: Run the Complete 41-Test Acceptance Suite
```bash
python3 tests/run_all_tests.py
```

### Step 5: Stop Services Cleanly
```bash
./scripts/stop-all.sh
```

---

## 4. Project Directory Layout

```
mini-soc-platform/
├── docs/                      # Comprehensive technical specifications
│   ├── architecture.md        # System architecture & resource budgeting
│   ├── network-design.md      # 3-tier network segmentation & port allocations
│   ├── technology-stack.md    # Technology inventory & ARM64 compatibility
│   ├── threat-model.md        # STRIDE threat model & safety bounds
│   ├── api-documentation.md  # Complete 24-endpoint REST API reference
│   ├── testing-report.md      # Acceptance test logs
│   ├── threat-investigation-report.md # Real telemetry investigation report
│   ├── demo-guide.md          # 10-minute presentation walkthrough
│   ├── final-demo-guide.md    # Live presentation script & runbook
│   ├── final-project-report.md # Comprehensive engineering & handover report
│   └── phase-tracker.md       # 8-phase execution tracking board
├── infrastructure/            # Orchestration & SIEM rules
│   ├── docker/                # Modular Docker Compose files
│   └── wazuh/                 # Custom XML decoders and detection rules
├── honeypots/                 # Multi-service honeynet
│   ├── cowrie/                # SSH/Telnet honeypot trap
│   ├── dionaea/               # SMB/HTTP/FTP malware trap (ARM64)
│   └── mqtt/                  # MQTT honeypot broker trap
├── iot-simulator/             # Virtual IoT device fleet (10 devices)
├── backend/                   # FastAPI / REST API application core
├── frontend/                  # React + TypeScript + Tailwind SOC Dashboard
├── detection-engine/          # Sigma rules, MITRE mapping & correlation
├── threat-intelligence/       # AbuseIPDB and VirusTotal caching clients
├── soar/                      # Incident manager, Telegram bot, response engine
├── ml-engine/                 # Isolation Forest anomaly detection
├── reports/                   # Audit chains, evidence manifests, forensic reports
├── scripts/                   # Staged lifecycle and attack simulation scripts
├── tests/                     # Unit, integration, and E2E test suites
└── docker-compose.yml         # Master Docker Compose wrapper
```

---

## 5. Development Phases Signoff

- **Phase 1 – Project Planning & Architecture**: **COMPLETED**
- **Phase 2 – Infrastructure & Honeypot Deployment**: **COMPLETED** (5/5 tests passed)
- **Phase 3 – IoT Device Simulation Fleet**: **COMPLETED** (6/6 tests passed)
- **Phase 4 – Wazuh SIEM Integration**: **COMPLETED** (7/7 tests passed)
- **Phase 5 – Custom Detection Engine & MITRE ATT&CK**: **COMPLETED** (5/5 tests passed)
- **Phase 6 – Threat Intelligence & SOAR Automation**: **COMPLETED** (6/6 tests passed)
- **Phase 7 – Machine Learning & SOC Dashboard**: **COMPLETED** (12/12 tests passed)
- **Phase 8 – Testing, Validation & Final Handover**: **COMPLETED** (41/41 master tests passed)
