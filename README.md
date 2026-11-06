# Mini SOC & Threat Detection Platform

A modular, enterprise-grade, locally deployable Security Operations Center (SOC) and Threat Detection platform built for security analysts, incident responders, and DevSecOps practitioners. Designed specifically to run natively on Apple Silicon (ARM64) macOS workstations.

---

## 1. Architecture Overview

```
[ATTACK SIMULATION] ──> [HONEYPOT FLEET] (Cowrie, Dionaea, MQTT)
                                │
                                ▼
                       [LOG COLLECTOR PIPELINE]
                                │
                                ▼
                       [WAZUH SIEM CORE]
                                │
       ┌────────────────────────┴────────────────────────┐
       ▼                                                 ▼
[SIGMA & MITRE ATT&CK]                         [THREAT INTELLIGENCE]
 (Custom Rules/Decoders)                        (AbuseIPDB & VirusTotal)
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
```

---

## 2. Key Platform Features

- **Multi-Vector Honeynet**: Cowrie SSH/Telnet, Dionaea multi-service trap (SMB/HTTP/FTP), and an isolated Mosquitto MQTT honeypot.
- **IoT Fleet Simulation**: 10 distinct simulated software IoT devices publishing realistic MQTT telemetry and controlled cyber attack scenarios.
- **Wazuh SIEM Centralization**: Full ingestion, custom decoders, and rule-based correlation mapping to the **MITRE ATT&CK** Enterprise framework.
- **Threat Intelligence Enrichment**: Automated lookup against AbuseIPDB and VirusTotal with local caching to preserve quota.
- **Multi-Factor Risk Scoring**: Explainable mathematical risk score (0-100) combining rule severity, occurrence frequency, threat reputation, and machine learning anomaly probability.
- **Attack Relationship Graph**: Interactive graph visualizing relationships between Attacker IPs, Honeypot targets, brute-force credentials, and incidents.
- **Incident Investigation Workspace**: Complete analyst workflow including alert timeline reconstruction, note taking, status assignment, and SHA-256 evidence integrity hashing.
- **SOAR Playbooks**: Automated Telegram alerts and controlled firewall containment with safety allowlists and rollback logging.
- **Unsupervised Anomaly Detection**: Isolation Forest model flagging behavioral deviations in network traffic and sensor intervals.
- **Modern Analyst UI**: High-performance React 18 + TypeScript + Vite + Tailwind CSS dashboard with responsive layouts and real-time feeds.

---

## 3. Host Environment & Hardware Profile

- **Hardware Architecture**: Apple Silicon (M3 ARM64)
- **Host Operating System**: macOS 26.5.2 (Darwin 25.x)
- **Unified RAM**: 8.0 GB (Optimized container memory budgets applied)
- **Available Storage**: 69 GB free
- **Python**: 3.13.0
- **Node.js**: v24.18.0
- **npm**: 11.16.0

---

## 4. Project Directory Layout

```
mini-soc-platform/
├── docs/                      # Architectural, network, and setup documentation
│   ├── architecture.md        # System architecture specification
│   ├── network-design.md      # Docker network segmentation & port allocations
│   ├── technology-stack.md    # Technology inventory & ARM64 compatibility
│   ├── installation-guide.md  # Step-by-step installation instructions
│   └── phase-tracker.md       # 8-phase execution tracking board
├── infrastructure/            # Container orchestration & configs
│   ├── docker/                # Compose definitions and .env templates
│   └── wazuh/                 # Custom Wazuh decoders, rules, and configs
├── honeypots/                 # Honeypot deployment definitions
│   ├── cowrie/                # SSH/Telnet honeypot configs
│   ├── dionaea/               # Malware trap configs
│   └── mqtt/                  # MQTT honeypot broker configs
├── iot-simulator/             # Python-based IoT fleet simulator
├── backend/                   # FastAPI backend core
├── frontend/                  # React + TypeScript + Tailwind SOC dashboard
├── detection-engine/          # Sigma rules and correlation logic
├── threat-intelligence/       # AbuseIPDB and VirusTotal enrichment modules
├── soar/                      # Telegram alerts & controlled response engine
├── ml-engine/                 # Isolation Forest anomaly detection
├── reports/                   # Generated forensic and investigation reports
├── scripts/                   # Attack simulation and helper utilities
├── tests/                     # Unit, integration, and E2E test suites
├── .gitignore                 # Security-hardened git exclusion rules
└── README.md                  # Master project guide
```

---

## 5. Current Development Status

- **Phase 1 – Project Planning and Architecture**: **COMPLETED**
- **Phase 2 – Cloud-Style Local Infrastructure & Honeypots**: **READY TO INITIATE** (Pending user confirmation)
