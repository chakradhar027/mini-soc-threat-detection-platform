# Mini SOC & Threat Detection Platform - Phase Progress Tracker

## Master Phase Status Board

| Phase | Title | Status | Completion Date | Signoff & Notes |
|---|---|---|---|---|
| **Phase 1** | Project Planning and Architecture | **Completed** | 2026-11-06 | Environment inspected, architecture and network designed, ARM64 verified. |
| **Phase 2** | Cloud-Style Local Infrastructure & Honeypots | **Not Started** | - | Awaiting Phase 1 review and user authorization. |
| **Phase 3** | IoT Device Simulation | **Not Started** | - | Pending Phase 2 completion. |
| **Phase 4** | Wazuh SIEM Integration | **Not Started** | - | Pending Phase 3 completion. |
| **Phase 5** | Custom Detection Engine & MITRE ATT&CK | **Not Started** | - | Pending Phase 4 completion. |
| **Phase 6** | Threat Intelligence & SOAR Automation | **Not Started** | - | Pending Phase 5 completion. |
| **Phase 7** | Machine Learning & SOC Dashboard | **Not Started** | - | Pending Phase 6 completion. |
| **Phase 8** | Testing, Documentation & Final Deployment | **Not Started** | - | Pending Phase 7 completion. |

---

## Detailed Phase Breakdown

### Phase 1 – Project Planning and Architecture
- [x] Inspect development environment (CPU, RAM, OS, Storage, Git, Node, Python, Docker).
- [x] Verify ARM64 compatibility for all target containers and libraries.
- [x] Establish resource budgeting for 8 GB RAM Apple Silicon host.
- [x] Finalize system architecture and data flow design (`docs/architecture.md`).
- [x] Design 3-tier Docker network topology and isolation boundaries (`docs/network-design.md`).
- [x] Define technology stack inventory and dependency profiles (`docs/technology-stack.md`).
- [x] Produce local installation and troubleshooting guide (`docs/installation-guide.md`).
- [x] Create standardized project directory structure.
- [x] Initialize Git repository with security-hardened `.gitignore`.
- [x] Prepare initial environment template (`infrastructure/docker/.env.example`).
- [x] Establish phase tracking matrix (`docs/phase-tracker.md`).

**Phase 1 Acceptance Criteria Verification:**
- [x] Architecture is documented with component breakdown and sequence flow.
- [x] Every major service has a defined purpose and interface.
- [x] Network boundaries and isolation rules are documented.
- [x] Resource requirements and limits for 8 GB RAM are established.
- [x] Docker compatibility for ARM64 evaluated; Docker absence flagged as prerequisite.

---

### Phase 2 – Cloud-Style Local Infrastructure and Honeypot Deployment
- [ ] Configure Docker Compose file with 3 isolated bridge networks.
- [ ] Deploy Cowrie SSH/Telnet honeypot with persistent volume mounts.
- [ ] Deploy Dionaea honeypot in isolated container for SMB/HTTP/FTP traps.
- [ ] Deploy Mosquitto MQTT honeypot broker.
- [ ] Implement service healthchecks and restart policies.
- [ ] Verify test connections and structured JSON log generation for each honeypot.
- [ ] Verify persistence after container restarts and enforce read-only log mounts.

---

### Phase 3 – IoT Device Simulation
- [ ] Develop async modular IoT device simulation framework in Python.
- [ ] Implement 10 device types (Camera, Router, Temperature, Motion, Lighting, Gateway, Door, Environmental, Energy, Controller).
- [ ] Configure normal telemetry publishing cycles over MQTT.
- [ ] Implement controlled attack simulation triggers (burst flood, unauthorized topic subscribe, credential guessing).
- [ ] Log device event streams with precise ISO-8601 timestamps.
- [ ] Verify event pipeline delivery to internal broker.

---

### Phase 4 – Wazuh SIEM Integration
- [ ] Deploy Wazuh single-node architecture (Manager, Indexer, Dashboard).
- [ ] Configure log ingestion pipelines for Cowrie, Dionaea, and Mosquitto.
- [ ] Author custom Wazuh decoders for honeypot and IoT log formats.
- [ ] Author custom Wazuh rules for credential brute force, exploit attempts, and unauthorized MQTT access.
- [ ] Verify alert indexing in Wazuh Indexer and visualize in Wazuh Dashboard.
- [ ] Implement programmatic alert retrieval via Wazuh REST API.

---

### Phase 5 – Custom Detection Engine and MITRE ATT&CK
- [ ] Define Sigma detection rules for top 8 threat scenarios.
- [ ] Translate Sigma rules to Wazuh XML detection format.
- [ ] Map all detections to MITRE ATT&CK techniques (T1110, T1059, T1046, etc.).
- [ ] Implement multi-event correlation logic (brute-force -> payload drop correlation).
- [ ] Implement explainable multi-factor risk scoring engine.
- [ ] Test with controlled attack scripts and evaluate false positive rates.

---

### Phase 6 – Threat Intelligence and SOAR Automation
- [ ] Implement AbuseIPDB REST client with rate limiting and local TTL caching.
- [ ] Implement VirusTotal file hash reputation lookup client.
- [ ] Build SOAR alert ingestion and incident management service.
- [ ] Implement Telegram Bot notification dispatcher with alert payload formatting.
- [ ] Implement Controlled Response Engine with simulation mode and strict host allowlist.
- [ ] Build audit logger recording all containment actions and rollback capabilities.

---

### Phase 7 – Machine Learning and SOC Dashboard
- [ ] Extract feature vectors from collected IoT and network telemetry.
- [ ] Train and evaluate Isolation Forest anomaly detection model using scikit-learn.
- [ ] Build ML REST inference endpoint in FastAPI.
- [ ] Develop full-stack React + TypeScript + Tailwind CSS SOC analyst dashboard.
- [ ] Implement 13 core dashboard pages and real-time event tables.
- [ ] Build interactive Attack Relationship Graph (IPs -> Sessions -> Honeypots -> Alerts).
- [ ] Build Incident Investigation Workspace with chronological timeline and evidence verification.
- [ ] Integrate Grafana analytics dashboards.

---

### Phase 8 – Testing, Documentation and Final Deployment
- [ ] Execute backend unit and integration test suite.
- [ ] Execute end-to-end attack simulation through complete pipeline.
- [ ] Verify evidence integrity verification (SHA-256 validation of log artifacts).
- [ ] Finalize API documentation and Swagger specs.
- [ ] Generate comprehensive Testing Report and Incident Investigation Report.
- [ ] Finalize Master README and demonstration walkthrough guide.
