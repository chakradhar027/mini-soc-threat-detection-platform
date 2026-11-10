# Project Demonstration Guide

This guide provides a structured 10-minute demonstration script for showcasing the **Mini SOC and Threat Detection Platform** during interviews, project reviews, or academic evaluations.

---

## 1. Quick Demonstration Commands

Open your terminal in the project root:

```bash
# Step 1: Start the Platform (Honeypots, IoT Fleet, and REST API Dashboard)
./scripts/start-all.sh

# Step 2: Open the SOC Analyst Dashboard in your browser
open http://127.0.0.1:8000

# Step 3: Execute the End-to-End Cyberattack Simulation
python3 scripts/simulate_attacks.py

# Step 4: Run the Complete 28-Test Acceptance Suite
python3 tests/run_all_tests.py
```

---

## 2. 10-Minute Walkthrough Script

### Minute 0–2: Architecture & Resource Planning (8 GB Apple Silicon)
- **What to show:** Open `docs/architecture.md` and `docs/network-design.md`.
- **Key Talking Points:**
  - Designed natively for Apple Silicon (M3 ARM64).
  - Addressed memory limitations of 8 GB RAM by budgeting container allocations (Wazuh Indexer JVM heap capped at 512m/1g).
  - 3-tier network segmentation: `soc-honeynet` (DMZ), `soc-iot-net` (private IoT), and `soc-mgmt-net` (localhost-only management).

### Minute 2–4: Honeynet & IoT Simulation Fleet
- **What to show:** In the Dashboard, navigate to **Honeypot Monitoring** and **IoT Device Fleet**.
- **Action:**
  - Show the 3 active honeypots: Cowrie (SSH:2222, Telnet:2223), Dionaea (SMB:4445, HTTP:8081, FTP:2121), and Mosquitto Honey (MQTT:18883).
  - Show the 10 simulated IoT devices (IP Camera, Router, Temperature, Motion, Lighting, Gateway, Door, Environmental, Energy, Controller).
  - Click the **"Simulate Camera Flood"** button on the IoT view.
  - Show the camera immediately transition to status `COMPROMISED` and emit high-rate telemetry.

### Minute 4–6: SIEM Detection, MITRE ATT&CK & Risk Scoring
- **What to show:** Navigate to **Security Alerts** and **MITRE ATT&CK Matrix**.
- **Key Talking Points:**
  - Detections are powered by custom Sigma rules and Wazuh decoders.
  - Explain the **Explainable 0–100 Risk Score Formula**:
    $$\text{Risk Score} = (\text{BaseSeverity} \times 0.35) + (\text{Frequency} \times 0.20) + (\text{ThreatIntel} \times 0.25) + (\text{MLAnomaly} \times 0.20)$$
  - Show the ATT&CK heat map highlighting detected techniques (`T1110`, `T1059.004`, `T1105`, `T1499`).

### Minute 6–8: Incident Investigation Workspace & Attack Relationship Graph
- **What to show:** Navigate to **Incident Workspace** and **Relationship Graph**.
- **Action:**
  - Select Incident `INC-F8BCDE0F` (Active Honeypot Breach & Payload Drop).
  - Review the evidence events stream showing the successful login on `root` and subsequent `wget` command.
  - Type an analyst note into the box: `"Confirmed malicious hash against C2 database. Recommending immediate quarantine."` and click **Add Note**.
  - Click **Contain Threat** to trigger the SOAR response.
  - Switch to **Relationship Graph** to show the interactive topological graph linking `Attacker IP -> Cowrie -> root -> Incident`.

### Minute 8–10: ML Anomaly Detection, Evidence Integrity & Verification
- **What to show:** Navigate to **ML Anomaly Detection** and **Evidence Integrity**.
- **Key Talking Points:**
  - Unsupervised Isolation Forest model trained on 8-dimensional behavioral vectors (100% precision, 100% recall on test partition).
  - Show the live anomaly scorer: adjust sliders to demonstrate anomaly classification in real time.
  - In Evidence Integrity, show the **unbroken SHA-256 hash chain** across all SOAR audit records.
  - Navigate to **Forensic Reports**, click **"Generate Executive Report"**, and display the compiled markdown threat report.

---

## 3. Stopping Services Cleanly

When finished with the demonstration:

```bash
./scripts/stop-all.sh
```
All background processes and containers are stopped cleanly.

