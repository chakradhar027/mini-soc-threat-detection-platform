# Mini SOC & Threat Detection Platform - Final Demonstration Guide

**Project Name:** Mini SOC & Threat Detection Platform  
**Target Architecture:** Apple Silicon M3 (ARM64) | macOS  
**Execution Runtime:** Native Python 3.13 (`.venv`) + OrbStack Wazuh Manager 4.9.0  
**Scope:** Educational & Research Threat Detection Simulation

---

## 1. Prerequisites & Environment Check

Before beginning the demonstration, verify that your environment meets the runtime prerequisites:

```bash
# Check Python version (requires Python 3.10+)
.venv/bin/python3 --version

# Check OrbStack / Docker Engine status
docker info >/dev/null 2>&1 && echo "[+] Docker Engine is running" || echo "[-] Docker Engine NOT running"

# Check available memory
docker stats --no-stream
```

---

## 2. Platform Startup Sequence

To start all components in the correct dependency order:

### Step 1: Start Honeynet Services
Launches the Cowrie SSH/Telnet emulator, Dionaea trap, and Mosquitto decoy broker:
```bash
bash scripts/start-honeypots.sh
```
*Expected Output:*
```text
[*] Starting Honeynet (Cowrie SSH/Telnet, Dionaea Trap, Mosquitto Honey)
[*] Launching Cowrie Honeypot (SSH:2222, Telnet:2223)...
[*] Launching Dionaea Trap (SMB:4445, HTTP:8081, FTP:2121)...
[*] Launching Mosquitto MQTT Honeypot (Port:18883)...
[+] All Honeypots running in native background processes (PIDs in .pids/).
[+] Honeynet is operational.
```

### Step 2: Start Wazuh SIEM Manager
Launches the standalone Wazuh Manager container:
```bash
docker compose -f infrastructure/docker/compose.wazuh-manager.yml up -d
```
*Expected Output:*
```text
[+] Running 1/1
 ✔ Container soc-wazuh-manager  Running
```

### Step 3: Start SOC Core Backend & Dashboard
Launches the FastAPI ASGI application on port 8000:
```bash
bash scripts/start-app.sh
```
*Expected Output:*
```text
=========================================================================
 Starting Mini SOC Application Core & Dashboard
=========================================================================
[*] Launching Mini SOC Backend Server on 127.0.0.1:8000...
[*] Using FastAPI / Uvicorn ASGI Server...
[+] Mini SOC Dashboard is LIVE at http://127.0.0.1:8000
```

---

## 3. Health & Connectivity Verification

Verify that all platform microservices are healthy before demonstrating attack scenarios:

### Core Platform Health
```bash
curl -s http://127.0.0.1:8000/api/v1/health | python3 -m json.tool
```
*Key checks:* `"status": "HEALTHY"`, `"fastapi_backend": "UP"`, `"wazuh_siem": "UP"`.

### Wazuh SIEM & Ingestion Status
```bash
curl -s http://127.0.0.1:8000/api/v1/wazuh/status | python3 -m json.tool
```
*Key checks:* `"ingestion_mode": "HYBRID_API_AND_FILE"`, `"api_reachable": true`, `"streaming_active": true`.

### IoT Fleet Health (10 Devices)
```bash
curl -s http://127.0.0.1:8000/api/v1/iot/devices | python3 -m json.tool
```
*Key checks:* 10 devices active (`iot-cam-01`, `iot-router-01`, `iot-thermo-01`, etc.).

---

## 4. Live Attack Demonstration Scenarios

### Scenario A: Controlled Harmless SSH Authentication Probe
Send a single harmless failed-login attempt to the Cowrie honeypot on port 2222:
```bash
.venv/bin/python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', 2222))
banner = s.recv(1024)
print('[-] Banner:', banner.decode().strip())
s.sendall(b'SSH-2.0-DemoAuditor\r\n')
time.sleep(0.1)
s.sendall(b'demo_user:InvalidDemoPassword2026!\n')
time.sleep(0.5)
s.close()
print('[+] Harmless authentication attempt sent.')
"
```
*Verification:*
1. Check `cowrie.json`:
   ```bash
   tail -n 2 infrastructure/docker/volumes/cowrie/log/cowrie.json
   ```
2. Verify Wazuh alert in `alerts.json`:
   ```bash
   tail -n 1 infrastructure/docker/volumes/wazuh/manager/logs/alerts/alerts.json
   ```
   Rule `100101` (*Cowrie: Authentication failed on honeypot.*) will be present.
3. Check FastAPI event feed:
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/events?limit=3 | python3 -m json.tool
   ```

---

### Scenario B: Multi-Vector End-to-End Cyberattack Simulation
Execute the full automated attack simulation suite covering 5 attack scenarios:
```bash
.venv/bin/python3 scripts/simulate_attacks.py
```
This script executes:
1. **Scenario 1:** SSH Brute-Force Spray (5 rapid failed logins -> Rule 100102).
2. **Scenario 2:** Decoy Root Breach & Payload Dropper Download (Rules 100103 & 100105 -> Incident `INC-F8BCDE0F`).
3. **Scenario 3:** SMB EternalBlue Probe on Dionaea (Port 4445 -> Rule 100201).
4. **Scenario 4:** Rogue MQTT Wildcard Subscription on Mosquitto (Port 18883 -> Rule 100301).
5. **Scenario 5:** IoT Camera Botnet DDoS Flood (High-frequency telemetry -> Flags `iot-cam-01` as `COMPROMISED`).

---

### Scenario C: SOC Analyst Dashboard Walkthrough
Open the dashboard in any web browser:
```text
http://127.0.0.1:8000/
```

**Key Views to Demonstrate:**
1. **Overview Tab:** Real-time metrics counters for Total Interactions, Security Alerts, and Incidents.
2. **SIEM Live Alerts:** Real-time stream of Wazuh-generated alerts with rule levels.
3. **Incidents Workspace:** Drill down into `INC-F8BCDE0F` (Critical Breach & Payload Drop) and `INC-47BB4E39` (IoT Camera DDoS).
4. **MITRE ATT&CK Matrix:** Show highlighted techniques (`T1110`, `T1078`, `T1105`, `T1499`).
5. **Attack Relationship Graph:** Visualize attacker IP links to honeypots and IoT devices.
6. **SOAR Response Center:** Demonstrate the Containment IP button and verify host protection allowlists.
7. **ML Anomaly Detection:** Demonstrate the Isolation Forest scoring tool with normal vs anomalous vectors.

---

### Scenario D: Threat Intelligence Lookup
Query the threat intelligence enrichment endpoint:
```bash
# Query an external suspicious IP
curl -s "http://127.0.0.1:8000/api/v1/threat-intel/lookup?ip=198.51.100.44" | python3 -m json.tool

# Query an RFC1918 private IP (shows safe local bypass)
curl -s "http://127.0.0.1:8000/api/v1/threat-intel/lookup?ip=192.168.1.101" | python3 -m json.tool

# Query a malicious payload hash
curl -s "http://127.0.0.1:8000/api/v1/threat-intel/lookup?hash=4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a" | python3 -m json.tool
```

---

### Scenario E: SOAR Automated Response & Containment Guardrail
Test the containment engine:
```bash
# Attempt to block an attacker IP (Simulated Containment)
curl -s -X POST http://127.0.0.1:8000/api/v1/response/block \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "198.51.100.44", "incident_id": "INC-78F8EFC2", "operator": "lead_analyst"}' | python3 -m json.tool

# Test Hard Allowlist Protection (Attempt to block host 127.0.0.1)
curl -s -X POST http://127.0.0.1:8000/api/v1/response/block \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "127.0.0.1", "incident_id": "INC-TEST", "operator": "lead_analyst"}' | python3 -m json.tool
```
*Expected Result:* The second call will be strictly rejected: `"status": "BLOCKED", "reason": "Protected IP"`.

---

### Scenario F: Evidence Integrity Manifest Verification
Verify the cryptographic SHA-256 evidence chain:
```bash
.venv/bin/python3 reports/generate_evidence_manifest.py
```
*Expected Output:*
```text
=========================================================================
 EVIDENCE INTEGRITY ATTESTATION MANIFEST GENERATED
=========================================================================
[*] Audit Hash Chain Status: VALID (UNBROKEN)
[*] Total Cryptographic Audit Records: 30
[*] Manifest Path: .../reports/evidence_integrity_manifest.json
```

---

## 5. Automated Master Test Suite Execution

Run the complete 30-test suite across all 8 development phases:
```bash
.venv/bin/python3 tests/run_all_tests.py
```
*Expected Output:*
```text
Ran 30 tests in 0.055s
OK
STATUS: ALL TESTS PASSED (100% SUCCESS)
```

---

## 6. Clean Platform Shutdown Sequence

When demonstration is complete, stop all background services gracefully:

```bash
# 1. Stop all native honeypots, IoT simulators, and backend processes
bash scripts/stop-all.sh

# 2. Stop Wazuh Manager container
docker compose -f infrastructure/docker/compose.wazuh-manager.yml down
```

*Verification that all ports are released:*
```bash
lsof -i :8000 -i :2222 -i :2223 -i :4445 -i :8081 -i :2121 -i :18883 -i :55000 2>/dev/null || echo "[+] All SOC ports cleanly released."
```

