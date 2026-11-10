# REST API Documentation: Mini SOC & Threat Detection Platform

## Base URL
```
http://127.0.0.1:8000/api/v1
```

All endpoints return JSON responses and support Cross-Origin Resource Sharing (CORS).

---

## 1. System Health & Diagnostics

### `GET /api/v1/health`
Returns the operational health and connectivity status of the platform and background services.

**Response (200 OK):**
```json
{
  "status": "HEALTHY",
  "timestamp": "2026-11-08T12:00:00Z",
  "platform": "Mini SOC & Threat Detection Platform",
  "architecture": "Apple Silicon (ARM64)",
  "memory_profile": "8GB Optimized",
  "services": {
    "fastapi_backend": "UP",
    "cowrie_honeypot": "UP",
    "dionaea_trap": "UP",
    "mqtt_honeypot": "UP",
    "iot_simulator": "UP",
    "detection_engine": "ACTIVE",
    "ml_anomaly_engine": "ACTIVE"
  }
}
```

---

## 2. SOC Overview & Metrics

### `GET /api/v1/overview`
Retrieves aggregated platform KPIs for the analyst overview dashboard.

**Response (200 OK):**
```json
{
  "total_interactions": 38,
  "security_alerts": 6,
  "critical_incidents": 1,
  "high_incidents": 2,
  "unique_source_ips": 17,
  "authentication_failures": 5,
  "active_honeypots": 3,
  "active_iot_devices": 10,
  "containment_actions": 1,
  "severity_distribution": {
    "LOW": 10,
    "MEDIUM": 7,
    "HIGH": 19,
    "CRITICAL": 2
  }
}
```

---

## 3. Security Events Feed

### `GET /api/v1/events`
Queries the chronological security event stream.

**Query Parameters:**
- `limit` (int, default: 100): Maximum events to return.
- `severity` (str, optional): Filter by `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `service` (str, optional): Filter by `cowrie`, `dionaea`, `mqtt_honeypot`, `iot`.

**Response (200 OK):**
```json
{
  "total": 38,
  "events": [
    {
      "event_id": "sim-breach-dl-1731067200",
      "timestamp": "2026-11-08T12:00:00Z",
      "source_ip": "203.0.113.99",
      "source_service": "cowrie",
      "event_type": "payload_download",
      "destination_port": 2222,
      "severity": "CRITICAL",
      "metadata": {
        "url": "http://c2-beacon.ru/agent.sh",
        "shasum": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
      }
    }
  ]
}
```

---

## 4. Honeypot Monitoring

### `GET /api/v1/honeypots`
Returns operational telemetry and listening traps for Cowrie, Dionaea, and Mosquitto.

---

## 5. IoT Device Fleet & Simulation

### `GET /api/v1/iot/devices`
Lists all 10 simulated IoT edge devices with live metrics and operational health.

### `POST /api/v1/iot/simulate`
Executes controlled cyberattack injection against the virtual IoT fleet.

**Request Body:**
```json
{
  "scenario": "burst_publish_flood",
  "device_id": "iot-cam-01",
  "count": 25
}
```
*Supported scenarios:* `burst_publish_flood`, `unauthorized_topic_access`, `telemetry_tampering`.

---

## 6. Incident Investigation Workspace

### `GET /api/v1/incidents`
Lists all correlated security incidents.

### `GET /api/v1/incidents/{incident_id}`
Retrieves complete forensic context, timeline, evidence events, and notes for an incident.

### `POST /api/v1/incidents/{incident_id}/notes`
Appends an analyst triage note to the incident timeline.

**Request Body:**
```json
{
  "author": "analyst_alice",
  "content": "Observed dropper download hash matches known Mirai botnet signature."
}
```

### `POST /api/v1/incidents/{incident_id}/status`
Updates investigation status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`).

---

## 7. Threat Intelligence & Enrichment

### `GET /api/v1/threat-intel/lookup`
**Query Parameters:**
- `ip`: IP address to inspect in AbuseIPDB.
- `hash`: SHA-256 or MD5 hash to inspect in VirusTotal.

---

## 8. MITRE ATT&CK Matrix

### `GET /api/v1/mitre/matrix`
Returns the Enterprise ATT&CK matrix and indicates which techniques are actively detected in current incidents.

---

## 9. Machine Learning Anomaly Detection

### `GET /api/v1/ml/anomalies`
Returns model metadata, 8-feature weights, and evaluation metrics (Precision, Recall, F1, FPR).

### `POST /api/v1/ml/anomalies`
Calculates real-time Isolation Forest anomaly score for an 8-dimensional feature vector.

---

## 10. SOAR Automated Response

### `GET /api/v1/response/containments`
Lists all currently active or simulated IP blocks and the immutable allowlist.

### `POST /api/v1/response/block`
Requests containment for an attacking IP.

**Request Body:**
```json
{
  "ip_address": "198.51.100.44",
  "incident_id": "INC-78F8EFC2",
  "reason": "SSH Brute-Force Spray Containment",
  "operator": "analyst_lead"
}
```

### `POST /api/v1/response/rollback`
Revokes an active containment rule and restores network access.

---

## 11. Attack Relationship Graph

### `GET /api/v1/graph`
Returns nodes (Attacker IPs, Honeypot Targets, Credentials, Incidents) and links for network visualization.

---

## 12. Evidence Integrity & Reports

### `GET /api/v1/evidence/integrity`
Returns SHA-256 cryptographic hashes and verifies the SOAR audit chain integrity.

### `POST /api/v1/reports/generate`
Generates a structured forensic threat report and saves it to `reports/`.

