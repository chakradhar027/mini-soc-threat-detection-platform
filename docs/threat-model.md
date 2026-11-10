# Threat Model: Mini SOC & Threat Detection Platform

## 1. Executive Summary

This Threat Model defines the threat landscape, trust boundaries, asset inventory, and defensive countermeasures for the **Mini SOC and Threat Detection Platform**. The model utilizes the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to ensure the platform itself remains secure while monitoring and interacting with simulated and real attack telemetry.

---

## 2. System Assets & Sensitivity Classification

| Asset ID | Asset Name | Description | Sensitivity |
|---|---|---|---|
| **A-1** | Threat Intel API Keys | AbuseIPDB and VirusTotal private API keys | **Critical** (Confidentiality) |
| **A-2** | SIEM / DB Credentials | PostgreSQL passwords, Wazuh admin credentials | **Critical** (Confidentiality, Integrity) |
| **A-3** | Honeypot Captured Payloads | Malware binaries, scripts downloaded by attackers | **High** (Integrity, Containment) |
| **A-4** | Forensic Audit Trails | SOAR action logs, containment history, incident notes | **High** (Integrity, Non-Repudiation) |
| **A-5** | IoT Device State Telemetry | Sensor readings, actuator states, device configurations | **Medium** (Integrity, Availability) |
| **A-6** | SOC Analyst Web Session | JWT tokens granting access to the SOC dashboard | **High** (Confidentiality, Integrity) |

---

## 3. Trust Boundaries & Network Zones

```
[ UNTRUSTED ZONE: ATTACKERS & SIMULATORS ]
                  │
══════════════════╪══════════════════════════════════════════════════════
[ BOUNDARY 1: Honeypot Ingress (Ports 2222, 2223, 4445, 8081, 18883) ]
══════════════════╪══════════════════════════════════════════════════════
                  ▼
        ┌──────────────────┐
        │   soc-honeynet   │  ◄── Honeypots (Cowrie, Dionaea, Mosquitto Honey)
        └────────┬─────────┘
                 │ (Read-Only Log Volume Mounts - No Network Routing)
═════════════════╪══════════════════════════════════════════════════════
[ BOUNDARY 2: Inter-Zone Isolation (soc-iot-net vs soc-mgmt-net) ]
═════════════════╪══════════════════════════════════════════════════════
                 ▼
        ┌──────────────────┐         ┌──────────────────┐
        │   soc-iot-net    │         │   soc-mgmt-net   │ (127.0.0.1 Binds)
        │ (IoT Fleet +     │         │ • Wazuh SIEM     │ • React SOC UI
        │  Private Broker) │         │ • FastAPI Backend│ • Grafana
        └──────────────────┘         │ • PostgreSQL     │ • SOAR Engine
                                     └──────────────────┘
```

### Trust Boundary Rules:
1. **Honeypot DMZ (`soc-honeynet`)**:
   - Zero outbound connectivity to `soc-mgmt-net` or `soc-iot-net`.
   - Read-only file mounts (`:ro`) are used by the log ingestion layer so honeypots cannot tamper with SIEM collectors.
2. **Localhost Restriction**:
   - All management interfaces (FastAPI backend, Wazuh API, PostgreSQL, React UI, Grafana) bind exclusively to loopback (`127.0.0.1`).
   - No management port is exposed to the local physical LAN or WAN.
3. **Execution Prohibition**:
   - Captured payloads in honeypots (`downloads/` directory) are treated as live malware: **they are never executed**, never marked executable (`+x`), and quarantined with read-only permissions.

---

## 4. STRIDE Threat Analysis & Mitigations

### 4.1 Spoofing (Identity)
- **Threat**: Attacker spoofs an IoT device identity to inject false telemetry into the MQTT broker.
  - *Mitigation*: The IoT broker enforces client ID validation and topic ACLs. Unrecognized or conflicting client IDs trigger an immediate high-priority alert.
- **Threat**: Attacker accesses the SOC dashboard without authentication.
  - *Mitigation*: FastAPI enforces JWT authentication (OAuth2 with Bearer token) and role-based access for all incident management and response endpoints.

### 4.2 Tampering (Data Integrity)
- **Threat**: Attacker attempts to modify honeypot logs or incident evidence to conceal malicious actions.
  - *Mitigation*: Honeypot containers write to isolated append-only logs. The evidence integrity engine calculates **SHA-256 cryptographic hashes** upon event capture and incident creation, storing hashes in an immutable verification manifest.
- **Threat**: Attacker injects malicious SQL into search fields.
  - *Mitigation*: SQLAlchemy ORM parameterized queries are used exclusively; raw SQL string concatenation is forbidden.

### 4.3 Repudiation
- **Threat**: SOC analyst modifies or closes an incident without accountability.
  - *Mitigation*: The SOAR audit logger records user identity, action type, previous status, updated status, timestamp, and client IP for every lifecycle event.

### 4.4 Information Disclosure
- **Threat**: Leakage of Threat Intel API keys (AbuseIPDB, VirusTotal) or database passwords via Git or logs.
  - *Mitigation*: Strict `.gitignore` rules prevent `.env`, credentials, or token files from being committed. Environment variables are loaded into memory and never logged in plain text.
- **Threat**: Exposure of internal server network details via error messages.
  - *Mitigation*: FastAPI production exception handlers suppress stack traces and return structured error codes.

### 4.5 Denial of Service (DoS)
- **Threat**: Attacker floods the honeypot or IoT MQTT broker with gigabytes of logs to exhaust disk space and host RAM.
  - *Mitigation*: Docker containers enforce memory constraints (RAM limits), CPU limits, and Docker log rotation (`max-size: 10m`, `max-file: 3`). Honeypot connection throttles prevent resource exhaustion on an 8 GB host.

### 4.6 Elevation of Privilege
- **Threat**: Attacker escapes from a honeypot container to the host macOS system.
  - *Mitigation*: Honeypot containers run as unprivileged, non-root users (`cowrie` UID 1000). Host filesystem mounts are strictly limited to the dedicated volume subdirectories. No privileged Docker containers or Docker socket mounts are permitted inside the honeypot containers.

---

## 5. Automated Response Safety Architecture

Automated IP blocking poses a potential self-inflicted Denial of Service (locking the analyst out of their own system). To prevent this, the SOAR engine enforces three hard architectural constraints:

1. **Simulation Mode by Default**:
   - `SOAR_SIMULATION_MODE=true` is enabled initially. Actions are simulated and recorded in the audit log without altering network tables.
2. **Strict Host & LAN Allowlist**:
   - The response engine maintains an immutable allowlist containing `127.0.0.1`, `::1`, `172.28.0.0/16` (Docker subnets), and private RFC1918 networks (`192.168.0.0/16`, `10.0.0.0/8`).
   - Any containment command targeting an allowlisted address is rejected immediately and logged as a safety violation.
3. **One-Click Rollback & Expiration**:
   - All containment actions have an automated Time-To-Live (TTL) expiration (default: 3600 seconds) and support instant analyst rollback from the dashboard.

