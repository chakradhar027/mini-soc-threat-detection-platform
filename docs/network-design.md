# Network Architecture & Isolation Design

## 1. Network Segmentation Strategy

To prevent honeypot breakout, avoid cross-contamination of honeypot telemetry, and protect host and management services, the platform enforces strict network segmentation using three dedicated Docker bridge networks.

```
                    HOST WORKSTATION (macOS ARM64)
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       │ (127.0.0.1 Ingress)      │ (Controlled Ingress)     │ (Host-only Loopback)
       ▼                          ▼                          ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│    soc-mgmt-net     │  │    soc-honeynet     │  │     soc-iot-net     │
│   (172.28.30.0/24)  │  │   (172.28.10.0/24)  │  │   (172.28.20.0/24)  │
├─────────────────────┤  ├─────────────────────┤  ├─────────────────────┤
│ • Wazuh Manager     │  │ • Cowrie SSH/Telnet │  │ • IoT Simulated     │
│ • Wazuh Indexer     │  │ • Dionaea Trap      │  │   Fleet (10 dev)    │
│ • Wazuh Dashboard   │  │ • Mosquitto Honey   │  │ • IoT MQTT Broker   │
│ • FastAPI Backend   │  │   Broker            │  │                     │
│ • PostgreSQL DB     │  │                     │  │                     │
│ • React SOC UI      │  │                     │  │                     │
│ • Grafana Analytics │  │                     │  │                     │
└──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
           │                        │                        │
           └────────────── Log Volume Bridges ───────────────┘
                     (Read-Only Shared Mounts on Host)
```

---

## 2. Subnet Definitions

| Network Name | Subnet | Gateway | Purpose & Isolation Rules |
|---|---|---|---|
| `soc-honeynet` | `172.28.10.0/24` | `172.28.10.1` | **Honeypot DMZ**: Isolated from internal management networks. Outbound WAN access is disabled or heavily throttled. No route into `soc-mgmt-net`. |
| `soc-iot-net` | `172.28.20.0/24` | `172.28.20.1` | **IoT Simulation Subnet**: Private network for IoT simulated devices and their MQTT broker. Completely isolated from the honeynet. |
| `soc-mgmt-net` | `172.28.30.0/24` | `172.28.30.1` | **SOC Core & Management**: Hosts SIEM, DB, APIs, and UI. Only accepts connections bound strictly to `127.0.0.1` (localhost). |

---

## 3. Port Allocation Matrix

All administrative and data services are bound exclusively to the local loopback interface (`127.0.0.1`). Only decoy honeypot ports may be accessed externally (or via test simulators).

| Service | Container Port | Host Port | Bind Address | Protocol | Network Zone | Purpose |
|---|---|---|---|---|---|---|
| **Cowrie SSH** | 2222 | 2222 | `0.0.0.0` or `127.0.0.1` | TCP | `soc-honeynet` | Decoy SSH Honeypot |
| **Cowrie Telnet** | 2223 | 2223 | `0.0.0.0` or `127.0.0.1` | TCP | `soc-honeynet` | Decoy Telnet Honeypot |
| **Dionaea SMB** | 445 | 4445 | `0.0.0.0` or `127.0.0.1` | TCP | `soc-honeynet` | Decoy SMB Exploitation |
| **Dionaea HTTP** | 80 | 8081 | `0.0.0.0` or `127.0.0.1` | TCP | `soc-honeynet` | Decoy Web Trap |
| **Dionaea FTP** | 21 | 2121 | `0.0.0.0` or `127.0.0.1` | TCP | `soc-honeynet` | Decoy FTP Capture |
| **Mosquitto Honey** | 1883 | 18883 | `0.0.0.0` or `127.0.0.1` | TCP | `soc-honeynet` | Rogue MQTT Probe Trap |
| **IoT MQTT Broker** | 1883 | 1883 | `127.0.0.1` | TCP | `soc-iot-net` | Internal IoT Telemetry |
| **FastAPI Backend** | 8000 | 8000 | `127.0.0.1` | TCP | `soc-mgmt-net` | REST API & WebSocket |
| **React SOC UI** | 3000 / 5173 | 3000 | `127.0.0.1` | TCP | `soc-mgmt-net` | Analyst Web Dashboard |
| **PostgreSQL DB** | 5432 | 5432 | `127.0.0.1` | TCP | `soc-mgmt-net` | SOC Relational Store |
| **Wazuh Dashboard** | 443 | 8443 | `127.0.0.1` | HTTPS | `soc-mgmt-net` | Wazuh Management UI |
| **Wazuh Manager API** | 55000 | 55000 | `127.0.0.1` | HTTPS | `soc-mgmt-net` | Wazuh REST API |
| **Wazuh Agent Comm** | 1514 | 1514 | `127.0.0.1` | UDP/TCP | `soc-mgmt-net` | Secure Agent Comm |
| **Grafana** | 3000 | 3001 | `127.0.0.1` | HTTP | `soc-mgmt-net` | Analytical Metrics UI |

---

## 4. Communication & Data Flow Pathways

### 4.1 Inter-Zone Isolation Rules
1. **No direct packet routing between `soc-honeynet` and `soc-mgmt-net`**:
   - A compromised honeypot container cannot initiate a TCP/UDP socket directly into PostgreSQL, Wazuh Manager, or the Backend API.
2. **Log ingestion via Read-Only Host Mounts**:
   - Instead of exposing direct network log shippers across subnets, honeypots flush structured logs to designated host directory volumes:
     - `infrastructure/docker/volumes/cowrie/log/`
     - `infrastructure/docker/volumes/dionaea/log/`
     - `infrastructure/docker/volumes/mosquitto/log/`
   - Wazuh Manager (or its logcollector sidecar) mounts these directories as `:ro` (read-only), completely decoupling network attack surface from log processing.

### 4.2 Automated Response & Containment Boundary
- SOAR actions operate on a **Containment List**:
  - The automation engine can dynamically apply Docker iptables rules or simulated drop policies within `soc-honeynet`.
  - **Host Protection Rule**: The response engine maintains a hardcoded immutable allowlist:
    ```json
    {
      "allowlist": [
        "127.0.0.1",
        "::1",
        "172.28.30.0/24",
        "192.168.0.0/16",
        "10.0.0.0/8"
      ]
    }
    ```
  - Blocking commands targeting localhost or LAN gateways are automatically rejected by the response engine and logged as safety violations.
