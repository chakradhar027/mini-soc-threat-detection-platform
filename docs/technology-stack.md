# Technology Stack Specification & ARM64 Compatibility

## 1. Complete Technology Inventory

| Layer | Component | Version / Specification | Rationale & Purpose |
|---|---|---|---|
| **Backend Framework** | FastAPI | `>= 0.111.0` | High-performance asynchronous Python REST API; automatic OpenAPI/Swagger documentation; native Pydantic validation. |
| **Data Validation** | Pydantic v2 | `>= 2.7.0` | Strict, high-speed type validation for incoming alerts, schemas, and API request models. |
| **Database ORM** | SQLAlchemy 2.0 | `>= 2.0.30` | Modern Python ORM supporting async engine and robust relational modeling. |
| **Relational Database** | PostgreSQL | `16-alpine` | High-reliability ACID relational database for incidents, analyst notes, indicators, and audit trails. |
| **Frontend Framework** | React 18 | `18.3.x` | Industry standard UI framework for building reactive, component-driven SOC interfaces. |
| **Language & Tooling** | TypeScript & Vite | `TS 5.4.x`, `Vite 5.x` | Strongly typed frontend development with instantaneous hot module reloading (HMR) and optimized builds. |
| **UI Styling** | Tailwind CSS | `3.4.x` | Utility-first styling enabling a clean, professional SOC visual aesthetic with responsive layouts. |
| **Data Visualization** | Recharts & Lucide | `Recharts 2.x`, `lucide-react` | Declarative SVG charting for telemetry time-series, event distributions, and modern cybersecurity icons. |
| **Relationship Graph** | Force-Directed Graph | `react-force-graph-2d` / SVG Canvas | Interactive graph representation of Source IPs, Honeypot Targets, Credentials, and Alerts. |
| **SIEM Core** | Wazuh Manager | `4.9.0` (ARM64) | Comprehensive SIEM engine performing real-time log analysis, decoding, and custom rule alerting. |
| **SIEM Storage** | Wazuh Indexer | `4.9.0` (OpenSearch 2.13) | Distributed search and analytics engine for security event storage and rapid retrieval. |
| **SIEM Visualizer** | Wazuh Dashboard | `4.9.0` (OpenSearch Dashboards) | Analytical dashboard for deep log inspection and operational compliance. |
| **SSH/Telnet Honeypot**| Cowrie | `cowrie/cowrie:latest` | Python-based SSH/Telnet honeypot capturing brute-force attacks and terminal interaction. |
| **Multi-Service Trap** | Dionaea | Native ARM64 build | Malware trap emulating SMB, HTTP, FTP, TFTP to capture exploits and payloads. |
| **MQTT Honeypot & IoT**| Eclipse Mosquitto | `2.0.x-alpine` | Lightweight MQTT broker for IoT telemetry and honeypot trapping. |
| **IoT Client Library** | Paho MQTT | `paho-mqtt >= 2.0.0` | Standard Python MQTT client powering the simulated IoT device fleet. |
| **Detection Rules** | Sigma & Wazuh Rules | Sigma Core Specification | Vendor-neutral detection definitions translated into native Wazuh XML decoders and rules. |
| **Threat Intelligence**| AbuseIPDB & VirusTotal | REST APIs v2 & v3 | External IP reputation and file hash analysis with local caching. |
| **Notification Engine**| Telegram Bot API | `python-telegram-bot` / REST | Mobile alert dispatch for high and critical security incidents. |
| **Machine Learning** | Scikit-Learn | `>= 1.5.0` | Isolation Forest anomaly detection model for behavioral anomaly scoring. |
| **Data Processing** | pandas & numpy | Latest stable | Efficient tabular data manipulation and numerical feature extraction. |
| **Metrics Engine** | Grafana | `10.4.x` | Metric dashboards and visualization for hardware and event metrics. |

---

## 2. ARM64 (Apple Silicon) Compatibility Analysis

The target host is an **Apple M3 Mac running macOS 26.5 (ARM64)**. Container images and native packages must be strictly evaluated for ARM64 compatibility:

### 2.1 Container Images Assessment

| Service | Target Image | Multi-Arch (ARM64) Support | Compatibility Notes |
|---|---|---|---|
| **Wazuh Indexer** | `wazuh/wazuh-indexer:4.9.0` | **Native `linux/arm64`** | Wazuh officially supports ARM64 on Wazuh Indexer (OpenSearch base). Memory heap configured to 512m/1g. |
| **Wazuh Manager** | `wazuh/wazuh-manager:4.9.0` | **Native `linux/arm64`** | Built on Debian/CentOS arm64. Runs natively on Apple Silicon. |
| **Wazuh Dashboard**| `wazuh/wazuh-dashboard:4.9.0`| **Native `linux/arm64`** | Node.js based OpenSearch Dashboards fork. Fully arm64 compatible. |
| **Cowrie** | `cowrie/cowrie:latest` | **Native `linux/arm64`** | Official Cowrie Docker Hub image supports `linux/amd64` and `linux/arm64`. |
| **Dionaea** | Custom Dockerfile / Native build | **ARM64 Native Dockerfile** | Many public prebuilt Dionaea images are amd64 only. To ensure 100% stability on Apple Silicon without Rosetta segmentation faults, we provide an optimized ARM64 Dockerfile based on Ubuntu/Debian arm64. |
| **Mosquitto** | `eclipse-mosquitto:2` | **Native `linux/arm64`** | Alpine-based multi-arch image, minimal resource footprint (~10 MB RAM). |
| **PostgreSQL** | `postgres:16-alpine` | **Native `linux/arm64`** | Native ARM64 Alpine build. |
| **Grafana** | `grafana/grafana:latest` | **Native `linux/arm64`** | Official multi-arch image. |

### 2.2 Host Development Environment

- **Python**: System Python `3.13.0` installed at `/Library/Frameworks/Python.framework/Versions/3.13/bin/python3`.
  - All selected libraries (`fastapi`, `uvicorn`, `sqlalchemy`, `pydantic`, `scikit-learn`, `pandas`, `numpy`) have pre-compiled wheels for macOS `arm64`.
- **Node.js & npm**: Node `v24.18.0` and npm `11.16.0` installed at `/usr/local/bin/`.
  - Fully compatible with Vite, React 18, Tailwind CSS, and Recharts.
- **Docker**:
  - Docker engine is not yet installed. Docker Desktop for Mac (Apple Silicon) or OrbStack is required.

---

## 3. Host Resource Budgeting Strategy (8 GB Unified Memory)

Running a complete SOC stack on an 8 GB workstation requires precise memory tuning:

1. **Wazuh Indexer JVM Tuning**:
   - Default OpenSearch JVM requests `1g-2g`.
   - Tuned in Docker Compose: `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx1024m`.
2. **PostgreSQL Tuning**:
   - `shared_buffers = 64MB`, `work_mem = 4MB`, `max_connections = 50`.
3. **Log Rotation**:
   - Docker JSON log driver restricted to `max-size: "10m"`, `max-file: "3"` to prevent storage ballooning.
4. **Decoupled Development**:
   - Frontend and Backend can run natively on macOS using the virtual environment and Node.js or within Docker, conserving container VM overhead.

