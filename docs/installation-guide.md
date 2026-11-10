# Installation & Local Setup Guide

## 1. Host Prerequisites

The platform is designed and optimized for macOS running on Apple Silicon (M1/M2/M3/M4).

### Host System State Observed:
- **Processor**: Apple M3 (ARM64)
- **Operating System**: macOS 26.5.2 (Darwin 25.x)
- **RAM**: 8.0 GB Unified Memory
- **Available Disk Space**: 69 GB free on `/System/Volumes/Data`
- **Installed Runtime**:
  - Python `3.13.0` (`/Library/Frameworks/Python.framework/Versions/3.13/bin/python3`)
  - Node.js `v24.18.0` (`/usr/local/bin/node`)
  - npm `11.16.0` (`/usr/local/bin/npm`)
  - Git `2.50.1` (`/usr/bin/git`)
  - Homebrew `installed` (`/opt/homebrew/bin/brew`)

---

## 2. Installing Container Runtime (Docker)

Docker is currently **not installed** on this machine. To run the honeypots and Wazuh SIEM containers, install either **Docker Desktop** or **OrbStack** (OrbStack is highly recommended on 8GB Apple Silicon machines for significantly lower memory and CPU overhead).

### Option A: Install OrbStack (Recommended for 8GB Mac)
OrbStack uses ~100MB RAM idle compared to Docker Desktop's ~1.5GB VM overhead.
```bash
brew install --cask orbstack
# Launch OrbStack from Applications or terminal:
open -a OrbStack
```

### Option B: Install Docker Desktop for Mac (Apple Silicon)
```bash
brew install --cask docker
# Launch Docker Desktop:
open -a Docker
```

#### Recommended Docker Resource Settings (Docker Desktop Preferences -> Resources):
- **CPUs**: 4 Cores
- **Memory**: 4.5 GB (Leaving ~3.5 GB for macOS and local tools)
- **Swap**: 1.5 GB
- **Virtual disk limit**: 40 GB

Verify installation once running:
```bash
docker --version
docker compose version
```

---

## 3. Python Virtual Environment Setup

Initialize the isolated Python virtual environment for the backend, IoT simulator, detection engine, and ML pipeline:

```bash
cd "/Users/muppurichakri/Desktop/chakri project/PROJECT 2 – MINI SOC & THREAT DETECTION PLATFORM"

# Create virtual environment
python3 -m venv .venv

# Activate environment
source .venv/bin/activate

# Upgrade pip and packaging tools
pip install --upgrade pip setuptools wheel
```

---

## 4. Environment Variables Configuration

Copy the sample environment file to `.env`:
```bash
cp infrastructure/docker/.env.example .env
```

Ensure `.env` contains:
```bash
# General
ENVIRONMENT=development
LOG_LEVEL=INFO

# PostgreSQL Configuration
POSTGRES_USER=soc_admin
POSTGRES_PASSWORD=soc_secure_password_2026!
POSTGRES_DB=mini_soc
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432

# FastAPI Backend Configuration
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
SECRET_KEY=generate_a_random_32_char_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Wazuh SIEM Configuration
WAZUH_MANAGER_HOST=127.0.0.1
WAZUH_API_PORT=55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=WazuhSecretPassword123!

# Threat Intelligence (Optional during Phase 1/2)
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=

# SOAR & Notifications (Optional during Phase 1/2)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SOAR_SIMULATION_MODE=true
```

---

## 5. Verification Commands for Phase 1

To confirm Phase 1 readiness:
1. Verify directory layout:
   ```bash
   ls -la docs/
   ```
2. Verify documentation integrity:
   - `docs/architecture.md`
   - `docs/network-design.md`
   - `docs/technology-stack.md`
   - `docs/installation-guide.md`
   - `docs/phase-tracker.md`
3. Inspect Git status:
   ```bash
   git status
   ```

---

## 6. Troubleshooting Common macOS Apple Silicon Issues

1. **Port 5000 / 7000 Conflict (AirPlay Receiver)**:
   - macOS Monterey, Ventura, Sonoma, and Sequoia utilize port `5000` and `7000` for AirPlay Receiver by default.
   - *Resolution*: Our architecture binds FastAPI to port `8000` and Wazuh to `55000`, completely avoiding port `5000`. If port 5000 is ever needed, disable AirPlay Receiver in *System Settings -> General -> AirDrop & AirPlay*.
2. **Rosetta 2 Emulation Warnings**:
   - All chosen core images (`wazuh-manager`, `wazuh-indexer`, `cowrie`, `mosquitto`, `postgres`, `grafana`) support native `linux/arm64`.
   - Never use `--platform linux/amd64` unless strictly building an x86 binary.
3. **Host Permission Errors on Log Mounts**:
   - Honeypot volume logs must be readable by Wazuh. We configure persistent directories under `infrastructure/docker/volumes/` with appropriate group read permissions (`chmod -R 755`).

