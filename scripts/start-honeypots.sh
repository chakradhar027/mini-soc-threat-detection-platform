#!/bin/bash
# =========================================================================
# START HONEYPOTS SERVICE (Dual-Mode: Docker or Native Standalone)
# =========================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PID_DIR="${ROOT_DIR}/.pids"
mkdir -p "${PID_DIR}"

echo "========================================================================="
echo " Starting Honeynet (Cowrie SSH/Telnet, Dionaea Trap, Mosquitto Honey)"
echo "========================================================================="

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "[*] Docker daemon detected. Launching Honeypots via Docker Compose..."
    docker compose -f "${ROOT_DIR}/infrastructure/docker/compose.honeypots.yml" up -d
    echo "[+] Docker Honeypot containers started successfully."
else
    echo "[!] Docker daemon not running or not installed."
    echo "[*] Launching Honeypots in Native Standalone Python Mode..."

    # Ensure python virtual environment
    PYTHON_BIN="python3"
    if [ -f "${ROOT_DIR}/.venv/bin/python3" ]; then
        PYTHON_BIN="${ROOT_DIR}/.venv/bin/python3"
    fi

    # Start Cowrie
    echo "[*] Launching Cowrie Honeypot (SSH:2222, Telnet:2223)..."
    nohup "${PYTHON_BIN}" "${ROOT_DIR}/honeypots/cowrie/service.py" > "${ROOT_DIR}/infrastructure/docker/volumes/cowrie/log/stdout.log" 2>&1 &
    echo $! > "${PID_DIR}/cowrie.pid"

    # Start Dionaea
    echo "[*] Launching Dionaea Trap (SMB:4445, HTTP:8081, FTP:2121)..."
    nohup "${PYTHON_BIN}" "${ROOT_DIR}/honeypots/dionaea/service.py" > "${ROOT_DIR}/infrastructure/docker/volumes/dionaea/log/stdout.log" 2>&1 &
    echo $! > "${PID_DIR}/dionaea.pid"

    # Start Mosquitto Honey
    echo "[*] Launching Mosquitto MQTT Honeypot (Port:18883)..."
    nohup "${PYTHON_BIN}" "${ROOT_DIR}/honeypots/mqtt/service.py" > "${ROOT_DIR}/infrastructure/docker/volumes/mosquitto/log/stdout.log" 2>&1 &
    echo $! > "${PID_DIR}/mqtt_honey.pid"

    echo "[+] All Honeypots running in native background processes (PIDs in .pids/)."
fi

echo "[+] Honeynet is operational."

