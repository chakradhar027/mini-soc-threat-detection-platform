#!/bin/bash
# =========================================================================
# STOP ALL MINI SOC SERVICES
# =========================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PID_DIR="${ROOT_DIR}/.pids"

echo "[*] Stopping all Mini SOC services..."

# 1. Stop Docker containers if Docker is available
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "[*] Stopping Docker Compose services..."
    docker compose -f "${ROOT_DIR}/infrastructure/docker/compose.honeypots.yml" down 2>/dev/null || true
    docker compose -f "${ROOT_DIR}/infrastructure/docker/compose.wazuh.yml" down 2>/dev/null || true
    docker compose -f "${ROOT_DIR}/infrastructure/docker/compose.application.yml" down 2>/dev/null || true
fi

# 2. Stop native background processes
if [ -d "${PID_DIR}" ]; then
    for pidfile in "${PID_DIR}"/*.pid; do
        if [ -f "${pidfile}" ]; then
            PID=$(cat "${pidfile}")
            SERVICE_NAME=$(basename "${pidfile}" .pid)
            if kill -0 "${PID}" 2>/dev/null; then
                echo "[*] Stopping native service ${SERVICE_NAME} (PID: ${PID})..."
                kill "${PID}" 2>/dev/null || true
            fi
            rm -f "${pidfile}"
        fi
    done
fi

echo "[+] All services stopped cleanly."

