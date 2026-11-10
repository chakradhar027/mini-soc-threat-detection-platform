#!/bin/bash
# =========================================================================
# START SOC APPLICATION & DASHBOARD (Dual-Mode: Docker or Native Standalone)
# =========================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PID_DIR="${ROOT_DIR}/.pids"
mkdir -p "${PID_DIR}"

# Source environment configuration if present
if [ -f "${ROOT_DIR}/.env" ]; then
    set -a
    source "${ROOT_DIR}/.env"
    set +a
fi

echo "========================================================================="
echo " Starting Mini SOC Application Core & Dashboard"
echo "========================================================================="

# Stop existing backend process if running
if [ -f "${PID_DIR}/backend.pid" ]; then
    OLD_PID=$(cat "${PID_DIR}/backend.pid" 2>/dev/null || true)
    if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
        echo "[*] Stopping previous backend instance (PID ${OLD_PID})..."
        kill "${OLD_PID}" 2>/dev/null || true
        sleep 1
    fi
fi

# Fallback: check if port 8000 is still bound and clear it
OCCUPIED_PID=$(lsof -ti :8000 2>/dev/null || true)
if [ -n "${OCCUPIED_PID}" ]; then
    echo "[*] Releasing port 8000 (killing stale PID ${OCCUPIED_PID})..."
    kill -9 ${OCCUPIED_PID} 2>/dev/null || true
    sleep 1
fi

PYTHON_BIN="python3"
UVICORN_BIN="${ROOT_DIR}/.venv/bin/uvicorn"
if [ -f "${ROOT_DIR}/.venv/bin/python3" ]; then
    PYTHON_BIN="${ROOT_DIR}/.venv/bin/python3"
fi

echo "[*] Launching Mini SOC Backend Server on 127.0.0.1:8000..."
if [ -x "${UVICORN_BIN}" ]; then
    echo "[*] Using FastAPI / Uvicorn ASGI Server..."
    nohup "${UVICORN_BIN}" backend.app.main:app --host 127.0.0.1 --port 8000 > "${ROOT_DIR}/reports/backend_stdout.log" 2>&1 &
    echo $! > "${PID_DIR}/backend.pid"
else
    echo "[*] Using Python REST Server..."
    nohup "${PYTHON_BIN}" "${ROOT_DIR}/backend/app/server.py" > "${ROOT_DIR}/reports/backend_stdout.log" 2>&1 &
    echo $! > "${PID_DIR}/backend.pid"
fi

sleep 1
echo "[+] Mini SOC Dashboard is LIVE at http://127.0.0.1:8000"
