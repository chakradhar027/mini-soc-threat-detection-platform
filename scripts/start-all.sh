#!/bin/bash
# =========================================================================
# START ALL MINI SOC PLATFORM MODULES (Staged & Memory Budgeted)
# =========================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "========================================================================="
echo " Starting Complete Mini SOC Platform (Honeypots, IoT, Backend, UI)"
echo "========================================================================="

# 1. Start Honeypots
"${SCRIPT_DIR}/start-honeypots.sh"
sleep 2

# 2. Start Application Core & Dashboard
"${SCRIPT_DIR}/start-app.sh"
sleep 2

echo ""
echo "========================================================================="
echo " [SUCCESS] MINI SOC & THREAT DETECTION PLATFORM IS OPERATIONAL"
echo " Access the SOC Analyst Dashboard at: http://127.0.0.1:8000"
echo "========================================================================="

