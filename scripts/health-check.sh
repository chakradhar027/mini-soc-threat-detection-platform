#!/bin/bash
# =========================================================================
# MINI SOC HEALTH & SERVICE CHECK
# =========================================================================
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "========================================================================="
echo " Mini SOC & Threat Detection Platform - Health Status"
echo "========================================================================="

check_port() {
    local name="$1"
    local port="$2"
    if nc -z -w 2 127.0.0.1 "${port}" 2>/dev/null; then
        echo -e "[PASS] ${name} is LISTENING on port ${port}"
    else
        echo -e "[DOWN] ${name} is NOT reachable on port ${port}"
    fi
}

echo "--- Honeynet Services ---"
check_port "Cowrie SSH" 2222
check_port "Cowrie Telnet" 2223
check_port "Dionaea SMB" 4445
check_port "Dionaea HTTP" 8081
check_port "Dionaea FTP" 2121
check_port "Mosquitto Honeypot" 18883

echo ""
echo "--- Application & Core Services ---"
check_port "IoT MQTT Broker" 1883
check_port "PostgreSQL DB" 5432
check_port "FastAPI Backend" 8000
check_port "React SOC Dashboard" 3000
check_port "Grafana Analytics" 3001

echo ""
echo "--- Wazuh SIEM Services ---"
check_port "Wazuh Indexer (OpenSearch)" 9200
check_port "Wazuh Manager API" 55000
check_port "Wazuh Dashboard" 8443

echo "========================================================================="

