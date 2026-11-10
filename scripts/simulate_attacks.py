#!/usr/bin/env python3
"""
End-to-End Cyberattack Simulation Script
Simulates realistic multi-vector attacks against Cowrie, Dionaea, Mosquitto, and the IoT Fleet.
Triggers detection, correlation, threat intelligence enrichment, and SOAR response.
"""

from datetime import datetime, timezone
import json
import os
import sys
import time

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, "backend/app/services"))

from soc_store import SOCDataStore


def append_log(file_rel_path: str, data: dict):
    """Appends raw event to host volume file monitored by Wazuh logcollector."""
    full_path = os.path.join(ROOT_DIR, file_rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")


def run_full_simulation():
    store = SOCDataStore.get_instance()
    print("=========================================================================")
    print(" STARTING END-TO-END MINI SOC CYBERATTACK SIMULATION")
    print("=========================================================================")

    # ---------------------------------------------------------------------
    # SCENARIO 1: SSH Brute-Force Spray (Cowrie)
    # ---------------------------------------------------------------------
    attacker_1 = "198.51.100.44"
    print(f"\n[*] Executing Scenario 1: SSH Brute-Force Spray from {attacker_1}...")
    for user, pwd in [("root", "123456"), ("root", "toor"), ("admin", "admin"), ("service", "service"), ("operator", "password")]:
        raw_evt = {
            "eventid": "cowrie.login.failed",
            "src_ip": attacker_1,
            "username": user,
            "password": pwd,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }
        evt = {
            "event_id": f"sim-ssh-{time.time_ns()}",
            "timestamp": raw_evt["timestamp"],
            "source_ip": attacker_1,
            "source_service": "cowrie",
            "event_type": "login_failed",
            "username": user,
            "destination_port": 2222,
            "severity": "MEDIUM",
            "raw_event": json.dumps(raw_evt),
            "metadata": {"username": user, "password": pwd, "protocol": "ssh"}
        }
        store.add_event(evt)
        append_log("infrastructure/docker/volumes/cowrie/log/cowrie.json", raw_evt)
        print(f"    [-] Login attempt failed: {user}:{pwd}")
        time.sleep(0.05)
    print("[+] Scenario 1 Complete: 5 failed logins emitted.")

    # ---------------------------------------------------------------------
    # SCENARIO 2: Honeypot Breach & Payload Dropper Download (Cowrie)
    # ---------------------------------------------------------------------
    attacker_2 = "203.0.113.99"
    print(f"\n[*] Executing Scenario 2: Decoy Breach & Payload Download from {attacker_2}...")
    breach_evt = {
        "eventid": "cowrie.login.success",
        "src_ip": attacker_2,
        "username": "root",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    store.add_event({
        "event_id": f"sim-breach-login-{time.time_ns()}",
        "timestamp": breach_evt["timestamp"],
        "source_ip": attacker_2,
        "source_service": "cowrie",
        "event_type": "login_success",
        "username": "root",
        "destination_port": 2222,
        "severity": "HIGH",
        "raw_event": json.dumps(breach_evt),
        "metadata": {"username": "root", "protocol": "ssh"}
    })
    append_log("infrastructure/docker/volumes/cowrie/log/cowrie.json", breach_evt)
    print(f"    [!] Unauthorized login SUCCESS on decoy account root from {attacker_2}")

    dl_evt = {
        "eventid": "cowrie.session.file_download",
        "src_ip": attacker_2,
        "url": "http://c2-beacon.ru/agent.sh",
        "shasum": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    store.add_event({
        "event_id": f"sim-breach-dl-{time.time_ns()}",
        "timestamp": dl_evt["timestamp"],
        "source_ip": attacker_2,
        "source_service": "cowrie",
        "event_type": "payload_download",
        "destination_port": 2222,
        "severity": "CRITICAL",
        "raw_event": json.dumps(dl_evt),
        "metadata": dl_evt
    })
    append_log("infrastructure/docker/volumes/cowrie/log/cowrie.json", dl_evt)
    print("    [!] Malicious payload downloaded: http://c2-beacon.ru/agent.sh")
    print("[+] Scenario 2 Complete: Critical killchain breach generated.")

    # ---------------------------------------------------------------------
    # SCENARIO 3: SMB Exploit Probe (Dionaea)
    # ---------------------------------------------------------------------
    attacker_3 = "192.0.2.188"
    print(f"\n[*] Executing Scenario 3: Dionaea SMB Exploit Probe from {attacker_3}...")
    dionaea_evt = {
        "service": "smb",
        "event_type": "smb_probe",
        "src_ip": attacker_3,
        "cve": "CVE-2017-0144",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    store.add_event({
        "event_id": f"sim-dionaea-{time.time_ns()}",
        "timestamp": dionaea_evt["timestamp"],
        "source_ip": attacker_3,
        "source_service": "dionaea_smb",
        "event_type": "smb_probe",
        "destination_port": 4445,
        "severity": "HIGH",
        "raw_event": json.dumps(dionaea_evt),
        "metadata": dionaea_evt
    })
    append_log("infrastructure/docker/volumes/dionaea/log/dionaea.json", dionaea_evt)
    print("[+] Scenario 3 Complete: SMB probe captured.")

    # ---------------------------------------------------------------------
    # SCENARIO 4: MQTT Wildcard Topic Sniffing (Mosquitto Honey)
    # ---------------------------------------------------------------------
    attacker_4 = "198.51.100.155"
    print(f"\n[*] Executing Scenario 4: MQTT Wildcard Subscription (#) from {attacker_4}...")
    mqtt_evt = {
        "event_type": "wildcard_subscription",
        "source_service": "mqtt_honeypot",
        "src_ip": attacker_4,
        "topics": ["#"],
        "client_id": "shodan_scanner",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    store.add_event({
        "event_id": f"sim-mqtt-sub-{time.time_ns()}",
        "timestamp": mqtt_evt["timestamp"],
        "source_ip": attacker_4,
        "source_service": "mqtt_honeypot",
        "event_type": "wildcard_subscription",
        "destination_port": 18883,
        "severity": "HIGH",
        "raw_event": json.dumps(mqtt_evt),
        "metadata": mqtt_evt
    })
    append_log("infrastructure/docker/volumes/mosquitto/log/mqtt_honey.json", mqtt_evt)
    print("[+] Scenario 4 Complete: Rogue wildcard subscription recorded.")

    # ---------------------------------------------------------------------
    # SCENARIO 5: IoT Camera Botnet DDoS Flood
    # ---------------------------------------------------------------------
    print("\n[*] Executing Scenario 5: IoT Camera Botnet DDoS Burst Flood...")
    flood_pkts = store.iot_fleet.trigger_burst_publish_flood(device_id="iot-cam-01", count=15)
    for p in flood_pkts:
        store.add_event({
            "event_id": p["event_id"],
            "timestamp": p["timestamp"],
            "source_ip": p["simulated_ip"],
            "device_id": "iot-cam-01",
            "source_service": "iot_camera",
            "event_type": "burst_publish_flood",
            "destination_port": 1883,
            "severity": "HIGH",
            "is_suspicious": True,
            "raw_event": json.dumps(p),
            "metadata": p
        })
        append_log("infrastructure/docker/volumes/mosquitto/log/iot_telemetry.json", p)
    print(f"[+] Scenario 5 Complete: {len(flood_pkts)} burst packets emitted.")

    # ---------------------------------------------------------------------
    # Summary of Generated Telemetry
    # ---------------------------------------------------------------------
    metrics = store.get_overview_metrics()
    incidents = store.incident_mgr.get_all_incidents()

    print("\n=========================================================================")
    print(" SIMULATION COMPLETE - SOC PIPELINE RESULTS")
    print("=========================================================================")
    print(f"[*] Total Security Events: {metrics['total_interactions']}")
    print(f"[*] Security Alerts Raised: {metrics['security_alerts']}")
    print(f"[*] Correlated Incidents:  {len(incidents)}")
    print(f"[*] Unique Attacking IPs:  {metrics['unique_source_ips']}")
    print("-------------------------------------------------------------------------")
    for inc in incidents:
        print(f"[INCIDENT] {inc['incident_id']} | Severity: {inc['severity']} ({inc['risk_score']}/100) | {inc['title']}")
    print("=========================================================================")


if __name__ == "__main__":
    run_full_simulation()

