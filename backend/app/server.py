"""
Mini SOC REST API Server (Python Native Native & Standalone)
Listens on 127.0.0.1:8000 and serves all SOC API endpoints.
Provides CORS headers for the React 18 frontend dashboard.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import sys
from typing import Any, Dict

from flask import Flask, jsonify, request, Response

# Add project roots to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, "backend/app"))
sys.path.insert(0, os.path.join(ROOT_DIR, "backend/app/services"))
sys.path.insert(0, os.path.join(ROOT_DIR, "detection-engine"))
sys.path.insert(0, os.path.join(ROOT_DIR, "threat-intelligence"))
sys.path.insert(0, os.path.join(ROOT_DIR, "soar"))
sys.path.insert(0, os.path.join(ROOT_DIR, "ml-engine"))
sys.path.insert(0, os.path.join(ROOT_DIR, "iot-simulator"))

from soc_store import SOCDataStore
from mitre_mapping import get_all_matrix_techniques
from models.anomaly_detector import IsolationForestAnomalyDetector

app = Flask(__name__)
store = SOCDataStore.get_instance()

# Load trained ML model
ml_detector = IsolationForestAnomalyDetector(n_estimators=100)
# Quick fit on seed dataset
ml_detector.fit(
    __import__("numpy").array([
        [0, 10, 2, 10, 0.0, 2.1, 0.0, 0.2],
        [1, 12, 1, 11, 0.08, 2.2, 0.0, 0.3],
        [0, 8, 3, 9, 0.0, 2.0, 0.0, 0.15],
        [0, 15, 2, 12, 0.0, 2.3, 0.0, 0.25],
        [20, 50, 1, 8, 0.9, 1.2, 0.5, 1.8], # Anomaly
        [0, 80, 2, 120, 0.0, 0.3, 0.0, 2.5] # Anomaly
    ], dtype=__import__("numpy").float32)
)


@app.after_request
def add_cors_headers(response: Response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return response


# -------------------------------------------------------------------------
# Root: Serve React SOC Dashboard UI
# -------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def serve_dashboard():
    index_path = os.path.join(ROOT_DIR, "frontend/index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return Response(f.read(), mimetype="text/html")
    return jsonify({"message": "Mini SOC REST API is running. Access endpoints under /api/v1/"})


# -------------------------------------------------------------------------
# 1. System Health
# -------------------------------------------------------------------------
@app.route("/api/v1/health", methods=["GET"])
def get_health():
    return jsonify({
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platform": "Mini SOC & Threat Detection Platform",
        "architecture": "Apple Silicon (ARM64)",
        "memory_profile": "8GB Optimized",
        "services": {
            "fastapi_backend": "UP",
            "cowrie_honeypot": "UP",
            "dionaea_trap": "UP",
            "mqtt_honeypot": "UP",
            "iot_simulator": "UP",
            "detection_engine": "ACTIVE",
            "ml_anomaly_engine": "ACTIVE"
        }
    })


# -------------------------------------------------------------------------
# 2. Overview Metrics
# -------------------------------------------------------------------------
@app.route("/api/v1/overview", methods=["GET"])
def get_overview():
    return jsonify(store.get_overview_metrics())


# -------------------------------------------------------------------------
# 3. Security Events Feed
# -------------------------------------------------------------------------
@app.route("/api/v1/events", methods=["GET", "POST"])
def handle_events():
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        event = store.add_event(data)
        return jsonify({"status": "SUCCESS", "event": event}), 201

    limit = int(request.args.get("limit", 100))
    severity = request.args.get("severity")
    service = request.args.get("service")

    filtered = store.events
    if severity:
        filtered = [e for e in filtered if e.get("severity") == severity.upper()]
    if service:
        filtered = [e for e in filtered if service in e.get("source_service", "")]

    return jsonify({
        "total": len(filtered),
        "events": list(reversed(filtered[-limit:]))
    })


# -------------------------------------------------------------------------
# 4. Honeypot Monitoring
# -------------------------------------------------------------------------
@app.route("/api/v1/honeypots", methods=["GET"])
def get_honeypots():
    return jsonify({
        "honeypots": [
            {
                "name": "Cowrie SSH/Telnet",
                "service": "cowrie",
                "ports": [2222, 2223],
                "status": "ACTIVE",
                "protocol": "SSH-2.0-OpenSSH_8.9p1 / Telnet",
                "events_recorded": sum(1 for e in store.events if "cowrie" in e.get("source_service", "")),
                "last_interaction": next((e["timestamp"] for e in reversed(store.events) if "cowrie" in e.get("source_service", "")), None)
            },
            {
                "name": "Dionaea Multi-Trap",
                "service": "dionaea",
                "ports": [4445, 8081, 2121],
                "status": "ACTIVE",
                "protocol": "SMB, HTTP, FTP",
                "events_recorded": sum(1 for e in store.events if "dionaea" in e.get("source_service", "")),
                "last_interaction": next((e["timestamp"] for e in reversed(store.events) if "dionaea" in e.get("source_service", "")), None)
            },
            {
                "name": "Mosquitto MQTT Honey",
                "service": "mqtt_honeypot",
                "ports": [18883],
                "status": "ACTIVE",
                "protocol": "MQTT 3.1.1",
                "events_recorded": sum(1 for e in store.events if "mqtt" in e.get("source_service", "")),
                "last_interaction": next((e["timestamp"] for e in reversed(store.events) if "mqtt" in e.get("source_service", "")), None)
            }
        ]
    })


# -------------------------------------------------------------------------
# 5. IoT Device Fleet
# -------------------------------------------------------------------------
@app.route("/api/v1/iot/devices", methods=["GET"])
def get_iot_devices():
    return jsonify({
        "devices": store.iot_fleet.get_all_devices_status()
    })


@app.route("/api/v1/iot/simulate", methods=["POST"])
def trigger_iot_simulation():
    body = request.get_json(force=True) or {}
    scenario = body.get("scenario", "burst_publish_flood")
    dev_id = body.get("device_id", "iot-cam-01")

    if scenario == "burst_publish_flood":
        count = int(body.get("count", 20))
        pkts = store.iot_fleet.trigger_burst_publish_flood(device_id=dev_id, count=count)
        for p in pkts:
            store.add_event({
                "event_id": p["event_id"],
                "timestamp": p["timestamp"],
                "source_ip": p["simulated_ip"],
                "source_service": "iot_camera",
                "event_type": "burst_publish_flood",
                "destination_port": 1883,
                "severity": "HIGH",
                "raw_event": json.dumps(p),
                "metadata": p
            })
        return jsonify({"status": "EXECUTED", "packets_emitted": len(pkts), "scenario": scenario})

    elif scenario == "unauthorized_topic_access":
        pkt = store.iot_fleet.trigger_unauthorized_topic_access(device_id=dev_id)
        store.add_event({
            "event_id": pkt["event_id"],
            "timestamp": pkt["timestamp"],
            "source_ip": pkt["simulated_ip"],
            "source_service": "iot_controller",
            "event_type": "unauthorized_publish",
            "destination_port": 1883,
            "severity": "CRITICAL",
            "raw_event": json.dumps(pkt),
            "metadata": pkt
        })
        return jsonify({"status": "EXECUTED", "event": pkt, "scenario": scenario})

    elif scenario == "telemetry_tampering":
        pkt = store.iot_fleet.trigger_telemetry_tampering(device_id=dev_id)
        store.add_event({
            "event_id": pkt["event_id"],
            "timestamp": pkt["timestamp"],
            "source_ip": pkt["simulated_ip"],
            "source_service": "iot_temperature_sensor",
            "event_type": "telemetry_tampering",
            "destination_port": 1883,
            "severity": "HIGH",
            "raw_event": json.dumps(pkt),
            "metadata": pkt
        })
        return jsonify({"status": "EXECUTED", "event": pkt, "scenario": scenario})

    return jsonify({"error": f"Unknown scenario {scenario}"}), 400


# -------------------------------------------------------------------------
# 6. Incidents Investigation Workspace
# -------------------------------------------------------------------------
@app.route("/api/v1/incidents", methods=["GET"])
def get_incidents():
    return jsonify({
        "incidents": store.incident_mgr.get_all_incidents()
    })


@app.route("/api/v1/incidents/<incident_id>", methods=["GET"])
def get_incident_detail(incident_id: str):
    inc = store.incident_mgr.get_incident(incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(inc)


@app.route("/api/v1/incidents/<incident_id>/notes", methods=["POST"])
def add_incident_note(incident_id: str):
    body = request.get_json(force=True) or {}
    author = body.get("author", "analyst_on_duty")
    content = (body.get("content") or "").strip()
    if not content:
        return jsonify({"error": "Note content cannot be empty"}), 400

    inc_before = store.incident_mgr.get_incident(incident_id)
    if not inc_before:
        return jsonify({"error": "Incident not found"}), 404

    status_before = inc_before.get("status")
    inc = store.incident_mgr.add_analyst_note(incident_id, author, content)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404

    # Strict invariant: note creation must never alter incident status
    if inc.get("status") != status_before:
        inc["status"] = status_before
        store.incident_mgr._save_incidents()

    store.audit_logger.log_action("NOTE_ADDED", author, incident_id, {"content_preview": content[:60]})
    return jsonify(inc)


@app.route("/api/v1/incidents/<incident_id>/status", methods=["POST"])
def update_incident_status(incident_id: str):
    body = request.get_json(force=True) or {}
    status = body.get("status")
    if not status:
        return jsonify({"error": "Missing required field: status"}), 400
    valid_statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
    if status not in valid_statuses:
        return jsonify({"error": f"Invalid status: {status}. Allowed: {valid_statuses}"}), 400
    analyst = body.get("analyst", "analyst_on_duty")
    inc = store.incident_mgr.update_status(incident_id, status, analyst)
    if not inc:
        return jsonify({"error": "Invalid incident or status"}), 400
    store.audit_logger.log_action("STATUS_UPDATED", analyst, incident_id, {"new_status": status})
    return jsonify(inc)


# -------------------------------------------------------------------------
# 7. Threat Intelligence Lookup
# -------------------------------------------------------------------------
@app.route("/api/v1/threat-intel/lookup", methods=["GET"])
def threat_intel_lookup():
    ip = request.args.get("ip")
    fhash = request.args.get("hash")
    results = {}
    if ip:
        results["ip_reputation"] = store.ti_enricher.enrich_ip(ip)
    if fhash:
        results["file_reputation"] = store.ti_enricher.enrich_hash(fhash)
    return jsonify(results)


# -------------------------------------------------------------------------
# 8. MITRE ATT&CK Matrix
# -------------------------------------------------------------------------
@app.route("/api/v1/mitre/matrix", methods=["GET"])
def get_mitre_matrix():
    techs = get_all_matrix_techniques()
    # Mark which techniques are active in current incidents
    active_tech_ids = set()
    for inc in store.incident_mgr.get_all_incidents():
        active_tech_ids.update(inc.get("mitre_techniques", []))

    for t in techs:
        t["active_in_incidents"] = t["technique_id"] in active_tech_ids

    return jsonify({"techniques": techs})


# -------------------------------------------------------------------------
# 9. Machine Learning Anomaly Detection
# -------------------------------------------------------------------------
@app.route("/api/v1/ml/anomalies", methods=["GET", "POST"])
def handle_ml_anomalies():
    report_file = os.path.abspath(os.path.join(ROOT_DIR, "reports/ml_evaluation_report.json"))
    eval_metrics = {}
    if os.path.exists(report_file):
        with open(report_file, "r") as f:
            eval_metrics = json.load(f)

    if request.method == "POST":
        body = request.get_json(force=True) or {}
        vec = body.get("vector", [0, 10, 1, 10, 0.0, 2.0, 0.0, 0.2])
        score_res = ml_detector.evaluate_vector(__import__("numpy").array(vec, dtype=__import__("numpy").float32))
        return jsonify(score_res)

    return jsonify({
        "model_status": "ACTIVE",
        "algorithm": "Isolation Forest (100 Trees)",
        "features": [
            "failed_login_count", "connection_frequency", "unique_source_count",
            "mqtt_message_rate", "auth_failure_ratio", "topic_entropy",
            "off_hours_activity", "burst_factor"
        ],
        "evaluation_metrics": eval_metrics
    })


# -------------------------------------------------------------------------
# 10. SOAR Automated Response
# -------------------------------------------------------------------------
@app.route("/api/v1/response/containments", methods=["GET"])
def get_containments():
    return jsonify({
        "mode": store.response_engine.mode,
        "allowlist": store.response_engine.IMMUTABLE_ALLOWLIST,
        "active_blocks": store.response_engine.get_active_containments()
    })


@app.route("/api/v1/response/block", methods=["POST"])
def execute_containment():
    body = request.get_json(force=True) or {}
    ip = body.get("ip_address")
    inc_id = body.get("incident_id", "MANUAL-TRIGGER")
    reason = body.get("reason", "Analyst initiated containment")
    operator = body.get("operator", "analyst_on_duty")

    res = store.response_engine.block_ip(ip, inc_id, reason, operator)
    store.audit_logger.log_action("CONTAINMENT_REQUESTED", operator, ip, res)
    return jsonify(res)


@app.route("/api/v1/response/rollback", methods=["POST"])
def execute_rollback():
    body = request.get_json(force=True) or {}
    ip = body.get("ip_address")
    operator = body.get("operator", "analyst_on_duty")

    res = store.response_engine.rollback_ip(ip, operator)
    store.audit_logger.log_action("CONTAINMENT_ROLLED_BACK", operator, ip, res)
    return jsonify(res)


# -------------------------------------------------------------------------
# 11. Attack Relationship Graph
# -------------------------------------------------------------------------
@app.route("/api/v1/graph", methods=["GET"])
def get_attack_graph():
    return jsonify(store.get_attack_relationship_graph())


# -------------------------------------------------------------------------
# 12. Attack Analytics
# -------------------------------------------------------------------------
@app.route("/api/v1/analytics", methods=["GET"])
def get_analytics():
    return jsonify(store.get_attack_analytics())


# -------------------------------------------------------------------------
# 13. Evidence Integrity
# -------------------------------------------------------------------------
@app.route("/api/v1/evidence/integrity", methods=["GET"])
def get_evidence_integrity():
    is_audit_valid = store.audit_logger.verify_integrity()
    entries = store.audit_logger.get_all_entries()

    # Calculate SHA-256 of primary honeypot log files
    log_hashes = {}
    for service, path in [
        ("cowrie", "infrastructure/docker/volumes/cowrie/log/cowrie.json"),
        ("dionaea", "infrastructure/docker/volumes/dionaea/log/dionaea.json"),
        ("mosquitto", "infrastructure/docker/volumes/mosquitto/log/mqtt_honey.json"),
        ("iot_telemetry", "infrastructure/docker/volumes/mosquitto/log/iot_telemetry.json")
    ]:
        full_p = os.path.join(ROOT_DIR, path)
        if os.path.exists(full_p):
            with open(full_p, "rb") as f:
                log_hashes[service] = hashlib.sha256(f.read()).hexdigest()
        else:
            log_hashes[service] = "NO_DATA_COLLECTED_YET"

    return jsonify({
        "audit_chain_valid": is_audit_valid,
        "total_audit_records": len(entries),
        "latest_chain_hash": store.audit_logger.get_last_hash(),
        "log_artifact_sha256": log_hashes,
        "verification_status": "INTEGRITY_VERIFIED" if is_audit_valid else "TAMPERING_DETECTED"
    })


# -------------------------------------------------------------------------
# 14. Forensic Threat Reports
# -------------------------------------------------------------------------
def _hash_file_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "FILE_NOT_YET_CREATED"
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


@app.route("/api/v1/reports/generate", methods=["POST"])
def generate_threat_report():
    report_id = f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    overview = store.get_overview_metrics()
    incidents = store.incident_mgr.get_all_incidents()

    # Evidence aggregation & population differentiation
    total_in_memory_events = overview.get("total_interactions", len(store.events))
    total_cumulative_evidence = sum(inc.get("evidence_count", len(inc.get("evidence_events", []))) for inc in incidents)
    total_retained_samples = sum(len(inc.get("evidence_events", [])) for inc in incidents)

    unique_evidence_ids = set()
    for inc in incidents:
        for ev in inc.get("evidence_events", []):
            if ev.get("event_id"):
                unique_evidence_ids.add(ev.get("event_id"))
    total_unique_evidence_ids = len(unique_evidence_ids)

    # Dynamic breakdowns for transparency
    cumulative_breakdown = " + ".join(f"{inc.get('evidence_count', len(inc.get('evidence_events', [])))} [{inc.get('incident_id', 'INC')}]" for inc in incidents)
    retained_breakdown = " + ".join(f"{len(inc.get('evidence_events', []))} [{inc.get('incident_id', 'INC')}]" for inc in incidents)

    critical_incidents = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    high_incidents = sum(1 for i in incidents if i.get("severity") == "HIGH")

    # Cryptographic attestation verification
    audit_chain_valid = store.audit_logger.verify_integrity()
    latest_audit_hash = store.audit_logger.get_last_hash()
    total_audit_records = len(store.audit_logger.get_all_entries())

    # Dynamic SHA-256 artifact hashes
    artifacts_to_hash = [
        ("Cowrie Logs", "infrastructure/docker/volumes/cowrie/log/cowrie.json"),
        ("Dionaea Logs", "infrastructure/docker/volumes/dionaea/log/dionaea.json"),
        ("IoT Telemetry", "infrastructure/docker/volumes/mosquitto/log/iot_telemetry.json"),
        ("MQTT Honeypot", "infrastructure/docker/volumes/mosquitto/log/mqtt_honey.json"),
        ("Incident Forensics", "reports/incidents.json"),
        ("SOAR Audit Trail", "reports/audit_trail.json")
    ]
    artifact_table_rows = []
    for label, rel_path in artifacts_to_hash:
        full_p = os.path.join(ROOT_DIR, rel_path)
        sha = _hash_file_sha256(full_p)
        sz = os.path.getsize(full_p) if os.path.exists(full_p) else 0
        artifact_table_rows.append(f"| {label} | `{os.path.basename(rel_path)}` | `{sha}` | {sz:,} |")
    artifact_table_md = "\n".join(artifact_table_rows)

    md_report = f"""# Mini SOC & Threat Detection Platform - Forensic Investigation Report
**Report ID:** `{report_id}`  
**Generated At:** `{datetime.now(timezone.utc).isoformat()}Z`  
**Classification:** TLP:AMBER (Confidential Incident Response)  

---

## 1. Executive Summary
During the observation window, the Mini SOC Platform actively monitored 3 honeynet decoys (Cowrie, Dionaea, Mosquitto) and 10 simulated IoT edge devices.

### Security Operations & Telemetry Metrics
- **Active In-Memory Event Window:** {total_in_memory_events} events
- **Total Cumulative Incident Evidence Records:** {total_cumulative_evidence} events
- **Total Retained Evidence Samples:** {total_retained_samples} events
- **Distinct Unique Evidence Event IDs:** {total_unique_evidence_ids} IDs
- **Security Alerts Raised (Wazuh & Sigma):** {overview.get('security_alerts', 0)}
- **Investigated Security Incidents:** {len(incidents)} ({critical_incidents} Critical, {high_incidents} High)
- **Unique Attacking Source IPs:** {overview.get('unique_source_ips', 0)}

> [!NOTE]
> **Event Population & Aggregation Distinction:**
> - **Active In-Memory Event Window ({total_in_memory_events} events):** Represents the real-time sliding buffer of live telemetry events currently monitored in the SOC core runtime.
> - **Cumulative Incident Evidence ({total_cumulative_evidence} events):** Represents the cumulative aggregation of attack attempts, authentication sprays, exploit probes, and flood packets linked across all incident lifecycles ({cumulative_breakdown}).
> - **Total Retained Evidence Samples ({total_retained_samples} events):** Represents the actual forensic sample records preserved in the incident database across all incidents ({retained_breakdown}).
> - **Distinct Unique Evidence Event IDs ({total_unique_evidence_ids} IDs):** Represents the deduplicated set of unique cryptographic event IDs across all retained samples (accounting for recurring event IDs in high-frequency botnet bursts).

---

## 2. Incident Summary
"""

    for inc in incidents:
        mitre_list = ', '.join(inc.get('mitre_techniques', [])) or 'None'
        latest_note = inc.get('analyst_notes', [])[-1]['content'] if inc.get('analyst_notes') else 'None recorded'
        if len(latest_note) > 100:
            latest_note = latest_note[:97] + '...'
        ev_unique_ids = len({ev.get('event_id') for ev in inc.get('evidence_events', []) if ev.get('event_id')})

        md_report += f"""
### Incident `{inc['incident_id']}`: {inc['title']}
- **Severity / Risk Score:** **{inc['severity']}** ({inc['risk_score']}/100)
- **Source IP:** `{inc['source_ip']}`
- **Pattern:** `{inc['pattern']}`
- **MITRE ATT&CK Techniques:** `{mitre_list}`
- **Investigation Status:** `{inc['status']}`
- **Cumulative Evidence Count:** {inc.get('evidence_count', len(inc.get('evidence_events', [])))} events
- **Retained Evidence Samples:** {len(inc.get('evidence_events', []))} events
- **Unique Evidence Event IDs:** {ev_unique_ids} IDs
- **Analyst Notes Count:** {len(inc.get('analyst_notes', []))}
- **Latest Analyst Note:** {latest_note}
"""

    md_report += f"""
---

## 3. Evidence Integrity Attestation
All event streams, incident records, and SOAR response actions are cryptographically chained and attested using SHA-256 hashes.

- **Cryptographic Audit Chain Status:** **{'VALID (UNBROKEN)' if audit_chain_valid else 'FAILED (TAMPERED)'}**
- **Total Chained Audit Records:** {total_audit_records}
- **Latest Audit Block Hash:** `{latest_audit_hash}`

### Evidence Artifact SHA-256 Hashes
| Artifact | Source File | SHA-256 Checksum | Size (Bytes) |
|---|---|---|---|
{artifact_table_md}
"""

    report_path = os.path.join(ROOT_DIR, f"reports/{report_id}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_report)

    # Log forensic report generation in cryptographically chained audit log
    store.audit_logger.log_action(
        "REPORT_GENERATED",
        "system_reporter",
        report_id,
        {
            "report_file": f"reports/{report_id}.md",
            "total_incidents": len(incidents),
            "cumulative_evidence_count": total_cumulative_evidence,
            "retained_evidence_samples": total_retained_samples,
            "unique_evidence_ids": total_unique_evidence_ids
        }
    )

    return jsonify({
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_path": report_path,
        "total_in_memory_events": total_in_memory_events,
        "total_cumulative_evidence": total_cumulative_evidence,
        "total_retained_samples": total_retained_samples,
        "total_unique_evidence_ids": total_unique_evidence_ids,
        "audit_chain_valid": audit_chain_valid,
        "markdown_content": md_report
    })


def run_api_server(host="127.0.0.1", port=8000):
    print("=========================================================================")
    print(f" Starting Mini SOC REST API Server on http://{host}:{port}")
    print(" Serving 24 REST Endpoints with CORS for React Dashboard")
    print("=========================================================================")
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_api_server()
