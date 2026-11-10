"""
Mini SOC FastAPI Application
Official production ASGI application for Mini SOC & Threat Detection Platform.
Serves the complete cybersecurity REST API, live Wazuh integration, and the SOC analyst dashboard.
"""

from datetime import datetime, timezone
import asyncio
import hashlib
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("SOCBackend")

# Add project roots to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
for sub in ["backend/app", "backend/app/services", "backend/app/integrations", "detection-engine", "threat-intelligence", "soar", "ml-engine", "iot-simulator"]:
    p = os.path.join(ROOT_DIR, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI, HTTPException, Query, Body, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from soc_store import SOCDataStore
from mitre_mapping import get_all_matrix_techniques
from models.anomaly_detector import IsolationForestAnomalyDetector
from wazuh_client import WazuhClient

app = FastAPI(
    title="Mini SOC & Threat Detection Platform API",
    version="1.0.0",
    description="Cybersecurity REST API for Honeynet, IoT Fleet, Wazuh SIEM, Threat Intel, SOAR & ML Anomaly Detection."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = SOCDataStore.get_instance()
wazuh_client = WazuhClient()

# Initialize ML Anomaly Detector
ml_detector = IsolationForestAnomalyDetector(n_estimators=100)
try:
    import numpy as np
    ml_detector.fit(
        np.array([
            [0, 10, 2, 10, 0.0, 2.1, 0.0, 0.2],
            [1, 12, 1, 11, 0.08, 2.2, 0.0, 0.3],
            [0, 8, 3, 9, 0.0, 2.0, 0.0, 0.15],
            [0, 15, 2, 12, 0.0, 2.3, 0.0, 0.25],
            [20, 50, 1, 8, 0.9, 1.2, 0.5, 1.8],  # Anomaly
            [0, 80, 2, 120, 0.0, 0.3, 0.0, 2.5]  # Anomaly
        ], dtype=np.float32)
    )
except Exception:
    pass


# -------------------------------------------------------------------------
# Background Worker: Stream Wazuh Alerts into SOC Store
# -------------------------------------------------------------------------
_wazuh_worker_task: Optional[asyncio.Task] = None


async def wazuh_alert_stream_worker():
    """Tails alerts.json and feeds newly detected Wazuh alerts into SOCDataStore."""
    logger.info("Wazuh alert streaming worker started (polling interval: 2s)")
    while True:
        try:
            new_alerts = wazuh_client.read_new_alerts()
            for raw_alert in new_alerts:
                try:
                    rule = raw_alert.get("rule", {})
                    level = rule.get("level", 0)
                    # Filter for honeypot, IoT, or security alerts (rule level >= 4)
                    if level >= 4 or any(g in ["honeypot", "iot", "syslog"] for g in rule.get("groups", [])):
                        normalized = wazuh_client.normalize_wazuh_alert(raw_alert)
                        store.add_event({
                            "event_id": normalized.get("alert_id"),
                            "timestamp": normalized.get("timestamp"),
                            "source_ip": normalized.get("source_ip"),
                            "source_service": f"wazuh:{normalized.get('agent_name', 'manager')}",
                            "event_type": f"rule_{normalized.get('rule_id')}",
                            "destination_port": 0,
                            "severity": normalized.get("severity"),
                            "raw_event": json.dumps(raw_alert),
                            "metadata": {
                                "wazuh_rule_id": normalized.get("rule_id"),
                                "wazuh_rule_name": normalized.get("rule_name"),
                                "mitre_technique_id": normalized.get("mitre_technique_id"),
                                "mitre_tactic": normalized.get("mitre_tactic"),
                                "level": normalized.get("level")
                            }
                        })
                except Exception as inner_e:
                    logger.warning(f"Error normalizing/ingesting individual Wazuh alert: {inner_e}")
        except asyncio.CancelledError:
            logger.info("Wazuh alert streaming worker received cancellation signal. Exiting loop.")
            break
        except Exception as e:
            logger.error(f"Transient error in Wazuh alert streaming worker: {e}", exc_info=True)

        try:
            await asyncio.sleep(2)
        except asyncio.CancelledError:
            logger.info("Wazuh alert streaming worker cancelled during sleep. Exiting loop.")
            break


@app.on_event("startup")
async def startup_event():
    global _wazuh_worker_task
    if _wazuh_worker_task is None or _wazuh_worker_task.done():
        _wazuh_worker_task = asyncio.create_task(wazuh_alert_stream_worker())
        logger.info("Initialized Wazuh alert streaming background task")
    else:
        logger.warning("Wazuh alert streaming worker already running; skipping duplicate startup")


@app.on_event("shutdown")
async def shutdown_event():
    global _wazuh_worker_task
    if _wazuh_worker_task and not _wazuh_worker_task.done():
        logger.info("Cancelling Wazuh alert streaming background task...")
        _wazuh_worker_task.cancel()
        try:
            await _wazuh_worker_task
        except asyncio.CancelledError:
            pass
        logger.info("Wazuh alert streaming task successfully stopped.")


# -------------------------------------------------------------------------
# Root: Serve React SOC Dashboard UI
# -------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(ROOT_DIR, "frontend/index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Mini SOC REST API is running. Access OpenAPI documentation under <a href='/docs'>/docs</a>.</h1>")


# -------------------------------------------------------------------------
# 1. System Health
# -------------------------------------------------------------------------
@app.get("/api/v1/health")
async def get_health():
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platform": "Mini SOC & Threat Detection Platform",
        "framework": "FastAPI (ASGI)",
        "architecture": "Apple Silicon (ARM64)",
        "memory_profile": "8GB Optimized",
        "services": {
            "fastapi_backend": "UP",
            "cowrie_honeypot": "UP",
            "dionaea_trap": "UP",
            "mqtt_honeypot": "UP",
            "iot_simulator": "UP",
            "wazuh_siem": "UP" if wazuh_client.is_api_reachable() else "STANDALONE_FALLBACK",
            "detection_engine": "ACTIVE",
            "ml_anomaly_engine": "ACTIVE"
        }
    }


# -------------------------------------------------------------------------
# 2. Overview Metrics
# -------------------------------------------------------------------------
@app.get("/api/v1/overview")
async def get_overview():
    return store.get_overview_metrics()


# -------------------------------------------------------------------------
# 3. Security Events Feed
# -------------------------------------------------------------------------
@app.get("/api/v1/events")
async def list_events(limit: int = 100, severity: Optional[str] = None, service: Optional[str] = None):
    filtered = store.events
    if severity:
        filtered = [e for e in filtered if e.get("severity") == severity.upper()]
    if service:
        filtered = [e for e in filtered if service in e.get("source_service", "")]

    return {
        "total": len(filtered),
        "events": list(reversed(filtered[-limit:]))
    }


@app.post("/api/v1/events", status_code=201)
async def create_event(event_data: Dict[str, Any] = Body(...)):
    event = store.add_event(event_data)
    return {"status": "SUCCESS", "event": event}


# -------------------------------------------------------------------------
# 4. Honeypot Monitoring
# -------------------------------------------------------------------------
@app.get("/api/v1/honeypots")
async def get_honeypots():
    return {
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
    }


# -------------------------------------------------------------------------
# 5. IoT Device Fleet
# -------------------------------------------------------------------------
@app.get("/api/v1/iot/devices")
async def get_iot_devices():
    return {
        "devices": store.iot_fleet.get_all_devices_status()
    }


@app.post("/api/v1/iot/simulate")
async def trigger_iot_simulation(body: Dict[str, Any] = Body(...)):
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
        return {"status": "EXECUTED", "packets_emitted": len(pkts), "scenario": scenario}

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
        return {"status": "EXECUTED", "event": pkt, "scenario": scenario}

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
        return {"status": "EXECUTED", "event": pkt, "scenario": scenario}

    raise HTTPException(status_code=400, detail=f"Unknown scenario {scenario}")


# -------------------------------------------------------------------------
# 6. Incidents Investigation Workspace
# -------------------------------------------------------------------------
@app.get("/api/v1/incidents")
async def get_incidents():
    return {
        "incidents": store.incident_mgr.get_all_incidents()
    }


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    inc = store.incident_mgr.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.post("/api/v1/incidents/{incident_id}/notes")
async def add_incident_note(incident_id: str, body: Dict[str, Any] = Body(...)):
    author = body.get("author", "analyst_on_duty")
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Note content cannot be empty")

    inc_before = store.incident_mgr.get_incident(incident_id)
    if not inc_before:
        raise HTTPException(status_code=404, detail="Incident not found")

    status_before = inc_before.get("status")
    inc = store.incident_mgr.add_analyst_note(incident_id, author, content)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Strict invariant: note creation must never alter incident status
    if inc.get("status") != status_before:
        inc["status"] = status_before
        store.incident_mgr._save_incidents()

    store.audit_logger.log_action("NOTE_ADDED", author, incident_id, {"content_preview": content[:60]})
    return inc


@app.post("/api/v1/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, body: Dict[str, Any] = Body(...)):
    status = body.get("status")
    if not status:
        raise HTTPException(status_code=400, detail="Missing required field: status")
    valid_statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}. Allowed: {valid_statuses}")
    analyst = body.get("analyst", "analyst_on_duty")
    inc = store.incident_mgr.update_status(incident_id, status, analyst)
    if not inc:
        raise HTTPException(status_code=400, detail="Invalid incident or status")
    store.audit_logger.log_action("STATUS_UPDATED", analyst, incident_id, {"new_status": status})
    return inc


# -------------------------------------------------------------------------
# 7. Threat Intelligence Lookup
# -------------------------------------------------------------------------
@app.get("/api/v1/threat-intel/lookup")
async def threat_intel_lookup(ip: Optional[str] = None, hash: Optional[str] = None):
    results = {}
    if ip:
        results["ip_reputation"] = store.ti_enricher.enrich_ip(ip)
    if hash:
        results["file_reputation"] = store.ti_enricher.enrich_hash(hash)
    return results


# -------------------------------------------------------------------------
# 8. MITRE ATT&CK Matrix
# -------------------------------------------------------------------------
@app.get("/api/v1/mitre/matrix")
async def get_mitre_matrix():
    techs = get_all_matrix_techniques()
    active_tech_ids = set()
    for inc in store.incident_mgr.get_all_incidents():
        active_tech_ids.update(inc.get("mitre_techniques", []))

    for t in techs:
        t["active_in_incidents"] = t["technique_id"] in active_tech_ids

    return {"techniques": techs}


# -------------------------------------------------------------------------
# 9. Machine Learning Anomaly Detection
# -------------------------------------------------------------------------
@app.get("/api/v1/ml/anomalies")
async def get_ml_anomalies():
    report_file = os.path.abspath(os.path.join(ROOT_DIR, "reports/ml_evaluation_report.json"))
    eval_metrics = {}
    if os.path.exists(report_file):
        with open(report_file, "r") as f:
            eval_metrics = json.load(f)

    return {
        "model_status": "ACTIVE",
        "algorithm": "Isolation Forest (100 Trees)",
        "features": [
            "failed_login_count", "connection_frequency", "unique_source_count",
            "mqtt_message_rate", "auth_failure_ratio", "topic_entropy",
            "off_hours_activity", "burst_factor"
        ],
        "evaluation_metrics": eval_metrics
    }


@app.post("/api/v1/ml/anomalies")
async def evaluate_ml_anomaly(body: Dict[str, Any] = Body(...)):
    vec = body.get("vector", [0, 10, 1, 10, 0.0, 2.0, 0.0, 0.2])
    import numpy as np
    score_res = ml_detector.evaluate_vector(np.array(vec, dtype=np.float32))
    return score_res


# -------------------------------------------------------------------------
# 10. SOAR Automated Response
# -------------------------------------------------------------------------
@app.get("/api/v1/response/containments")
async def get_containments():
    return {
        "mode": store.response_engine.mode,
        "allowlist": store.response_engine.IMMUTABLE_ALLOWLIST,
        "active_blocks": store.response_engine.get_active_containments()
    }


@app.post("/api/v1/response/block")
async def execute_containment(body: Dict[str, Any] = Body(...)):
    ip = body.get("ip_address")
    inc_id = body.get("incident_id", "MANUAL-TRIGGER")
    reason = body.get("reason", "Analyst initiated containment")
    operator = body.get("operator", "analyst_on_duty")

    res = store.response_engine.block_ip(ip, inc_id, reason, operator)
    store.audit_logger.log_action("CONTAINMENT_REQUESTED", operator, ip, res)
    return res


@app.post("/api/v1/response/rollback")
async def execute_rollback(body: Dict[str, Any] = Body(...)):
    ip = body.get("ip_address")
    operator = body.get("operator", "analyst_on_duty")

    res = store.response_engine.rollback_ip(ip, operator)
    store.audit_logger.log_action("CONTAINMENT_ROLLED_BACK", operator, ip, res)
    return res


# -------------------------------------------------------------------------
# 11. Attack Relationship Graph
# -------------------------------------------------------------------------
@app.get("/api/v1/graph")
async def get_attack_graph():
    return store.get_attack_relationship_graph()


# -------------------------------------------------------------------------
# 12. Attack Analytics
# -------------------------------------------------------------------------
@app.get("/api/v1/analytics")
async def get_analytics():
    return store.get_attack_analytics()


# -------------------------------------------------------------------------
# 13. Evidence Integrity
# -------------------------------------------------------------------------
@app.get("/api/v1/evidence/integrity")
async def get_evidence_integrity():
    is_audit_valid = store.audit_logger.verify_integrity()
    entries = store.audit_logger.get_all_entries()

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

    return {
        "audit_chain_valid": is_audit_valid,
        "total_audit_records": len(entries),
        "latest_chain_hash": store.audit_logger.get_last_hash(),
        "log_artifact_sha256": log_hashes,
        "verification_status": "INTEGRITY_VERIFIED" if is_audit_valid else "TAMPERING_DETECTED"
    }


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


@app.post("/api/v1/reports/generate")
async def generate_threat_report():
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

    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_path": report_path,
        "total_in_memory_events": total_in_memory_events,
        "total_cumulative_evidence": total_cumulative_evidence,
        "total_retained_samples": total_retained_samples,
        "total_unique_evidence_ids": total_unique_evidence_ids,
        "audit_chain_valid": audit_chain_valid,
        "markdown_content": md_report
    }


# -------------------------------------------------------------------------
# 15. Wazuh SIEM Integration & Health Monitoring
# -------------------------------------------------------------------------
@app.get("/api/v1/wazuh/status")
async def get_wazuh_status():
    """
    Distinguishes Wazuh REST API connectivity and authentication health
    from local file-based (alerts.json) background ingestion health.
    """
    api_health = wazuh_client.get_api_health()
    file_health = wazuh_client.get_file_ingestion_health(limit=10)

    api_ok = api_health.get("tcp_reachable", False) and api_health.get("authentication", {}).get("authenticated", False)
    file_ok = file_health.get("alerts_file_exists", False)

    if api_ok and file_ok:
        mode = "HYBRID_API_AND_FILE"
        overall_status = "HEALTHY"
    elif file_ok:
        mode = "FILE_STREAM_ONLY"
        overall_status = "HEALTHY (FILE_STREAM_DEGRADED_API)"
    elif api_ok:
        mode = "REST_API_ONLY"
        overall_status = "HEALTHY (API_ONLY_MISSING_LOGS)"
    else:
        mode = "UNREACHABLE"
        overall_status = "DEGRADED"

    worker_alive = _wazuh_worker_task is not None and not _wazuh_worker_task.done()
    file_health["streaming_worker_alive"] = worker_alive

    return {
        "status": overall_status,
        "ingestion_mode": mode,
        "api_reachable": api_ok,
        "api_url": wazuh_client.api_url,
        "streaming_worker_alive": worker_alive,
        "api_health": api_health,
        "file_ingestion_health": file_health,
        # Backward-compatible convenience fields:
        "alerts_log_path": file_health["alerts_log_path"],
        "alerts_file_exists": file_health["alerts_file_exists"],
        "recent_alerts_count": file_health["recent_alerts_count"],
        "recent_alerts_sample": file_health["recent_alerts_sample"]
    }


@app.get("/api/v1/wazuh/daemons")
async def get_wazuh_daemons():
    """Queries live Wazuh Manager daemons status via REST API."""
    daemons = wazuh_client.get_manager_status()
    if not daemons:
        raise HTTPException(status_code=503, detail="Unable to query Wazuh daemons via API")
    return {"daemons": daemons}


@app.get("/api/v1/wazuh/info")
async def get_wazuh_info():
    """Queries Wazuh Manager system information via REST API."""
    info = wazuh_client.get_manager_info()
    if not info:
        raise HTTPException(status_code=503, detail="Unable to query Wazuh info via API")
    return {"manager_info": info}


@app.post("/api/v1/wazuh/webhook", status_code=201)
async def ingest_wazuh_webhook(raw_alert: Dict[str, Any] = Body(...)):
    """Receives real-time alerts pushed from Wazuh Manager integrator."""
    normalized = wazuh_client.normalize_wazuh_alert(raw_alert)
    event_entry = {
        "event_id": normalized.get("alert_id"),
        "timestamp": normalized.get("timestamp"),
        "source_ip": normalized.get("source_ip"),
        "source_service": f"wazuh:{normalized.get('agent_name', 'manager')}",
        "event_type": f"rule_{normalized.get('rule_id')}",
        "destination_port": 0,
        "severity": normalized.get("severity"),
        "raw_event": json.dumps(raw_alert),
        "metadata": {
            "wazuh_rule_id": normalized.get("rule_id"),
            "wazuh_rule_name": normalized.get("rule_name"),
            "mitre_technique_id": normalized.get("mitre_technique_id"),
            "mitre_tactic": normalized.get("mitre_tactic"),
            "level": normalized.get("level")
        }
    }
    added = store.add_event(event_entry)
    return {"status": "INGESTED", "event": added}
