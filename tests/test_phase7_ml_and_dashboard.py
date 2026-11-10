"""
Phase 7 Acceptance Tests: ML Anomaly Detection & Full-Stack Dashboard API
"""

import os
import sys
import tempfile
import unittest
import numpy as np

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, "ml-engine"))
sys.path.insert(0, os.path.join(ROOT_DIR, "backend/app"))
sys.path.insert(0, os.path.join(ROOT_DIR, "backend/app/services"))

from preprocessing.extractor import FeatureExtractor
from models.anomaly_detector import IsolationForestAnomalyDetector
from backend.app.server import app, store


class Phase7MLAndDashboardTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_feature_extractor_dimensions(self):
        events = [
            {"event_type": "login_failed", "source_ip": "1.2.3.4", "timestamp": "2026-11-08T10:00:00Z"},
            {"event_type": "login_failed", "source_ip": "1.2.3.4", "timestamp": "2026-11-08T10:00:05Z"},
            {"event_type": "telemetry", "source_ip": "1.2.3.4", "topic": "iot/test", "timestamp": "2026-11-08T10:00:10Z"}
        ]
        vec = FeatureExtractor.extract_window_features(events)
        self.assertEqual(len(vec), 8)
        self.assertEqual(vec[0], 2.0) # 2 failed logins
        self.assertGreater(vec[1], 0) # Connection frequency

    def test_isolation_forest_anomaly_scoring(self):
        detector = IsolationForestAnomalyDetector(n_estimators=50, random_state=42)

        # Baseline normal samples
        X_normal = np.random.normal(loc=0.0, scale=1.0, size=(100, 8))
        detector.fit(X_normal)

        # Normal test vector
        normal_vec = np.zeros(8, dtype=np.float32)
        res_normal = detector.evaluate_vector(normal_vec)
        self.assertIn("anomaly_score", res_normal)
        self.assertIn("is_anomaly", res_normal)

        # Severe outlier vector
        outlier_vec = np.ones(8, dtype=np.float32) * 50.0
        res_outlier = detector.evaluate_vector(outlier_vec)
        self.assertTrue(res_outlier["is_anomaly"])
        self.assertGreater(res_outlier["anomaly_score"], res_normal["anomaly_score"])

    def test_api_health_endpoint(self):
        resp = self.client.get("/api/v1/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertEqual(data["architecture"], "Apple Silicon (ARM64)")

    def test_api_overview_endpoint(self):
        resp = self.client.get("/api/v1/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total_interactions", data)
        self.assertIn("security_alerts", data)
        self.assertIn("unique_source_ips", data)

    def test_api_events_and_incidents(self):
        # Events feed
        resp_ev = self.client.get("/api/v1/events?limit=10")
        self.assertEqual(resp_ev.status_code, 200)
        ev_data = resp_ev.get_json()
        self.assertIn("events", ev_data)

        # Incidents workspace
        resp_inc = self.client.get("/api/v1/incidents")
        self.assertEqual(resp_inc.status_code, 200)
        inc_data = resp_inc.get_json()
        self.assertIn("incidents", inc_data)

    def test_api_attack_relationship_graph(self):
        resp_graph = self.client.get("/api/v1/graph")
        self.assertEqual(resp_graph.status_code, 200)
        graph_data = resp_graph.get_json()
        self.assertIn("nodes", graph_data)
        self.assertIn("links", graph_data)

    def test_dashboard_ui_html_served(self):
        resp_ui = self.client.get("/")
        self.assertEqual(resp_ui.status_code, 200)
        self.assertIn(b"Mini SOC & Threat Detection Platform", resp_ui.data)
        self.assertIn(b"Overview", resp_ui.data)
        self.assertIn(b"Incident Workspace", resp_ui.data)
        # Verify Incident Workspace card selection and state handlers
        self.assertIn(b"selectedIncidentId", resp_ui.data)
        self.assertIn(b"selectIncident", resp_ui.data)
        self.assertIn(b"submitNote", resp_ui.data)
        self.assertIn(b"updateIncidentStatus", resp_ui.data)

    def test_incident_workspace_selection_and_records(self):
        # Fetch all open incidents
        resp = self.client.get("/api/v1/incidents")
        self.assertEqual(resp.status_code, 200)
        incidents = resp.get_json().get("incidents", [])
        self.assertGreaterEqual(len(incidents), 3)

        # Verify each of the 3 incidents can be individually selected and queried
        for inc in incidents:
            inc_id = inc.get("incident_id")
            self.assertTrue(inc_id.startswith("INC-"))

            # Fetch individual incident detail
            detail_resp = self.client.get(f"/api/v1/incidents/{inc_id}")
            self.assertEqual(detail_resp.status_code, 200)
            detail = detail_resp.get_json()

            # Check required fields for the investigation panel
            self.assertEqual(detail["incident_id"], inc_id)
            self.assertTrue(len(detail["title"]) > 0)
            self.assertTrue(len(detail["source_ip"]) > 0)
            self.assertIn(detail["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            self.assertGreaterEqual(detail["risk_score"], 0)
            self.assertIsInstance(detail["mitre_techniques"], list)
            self.assertIsInstance(detail["evidence_events"], list)
            self.assertGreaterEqual(len(detail["evidence_events"]), 1)
            self.assertIn(detail["status"], ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"])

    def test_note_submission_endpoint_preserves_investigating_status(self):
        """API Regression Test: Submitting a note to an INVESTIGATING incident leaves status unchanged."""
        # Query incidents
        resp = self.client.get("/api/v1/incidents")
        self.assertEqual(resp.status_code, 200)
        incidents = resp.get_json().get("incidents", [])
        self.assertGreaterEqual(len(incidents), 1)
        inc_id = incidents[0]["incident_id"]

        # Explicitly transition status to INVESTIGATING
        status_resp = self.client.post(f"/api/v1/incidents/{inc_id}/status", json={"status": "INVESTIGATING", "analyst": "test_lead"})
        self.assertEqual(status_resp.status_code, 200)
        self.assertEqual(status_resp.get_json()["status"], "INVESTIGATING")

        # Submit note via POST /notes
        note_resp = self.client.post(
            f"/api/v1/incidents/{inc_id}/notes",
            json={"author": "analyst_lead", "content": "Regression verification: status must remain INVESTIGATING."}
        )
        self.assertEqual(note_resp.status_code, 200)
        self.assertEqual(note_resp.get_json()["status"], "INVESTIGATING")

        # Re-fetch incident to guarantee persisted status remains INVESTIGATING
        detail_after = self.client.get(f"/api/v1/incidents/{inc_id}").get_json()
        self.assertEqual(detail_after["status"], "INVESTIGATING")

    def test_forensic_report_event_count_consistency_and_live_status(self):
        """Regression Test: Forensic report distinguishes event populations and reflects live statuses."""
        # 1. Fetch current incidents and ensure diverse live statuses
        inc_resp = self.client.get("/api/v1/incidents")
        incidents = inc_resp.get_json().get("incidents", [])
        self.assertGreaterEqual(len(incidents), 2)

        # Explicitly set incident 0 to INVESTIGATING and incident 1 to CONTAINED
        id_0 = incidents[0]["incident_id"]
        id_1 = incidents[1]["incident_id"]
        self.client.post(f"/api/v1/incidents/{id_0}/status", json={"status": "INVESTIGATING", "analyst": "tester"})
        self.client.post(f"/api/v1/incidents/{id_1}/status", json={"status": "CONTAINED", "analyst": "tester"})

        # 2. Generate report
        rep_resp = self.client.post("/api/v1/reports/generate")
        self.assertEqual(rep_resp.status_code, 200)
        rep_data = rep_resp.get_json()
        self.assertIn("markdown_content", rep_data)
        md = rep_data["markdown_content"]

        # 3. Verify event count distinction & exact arithmetic consistency
        self.assertIn("Active In-Memory Event Window:", md)
        self.assertIn("Total Cumulative Incident Evidence Records:", md)
        self.assertIn("Total Retained Evidence Samples:", md)
        self.assertIn("Distinct Unique Evidence Event IDs:", md)

        # Calculate expected sums dynamically from fresh incident records
        fresh_incidents = self.client.get("/api/v1/incidents").get_json()["incidents"]
        expected_cumulative = sum(i.get("evidence_count", len(i.get("evidence_events", []))) for i in fresh_incidents)
        expected_retained = sum(len(i.get("evidence_events", [])) for i in fresh_incidents)
        unique_ids = {ev.get("event_id") for i in fresh_incidents for ev in i.get("evidence_events", []) if ev.get("event_id")}
        expected_unique = len(unique_ids)

        self.assertIn(f"Total Cumulative Incident Evidence Records:** {expected_cumulative} events", md)
        self.assertIn(f"Total Retained Evidence Samples:** {expected_retained} events", md)
        self.assertIn(f"Distinct Unique Evidence Event IDs:** {expected_unique} IDs", md)

        # Verify returned JSON payload matches exact calculations
        self.assertEqual(rep_data.get("total_cumulative_evidence"), expected_cumulative)
        self.assertEqual(rep_data.get("total_retained_samples"), expected_retained)
        self.assertEqual(rep_data.get("total_unique_evidence_ids"), expected_unique)

        # 4. Verify live status accuracy and per-incident metrics (not hardcoded to RESOLVED)
        self.assertIn(f"### Incident `{id_0}`", md)
        self.assertIn("Investigation Status:** `INVESTIGATING`", md)
        self.assertIn(f"### Incident `{id_1}`", md)
        self.assertIn("Investigation Status:** `CONTAINED`", md)
        self.assertIn("Unique Evidence Event IDs:", md)

        # 5. Verify cryptographic SHA-256 evidence integrity attestation
        self.assertIn("Cryptographic Audit Chain Status:** **VALID (UNBROKEN)**", md)
        self.assertIn("Latest Audit Block Hash:**", md)
        self.assertIn("Evidence Artifact SHA-256 Hashes", md)
        self.assertIn("cowrie.json", md)
        self.assertIn("incidents.json", md)
        self.assertIn("audit_trail.json", md)

    def test_live_telemetry_buffer_independence_and_metric_accuracy(self):
        """Regression Test: Active In-Memory Event Window is strictly calculated from the live buffer."""
        # 1. Baseline buffer size
        initial_buffer_len = len(store.events)
        overview_resp = self.client.get("/api/v1/overview").get_json()
        self.assertEqual(overview_resp["total_interactions"], initial_buffer_len)

        # 2. Add an isolated, benign live telemetry event to the buffer
        import uuid
        test_event = {
            "event_id": f"live-test-{uuid.uuid4().hex[:8]}",
            "timestamp": "2026-11-10T12:00:00Z",
            "source_ip": "192.168.1.250",
            "source_service": "iot_heartbeat",
            "event_type": "telemetry_ping",
            "destination_port": 1883,
            "severity": "LOW",
            "raw_event": "{}",
            "metadata": {"test": True}
        }
        store.add_event(test_event)

        # 3. Buffer length must increase by exactly 1
        self.assertEqual(len(store.events), initial_buffer_len + 1)
        updated_overview = self.client.get("/api/v1/overview").get_json()
        self.assertEqual(updated_overview["total_interactions"], initial_buffer_len + 1)

        # 4. Generate report and verify Active In-Memory Event Window reflects live buffer
        rep_resp = self.client.post("/api/v1/reports/generate")
        self.assertEqual(rep_resp.status_code, 200)
        rep_data = rep_resp.get_json()
        self.assertEqual(rep_data["total_in_memory_events"], len(store.events))
        self.assertIn(f"Active In-Memory Event Window:** {len(store.events)} events", rep_data["markdown_content"])

    def test_audit_hash_chain_preservation_and_genesis_verification(self):
        """Regression Test: Audit chain preserves full historical records from genesis block to latest."""
        entries = store.audit_logger.get_all_entries()
        self.assertGreaterEqual(len(entries), 50, "Historical audit records must be preserved")

        # Verify Genesis record
        genesis = entries[0]
        self.assertEqual(genesis["prev_hash"], "GENESIS_BLOCK_0000000000000000")
        self.assertTrue(genesis["entry_hash"])

        # Cryptographic step-by-step verification from genesis to latest
        import hashlib, json
        expected_prev = "GENESIS_BLOCK_0000000000000000"
        for idx, entry in enumerate(entries):
            self.assertEqual(
                entry.get("prev_hash"),
                expected_prev,
                f"Hash link break at index {idx}: expected prev_hash {expected_prev}"
            )
            payload = f"{entry['entry_id']}:{entry['timestamp']}:{entry['action_type']}:{entry['operator']}:{entry['target']}:{entry['prev_hash']}:{json.dumps(entry['details'], sort_keys=True)}"
            computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            self.assertEqual(
                computed_hash,
                entry.get("entry_hash"),
                f"Cryptographic digest mismatch at index {idx}"
            )
            expected_prev = entry.get("entry_hash")

        # Verify master AuditLogger verification
        self.assertTrue(store.audit_logger.verify_integrity())


if __name__ == "__main__":
    unittest.main()

