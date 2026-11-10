"""
Phase 6 Acceptance Tests: Threat Intelligence, Incident Manager, SOAR Response & Audit Trail
"""

import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "threat-intelligence"))
sys.path.insert(0, os.path.join(ROOT_DIR, "soar"))

from abuseipdb.client import AbuseIPDBClient
from virustotal.client import VirusTotalClient
from enrichment import ThreatIntelligenceEnricher
from incident_manager import IncidentManager
from response_engine import ResponseEngine
from telegram_notifier import TelegramNotifier
from audit_logger import AuditLogger


class Phase6SOARTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_abuseipdb_private_ip_handling(self):
        client = AbuseIPDBClient()
        res_loopback = client.check_ip("127.0.0.1")
        self.assertFalse(res_loopback["is_public"])
        self.assertEqual(res_loopback["abuse_confidence_score"], 0)
        self.assertEqual(res_loopback["status"], "RFC1918_PRIVATE_IP")

        res_lan = client.check_ip("192.168.1.100")
        self.assertFalse(res_lan["is_public"])
        self.assertEqual(res_lan["status"], "RFC1918_PRIVATE_IP")

    def test_virustotal_offline_hash_lookup(self):
        client = VirusTotalClient()
        dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = client.check_file_hash(dummy_hash)
        self.assertEqual(res["hash"], dummy_hash)
        self.assertIn("malicious_count", res)

    def test_incident_lifecycle(self):
        inc_file = os.path.join(self.temp_dir.name, "incidents.json")
        mgr = IncidentManager(persistence_file=inc_file)

        inc = mgr.create_or_update_incident(
            title="Suspicious SSH Brute Force",
            description="5 failed attempts from 198.51.100.4",
            source_ip="198.51.100.4",
            severity="HIGH",
            risk_score=78.5,
            pattern="BRUTE_FORCE_SPRAY",
            mitre_techniques=["T1110"],
            evidence_events=[{"event_id": "1", "data": "attempt"}]
        )

        self.assertTrue(inc["incident_id"].startswith("INC-"))
        self.assertEqual(inc["status"], "OPEN")
        self.assertEqual(inc["severity"], "HIGH")

        # Add analyst note
        updated = mgr.add_analyst_note(inc["incident_id"], "analyst_alice", "Triaged and investigating source.")
        self.assertEqual(len(updated["analyst_notes"]), 1)
        self.assertEqual(updated["analyst_notes"][0]["author"], "analyst_alice")

        # Update status
        mgr.update_status(inc["incident_id"], "CONTAINED", "analyst_alice")
        final_inc = mgr.get_incident(inc["incident_id"])
        self.assertEqual(final_inc["status"], "CONTAINED")

    def test_note_submission_preserves_investigating_status(self):
        """Regression Test: Submitting a note to an INVESTIGATING incident leaves status strictly INVESTIGATING."""
        inc_file = os.path.join(self.temp_dir.name, "incidents_regression.json")
        mgr = IncidentManager(persistence_file=inc_file)

        inc = mgr.create_or_update_incident(
            title="Active Threat Investigation",
            description="Multi-stage attack requiring analyst triage",
            source_ip="203.0.113.99",
            severity="CRITICAL",
            risk_score=85.0,
            pattern="PAYLOAD_DROP",
            mitre_techniques=["T1105"],
            evidence_events=[{"event_id": "ev-1", "data": "c2_beacon"}]
        )
        inc_id = inc["incident_id"]

        # Transition status to INVESTIGATING
        mgr.update_status(inc_id, "INVESTIGATING", "analyst_lead")
        self.assertEqual(mgr.get_incident(inc_id)["status"], "INVESTIGATING")

        # Submit note
        updated = mgr.add_analyst_note(inc_id, "analyst_lead", "Analyzing malware sample hash.")

        # Verify status did not revert to OPEN or change to anything else
        self.assertEqual(updated["status"], "INVESTIGATING")
        persisted = mgr.get_incident(inc_id)
        self.assertEqual(persisted["status"], "INVESTIGATING")
        self.assertEqual(len(persisted["analyst_notes"]), 2)

    def test_response_engine_allowlist_protection(self):
        engine = ResponseEngine(mode="simulation")

        # Attempt to block localhost
        block_local = engine.block_ip("127.0.0.1", "INC-001", "Testing protection")
        self.assertEqual(block_local["status"], "REJECTED_ALLOWLIST_PROTECTION")

        # Attempt to block Docker management subnet gateway
        block_gw = engine.block_ip("172.28.10.1", "INC-001", "Testing protection")
        self.assertEqual(block_gw["status"], "REJECTED_ALLOWLIST_PROTECTION")

        # Valid simulated containment of external attacker IP
        attacker_ip = "198.51.100.99"
        block_ext = engine.block_ip(attacker_ip, "INC-002", "Brute force containment")
        self.assertEqual(block_ext["status"], "SIMULATED_CONTAINMENT")
        self.assertEqual(len(engine.get_active_containments()), 1)

        # Rollback
        rollback = engine.rollback_ip(attacker_ip)
        self.assertEqual(rollback["status"], "CONTAINMENT_REVOKED")
        self.assertEqual(len(engine.get_active_containments()), 0)

    def test_cryptographic_audit_logger_hash_chain(self):
        log_file = os.path.join(self.temp_dir.name, "audit_trail.json")
        audit = AuditLogger(log_path=log_file)

        audit.log_action("INCIDENT_CREATED", "SYSTEM", "INC-101", {"score": 80.0})
        audit.log_action("CONTAINMENT_APPLIED", "analyst_bob", "198.51.100.99", {"mode": "simulation"})
        audit.log_action("STATUS_CHANGED", "analyst_bob", "INC-101", {"new_status": "CONTAINED"})

        entries = audit.get_all_entries()
        self.assertEqual(len(entries), 3)

        # Verify unbroken hash chain
        self.assertTrue(audit.verify_integrity())

        # Tamper with an entry and verify integrity failure
        entries[1]["details"]["mode"] = "TAMPERED_MODE"
        audit.entries = entries
        self.assertFalse(audit.verify_integrity())


if __name__ == "__main__":
    unittest.main()

