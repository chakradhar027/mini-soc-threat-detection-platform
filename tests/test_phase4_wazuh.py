"""
Phase 4 Acceptance Tests: Wazuh SIEM Integration
Validates decoder/rule XML syntax, alert ingestion, and normalization logic.
"""

import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

from backend.app.integrations.wazuh_client import WazuhClient


class Phase4WazuhTests(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.decoders_dir = os.path.join(self.root_dir, "infrastructure/wazuh/decoders")
        self.rules_dir = os.path.join(self.root_dir, "infrastructure/wazuh/rules")

    def test_honeypot_decoders_xml_syntax(self):
        path = os.path.join(self.decoders_dir, "honeypot_decoders.xml")
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # Wrap in a single dummy root tag to validate XML fragment
        xml_doc = f"<decoders>{content}</decoders>"
        root = ET.fromstring(xml_doc)
        decoders = root.findall("decoder")
        self.assertGreaterEqual(len(decoders), 4)

    def test_iot_decoders_xml_syntax(self):
        path = os.path.join(self.decoders_dir, "iot_decoders.xml")
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        xml_doc = f"<decoders>{content}</decoders>"
        root = ET.fromstring(xml_doc)
        decoders = root.findall("decoder")
        self.assertGreaterEqual(len(decoders), 2)

    def test_honeypot_rules_xml_syntax(self):
        path = os.path.join(self.rules_dir, "honeypot_rules.xml")
        self.assertTrue(os.path.exists(path))
        tree = ET.parse(path)
        root = tree.getroot()
        self.assertEqual(root.tag, "group")
        rules = root.findall("rule")
        rule_ids = [r.get("id") for r in rules]
        # Check presence of key honeypot rules
        self.assertIn("100101", rule_ids) # Cowrie login failed
        self.assertIn("100102", rule_ids) # Cowrie brute force
        self.assertIn("100105", rule_ids) # Cowrie payload download
        self.assertIn("100201", rule_ids) # Dionaea SMB probe
        self.assertIn("100301", rule_ids) # MQTT wildcard

    def test_iot_rules_xml_syntax(self):
        path = os.path.join(self.rules_dir, "iot_rules.xml")
        self.assertTrue(os.path.exists(path))
        tree = ET.parse(path)
        root = tree.getroot()
        self.assertEqual(root.tag, "group")
        rules = root.findall("rule")
        rule_ids = [r.get("id") for r in rules]
        self.assertIn("100401", rule_ids) # Burst flood
        self.assertIn("100402", rule_ids) # Unauthorized command
        self.assertIn("100403", rule_ids) # Out of bounds

    def test_wazuh_alert_normalization(self):
        raw_alert = {
            "timestamp": "2026-11-08T11:00:00.000+0000",
            "rule": {
                "level": 14,
                "description": "Cowrie: Malicious payload downloaded into honeypot.",
                "id": "100105",
                "mitre": {
                    "id": ["T1105"],
                    "tactic": ["Command and Control"]
                }
            },
            "agent": {"id": "000", "name": "wazuh-manager"},
            "data": {"src_ip": "198.51.100.89"},
            "full_log": "Downloaded payload binary"
        }

        client = WazuhClient()
        normalized = client.normalize_wazuh_alert(raw_alert)

        self.assertEqual(normalized["rule_id"], "100105")
        self.assertEqual(normalized["severity"], "CRITICAL")
        self.assertEqual(normalized["level"], 14)
        self.assertEqual(normalized["source_ip"], "198.51.100.89")
        self.assertEqual(normalized["mitre_technique_id"], "T1105")
        self.assertEqual(normalized["mitre_tactic"], "Command and Control")

    def test_wazuh_api_health_structure(self):
        client = WazuhClient()
        api_health = client.get_api_health()
        self.assertIn("api_url", api_health)
        self.assertIn("tcp_reachable", api_health)
        self.assertIn("tls_listener", api_health)
        self.assertIn("authentication", api_health)
        self.assertIn("daemons", api_health)

    def test_wazuh_file_ingestion_health_structure(self):
        client = WazuhClient()
        file_health = client.get_file_ingestion_health()
        self.assertIn("alerts_log_path", file_health)
        self.assertIn("alerts_file_exists", file_health)
        self.assertIn("file_size_bytes", file_health)
        self.assertIn("streaming_active", file_health)
        self.assertIn("recent_alerts_count", file_health)


if __name__ == "__main__":
    unittest.main()

