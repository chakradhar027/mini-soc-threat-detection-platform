"""
Phase 2 Acceptance Tests: Honeypots & Event Normalization
Verifies that Cowrie, Dionaea, and MQTT Honeypot events are correctly formatted,
written to disk, and normalized into the unified SecurityEvent schema.
"""

import json
import os
import tempfile
import unittest

from backend.app.schemas.event import SecurityEvent, SeverityLevel
from backend.app.services.log_normalizer import LogNormalizer


class Phase2HoneypotTests(unittest.TestCase):
    def test_cowrie_normalization(self):
        raw_cowrie = {
            "eventid": "cowrie.login.failed",
            "src_ip": "198.51.100.23",
            "src_port": 45123,
            "dst_port": 2222,
            "session": "a1b2c3d4",
            "username": "root",
            "password": "Password123!",
            "message": "login attempt [root/Password123!] failed",
            "timestamp": "2026-11-08T10:00:00.000000Z"
        }

        event = LogNormalizer.normalize_cowrie(raw_cowrie)
        self.assertIsNotNone(event)
        self.assertIsInstance(event, SecurityEvent)
        self.assertEqual(event.source_ip, "198.51.100.23")
        self.assertEqual(event.source_service, "cowrie")
        self.assertEqual(event.event_type, "login_failed")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.severity, SeverityLevel.MEDIUM)
        self.assertEqual(event.metadata.get("password"), "Password123!")

    def test_cowrie_command_and_payload_download(self):
        raw_download = {
            "eventid": "cowrie.session.file_download",
            "src_ip": "198.51.100.45",
            "src_port": 50123,
            "dst_port": 2222,
            "session": "f9e8d7c6",
            "url": "http://malicious.ru/dropper.sh",
            "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "message": "Downloaded URL to downloads",
            "timestamp": "2026-11-08T10:05:00.000000Z"
        }

        event = LogNormalizer.normalize_cowrie(raw_download)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "payload_download")
        self.assertEqual(event.severity, SeverityLevel.CRITICAL)
        self.assertEqual(event.metadata.get("shasum"), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_dionaea_smb_payload_capture(self):
        raw_dionaea = {
            "service": "smb",
            "connection_id": "smb999",
            "src_ip": "203.0.113.88",
            "src_port": 49152,
            "dst_port": 4445,
            "event_type": "payload_capture",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "payload_size": 1024,
            "severity": "CRITICAL",
            "message": "Captured binary payload",
            "timestamp": "2026-11-08T10:10:00.000000Z"
        }

        event = LogNormalizer.normalize_dionaea(raw_dionaea)
        self.assertIsNotNone(event)
        self.assertEqual(event.source_service, "dionaea_smb")
        self.assertEqual(event.severity, SeverityLevel.CRITICAL)
        self.assertEqual(event.metadata.get("sha256"), "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a")

    def test_mqtt_honeypot_wildcard_subscribe(self):
        raw_mqtt = {
            "event_type": "wildcard_subscription",
            "session_id": "mqtt001",
            "client_id": "scanner_bot_1",
            "src_ip": "192.0.2.105",
            "src_port": 38192,
            "dst_port": 18883,
            "topics": ["#", "iot/+/control"],
            "severity": "HIGH",
            "message": "Wildcard subscription",
            "timestamp": "2026-11-08T10:15:00.000000Z"
        }

        event = LogNormalizer.normalize_mqtt_honey(raw_mqtt)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "wildcard_subscription")
        self.assertEqual(event.severity, SeverityLevel.HIGH)
        self.assertIn("#", event.metadata.get("topics"))

    def test_honeypot_log_emission_integrity(self):
        from honeypots.cowrie.service import emit_event as emit_cowrie
        from honeypots.dionaea.service import emit_event as emit_dionaea
        from honeypots.mqtt.service import emit_event as emit_mqtt

        with tempfile.TemporaryDirectory() as tmpdir:
            cowrie_path = os.path.join(tmpdir, "cowrie.json")
            dionaea_path = os.path.join(tmpdir, "dionaea.json")
            mqtt_path = os.path.join(tmpdir, "mqtt.json")

            import honeypots.cowrie.service as cs
            import honeypots.dionaea.service as ds
            import honeypots.mqtt.service as ms

            cs.LOG_FILE = cowrie_path
            ds.LOG_FILE = dionaea_path
            ms.LOG_FILE = mqtt_path

            emit_cowrie({"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", "message": "Test connect"})
            emit_dionaea({"service": "http", "event_type": "exploit_probe", "src_ip": "2.3.4.5", "message": "Test HTTP"})
            emit_mqtt({"event_type": "mqtt_connect", "client_id": "test_dev", "src_ip": "3.4.5.6", "message": "Test MQTT"})

            self.assertTrue(os.path.exists(cowrie_path))
            self.assertTrue(os.path.exists(dionaea_path))
            self.assertTrue(os.path.exists(mqtt_path))

            with open(cowrie_path) as f:
                line = json.loads(f.readline())
                self.assertEqual(line["eventid"], "cowrie.session.connect")
                self.assertIn("timestamp", line)

            with open(dionaea_path) as f:
                line = json.loads(f.readline())
                self.assertEqual(line["service"], "http")
                self.assertIn("timestamp", line)

            with open(mqtt_path) as f:
                line = json.loads(f.readline())
                self.assertEqual(line["event_type"], "mqtt_connect")
                self.assertIn("timestamp", line)


if __name__ == "__main__":
    unittest.main()
