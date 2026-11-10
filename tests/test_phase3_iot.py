"""
Phase 3 Acceptance Tests: IoT Device Fleet Simulation
Verifies all 10 IoT devices, telemetry generation, and controlled attack scenarios.
"""

import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IOT_DIR = os.path.join(ROOT_DIR, "iot-simulator")
sys.path.insert(0, IOT_DIR)

from devices.device_models import (
    IPCameraDevice,
    SmartRouterDevice,
    TemperatureSensorDevice,
    MotionSensorDevice,
    SmartLightingDevice,
    MQTTGatewayDevice,
    DoorSensorDevice,
    EnvironmentalSensorDevice,
    SmartEnergyMeterDevice,
    DeviceMonitoringControllerDevice,
    DEVICE_CLASS_MAP
)
from event_generator.simulator import IoTSimulatorFleet


class Phase3IoTTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.temp_dir.name, "iot_telemetry.json")
        self.fleet = IoTSimulatorFleet(log_file=self.log_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_all_ten_devices_instantiated(self):
        expected_types = [
            "IP Camera",
            "Smart Router",
            "Temperature Sensor",
            "Motion Sensor",
            "Smart Lighting Controller",
            "MQTT Gateway",
            "Door Sensor",
            "Environmental Sensor",
            "Smart Energy Meter",
            "Device Monitoring Controller"
        ]
        self.assertEqual(len(self.fleet.devices), 10)
        fleet_types = [dev.device_type for dev in self.fleet.devices.values()]
        for expected in expected_types:
            self.assertIn(expected, fleet_types)

    def test_normal_telemetry_generation(self):
        events = self.fleet.generate_fleet_telemetry_snapshot()
        self.assertEqual(len(events), 10)

        for event in events:
            self.assertIn("event_id", event)
            self.assertIn("timestamp", event)
            self.assertIn("device_id", event)
            self.assertIn("device_type", event)
            self.assertIn("simulated_ip", event)
            self.assertIn("topic", event)
            self.assertIn("telemetry", event)
            self.assertEqual(event["status"], "ONLINE")
            self.assertFalse(event["is_suspicious"])
            self.assertTrue(event["timestamp"].endswith("Z"))

    def test_burst_publish_flood_scenario(self):
        flood = self.fleet.trigger_burst_publish_flood(device_id="iot-cam-01", count=25)
        self.assertEqual(len(flood), 25)

        cam = self.fleet.devices["iot-cam-01"]
        self.assertEqual(cam.status, "COMPROMISED")
        self.assertTrue(cam.compromised)

        first_pkt = flood[0]
        self.assertTrue(first_pkt["is_suspicious"])
        self.assertEqual(first_pkt["anomaly_type"], "BURST_PUBLISH_FLOOD")
        self.assertEqual(first_pkt["telemetry"]["fps"], 120)

    def test_unauthorized_topic_access_scenario(self):
        alert = self.fleet.trigger_unauthorized_topic_access(
            device_id="iot-ctrl-01",
            topic="iot/controller/hvac/admin/override",
            payload='{"cmd": "DISABLE_SAFETY_SHUTDOWN"}'
        )
        self.assertTrue(alert["is_suspicious"])
        self.assertEqual(alert["anomaly_type"], "UNAUTHORIZED_TOPIC_COMMAND")
        self.assertIn("DISABLE_SAFETY_SHUTDOWN", alert["payload"])

    def test_telemetry_tampering_scenario(self):
        alert = self.fleet.trigger_telemetry_tampering(
            device_id="iot-temp-01",
            key="temperature_celsius",
            value=99.9
        )
        self.assertTrue(alert["is_suspicious"])
        self.assertEqual(alert["anomaly_type"], "TELEMETRY_OUT_OF_BOUNDS")
        self.assertEqual(alert["telemetry"]["temperature_celsius"], 99.9)

    def test_get_all_devices_status(self):
        statuses = self.fleet.get_all_devices_status()
        self.assertEqual(len(statuses), 10)
        for s in statuses:
            self.assertIn("device_id", s)
            self.assertIn("status", s)
            self.assertIn("metrics", s)


if __name__ == "__main__":
    unittest.main()
