"""
IoT Simulation Fleet Engine
Orchestrates 10 simulated IoT devices, schedules periodic telemetry,
and executes controlled cyber attack scenarios.
"""

import asyncio
import datetime
import json
import os
import sys
import uuid
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from ..devices.device_models import DEVICE_CLASS_MAP, BaseIoTDevice
except (ImportError, ValueError):
    from devices.device_models import DEVICE_CLASS_MAP, BaseIoTDevice

CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../config/simulation_config.json")
)
DEFAULT_LOG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../infrastructure/docker/volumes/mosquitto/log/iot_telemetry.json")
)


class IoTSimulatorFleet:
    def __init__(self, config_path: str = CONFIG_FILE, log_file: str = DEFAULT_LOG_FILE):
        self.config_path = config_path
        self.log_file = log_file
        self.devices: Dict[str, BaseIoTDevice] = {}
        self.running = False
        self.load_config()
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def load_config(self):
        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        self.simulation_cfg = cfg.get("simulation", {})
        self.attack_scenarios = cfg.get("attack_scenarios", {})

        for dev_data in cfg.get("devices", []):
            dtype = dev_data.get("device_type")
            cls = DEVICE_CLASS_MAP.get(dtype)
            if cls:
                dev = cls(
                    device_id=dev_data["device_id"],
                    device_name=dev_data["device_name"],
                    device_type=dtype,
                    simulated_ip=dev_data["simulated_ip"],
                    mac_address=dev_data["mac_address"],
                    mqtt_topic=dev_data["mqtt_topic"],
                    firmware_version=dev_data["firmware_version"],
                    normal_interval_sec=dev_data["normal_interval_sec"],
                    metrics=dev_data.get("metrics", {})
                )
                self.devices[dev.device_id] = dev

    def emit_event(self, event: Dict[str, Any]):
        """Logs event to central IoT telemetry JSON file."""
        line = json.dumps(event) + "\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

    def generate_fleet_telemetry_snapshot(self) -> List[Dict[str, Any]]:
        """Generates one telemetry packet for each device in the fleet."""
        events = []
        for dev in self.devices.values():
            packet = dev.generate_normal_telemetry()
            self.emit_event(packet)
            events.append(packet)
        return events

    def trigger_burst_publish_flood(self, device_id: str = "iot-cam-01", count: int = 50) -> List[Dict[str, Any]]:
        """Controlled attack scenario: High-frequency telemetry burst simulating a compromised botnet device."""
        dev = self.devices.get(device_id)
        if not dev:
            return []

        dev.status = "COMPROMISED"
        dev.compromised = True
        events = []

        for i in range(count):
            pkt = dev.build_event_packet(
                {
                    "fps": 120,
                    "bitrate_kbps": 95000,
                    "flood_packet_seq": i + 1,
                    "ddos_target": "10.0.0.1:443",
                    "command_control": "irc://c2-botnet.darknet:6667"
                },
                is_suspicious=True,
                anomaly_type="BURST_PUBLISH_FLOOD"
            )
            self.emit_event(pkt)
            events.append(pkt)

        return events

    def trigger_unauthorized_topic_access(
        self,
        device_id: str = "iot-ctrl-01",
        topic: str = "iot/controller/hvac/admin/override",
        payload: str = '{"cmd": "DISABLE_SAFETY_SHUTDOWN", "force": true}'
    ) -> Dict[str, Any]:
        """Controlled attack scenario: Unauthorized actuator command execution."""
        dev = self.devices.get(device_id)
        if dev:
            dev.status = "WARNING"

        pkt = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "device_id": device_id,
            "simulated_ip": dev.simulated_ip if dev else "192.168.1.200",
            "topic": topic,
            "status": "UNAUTHORIZED_ACCESS",
            "is_suspicious": True,
            "anomaly_type": "UNAUTHORIZED_TOPIC_COMMAND",
            "payload": payload
        }
        self.emit_event(pkt)
        return pkt

    def trigger_telemetry_tampering(self, device_id: str = "iot-temp-01", key: str = "temperature_celsius", value: float = 99.9) -> Dict[str, Any]:
        """Controlled attack scenario: Sensor data spoofing exceeding safety bounds."""
        dev = self.devices.get(device_id)
        if not dev:
            return {}

        dev.status = "WARNING"
        data = dev.metrics.copy()
        data[key] = value
        data["tamper_flag"] = True

        pkt = dev.build_event_packet(data, is_suspicious=True, anomaly_type="TELEMETRY_OUT_OF_BOUNDS")
        self.emit_event(pkt)
        return pkt

    def get_all_devices_status(self) -> List[Dict[str, Any]]:
        return [dev.get_info() for dev in self.devices.values()]

    async def run_continuous_simulation(self, iterations: Optional[int] = None):
        """Runs periodic telemetry loop for all 10 devices."""
        self.running = True
        count = 0
        while self.running:
            self.generate_fleet_telemetry_snapshot()
            count += 1
            if iterations and count >= iterations:
                break
            await asyncio.sleep(self.simulation_cfg.get("tick_interval_seconds", 3.0))


if __name__ == "__main__":
    fleet = IoTSimulatorFleet()
    print(f"[*] Initialized IoT Simulator with {len(fleet.devices)} devices.")
    print("[*] Generating test fleet telemetry snapshot...")
    events = fleet.generate_fleet_telemetry_snapshot()
    print(f"[+] Successfully emitted {len(events)} telemetry events.")
    print("[*] Simulating controlled burst flood attack on iot-cam-01...")
    flood_events = fleet.trigger_burst_publish_flood(count=10)
    print(f"[+] Emitted {len(flood_events)} burst flood attack packets.")
