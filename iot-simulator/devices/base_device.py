"""
Base IoT Device Model
Abstract foundation for the 10 simulated IoT devices.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict


class BaseIoTDevice(ABC):
    def __init__(
        self,
        device_id: str,
        device_name: str,
        device_type: str,
        simulated_ip: str,
        mac_address: str,
        mqtt_topic: str,
        firmware_version: str,
        normal_interval_sec: int,
        metrics: Dict[str, Any]
    ):
        self.device_id = device_id
        self.device_name = device_name
        self.device_type = device_type
        self.simulated_ip = simulated_ip
        self.mac_address = mac_address
        self.mqtt_topic = mqtt_topic
        self.firmware_version = firmware_version
        self.normal_interval_sec = normal_interval_sec
        self.metrics = dict(metrics)
        self.status = "ONLINE"
        self.last_communication = datetime.now(timezone.utc)
        self.message_count = 0
        self.compromised = False

    @abstractmethod
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        """Generates a realistic normal telemetry payload for this device type."""
        pass

    def build_event_packet(self, data: Dict[str, Any], is_suspicious: bool = False, anomaly_type: str = None) -> Dict[str, Any]:
        self.last_communication = datetime.now(timezone.utc)
        self.message_count += 1
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": self.last_communication.isoformat().replace("+00:00", "Z"),
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "simulated_ip": self.simulated_ip,
            "mac_address": self.mac_address,
            "topic": self.mqtt_topic,
            "status": self.status,
            "firmware_version": self.firmware_version,
            "is_suspicious": is_suspicious,
            "anomaly_type": anomaly_type,
            "telemetry": data
        }

    def get_info(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "simulated_ip": self.simulated_ip,
            "mac_address": self.mac_address,
            "topic": self.mqtt_topic,
            "status": self.status,
            "firmware_version": self.firmware_version,
            "last_communication": self.last_communication.isoformat() if self.last_communication else None,
            "message_count": self.message_count,
            "compromised": self.compromised,
            "metrics": self.metrics
        }

