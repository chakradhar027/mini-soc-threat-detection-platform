"""
Concrete IoT Device Models for All 10 Simulated Devices
"""

import random
from typing import Any, Dict
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from .base_device import BaseIoTDevice
except ImportError:
    from base_device import BaseIoTDevice


class IPCameraDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        fps = random.randint(28, 30)
        bitrate = random.randint(1900, 2200)
        motion = random.random() < 0.05
        self.metrics.update({"fps": fps, "bitrate_kbps": bitrate, "motion_detected": motion})
        return self.build_event_packet({
            "fps": fps,
            "bitrate_kbps": bitrate,
            "motion_detected": motion,
            "stream_uri": f"rtsp://{self.simulated_ip}:554/live/ch0",
            "storage_remaining_gb": 124.5
        })


class SmartRouterDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        cpu = round(random.uniform(12.0, 28.0), 1)
        mem = round(random.uniform(32.0, 42.0), 1)
        clients = random.randint(12, 16)
        self.metrics.update({"cpu_usage_pct": cpu, "mem_usage_pct": mem, "active_clients": clients})
        return self.build_event_packet({
            "active_clients": clients,
            "cpu_usage_pct": cpu,
            "mem_usage_pct": mem,
            "wan_status": "connected",
            "wan_ip": "198.51.100.2",
            "bandwidth_rx_mbps": round(random.uniform(10.0, 45.0), 2),
            "bandwidth_tx_mbps": round(random.uniform(2.0, 15.0), 2)
        })


class TemperatureSensorDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        temp = round(random.uniform(20.8, 22.4), 2)
        humidity = round(random.uniform(43.0, 47.0), 1)
        self.metrics.update({"temperature_celsius": temp, "humidity_pct": humidity})
        return self.build_event_packet({
            "temperature_celsius": temp,
            "humidity_pct": humidity,
            "threshold_max_c": 28.0,
            "sensor_health": "OK",
            "battery_pct": 98
        })


class MotionSensorDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        motion = random.random() < 0.10
        lux = random.randint(140, 160)
        self.metrics.update({"motion_detected": motion, "light_lux": lux})
        return self.build_event_packet({
            "motion_detected": motion,
            "light_lux": lux,
            "zone": "Vault Corridor A",
            "tamper_switch": "SECURE"
        })


class SmartLightingDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        brightness = random.randint(70, 80)
        self.metrics.update({"brightness_pct": brightness})
        return self.build_event_packet({
            "power_state": "ON",
            "brightness_pct": brightness,
            "color_temp_k": 4000,
            "circuit_load_w": round(brightness * 1.2, 1)
        })


class MQTTGatewayDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        packets = self.metrics.get("packets_relayed", 1400) + random.randint(5, 15)
        self.metrics.update({"packets_relayed": packets})
        return self.build_event_packet({
            "bridged_nodes": 8,
            "packets_relayed": packets,
            "error_count": 0,
            "uptime_seconds": 864000
        })


class DoorSensorDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        is_opened = random.random() < 0.05
        state = "OPEN" if is_opened else "CLOSED"
        self.metrics.update({"door_state": state})
        return self.build_event_packet({
            "door_state": state,
            "badge_id_last": "BADGE-9941" if is_opened else None,
            "tamper_detected": False,
            "lock_status": "ENGAGED" if state == "CLOSED" else "UNLOCKED"
        })


class EnvironmentalSensorDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        co2 = random.randint(410, 435)
        aqi = random.randint(18, 25)
        pm25 = round(random.uniform(3.5, 5.0), 1)
        self.metrics.update({"co2_ppm": co2, "air_quality_index": aqi, "particulate_pm25": pm25})
        return self.build_event_packet({
            "air_quality_index": aqi,
            "co2_ppm": co2,
            "particulate_pm25": pm25,
            "filter_status": "CLEAN"
        })


class SmartEnergyMeterDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        voltage = round(random.uniform(229.5, 231.5), 1)
        current = round(random.uniform(15.8, 17.2), 2)
        power = round((voltage * current * 0.98) / 1000.0, 2)
        self.metrics.update({"voltage_v": voltage, "current_a": current, "active_power_kw": power})
        return self.build_event_packet({
            "voltage_v": voltage,
            "current_a": current,
            "active_power_kw": power,
            "power_factor": 0.98,
            "frequency_hz": 50.0
        })


class DeviceMonitoringControllerDevice(BaseIoTDevice):
    def generate_normal_telemetry(self) -> Dict[str, Any]:
        rpm = random.randint(1180, 1220)
        self.metrics.update({"fan_speed_rpm": rpm})
        return self.build_event_packet({
            "fan_speed_rpm": rpm,
            "chiller_stage": 2,
            "setpoint_celsius": 21.0,
            "alarm_active": False,
            "cop_efficiency": 3.85
        })


DEVICE_CLASS_MAP = {
    "IP Camera": IPCameraDevice,
    "Smart Router": SmartRouterDevice,
    "Temperature Sensor": TemperatureSensorDevice,
    "Motion Sensor": MotionSensorDevice,
    "Smart Lighting Controller": SmartLightingDevice,
    "MQTT Gateway": MQTTGatewayDevice,
    "Door Sensor": DoorSensorDevice,
    "Environmental Sensor": EnvironmentalSensorDevice,
    "Smart Energy Meter": SmartEnergyMeterDevice,
    "Device Monitoring Controller": DeviceMonitoringControllerDevice
}
