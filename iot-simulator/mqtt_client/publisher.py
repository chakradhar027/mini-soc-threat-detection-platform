"""
MQTT Telemetry Publisher for IoT Simulator
Transmits device telemetry and attack payloads over MQTT using paho-mqtt.
"""

import json
import logging
from typing import Any, Dict, Optional

try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False

logger = logging.getLogger("IoTMQTTPublisher")


class IoTMQTTPublisher:
    def __init__(self, broker_host: str = "127.0.0.1", broker_port: int = 1883):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.connected = False
        self.client: Optional[Any] = None

        if PAHO_AVAILABLE:
            try:
                # Support both paho-mqtt v1 and v2 API
                if hasattr(mqtt, "CallbackAPIVersion"):
                    self.client = mqtt.Client(
                        mqtt.CallbackAPIVersion.VERSION2,
                        client_id="iot_simulation_bridge"
                    )
                else:
                    self.client = mqtt.Client(client_id="iot_simulation_bridge")

                self.client.on_connect = self._on_connect
                self.client.on_disconnect = self._on_disconnect
            except Exception as e:
                logger.warning(f"MQTT client initialization warning: {e}")

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.connected = True
            logger.info(f"Connected to MQTT broker at {self.broker_host}:{self.broker_port}")
        else:
            self.connected = False
            logger.warning(f"MQTT connection refused with code {rc}")

    def _on_disconnect(self, client, userdata, rc, properties=None):
        self.connected = False
        logger.info("Disconnected from MQTT broker")

    def connect(self):
        if self.client:
            try:
                self.client.connect_async(self.broker_host, self.broker_port, 60)
                self.client.loop_start()
            except Exception as e:
                logger.warning(f"Could not connect to MQTT broker ({e}). Simulation will run in local logging mode.")

    def publish_event(self, topic: str, payload_dict: Dict[str, Any]) -> bool:
        payload_str = json.dumps(payload_dict)
        if self.connected and self.client:
            try:
                self.client.publish(topic, payload_str, qos=0)
                return True
            except Exception as e:
                logger.error(f"Publish failed: {e}")
        return False

    def disconnect(self):
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass

