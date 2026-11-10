"""
Common Security Event Schema for Mini SOC & Threat Detection Platform
Normalizes raw telemetry from Cowrie, Dionaea, Mosquitto, and IoT simulators into a unified schema.
Supports both Pydantic v2 and standard Python dataclass/BaseModel fallback.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import json

try:
    from pydantic import BaseModel, Field

    class SeverityLevel(str, Enum):
        LOW = "LOW"
        MEDIUM = "MEDIUM"
        HIGH = "HIGH"
        CRITICAL = "CRITICAL"

    class SecurityEvent(BaseModel):
        event_id: str = Field(..., description="Unique event identifier (UUID)")
        timestamp: datetime = Field(..., description="ISO-8601 UTC timestamp of occurrence")
        source_ip: str = Field(..., description="Source IPv4/IPv6 address of the actor")
        source_service: str = Field(..., description="Reporting service (e.g. cowrie, dionaea, mqtt_honey, iot_sensor)")
        event_type: str = Field(..., description="Specific event action (e.g. login_failed, command_input, smb_probe)")
        username: Optional[str] = Field(None, description="Targeted or attempted username")
        destination_port: int = Field(..., description="Destination service port on the host/honeypot")
        severity: SeverityLevel = Field(default=SeverityLevel.LOW, description="Normalized event severity")
        raw_event: str = Field(..., description="Original unparsed log entry or JSON string")
        metadata: Dict[str, Any] = Field(default_factory=dict, description="Extensible context (hashes, MITRE, session, etc.)")

        def to_dict(self) -> Dict[str, Any]:
            data = self.model_dump()
            data["timestamp"] = self.timestamp.isoformat()
            data["severity"] = self.severity.value
            return data

except ImportError:
    # Graceful fallback when pydantic is not yet installed in local env
    class SeverityLevel(str, Enum):
        LOW = "LOW"
        MEDIUM = "MEDIUM"
        HIGH = "HIGH"
        CRITICAL = "CRITICAL"

    class SecurityEvent:
        def __init__(
            self,
            event_id: str,
            timestamp: datetime,
            source_ip: str,
            source_service: str,
            event_type: str,
            destination_port: int,
            severity: SeverityLevel = SeverityLevel.LOW,
            username: Optional[str] = None,
            raw_event: str = "",
            metadata: Optional[Dict[str, Any]] = None
        ):
            self.event_id = event_id
            self.timestamp = timestamp
            self.source_ip = source_ip
            self.source_service = source_service
            self.event_type = event_type
            self.destination_port = destination_port
            self.severity = severity if isinstance(severity, SeverityLevel) else SeverityLevel(severity)
            self.username = username
            self.raw_event = raw_event
            self.metadata = metadata or {}

        def to_dict(self) -> Dict[str, Any]:
            return {
                "event_id": self.event_id,
                "timestamp": self.timestamp.isoformat() if hasattr(self.timestamp, "isoformat") else str(self.timestamp),
                "source_ip": self.source_ip,
                "source_service": self.source_service,
                "event_type": self.event_type,
                "username": self.username,
                "destination_port": self.destination_port,
                "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
                "raw_event": self.raw_event,
                "metadata": self.metadata
            }
