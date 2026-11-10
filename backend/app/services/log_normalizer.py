"""
Log Normalization Engine
Converts heterogeneous log entries from Cowrie, Dionaea, and MQTT Honeypots
into the standardized SecurityEvent model.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional
from backend.app.schemas.event import SecurityEvent, SeverityLevel


class LogNormalizer:
    @staticmethod
    def normalize_cowrie(entry: dict) -> Optional[SecurityEvent]:
        eventid = entry.get("eventid", "")
        if not eventid:
            return None

        # Determine normalized event_type & severity
        if eventid == "cowrie.login.failed":
            event_type = "login_failed"
            severity = SeverityLevel.MEDIUM
        elif eventid == "cowrie.login.success":
            event_type = "login_success"
            severity = SeverityLevel.HIGH
        elif eventid == "cowrie.command.input":
            event_type = "command_input"
            severity = SeverityLevel.HIGH
        elif eventid == "cowrie.session.file_download":
            event_type = "payload_download"
            severity = SeverityLevel.CRITICAL
        elif eventid == "cowrie.session.connect":
            event_type = "connection_opened"
            severity = SeverityLevel.LOW
        elif eventid == "cowrie.session.closed":
            event_type = "connection_closed"
            severity = SeverityLevel.LOW
        else:
            event_type = eventid.replace("cowrie.", "")
            severity = SeverityLevel.LOW

        ts_str = entry.get("timestamp")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        metadata = {
            "session": entry.get("session"),
            "protocol": entry.get("protocol", "ssh"),
            "system": entry.get("system", "cowrie"),
            "input": entry.get("input"),
            "url": entry.get("url"),
            "shasum": entry.get("shasum"),
            "password": entry.get("password")
        }
        # Clean null values
        metadata = {k: v for k, v in metadata.items() if v is not None}

        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_ip=entry.get("src_ip", "0.0.0.0"),
            source_service="cowrie",
            event_type=event_type,
            username=entry.get("username"),
            destination_port=entry.get("dst_port", 2222),
            severity=severity,
            raw_event=json.dumps(entry),
            metadata=metadata
        )

    @staticmethod
    def normalize_dionaea(entry: dict) -> Optional[SecurityEvent]:
        service = entry.get("service", "unknown")
        event_type = entry.get("event_type", "probe")
        sev_str = entry.get("severity", "LOW").upper()
        severity = getattr(SeverityLevel, sev_str, SeverityLevel.LOW)

        ts_str = entry.get("timestamp")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        metadata = {
            "connection_id": entry.get("connection_id"),
            "sha256": entry.get("sha256"),
            "md5": entry.get("md5"),
            "method": entry.get("method"),
            "url": entry.get("url"),
            "payload_size": entry.get("payload_size"),
            "password": entry.get("password")
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}

        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_ip=entry.get("src_ip", "0.0.0.0"),
            source_service=f"dionaea_{service}",
            event_type=event_type,
            username=entry.get("username"),
            destination_port=entry.get("dst_port", 80),
            severity=severity,
            raw_event=json.dumps(entry),
            metadata=metadata
        )

    @staticmethod
    def normalize_mqtt_honey(entry: dict) -> Optional[SecurityEvent]:
        event_type = entry.get("event_type", "mqtt_event")
        sev_str = entry.get("severity", "LOW").upper()
        severity = getattr(SeverityLevel, sev_str, SeverityLevel.LOW)

        ts_str = entry.get("timestamp")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        metadata = {
            "session_id": entry.get("session_id"),
            "client_id": entry.get("client_id"),
            "topic": entry.get("topic"),
            "topics": entry.get("topics"),
            "payload": entry.get("payload"),
            "protocol": entry.get("protocol")
        }
        metadata = {k: v for k, v in metadata.items() if v is not None}

        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_ip=entry.get("src_ip", "0.0.0.0"),
            source_service="mqtt_honeypot",
            event_type=event_type,
            username=entry.get("username"),
            destination_port=entry.get("dst_port", 18883),
            severity=severity,
            raw_event=json.dumps(entry),
            metadata=metadata
        )

