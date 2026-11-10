"""
Multi-Source Security Event Correlation Engine
Identifies compound multi-stage attacks by correlating honeypot and IoT events
across sliding temporal windows.
"""

from collections import defaultdict
from datetime import datetime, timezone
import os
import sys
import uuid
from typing import Any, Dict, List, Optional

DETECTION_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, DETECTION_DIR)
sys.path.insert(0, os.path.join(DETECTION_DIR, "risk-scoring"))

from mitre_mapping import map_event_to_mitre
from risk_calculator import RiskScoreCalculator


class EventCorrelator:
    def __init__(self, time_window_seconds: int = 120):
        self.time_window_seconds = time_window_seconds
        # Maps source_ip -> list of events
        self.ip_event_buffer = defaultdict(list)
        # Maps device_id -> list of events
        self.device_event_buffer = defaultdict(list)

    def add_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Ingests an event, appends to the temporal buffer,
        and evaluates if any correlation rule triggers.
        Returns a list of newly generated Composite Incidents (if any).
        """
        src_ip = event.get("source_ip", "0.0.0.0")
        device_id = event.get("device_id")
        created_incidents = []

        if src_ip and src_ip != "0.0.0.0":
            self.ip_event_buffer[src_ip].append(event)
            # Prune old events beyond window
            self._prune_buffer(self.ip_event_buffer[src_ip])
            inc = self._evaluate_ip_correlation(src_ip)
            if inc:
                created_incidents.append(inc)

        if device_id:
            self.device_event_buffer[device_id].append(event)
            self._prune_buffer(self.device_event_buffer[device_id])
            inc = self._evaluate_device_correlation(device_id)
            if inc:
                created_incidents.append(inc)

        return created_incidents

    def _prune_buffer(self, event_list: List[Dict[str, Any]]):
        """
        Sliding window pruning based on event-time with wall-clock fallback.
        Supports both live streaming and historical/test log replays.
        """
        if not event_list:
            return

        now = datetime.now(timezone.utc)
        parsed_times = []
        for e in event_list:
            t_str = e.get("timestamp")
            if t_str:
                try:
                    parsed_times.append(datetime.fromisoformat(t_str.replace("Z", "+00:00")))
                except Exception:
                    pass

        if parsed_times:
            max_t = max(parsed_times)
            # If all events are historical/replayed, use the latest event time as the reference
            ref_time = max_t if (now - max_t).total_seconds() > self.time_window_seconds else now
        else:
            ref_time = now

        valid = []
        for e in event_list:
            t_str = e.get("timestamp")
            try:
                t = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                if abs((ref_time - t).total_seconds()) <= self.time_window_seconds:
                    valid.append(e)
            except Exception:
                valid.append(e)
        event_list[:] = valid

    def _evaluate_ip_correlation(self, src_ip: str) -> Optional[Dict[str, Any]]:
        events = self.ip_event_buffer[src_ip]
        if len(events) < 2:
            return None

        event_types = [e.get("event_type") for e in events]
        services = set(e.get("source_service", "") for e in events)

        # Pattern 1: Brute Force Success + Payload Download (Critical Killchain)
        has_login_success = "login_success" in event_types
        has_payload_download = "payload_download" in event_types or any("wget" in e.get("raw_event", "") or "curl" in e.get("raw_event", "") for e in events)

        if has_login_success and has_payload_download:
            risk = RiskScoreCalculator.calculate_risk(
                severity="CRITICAL",
                event_count=len(events),
                threat_intel_score=75.0,
                ml_anomaly_score=85.0
            )
            return {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "title": f"Active Honeypot Breach & Payload Drop from {src_ip}",
                "description": f"Attacker at {src_ip} successfully authenticated and downloaded a payload within {self.time_window_seconds}s.",
                "source_ip": src_ip,
                "severity": "CRITICAL",
                "risk_score": risk["score"],
                "risk_details": risk,
                "pattern": "BREACH_AND_PAYLOAD_DROP",
                "mitre_techniques": ["T1078", "T1059.004", "T1105"],
                "evidence_count": len(events),
                "evidence_events": events[-5:],
                "status": "OPEN",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }

        # Pattern 2: Multi-Protocol Scanner (Cowrie + Dionaea probe)
        has_cowrie = any("cowrie" in s for s in services)
        has_dionaea = any("dionaea" in s for s in services)
        if has_cowrie and has_dionaea and len(events) >= 3:
            risk = RiskScoreCalculator.calculate_risk(
                severity="HIGH",
                event_count=len(events),
                threat_intel_score=60.0
            )
            return {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "title": f"Multi-Protocol Infrastructure Reconnaissance from {src_ip}",
                "description": f"Actor probed both SSH and SMB/Web services across honeynet boundaries.",
                "source_ip": src_ip,
                "severity": "HIGH",
                "risk_score": risk["score"],
                "risk_details": risk,
                "pattern": "MULTI_PROTOCOL_RECON",
                "mitre_techniques": ["T1046", "T1110.001", "T1190"],
                "evidence_count": len(events),
                "evidence_events": events[-5:],
                "status": "OPEN",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }

        # Pattern 3: Brute Force Spray (5+ login failures)
        failed_count = sum(1 for et in event_types if et == "login_failed")
        if failed_count >= 5:
            risk = RiskScoreCalculator.calculate_risk(
                severity="HIGH",
                event_count=failed_count
            )
            return {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "title": f"Distributed SSH Brute-Force Spray from {src_ip}",
                "description": f"Observed {failed_count} rapid authentication failures against decoy SSH/Telnet accounts.",
                "source_ip": src_ip,
                "severity": "HIGH",
                "risk_score": risk["score"],
                "risk_details": risk,
                "pattern": "BRUTE_FORCE_SPRAY",
                "mitre_techniques": ["T1110", "T1110.001"],
                "evidence_count": failed_count,
                "evidence_events": events[-5:],
                "status": "OPEN",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }

        return None

    def _evaluate_device_correlation(self, device_id: str) -> Optional[Dict[str, Any]]:
        events = self.device_event_buffer[device_id]
        suspicious = [e for e in events if e.get("is_suspicious")]

        if len(suspicious) >= 5:
            risk = RiskScoreCalculator.calculate_risk(
                severity="HIGH",
                event_count=len(suspicious),
                ml_anomaly_score=90.0,
                asset_criticality=1.1
            )
            return {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "title": f"IoT Device Compromise & High-Frequency Anomaly: {device_id}",
                "description": f"Device {device_id} produced {len(suspicious)} suspicious anomaly packets within the observation window.",
                "source_ip": suspicious[0].get("simulated_ip", "192.168.1.100"),
                "device_id": device_id,
                "severity": "HIGH",
                "risk_score": risk["score"],
                "risk_details": risk,
                "pattern": "IOT_BOTNET_ACTIVITY",
                "mitre_techniques": ["T1499", "T1565.001"],
                "evidence_count": len(suspicious),
                "evidence_events": suspicious[-5:],
                "status": "OPEN",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }
        return None
