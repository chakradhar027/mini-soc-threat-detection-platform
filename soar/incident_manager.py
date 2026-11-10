"""
SOAR Incident Manager
Manages the incident investigation lifecycle:
OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED.
Supports attaching evidence events, analyst notes, severity updates, and threat intel.
"""

from datetime import datetime, timezone
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("IncidentManager")


class IncidentManager:
    def __init__(self, persistence_file: Optional[str] = None):
        self.persistence_file = persistence_file or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../reports/incidents.json")
        )
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self._load_incidents()

    def _load_incidents(self):
        if os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.incidents = {inc["incident_id"]: inc for inc in data}
            except Exception:
                self.incidents = {}

    def _save_incidents(self):
        try:
            os.makedirs(os.path.dirname(self.persistence_file), exist_ok=True)
            with open(self.persistence_file, "w", encoding="utf-8") as f:
                json.dump(list(self.incidents.values()), f, indent=2)
        except Exception:
            pass

    def create_or_update_incident(
        self,
        title: str,
        description: str,
        source_ip: str,
        severity: str,
        risk_score: float,
        pattern: str,
        mitre_techniques: List[str],
        evidence_events: List[Dict[str, Any]],
        threat_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates a new incident or appends evidence if an open incident exists for the source IP."""
        # Check for existing open incident for this source_ip
        for inc_id, inc in self.incidents.items():
            if inc.get("source_ip") == source_ip and inc.get("status") in ["OPEN", "INVESTIGATING"]:
                # Update existing incident
                inc["evidence_count"] = inc.get("evidence_count", 0) + len(evidence_events)
                inc["evidence_events"].extend(evidence_events)
                # Keep latest 10 evidence events
                inc["evidence_events"] = inc["evidence_events"][-10:]
                inc["risk_score"] = max(inc["risk_score"], risk_score)
                inc["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                self._save_incidents()
                return inc

        # Create new incident
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        incident = {
            "incident_id": inc_id,
            "title": title,
            "description": description,
            "source_ip": source_ip,
            "severity": severity,
            "risk_score": risk_score,
            "pattern": pattern,
            "mitre_techniques": mitre_techniques,
            "evidence_count": len(evidence_events),
            "evidence_events": evidence_events[-10:],
            "threat_intel": threat_intel or {},
            "status": "OPEN",
            "analyst_notes": [],
            "response_history": [],
            "created_at": now,
            "updated_at": now
        }
        self.incidents[inc_id] = incident
        self._save_incidents()
        return incident

    def add_analyst_note(self, incident_id: str, author: str, note_text: str) -> Optional[Dict[str, Any]]:
        inc = self.incidents.get(incident_id)
        if not inc:
            return None

        # Guarantee status immutability: adding an analyst note MUST NOT mutate status
        preserved_status = inc.get("status")

        note_entry = {
            "note_id": str(uuid.uuid4())[:8],
            "author": author,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "content": note_text
        }
        inc.setdefault("analyst_notes", []).append(note_entry)
        inc["status"] = preserved_status
        inc["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._save_incidents()
        return inc

    def update_status(self, incident_id: str, new_status: str, analyst: str) -> Optional[Dict[str, Any]]:
        valid_statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
        if new_status not in valid_statuses:
            return None

        inc = self.incidents.get(incident_id)
        if not inc:
            return None

        old_status = inc.get("status")
        # No-op if status is unchanged
        if old_status == new_status:
            return inc

        inc["status"] = new_status
        inc["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        note = f"Status changed from {old_status} to {new_status} by {analyst}"
        self.add_analyst_note(incident_id, "SYSTEM_AUDIT", note)
        self._save_incidents()
        return inc

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        return list(self.incidents.values())

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.incidents.get(incident_id)

