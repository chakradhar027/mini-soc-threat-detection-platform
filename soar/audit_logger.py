"""
Cryptographic SOAR Audit Logger
Maintains an append-only, SHA-256 hash-chained audit log of all security operations,
incident updates, and automated response actions.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional


class AuditLogger:
    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../reports/audit_trail.json")
        )
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.entries: List[Dict[str, Any]] = []
        self._last_mtime: float = 0.0
        self._load_entries()

    def _load_entries(self):
        if os.path.exists(self.log_path):
            try:
                mtime = os.path.getmtime(self.log_path)
                if mtime > getattr(self, "_last_mtime", 0.0):
                    with open(self.log_path, "r", encoding="utf-8") as f:
                        self.entries = json.load(f)
                    self._last_mtime = mtime
            except Exception:
                if not self.entries:
                    self.entries = []

    def _save_entries(self):
        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(self.entries, f, indent=2)
            if os.path.exists(self.log_path):
                self._last_mtime = os.path.getmtime(self.log_path)
        except Exception:
            pass

    def get_last_hash(self) -> str:
        self._load_entries()
        if self.entries:
            return self.entries[-1].get("entry_hash", "GENESIS_BLOCK_0000000000000000")
        return "GENESIS_BLOCK_0000000000000000"

    def log_action(
        self,
        action_type: str,
        operator: str,
        target: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Appends a new cryptographically chained audit log entry."""
        self._load_entries()
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        prev_hash = self.get_last_hash()

        payload_to_hash = f"{entry_id}:{timestamp}:{action_type}:{operator}:{target}:{prev_hash}:{json.dumps(details, sort_keys=True)}"
        entry_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()

        entry = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "action_type": action_type,
            "operator": operator,
            "target": target,
            "details": details,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash
        }

        self.entries.append(entry)
        self._save_entries()
        return entry

    def verify_integrity(self) -> bool:
        """Verifies the unbroken cryptographic hash chain across all log entries."""
        self._load_entries()
        if not self.entries:
            return True

        expected_prev = "GENESIS_BLOCK_0000000000000000"
        for entry in self.entries:
            if entry.get("prev_hash") != expected_prev:
                return False
            payload = f"{entry['entry_id']}:{entry['timestamp']}:{entry['action_type']}:{entry['operator']}:{entry['target']}:{entry['prev_hash']}:{json.dumps(entry['details'], sort_keys=True)}"
            computed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if computed != entry.get("entry_hash"):
                return False
            expected_prev = entry.get("entry_hash")

        return True

    def get_all_entries(self) -> List[Dict[str, Any]]:
        self._load_entries()
        return list(self.entries)

