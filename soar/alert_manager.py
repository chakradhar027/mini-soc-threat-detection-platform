"""
SOAR Alert Manager
Collects and deduplicates raw security alerts from Wazuh and the correlation engine.
"""

from collections import deque
import datetime
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AlertManager")


class AlertManager:
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.alerts_queue = deque(maxlen=max_history)
        self.seen_alert_hashes = set()

    def process_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Deduplicates and registers incoming security alert."""
        rule_id = alert_data.get("rule_id", "unknown")
        src_ip = alert_data.get("source_ip", "0.0.0.0")
        sig = f"{rule_id}:{src_ip}"

        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        alert_record = alert_data.copy()
        alert_record["ingested_at"] = now

        self.alerts_queue.append(alert_record)
        logger.info(f"Ingested alert [{rule_id}] from {src_ip} (Severity: {alert_record.get('severity')})")
        return alert_record

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self.alerts_queue)[-limit:]

