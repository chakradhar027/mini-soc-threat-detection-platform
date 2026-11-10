"""
Telegram Notification Dispatcher
Sends real-time high & critical security alerts to the SOC analyst Telegram channel.
"""

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

logger = logging.getLogger("TelegramNotifier")


class TelegramNotifier:
    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        outbox_log: Optional[str] = None
    ):
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
        self.outbox_log = outbox_log or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../reports/telegram_outbox.log")
        )
        os.makedirs(os.path.dirname(self.outbox_log), exist_ok=True)

    def format_incident_alert(self, incident: Dict[str, Any]) -> str:
        severity = incident.get("severity", "HIGH")
        emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"

        techniques = ", ".join(incident.get("mitre_techniques", ["N/A"]))
        msg = (
            f"{emoji} *MINI SOC SECURITY ALERT*\n\n"
            f"*Incident ID:* `{incident.get('incident_id')}`\n"
            f"*Title:* {incident.get('title')}\n"
            f"*Severity:* *{severity}* (Risk Score: *{incident.get('risk_score', 0)}/100*)\n"
            f"*Source IP:* `{incident.get('source_ip', '0.0.0.0')}`\n"
            f"*MITRE ATT&CK:* `{techniques}`\n"
            f"*Pattern:* `{incident.get('pattern', 'ANOMALY')}`\n"
            f"*Status:* `{incident.get('status', 'OPEN')}`\n\n"
            f"⚡ *Recommended Action:* Investigate in SOC Dashboard & consider IP containment."
        )
        return msg

    def send_notification(self, incident: Dict[str, Any]) -> bool:
        message_text = self.format_incident_alert(incident)

        # Log to outbox audit file
        with open(self.outbox_log, "a", encoding="utf-8") as f:
            f.write(f"[{incident.get('incident_id')}] {message_text}\n{'='*50}\n")

        # If token and chat_id are present, send via Telegram Bot API
        if self.bot_token and self.chat_id:
            api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": message_text,
                "parse_mode": "Markdown"
            }
            req = urllib.request.Request(
                api_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        logger.info(f"Telegram alert dispatched for {incident.get('incident_id')}")
                        return True
            except Exception as e:
                logger.warning(f"Telegram dispatch failed: {e}")
                return False

        logger.info(f"Telegram alert logged to outbox for {incident.get('incident_id')}")
        return True

