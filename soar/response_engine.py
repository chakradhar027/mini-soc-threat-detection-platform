"""
Controlled SOAR Incident Response Engine
Executes automated IP containment with simulation mode, safety allowlists, and rollback audit.
"""

from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ResponseEngine")


class ResponseEngine:
    IMMUTABLE_ALLOWLIST = [
        "127.0.0.1",
        "::1",
        "172.28.30.0/24",  # SOC management network
        "172.28.20.0/24",  # IoT simulation network
        "172.28.10.1",      # Gateway
        "192.168.0.0/16",  # Local LAN
        "10.0.0.0/8"
    ]

    def __init__(self, mode: str = "simulation", ban_duration_sec: int = 3600):
        # Modes: 'simulation', 'approval_required', 'active'
        self.mode = os.environ.get("SOAR_RESPONSE_MODE", mode)
        self.ban_duration_sec = ban_duration_sec
        self.active_blocks: Dict[str, Dict[str, Any]] = {}

    def is_allowlisted(self, ip_str: str) -> bool:
        """Verifies if an IP address is protected by the immutable allowlist."""
        try:
            target_ip = ipaddress.ip_address(ip_str)
            for entry in self.IMMUTABLE_ALLOWLIST:
                if "/" in entry:
                    if target_ip in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if target_ip == ipaddress.ip_address(entry):
                        return True
        except ValueError:
            return True
        return False

    def block_ip(
        self,
        ip_address: str,
        incident_id: str,
        reason: str,
        operator: str = "SOAR_AUTOMATION",
        force_approve: bool = False
    ) -> Dict[str, Any]:
        """
        Executes or simulates IP containment.
        Returns detailed action summary and audit record.
        """
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # 1. Safety Check: Verify Allowlist
        if self.is_allowlisted(ip_address):
            logger.warning(f"BLOCKED ACTION: Attempted to contain protected IP {ip_address}!")
            return {
                "action_id": action_id,
                "status": "REJECTED_ALLOWLIST_PROTECTION",
                "ip_address": ip_address,
                "incident_id": incident_id,
                "mode": self.mode,
                "timestamp": now,
                "message": f"Containment rejected: {ip_address} is in the immutable SOC allowlist."
            }

        # 2. Check Approval Requirement
        if self.mode == "approval_required" and not force_approve:
            return {
                "action_id": action_id,
                "status": "PENDING_ANALYST_APPROVAL",
                "ip_address": ip_address,
                "incident_id": incident_id,
                "mode": self.mode,
                "timestamp": now,
                "message": f"Containment for {ip_address} is staged and requires explicit analyst sign-off."
            }

        # 3. Simulation Mode
        if self.mode == "simulation":
            block_record = {
                "action_id": action_id,
                "status": "SIMULATED_CONTAINMENT",
                "ip_address": ip_address,
                "incident_id": incident_id,
                "mode": "simulation",
                "reason": reason,
                "operator": operator,
                "ban_duration_seconds": self.ban_duration_sec,
                "timestamp": now,
                "command_simulated": f"iptables -A DOCKER-USER -s {ip_address} -j DROP",
                "message": f"Simulated containment applied for {ip_address} (Host safe)."
            }
            self.active_blocks[ip_address] = block_record
            return block_record

        # 4. Active Mode (Applied only within dedicated test honeynet)
        block_record = {
            "action_id": action_id,
            "status": "ACTIVE_CONTAINMENT",
            "ip_address": ip_address,
            "incident_id": incident_id,
            "mode": "active",
            "reason": reason,
            "operator": operator,
            "timestamp": now,
            "message": f"Active iptables rule staged for {ip_address}."
        }
        self.active_blocks[ip_address] = block_record
        return block_record

    def rollback_ip(self, ip_address: str, operator: str = "SOC_ANALYST") -> Dict[str, Any]:
        """Rolls back an existing containment rule."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if ip_address in self.active_blocks:
            del self.active_blocks[ip_address]
            return {
                "status": "CONTAINMENT_REVOKED",
                "ip_address": ip_address,
                "operator": operator,
                "timestamp": now,
                "message": f"Containment rule for {ip_address} successfully rolled back."
            }
        return {
            "status": "NOT_FOUND",
            "ip_address": ip_address,
            "timestamp": now,
            "message": f"No active containment found for {ip_address}."
        }

    def get_active_containments(self) -> List[Dict[str, Any]]:
        return list(self.active_blocks.values())

