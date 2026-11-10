"""
SOC Data Store & Aggregation Service
Central persistence and query layer for events, incidents, attack graphs, and analytics.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, os.path.join(ROOT_DIR, "detection-engine"))
sys.path.insert(0, os.path.join(ROOT_DIR, "detection-engine/risk-scoring"))
sys.path.insert(0, os.path.join(ROOT_DIR, "detection-engine/correlation"))
sys.path.insert(0, os.path.join(ROOT_DIR, "threat-intelligence"))
sys.path.insert(0, os.path.join(ROOT_DIR, "soar"))
sys.path.insert(0, os.path.join(ROOT_DIR, "ml-engine"))
sys.path.insert(0, os.path.join(ROOT_DIR, "iot-simulator"))

from mitre_mapping import map_event_to_mitre, get_all_matrix_techniques
from risk_calculator import RiskScoreCalculator
from correlator import EventCorrelator
from incident_manager import IncidentManager
from response_engine import ResponseEngine
from audit_logger import AuditLogger
from enrichment import ThreatIntelligenceEnricher
from event_generator.simulator import IoTSimulatorFleet


class SOCDataStore:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SOCDataStore()
        return cls._instance

    def __init__(self):
        self.events: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.correlator = EventCorrelator()
        self.incident_mgr = IncidentManager()
        self.response_engine = ResponseEngine(mode="simulation")
        self.audit_logger = AuditLogger()
        self.ti_enricher = ThreatIntelligenceEnricher()
        self.iot_fleet = IoTSimulatorFleet()
        self._seed_telemetry()

    def _seed_telemetry(self):
        """Seeds initial realistic telemetry from IoT fleet and Honeypots."""
        # 1. IoT baseline telemetry
        iot_events = self.iot_fleet.generate_fleet_telemetry_snapshot()
        for pkt in iot_events:
            self.add_event({
                "event_id": pkt["event_id"],
                "timestamp": pkt["timestamp"],
                "source_ip": pkt["simulated_ip"],
                "source_service": f"iot_{pkt['device_type'].lower().replace(' ', '_')}",
                "event_type": "telemetry_heartbeat",
                "destination_port": 1883,
                "severity": "LOW",
                "raw_event": json.dumps(pkt),
                "metadata": pkt
            })

        # 2. Simulated Honeypot seed events
        honeypot_seeds = [
            {
                "event_id": "seed-01",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source_ip": "198.51.100.23",
                "source_service": "cowrie",
                "event_type": "login_failed",
                "username": "root",
                "destination_port": 2222,
                "severity": "MEDIUM",
                "raw_event": '{"eventid":"cowrie.login.failed","username":"root","password":"Password123"}',
                "metadata": {"password": "Password123", "protocol": "ssh"}
            },
            {
                "event_id": "seed-02",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source_ip": "198.51.100.23",
                "source_service": "cowrie",
                "event_type": "login_failed",
                "username": "admin",
                "destination_port": 2222,
                "severity": "MEDIUM",
                "raw_event": '{"eventid":"cowrie.login.failed","username":"admin","password":"admin"}',
                "metadata": {"password": "admin", "protocol": "ssh"}
            },
            {
                "event_id": "seed-03",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source_ip": "203.0.113.88",
                "source_service": "dionaea_smb",
                "event_type": "smb_probe",
                "destination_port": 4445,
                "severity": "HIGH",
                "raw_event": '{"service":"smb","event_type":"smb_probe","message":"MS17-010 EternalBlue probe"}',
                "metadata": {"cve": "CVE-2017-0144", "protocol": "smb"}
            },
            {
                "event_id": "seed-04",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source_ip": "192.0.2.105",
                "source_service": "mqtt_honeypot",
                "event_type": "wildcard_subscription",
                "destination_port": 18883,
                "severity": "HIGH",
                "raw_event": '{"event_type":"wildcard_subscription","topics":["#"]}',
                "metadata": {"topics": ["#"], "client_id": "scanner_bot"}
            }
        ]

        for s in honeypot_seeds:
            self.add_event(s)

    def add_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Ingests event, checks correlation, generates incidents, and registers audit."""
        self.events.append(event)
        # Keep latest 5000 events in memory
        if len(self.events) > 5000:
            self.events.pop(0)

        # Run correlation engine
        new_incidents = self.correlator.add_event(event)
        for inc in new_incidents:
            # Check threat intelligence for incident IP
            ti = self.ti_enricher.enrich_ip(inc["source_ip"])
            created = self.incident_mgr.create_or_update_incident(
                title=inc["title"],
                description=inc["description"],
                source_ip=inc["source_ip"],
                severity=inc["severity"],
                risk_score=inc["risk_score"],
                pattern=inc["pattern"],
                mitre_techniques=inc["mitre_techniques"],
                evidence_events=inc["evidence_events"],
                threat_intel=ti
            )
            # Log audit
            self.audit_logger.log_action(
                action_type="CORRELATED_INCIDENT_CREATED",
                operator="CORRELATION_ENGINE",
                target=inc["source_ip"],
                details={"incident_id": created["incident_id"], "risk_score": inc["risk_score"]}
            )

        return event

    def get_overview_metrics(self) -> Dict[str, Any]:
        total_events = len(self.events)
        incidents = self.incident_mgr.get_all_incidents()
        critical_incidents = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
        high_incidents = sum(1 for i in incidents if i.get("severity") == "HIGH")

        source_ips = set(e.get("source_ip") for e in self.events if e.get("source_ip"))
        auth_failures = sum(1 for e in self.events if "failed" in e.get("event_type", ""))

        sev_counts = Counter(e.get("severity", "LOW") for e in self.events)
        service_counts = Counter(e.get("source_service", "other") for e in self.events)

        return {
            "total_interactions": total_events,
            "security_alerts": len(self.alerts) + len(incidents),
            "critical_incidents": critical_incidents,
            "high_incidents": high_incidents,
            "unique_source_ips": len(source_ips),
            "authentication_failures": auth_failures,
            "active_honeypots": 3,
            "active_iot_devices": len(self.iot_fleet.devices),
            "containment_actions": len(self.response_engine.get_active_containments()),
            "severity_distribution": dict(sev_counts),
            "service_distribution": dict(service_counts.most_common(6))
        }

    def get_attack_relationship_graph(self) -> Dict[str, Any]:
        """
        Builds the Attack Relationship Graph connecting:
        Attacker IPs -> Honeypots / Targets -> Credentials Attempted -> Incidents.
        """
        nodes = []
        links = []
        node_ids = set()

        def add_node(nid: str, label: str, ntype: str, severity: str = "INFO"):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "label": label,
                    "type": ntype,
                    "severity": severity
                })

        # Add Honeypot Target Nodes
        add_node("target:cowrie", "Cowrie SSH/Telnet", "HONEYPOT", "LOW")
        add_node("target:dionaea", "Dionaea Trap", "HONEYPOT", "LOW")
        add_node("target:mqtt", "Mosquitto Honeypot", "HONEYPOT", "LOW")
        add_node("target:iot", "IoT Fleet", "IOT_FLEET", "LOW")

        for inc in self.incident_mgr.get_all_incidents():
            inc_id = inc["incident_id"]
            src_ip = inc.get("source_ip", "0.0.0.0")

            add_node(f"ip:{src_ip}", src_ip, "ATTACKER_IP", inc.get("severity", "HIGH"))
            add_node(inc_id, inc.get("title", inc_id), "INCIDENT", inc.get("severity", "HIGH"))

            links.append({
                "source": f"ip:{src_ip}",
                "target": inc_id,
                "relationship": "TRIGGERED_INCIDENT"
            })

            # Link IP to target honeypot
            pattern = inc.get("pattern", "")
            if "SSH" in pattern or "BREACH" in pattern:
                links.append({"source": f"ip:{src_ip}", "target": "target:cowrie", "relationship": "PROBED"})
            elif "MULTI" in pattern or "SMB" in pattern:
                links.append({"source": f"ip:{src_ip}", "target": "target:dionaea", "relationship": "EXPLOITED"})
            elif "IOT" in pattern:
                links.append({"source": f"ip:{src_ip}", "target": "target:iot", "relationship": "ATTACKED"})

        # Add credential nodes
        for e in self.events[-50:]:
            u = e.get("username")
            ip = e.get("source_ip")
            if u and ip:
                cred_id = f"cred:{u}"
                add_node(cred_id, f"User: {u}", "CREDENTIAL", "MEDIUM")
                links.append({
                    "source": f"ip:{ip}",
                    "target": cred_id,
                    "relationship": "ATTEMPTED_CREDENTIAL"
                })

        return {"nodes": nodes, "links": links}

    def get_attack_analytics(self) -> Dict[str, Any]:
        """Returns deep telemetry analytics (top attackers, credential wordcloud, timelines)."""
        ip_counts = Counter(e.get("source_ip") for e in self.events if e.get("source_ip") and e.get("source_ip") != "0.0.0.0")
        cred_counts = Counter(e.get("username") for e in self.events if e.get("username"))
        port_counts = Counter(e.get("destination_port") for e in self.events if e.get("destination_port"))

        # Hourly distribution
        hourly = defaultdict(int)
        for e in self.events:
            ts = e.get("timestamp", "")
            if len(ts) >= 13:
                hr = ts[11:13] + ":00"
                hourly[hr] += 1

        return {
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(10)],
            "targeted_credentials": [{"username": u, "count": count} for u, count in cred_counts.most_common(10)],
            "targeted_ports": [{"port": p, "count": count} for p, count in port_counts.most_common(8)],
            "hourly_timeline": [{"hour": hr, "events": count} for hr, count in sorted(hourly.items())]
        }
