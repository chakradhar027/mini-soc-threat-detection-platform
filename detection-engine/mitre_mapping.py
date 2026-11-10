"""
MITRE ATT&CK Enterprise Mapping Matrix
Provides comprehensive mapping between detected security event types,
Wazuh rule IDs, Sigma rule IDs, and MITRE ATT&CK tactics/techniques.
"""

from typing import Any, Dict, List, Optional


MITRE_TECHNIQUES_DATABASE = {
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or password spraying.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may guess passwords to attempt to gain access to system accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1059.004": {
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix-based shells to execute various commands and scripts.",
        "url": "https://attack.mitre.org/techniques/T1059/004/"
    },
    "T1105": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1046": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts or brokers.",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1210": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems.",
        "url": "https://attack.mitre.org/techniques/T1210/"
    },
    "T1190": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing software program.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "T1204.002": {
        "technique_id": "T1204.002",
        "technique_name": "Malicious File",
        "tactic": "Execution",
        "description": "An adversary may deliver executable payloads or scripts that are executed in the environment.",
        "url": "https://attack.mitre.org/techniques/T1204/002/"
    },
    "T1499": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform endpoint denial of service attacks to degrade or block the availability of targeted systems.",
        "url": "https://attack.mitre.org/techniques/T1499/"
    },
    "T1565.001": {
        "technique_id": "T1565.001",
        "technique_name": "Stored Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may insert, delete, or manipulate data at rest to disrupt normal business operations.",
        "url": "https://attack.mitre.org/techniques/T1565/001/"
    }
}


EVENT_TYPE_TO_MITRE = {
    "login_failed": "T1110.001",
    "brute_force": "T1110",
    "login_success": "T1078",
    "command_input": "T1059.004",
    "payload_download": "T1105",
    "smb_probe": "T1210",
    "payload_capture": "T1204.002",
    "exploit_probe": "T1190",
    "wildcard_subscription": "T1046",
    "unauthorized_publish": "T1499",
    "burst_publish_flood": "T1499",
    "telemetry_tampering": "T1565.001"
}


def map_event_to_mitre(event_type: str) -> Optional[Dict[str, Any]]:
    """Resolves an event type to its MITRE ATT&CK technique metadata."""
    tech_id = EVENT_TYPE_TO_MITRE.get(event_type)
    if tech_id:
        return MITRE_TECHNIQUES_DATABASE.get(tech_id)
    return None


def get_all_matrix_techniques() -> List[Dict[str, Any]]:
    """Returns the full list of supported ATT&CK techniques for dashboard visualization."""
    return list(MITRE_TECHNIQUES_DATABASE.values())

