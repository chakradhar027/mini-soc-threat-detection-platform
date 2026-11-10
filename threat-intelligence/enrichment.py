"""
Unified Threat Intelligence Enrichment Service
Coordinates AbuseIPDB and VirusTotal lookups to enrich events and incidents with reputation data.
"""

import os
import sys
from typing import Any, Dict, Optional

TI_DIR = os.path.dirname(__file__)
sys.path.insert(0, TI_DIR)

from abuseipdb.client import AbuseIPDBClient
from virustotal.client import VirusTotalClient


class ThreatIntelligenceEnricher:
    def __init__(self):
        self.abuse_client = AbuseIPDBClient()
        self.vt_client = VirusTotalClient()

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Queries AbuseIPDB reputation for a given IP."""
        return self.abuse_client.check_ip(ip_address)

    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """Queries VirusTotal reputation for a given file hash."""
        return self.vt_client.check_file_hash(file_hash)

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches an event with threat intelligence metrics."""
        enriched = event.copy()
        src_ip = event.get("source_ip")
        metadata = enriched.get("metadata", {})

        if src_ip and src_ip != "0.0.0.0":
            ti_ip = self.enrich_ip(src_ip)
            enriched["threat_intel_ip"] = ti_ip

        # Check for hashes in metadata
        sha256 = metadata.get("sha256") or metadata.get("shasum")
        if sha256:
            ti_hash = self.enrich_hash(sha256)
            enriched["threat_intel_hash"] = ti_hash

        return enriched

