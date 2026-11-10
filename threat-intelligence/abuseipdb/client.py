"""
AbuseIPDB Threat Intelligence Client
Queries the AbuseIPDB REST API v2 for IP reputation and abuse confidence scores.
Includes private IP detection, rate-limit backoff, and local TTL-based caching.
"""

import datetime
import ipaddress
import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

logger = logging.getLogger("AbuseIPDBClient")


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl_seconds: int = 86400,
        cache_file: Optional[str] = None
    ):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_file = cache_file or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../abuseipdb_cache.json")
        )
        self.cache: Dict[str, Any] = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def _save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Determines if the IP address is private, loopback, or reserved."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
        except ValueError:
            return True

    def check_ip(self, ip_str: str) -> Dict[str, Any]:
        """
        Retrieves reputation metadata for an IP address.
        Returns cached data if valid, queries API for public IPs,
        or returns local assessment for RFC1918 private IPs.
        """
        # 1. Handle Private / Reserved IP addresses
        if self.is_private_ip(ip_str):
            return {
                "ip_address": ip_str,
                "is_public": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "country_code": "LOCAL",
                "usage_type": "Private / Honeynet Subnet",
                "isp": "Local Test Network",
                "is_whitelisted": True,
                "cached": False,
                "status": "RFC1918_PRIVATE_IP"
            }

        # 2. Check Local TTL Cache
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if ip_str in self.cache:
            entry = self.cache[ip_str]
            if now - entry.get("cached_at", 0) < self.cache_ttl_seconds:
                result = entry.get("data", {}).copy()
                result["cached"] = True
                return result

        # 3. If no API key configured, return neutral analysis
        if not self.api_key:
            return {
                "ip_address": ip_str,
                "is_public": True,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "country_code": "UNKNOWN",
                "usage_type": "Commercial / Unknown",
                "isp": "Unknown ISP",
                "cached": False,
                "status": "NO_API_KEY_CONFIGURED"
            }

        # 4. Query AbuseIPDB REST API
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_str}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(
            url,
            headers={
                "Key": self.api_key,
                "Accept": "application/json"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8")).get("data", {})
                    result = {
                        "ip_address": ip_str,
                        "is_public": True,
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode", "US"),
                        "usage_type": data.get("usageType", "Data Center / Web Hosting"),
                        "isp": data.get("isp", "Cloud Provider"),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "cached": False,
                        "status": "SUCCESS"
                    }
                    # Save to cache
                    self.cache[ip_str] = {"cached_at": now, "data": result}
                    self._save_cache()
                    return result
        except urllib.error.HTTPError as e:
            logger.warning(f"AbuseIPDB API error ({e.code}): {e.reason}")
        except Exception as e:
            logger.warning(f"AbuseIPDB request exception: {e}")

        return {
            "ip_address": ip_str,
            "is_public": True,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "cached": False,
            "status": "API_QUERY_FAILED"
        }

