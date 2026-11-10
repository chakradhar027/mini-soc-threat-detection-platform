"""
VirusTotal Threat Intelligence Client (Hash Lookup Only)
Queries VirusTotal API v3 for file hash reputation (SHA-256 / MD5).
STRICT RULE: Never uploads live files or samples. Queries metadata by hash only.
"""

import datetime
import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

logger = logging.getLogger("VirusTotalClient")


class VirusTotalClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl_seconds: int = 86400,
        cache_file: Optional[str] = None
    ):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_file = cache_file or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../virustotal_cache.json")
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

    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for reputation of a SHA-256 or MD5 hash.
        """
        clean_hash = file_hash.strip().lower()
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()

        # Check Cache
        if clean_hash in self.cache:
            entry = self.cache[clean_hash]
            if now - entry.get("cached_at", 0) < self.cache_ttl_seconds:
                res = entry.get("data", {}).copy()
                res["cached"] = True
                return res

        # If no API key configured, return clean/neutral response
        if not self.api_key:
            return {
                "hash": clean_hash,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 72,
                "reputation": 0,
                "threat_name": "Undetected / Offline Assessment",
                "cached": False,
                "status": "NO_API_KEY_CONFIGURED"
            }

        url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
        req = urllib.request.Request(
            url,
            headers={"x-apikey": self.api_key, "Accept": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8")).get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)

                    result = {
                        "hash": clean_hash,
                        "malicious_count": malicious,
                        "suspicious_count": stats.get("suspicious", 0),
                        "total_engines": sum(stats.values()) if stats else 72,
                        "reputation": attr.get("reputation", 0),
                        "threat_name": attr.get("meaningful_name", "Malicious Dropper" if malicious > 5 else "Benign"),
                        "type_description": attr.get("type_description", "Binary"),
                        "cached": False,
                        "status": "SUCCESS"
                    }
                    self.cache[clean_hash] = {"cached_at": now, "data": result}
                    self._save_cache()
                    return result
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result = {
                    "hash": clean_hash,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "total_engines": 0,
                    "reputation": 0,
                    "threat_name": "Not Found in VirusTotal Database",
                    "cached": True,
                    "status": "NOT_FOUND"
                }
                self.cache[clean_hash] = {"cached_at": now, "data": result}
                self._save_cache()
                return result
            logger.warning(f"VirusTotal API HTTP error ({e.code}): {e.reason}")
        except Exception as e:
            logger.warning(f"VirusTotal request error: {e}")

        return {
            "hash": clean_hash,
            "malicious_count": 0,
            "suspicious_count": 0,
            "cached": False,
            "status": "API_QUERY_FAILED"
        }

