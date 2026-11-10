"""
Wazuh SIEM Integration Client
Interfaces with the Wazuh Manager REST API (Port 55000) and alert logs.
Provides dual-mode integration:
  1. Live REST API query and management client (HTTPS / JWT Bearer).
  2. High-performance file-based alerts stream reader (alerts.json).
"""

import base64
import datetime
import json
import logging
import os
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("WazuhClient")


def _load_env_file():
    """Reads .env from project root if present to populate os.environ safely."""
    potential_paths = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.env")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../infrastructure/docker/.env")),
    ]
    for p in potential_paths:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip()
                            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                                v = v[1:-1]
                            if k not in os.environ and v:
                                os.environ[k] = v
                break
            except Exception as e:
                logger.debug(f"Could not parse env file {p}: {e}")


# Initialize environment on module load
_load_env_file()


class WazuhClient:
    def __init__(
        self,
        api_host: Optional[str] = None,
        api_port: Optional[int] = None,
        api_user: Optional[str] = None,
        api_password: Optional[str] = None,
        alerts_log_path: Optional[str] = None
    ):
        self.api_host = api_host or os.environ.get("WAZUH_MANAGER_HOST", "127.0.0.1")
        self.api_port = api_port or int(os.environ.get("WAZUH_API_PORT", 55000))
        self.api_url = f"https://{self.api_host}:{self.api_port}"
        self.api_user = api_user or os.environ.get("WAZUH_API_USER", "wazuh-wui")
        self.api_password = api_password or os.environ.get("WAZUH_API_PASSWORD", "")
        self.token: Optional[str] = None
        self.token_expiry: Optional[datetime.datetime] = None
        self._last_log_offset: int = 0
        self._last_inode: Optional[int] = None

        if alerts_log_path:
            self.alerts_log_path = alerts_log_path
        else:
            self.alerts_log_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../infrastructure/docker/volumes/wazuh/manager/logs/alerts/alerts.json"
                )
            )

    @staticmethod
    def _get_ssl_context() -> ssl.SSLContext:
        """Returns SSL context configured for localhost loopback self-signed certs."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -------------------------------------------------------------------------
    # 1. API Probing & Authentication
    # -------------------------------------------------------------------------
    def is_tcp_reachable(self, timeout: float = 1.5) -> bool:
        """Checks if Wazuh API TCP port is open and accepting connections."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.api_host, self.api_port))
                return True
        except Exception:
            return False

    def is_api_reachable(self) -> bool:
        """Backward-compatible TCP reachability probe."""
        return self.is_tcp_reachable()

    def check_tls_listener(self, timeout: float = 3.0) -> Tuple[bool, str]:
        """Probes the HTTPS endpoint to verify TLS listener is responsive."""
        if not self.is_tcp_reachable(timeout=1.0):
            return False, "TCP port unreachable"

        req = urllib.request.Request(f"{self.api_url}/")
        try:
            with urllib.request.urlopen(req, context=self._get_ssl_context(), timeout=timeout) as resp:
                return True, f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            # HTTP 401 is normal for root endpoint without auth token
            if e.code in (401, 403, 200):
                return True, f"HTTP {e.code} (TLS active)"
            return False, f"HTTP Error {e.code}"
        except Exception as e:
            return False, str(e)

    def authenticate(self) -> Tuple[bool, str]:
        """
        Authenticates against Wazuh REST API (/security/user/authenticate)
        using HTTP Basic Auth and retrieves a valid JWT Bearer token.
        """
        if not self.api_password:
            return False, "Missing WAZUH_API_PASSWORD in environment"

        if not self.is_tcp_reachable(timeout=1.0):
            return False, "TCP port 55000 is not reachable"

        auth_endpoint = f"{self.api_url}/security/user/authenticate"
        cred_bytes = f"{self.api_user}:{self.api_password}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(cred_bytes).decode('utf-8')}"

        req = urllib.request.Request(
            auth_endpoint,
            headers={"Authorization": auth_header, "Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, context=self._get_ssl_context(), timeout=5) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode("utf-8"))
                    token = payload.get("data", {}).get("token")
                    if token:
                        self.token = token
                        # Wazuh tokens typically expire in 900 seconds (15 min)
                        self.token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=840)
                        return True, "Authentication successful"
                    return False, "No token found in response payload"
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.debug(f"Wazuh API auth HTTP {e.code}: {err_body}")
            try:
                parsed = json.loads(err_body)
                return False, parsed.get("detail", f"HTTP {e.code}")
            except Exception:
                return False, f"HTTP {e.code} Unauthorized"
        except Exception as e:
            logger.debug(f"Wazuh API auth error: {e}")
            return False, str(e)

        return False, "Authentication failed"

    def ensure_authenticated(self) -> bool:
        """Ensures an active, non-expired JWT token is available."""
        now = datetime.datetime.now(datetime.timezone.utc)
        if self.token and self.token_expiry and now < self.token_expiry:
            return True
        ok, _ = self.authenticate()
        return ok

    def query_api(self, endpoint: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any]:
        """Executes an authenticated API request against Wazuh REST API."""
        if not self.ensure_authenticated():
            return False, {"error": "Authentication required"}

        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = f"{self.api_url}{endpoint}"

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        data_bytes = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, headers=headers, data=data_bytes, method=method)

        try:
            with urllib.request.urlopen(req, context=self._get_ssl_context(), timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return True, data
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            return False, {"http_code": e.code, "detail": err_msg}
        except Exception as e:
            return False, {"error": str(e)}

    # -------------------------------------------------------------------------
    # 2. Live Wazuh Manager Telemetry Queries
    # -------------------------------------------------------------------------
    def get_manager_status(self) -> Dict[str, Any]:
        """Queries Wazuh API /manager/status for running daemon states."""
        ok, res = self.query_api("/manager/status")
        if ok and isinstance(res, dict):
            items = res.get("data", {}).get("affected_items", [])
            return items[0] if items else {}
        return {}

    def get_manager_info(self) -> Dict[str, Any]:
        """Queries Wazuh API /manager/info for version and system information."""
        ok, res = self.query_api("/manager/info")
        if ok and isinstance(res, dict):
            items = res.get("data", {}).get("affected_items", [])
            return items[0] if items else {}
        return {}

    # -------------------------------------------------------------------------
    # 3. Comprehensive Health Status Inspection
    # -------------------------------------------------------------------------
    def get_api_health(self) -> Dict[str, Any]:
        """Distinguishes TCP connectivity, TLS handshake, and API Authentication."""
        tcp_ok = self.is_tcp_reachable()
        tls_ok, tls_detail = self.check_tls_listener() if tcp_ok else (False, "TCP unreachable")

        auth_ok = False
        auth_msg = "Not attempted"
        manager_info = {}
        daemons = {}

        if tcp_ok and tls_ok:
            auth_ok, auth_msg = self.authenticate()
            if auth_ok:
                daemons = self.get_manager_status()
                manager_info = self.get_manager_info()

        return {
            "api_url": self.api_url,
            "tcp_reachable": tcp_ok,
            "tls_listener": {
                "active": tls_ok,
                "detail": tls_detail
            },
            "authentication": {
                "configured_user": self.api_user,
                "authenticated": auth_ok,
                "status_message": auth_msg,
                "token_active": bool(self.token)
            },
            "manager_version": manager_info.get("version", "v4.9.0"),
            "daemons": daemons
        }

    def get_file_ingestion_health(self, limit: int = 10) -> Dict[str, Any]:
        """Inspects the local alerts.json log file ingestion pipeline."""
        exists = os.path.exists(self.alerts_log_path)
        file_size = os.path.getsize(self.alerts_log_path) if exists else 0
        recent = self.get_alerts_from_log(limit=limit) if exists else []

        return {
            "alerts_log_path": self.alerts_log_path,
            "alerts_file_exists": exists,
            "file_size_bytes": file_size,
            "last_read_offset": self._last_log_offset,
            "streaming_active": exists,
            "recent_alerts_count": len(recent),
            "recent_alerts_sample": recent[:3]
        }

    # -------------------------------------------------------------------------
    # 4. File-Based Alert Stream Reader & Normalization (Preserved)
    # -------------------------------------------------------------------------
    def read_new_alerts(self) -> List[Dict[str, Any]]:
        """Reads newly appended JSON alerts from alerts.json since last read."""
        if not os.path.exists(self.alerts_log_path):
            return []

        try:
            stat = os.stat(self.alerts_log_path)
            curr_size = stat.st_size
            curr_inode = getattr(stat, "st_ino", None)
            if curr_inode is not None and self._last_inode is not None and curr_inode != self._last_inode:
                # Log file was rotated / replaced with a new inode
                self._last_log_offset = 0
            elif curr_size < self._last_log_offset:
                # File was truncated in place
                self._last_log_offset = 0
            self._last_inode = curr_inode
        except OSError:
            pass

        new_alerts = []
        try:
            with open(self.alerts_log_path, "r", encoding="utf-8") as f:
                f.seek(self._last_log_offset)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            new_alerts.append(json.loads(line))
                        except Exception:
                            continue
                self._last_log_offset = f.tell()
        except Exception as e:
            logger.error(f"Error streaming Wazuh alerts log: {e}")
        return new_alerts

    def get_alerts_from_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Reads and parses alerts directly from the Wazuh alerts.json file."""
        if not os.path.exists(self.alerts_log_path):
            return []

        alerts = []
        try:
            with open(self.alerts_log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in reversed(lines[-limit:]):
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except Exception:
                            continue
        except Exception as e:
            logger.error(f"Error reading Wazuh alerts log: {e}")
        return alerts

    @staticmethod
    def map_wazuh_level_to_severity(level: int) -> str:
        """Maps Wazuh numeric rule level (1-15) to SOC severity tiers."""
        if level >= 12:
            return "CRITICAL"
        elif level >= 8:
            return "HIGH"
        elif level >= 4:
            return "MEDIUM"
        else:
            return "LOW"

    def normalize_wazuh_alert(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes a native Wazuh alert into our SOC alert schema."""
        rule = raw_alert.get("rule", {})
        mitre = rule.get("mitre", {})
        rule_level = rule.get("level", 3)

        return {
            "alert_id": raw_alert.get("id", str(raw_alert.get("timestamp", ""))),
            "timestamp": raw_alert.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_name": rule.get("description"),
            "severity": self.map_wazuh_level_to_severity(rule_level),
            "level": rule_level,
            "source_ip": raw_alert.get("data", {}).get("src_ip") or raw_alert.get("srcip", "0.0.0.0"),
            "mitre_technique_id": mitre.get("id", [None])[0] if isinstance(mitre.get("id"), list) else mitre.get("id"),
            "mitre_tactic": mitre.get("tactic", [None])[0] if isinstance(mitre.get("tactic"), list) else mitre.get("tactic"),
            "agent_id": raw_alert.get("agent", {}).get("id", "000"),
            "agent_name": raw_alert.get("agent", {}).get("name", "wazuh-manager"),
            "raw_log": raw_alert.get("full_log", "")
        }
