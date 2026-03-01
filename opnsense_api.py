"""
OPNsense REST API client for automated threat response.
"""

import json
import logging
import os
import urllib3
from pathlib import Path

# Suppress insecure request warnings (self-signed cert)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

CREDS_FILE = Path(os.environ.get("OPN_CREDS_FILE", "/tmp/.opn_creds"))
BASE_URL = os.environ.get("OPN_BASE_URL", "https://192.168.1.1/api")


class OPNsenseAPI:
    """Client for OPNsense REST API."""

    def __init__(self, base_url: str = BASE_URL, creds_file: Path = CREDS_FILE):
        self.base_url = base_url.rstrip("/")
        self.session = None
        self._load_creds(creds_file)

    def _load_creds(self, creds_file: Path):
        """Load API key and secret from credentials file."""
        import requests
        self.session = requests.Session()
        self.session.verify = False

        if creds_file.exists():
            creds = creds_file.read_text().strip()
            key, secret = creds.split(":")
            self.session.auth = (key, secret)
            logger.info("OPNsense API credentials loaded")
        else:
            logger.warning(f"Credentials file not found: {creds_file}")

    def _get(self, endpoint: str) -> dict:
        resp = self.session.get(f"{self.base_url}/{endpoint}")
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict = None) -> dict:
        kwargs = {}
        if data is not None:
            kwargs["json"] = data
            kwargs["headers"] = {"Content-Type": "application/json"}
        resp = self.session.post(f"{self.base_url}/{endpoint}", **kwargs)
        resp.raise_for_status()
        return resp.json()

    def add_ip_to_alias(self, alias_name: str, ip: str, description: str = "") -> bool:
        """Add an IP to a firewall alias (blocklist)."""
        try:
            # Search for alias
            aliases = self._get("firewall/alias/searchItem")
            alias_uuid = None
            for row in aliases.get("rows", []):
                if row.get("name") == alias_name:
                    alias_uuid = row.get("uuid")
                    break

            if not alias_uuid:
                logger.error(f"Alias '{alias_name}' not found")
                return False

            # Get current alias content
            alias_data = self._get(f"firewall/alias/getItem/{alias_uuid}")
            content_raw = alias_data.get("alias", {}).get("content", {})

            # OPNsense returns content as dict: {"ip1": {"selected": 1, ...}, ...}
            # Only entries with selected=1 are actually in the alias;
            # selected=0 entries are other aliases/options shown as available
            if isinstance(content_raw, dict):
                existing_ips = [
                    k for k, v in content_raw.items()
                    if k and isinstance(v, dict) and v.get("selected") == 1
                ]
            elif isinstance(content_raw, str):
                existing_ips = [x.strip() for x in content_raw.split("\n") if x.strip()]
            else:
                existing_ips = []

            # Add IP if not already present
            if ip in existing_ips:
                logger.info(f"IP {ip} already in alias {alias_name}")
                return True

            existing_ips.append(ip)
            new_content = "\n".join(existing_ips)
            result = self._post(f"firewall/alias/setItem/{alias_uuid}", {
                "alias": {"content": new_content}
            })

            if result.get("result") == "saved":
                # Apply changes
                self._post("firewall/alias/reconfigure")
                logger.info(f"Blocked IP {ip} via alias {alias_name}: {description}")
                return True

            return False
        except Exception as e:
            logger.error(f"Failed to add {ip} to alias: {e}")
            return False

    def get_suricata_alerts(self) -> list:
        """Get recent Suricata alerts from OPNsense API."""
        try:
            data = self._get("ids/service/queryAlerts")
            return data.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
