"""
AI-powered Suricata alert analyzer.
Consumes EVE JSON alerts from Redis, analyzes with HiveCoder, stores results.
"""

import json
import hashlib
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import os

import requests

from prompts import (
    SYSTEM_PROMPT,
    ALERT_ANALYSIS_PROMPT,
    BATCH_CORRELATION_PROMPT,
    DAILY_SUMMARY_PROMPT,
)

logger = logging.getLogger(__name__)

HIVECODER_URL = os.environ.get(
    "HIVECODER_URL", "http://127.0.0.1:8090/v1/chat/completions"
)
MAX_TOKENS = 512
CORRELATION_WINDOW = 300  # 5 minutes — group alerts within this window

# ---------------------------------------------------------------------------
# GeoIP enrichment (optional)
# ---------------------------------------------------------------------------
GEOIP_ENABLED = os.environ.get("GEOIP_ENABLED", "0") == "1"
GEOIP_CITY_DB = os.environ.get("GEOIP_CITY_DB", "/app/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.environ.get("GEOIP_ASN_DB", "/app/geoip/GeoLite2-ASN.mmdb")

_geoip_city = None
_geoip_asn = None

if GEOIP_ENABLED:
    try:
        import geoip2.database
        _geoip_city = geoip2.database.Reader(GEOIP_CITY_DB)
        _geoip_asn = geoip2.database.Reader(GEOIP_ASN_DB)
        logger.info("GeoIP databases loaded")
    except Exception as e:
        logger.warning(f"GeoIP init failed (enrichment disabled): {e}")


def geoip_lookup(ip: str) -> dict:
    """Look up country and ASN for an IP. Returns empty dict on failure."""
    if not _geoip_city and not _geoip_asn:
        return {}
    if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
        return {}
    result = {}
    try:
        if _geoip_city:
            city = _geoip_city.city(ip)
            result["country"] = city.country.iso_code or ""
            result["country_name"] = city.country.name or ""
            result["city"] = city.city.name or ""
    except Exception:
        pass
    try:
        if _geoip_asn:
            asn = _geoip_asn.asn(ip)
            result["asn"] = f"AS{asn.autonomous_system_number}" if asn.autonomous_system_number else ""
            result["asn_org"] = asn.autonomous_system_organization or ""
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# AbuseIPDB enrichment (optional)
# ---------------------------------------------------------------------------
ABUSEIPDB_ENABLED = os.environ.get("ABUSEIPDB_ENABLED", "0") == "1"
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
ABUSEIPDB_CACHE_TTL = int(os.environ.get("ABUSEIPDB_CACHE_TTL", "86400"))
_abuseipdb_cache: dict[str, tuple[float, dict]] = {}  # ip -> (timestamp, data)


def abuseipdb_check(ip: str) -> dict:
    """Check an IP against AbuseIPDB. Returns cached or fresh result."""
    if not ABUSEIPDB_ENABLED or not ABUSEIPDB_KEY:
        return {}
    if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
        return {}
    now = time.time()
    if ip in _abuseipdb_cache:
        ts, data = _abuseipdb_cache[ip]
        if now - ts < ABUSEIPDB_CACHE_TTL:
            return data
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            timeout=10,
        )
        resp.raise_for_status()
        raw = resp.json().get("data", {})
        result = {
            "abuse_score": raw.get("abuseConfidenceScore", 0),
            "total_reports": raw.get("totalReports", 0),
            "isp": raw.get("isp", ""),
            "usage_type": raw.get("usageType", ""),
            "domain": raw.get("domain", ""),
            "country": raw.get("countryCode", ""),
        }
        _abuseipdb_cache[ip] = (now, result)
        return result
    except Exception as e:
        logger.debug(f"AbuseIPDB check failed for {ip}: {e}")
        return {}


def abuseipdb_report(ip: str, categories: list[int], comment: str):
    """Report an IP to AbuseIPDB after auto-block."""
    if not ABUSEIPDB_ENABLED or not ABUSEIPDB_KEY:
        return
    try:
        requests.post(
            "https://api.abuseipdb.com/api/v2/report",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            data={
                "ip": ip,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment[:1024],
            },
            timeout=10,
        )
        logger.info(f"Reported {ip} to AbuseIPDB")
    except Exception as e:
        logger.debug(f"AbuseIPDB report failed for {ip}: {e}")


def alert_hash(alert: dict) -> str:
    """Generate a dedup hash for an alert."""
    key = json.dumps({
        "sig": alert.get("alert", {}).get("signature_id", ""),
        "src": alert.get("src_ip", ""),
        "dst": alert.get("dest_ip", ""),
    }, sort_keys=True)
    return hashlib.md5(key.encode()).hexdigest()


def call_hivecoder(prompt: str, system: str = SYSTEM_PROMPT) -> Optional[dict]:
    """Send a prompt to HiveCoder and parse JSON response."""
    try:
        resp = requests.post(
            HIVECODER_URL,
            json={
                "model": "hivecoder",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": MAX_TOKENS,
                "temperature": 0.1,
            },
            timeout=60,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]

        # Extract JSON from response (handle markdown code blocks)
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse HiveCoder response as JSON: {e}")
        logger.debug(f"Raw response: {content}")
        return None
    except Exception as e:
        logger.error(f"HiveCoder call failed: {e}")
        return None


class AlertAnalyzer:
    """Analyzes Suricata alerts using HiveCoder."""

    def __init__(self):
        self.seen_hashes: dict[str, float] = {}  # hash -> timestamp
        self.dedup_ttl = 3600  # 1 hour dedup window
        self.alert_buffer: dict[str, list] = defaultdict(list)  # src_ip -> alerts
        self.stats = {
            "analyzed": 0,
            "deduplicated": 0,
            "critical": 0,
            "high": 0,
            "blocked": 0,
            "errors": 0,
        }

    @staticmethod
    def _time_span(alerts: list) -> int:
        """Calculate seconds between first and last alert."""
        timestamps = []
        for a in alerts:
            ts = a.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    pass
        if len(timestamps) >= 2:
            return int(max(timestamps) - min(timestamps))
        return 0

    def _cleanup_seen(self):
        """Remove expired dedup entries."""
        now = time.time()
        self.seen_hashes = {
            h: t for h, t in self.seen_hashes.items()
            if now - t < self.dedup_ttl
        }

    def is_duplicate(self, alert: dict) -> bool:
        """Check if this alert was recently analyzed."""
        h = alert_hash(alert)
        if h in self.seen_hashes:
            self.stats["deduplicated"] += 1
            return True
        self.seen_hashes[h] = time.time()
        return False

    def analyze_alert(self, alert: dict) -> Optional[dict]:
        """Analyze a single Suricata alert with HiveCoder."""
        if self.is_duplicate(alert):
            return None

        self._cleanup_seen()

        # Build rich alert context for LLM
        alert_sub = alert.get("alert", {})
        alert_context = {
            "signature": alert_sub.get("signature", ""),
            "signature_id": alert_sub.get("signature_id", ""),
            "category": alert_sub.get("category", ""),
            "severity": alert_sub.get("severity", ""),
            "action": alert_sub.get("action", ""),
            "src_ip": alert.get("src_ip", ""),
            "src_port": alert.get("src_port", ""),
            "dest_ip": alert.get("dest_ip", ""),
            "dest_port": alert.get("dest_port", ""),
            "proto": alert.get("proto", ""),
            "app_proto": alert.get("app_proto", ""),
            "direction": alert.get("direction", ""),
            "timestamp": alert.get("timestamp", ""),
            "in_iface": alert.get("in_iface", ""),
        }

        # Suricata rule metadata (author's confidence/severity assessment)
        metadata = alert_sub.get("metadata", {})
        if metadata:
            alert_context["rule_metadata"] = {
                k: v[0] if isinstance(v, list) and len(v) == 1 else v
                for k, v in metadata.items()
            }

        # Flow data (packet/byte counts, duration)
        flow = alert.get("flow", {})
        if flow:
            alert_context["flow"] = {
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "age": flow.get("age", 0),
                "state": flow.get("state", ""),
            }

        # Add payload sample if present
        if "payload_printable" in alert:
            alert_context["payload_sample"] = alert["payload_printable"][:300]

        # GeoIP enrichment
        src_geo = geoip_lookup(alert_context["src_ip"])
        dst_geo = geoip_lookup(alert_context["dest_ip"])
        if src_geo:
            alert_context["src_geo"] = src_geo
        if dst_geo:
            alert_context["dest_geo"] = dst_geo

        # AbuseIPDB enrichment
        abuse_data = abuseipdb_check(alert_context["src_ip"])
        if abuse_data:
            alert_context["abuseipdb"] = abuse_data

        prompt = ALERT_ANALYSIS_PROMPT.format(
            alert_json=json.dumps(alert_context, indent=2)
        )

        result = call_hivecoder(prompt)
        if result:
            self.stats["analyzed"] += 1
            severity = result.get("severity", "info")
            if severity == "critical":
                self.stats["critical"] += 1
            elif severity == "high":
                self.stats["high"] += 1

            # Attach analysis to original alert
            result["alert_hash"] = alert_hash(alert)
            result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            result["source_alert"] = alert_context
            return result
        else:
            self.stats["errors"] += 1
            return None

    def buffer_for_correlation(self, alert: dict):
        """Buffer an alert for batch correlation analysis."""
        src_ip = alert.get("src_ip", "unknown")
        self.alert_buffer[src_ip].append(alert)

    def correlate_buffered(self) -> list[dict]:
        """Run correlation analysis on buffered alerts grouped by source IP."""
        results = []
        for src_ip, alerts in self.alert_buffer.items():
            if len(alerts) < 3:
                continue  # Not enough for correlation

            # Build rich summary for LLM
            alert_summaries = []
            for a in alerts[-20:]:  # Last 20 alerts max
                entry = {
                    "signature": a.get("alert", {}).get("signature", ""),
                    "severity": a.get("alert", {}).get("severity", ""),
                    "category": a.get("alert", {}).get("category", ""),
                    "dest_ip": a.get("dest_ip", ""),
                    "dest_port": a.get("dest_port", ""),
                    "proto": a.get("proto", ""),
                    "app_proto": a.get("app_proto", ""),
                    "direction": a.get("direction", ""),
                    "timestamp": a.get("timestamp", ""),
                }
                flow = a.get("flow", {})
                if flow:
                    entry["pkts"] = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
                    entry["bytes"] = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
                alert_summaries.append(entry)

            # Unique destination ports for scan detection
            dest_ports = sorted(set(
                a.get("dest_port", 0) for a in alerts if a.get("dest_port")
            ))

            prompt = BATCH_CORRELATION_PROMPT.format(
                alerts_json=json.dumps({
                    "source_ip": src_ip,
                    "alert_count": len(alerts),
                    "unique_dest_ports": len(dest_ports),
                    "dest_ports_sample": dest_ports[:30],
                    "time_span_seconds": self._time_span(alerts),
                    "alerts": alert_summaries,
                }, indent=2)
            )

            result = call_hivecoder(prompt)
            if result:
                result["source_ip"] = src_ip
                result["alert_count"] = len(alerts)
                result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
                # GeoIP enrichment for correlation
                src_geo = geoip_lookup(src_ip)
                if src_geo:
                    result["source_geo"] = src_geo
                results.append(result)

        self.alert_buffer.clear()
        return results

    def generate_daily_summary(self, day_stats: dict) -> Optional[dict]:
        """Generate an AI-powered daily threat summary."""
        prompt = DAILY_SUMMARY_PROMPT.format(
            stats_json=json.dumps(day_stats, indent=2)
        )
        return call_hivecoder(prompt)
