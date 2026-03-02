#!/usr/bin/env python3
"""
AI Suricata MCP Server

Exposes Suricata IDS threat intelligence via Model Context Protocol.
Connects to Redis cluster for alert data and HiveCoder for AI analysis.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp
import redis.asyncio as aioredis
from redis.asyncio.cluster import RedisCluster, ClusterNode

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Log to stderr — stdout is MCP JSON-RPC protocol
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ai-suricata-mcp")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_NODES = [
    {"host": "127.0.0.1", "port": 7000},
    {"host": "127.0.0.1", "port": 7001},
    {"host": "127.0.0.1", "port": 7002},
]
REDIS_PASS = os.environ.get(
    "REDIS_PASS", "P1MC0OSpZ9Iuss5b36Bmpl2U9Yf5JwtFJTXf2Eb5WkQ="
)

HIVECODER_URL = os.environ.get("HIVECODER_URL", "http://127.0.0.1:8090")
OPNSENSE_URL = os.environ.get("OPNSENSE_URL", "https://192.168.1.1/api")
OPNSENSE_CREDS = os.environ.get("OPNSENSE_CREDS", "/tmp/.opn_creds")

# Redis keys
KEY_ALERTS = "suricata:alerts"
KEY_EVE = "suricata:eve"
KEY_AI_RESULTS = "suricata:ai_results"
KEY_AI_CORRELATIONS = "suricata:ai_correlations"
KEY_AI_SUMMARY = "suricata:ai_daily_summary"
KEY_AI_BLOCKS = "suricata:ai_blocks"
KEY_REPEAT_OFFENDERS = "suricata:repeat_offenders"
KEY_REPEAT_TS = "suricata:repeat_offender_ts"
KEY_DAILY_STATS = "suricata:daily_stats"
KEY_DNSBL = "suricata:dnsbl"

# Prompts (inline — keep MCP server self-contained)
ANALYSIS_SYSTEM = (
    "/no_think You are a cybersecurity threat analyst specializing in IDS/IPS alert triage. "
    "You analyze Suricata EVE JSON alerts and provide structured assessments. "
    "Always respond in valid JSON format with the exact schema requested. "
    "Be concise and precise. Focus on actionable intelligence."
)

ANALYSIS_PROMPT = """Analyze this Suricata IDS alert and provide a threat assessment.

Alert data:
```json
{alert_json}
```

Respond with ONLY valid JSON in this exact schema:
{{
  "severity": "critical|high|medium|low|info",
  "category": "scan|exploit|c2|exfiltration|malware|dos|bruteforce|policy|info|false_positive",
  "confidence": 0.0-1.0,
  "false_positive_likelihood": "high|medium|low",
  "description": "one sentence summary of the threat",
  "recommended_action": "block|monitor|investigate|ignore",
  "ioc_type": "ip|domain|url|hash|none",
  "context": "brief technical context"
}}"""

CORRELATION_PROMPT = """/think Analyze these related Suricata alerts for attack correlation.
Look for patterns: scanning followed by exploitation, lateral movement, C2 callbacks, data exfiltration.

Alerts (grouped by source IP):
```json
{alerts_json}
```

Respond with ONLY valid JSON:
{{
  "attack_pattern": "reconnaissance|exploitation|persistence|lateral_movement|exfiltration|none",
  "kill_chain_stage": "reconnaissance|weaponization|delivery|exploitation|installation|c2|actions_on_objectives|none",
  "campaign_likely": true/false,
  "threat_actor_profile": "automated_scanner|opportunistic|targeted|apt|unknown",
  "severity_override": "critical|high|medium|low|null",
  "summary": "1-2 sentence campaign summary",
  "recommended_actions": ["list of recommended actions"]
}}"""


# ---------------------------------------------------------------------------
# Core MCP Backend
# ---------------------------------------------------------------------------
class AISuricataMCP:
    """AI Suricata threat intelligence backend."""

    def __init__(self):
        self.redis: Optional[RedisCluster] = None
        self.http_session: Optional[aiohttp.ClientSession] = None

    async def connect(self):
        """Connect to Redis cluster."""
        startup_nodes = [
            ClusterNode(n["host"], n["port"]) for n in REDIS_NODES
        ]
        self.redis = RedisCluster(
            startup_nodes=startup_nodes,
            password=REDIS_PASS,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
        )
        await self.redis.initialize()
        await self.redis.ping()
        logger.info("Connected to Redis cluster")

        self.http_session = aiohttp.ClientSession()

    async def disconnect(self):
        if self.redis:
            await self.redis.aclose()
        if self.http_session:
            await self.http_session.close()

    # -------------------------------------------------------------------
    # Tool implementations
    # -------------------------------------------------------------------

    async def threat_status(self) -> dict:
        """Get current threat posture overview."""
        # Counts
        alert_count = await self.redis.llen(KEY_ALERTS)
        eve_count = await self.redis.llen(KEY_EVE)
        result_count = await self.redis.llen(KEY_AI_RESULTS)
        block_count = await self.redis.llen(KEY_AI_BLOCKS)

        # Latest daily summary
        summary_raw = await self.redis.get(KEY_AI_SUMMARY)
        summary = json.loads(summary_raw) if summary_raw else None

        # Recent critical/high results
        critical_alerts = []
        raw_results = await self.redis.lrange(KEY_AI_RESULTS, 0, 49)
        for raw in raw_results:
            try:
                r = json.loads(raw)
                if r.get("severity") in ("critical", "high"):
                    critical_alerts.append({
                        "severity": r["severity"],
                        "category": r.get("category", "?"),
                        "description": r.get("description", ""),
                        "src_ip": r.get("source_alert", {}).get("src_ip", "?"),
                        "dest_ip": r.get("source_alert", {}).get("dest_ip", "?"),
                        "action": r.get("recommended_action", "?"),
                        "analyzed_at": r.get("analyzed_at", ""),
                    })
            except json.JSONDecodeError:
                continue

        # Repeat offenders (top 10)
        repeat_offenders = []
        try:
            top = await self.redis.zrevrangebyscore(
                KEY_REPEAT_OFFENDERS, "+inf", "1", start=0, num=10, withscores=True
            )
            for ip, score in top:
                repeat_offenders.append({"ip": ip, "appearances": int(score)})
        except Exception:
            pass

        return {
            "queued_alerts": alert_count,
            "total_eve_events": eve_count,
            "ai_results_stored": result_count,
            "ips_blocked": block_count,
            "daily_summary": summary,
            "recent_critical": critical_alerts[:10],
            "repeat_offenders": repeat_offenders,
        }

    async def query_alerts(
        self, limit: int = 20, severity: Optional[str] = None,
        src_ip: Optional[str] = None, category: Optional[str] = None,
    ) -> dict:
        """Query analyzed alert results with optional filters."""
        results = []
        # Scan more than limit to account for filtering
        scan_limit = limit * 5 if (severity or src_ip or category) else limit
        raw_results = await self.redis.lrange(KEY_AI_RESULTS, 0, scan_limit - 1)

        for raw in raw_results:
            try:
                r = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # Apply filters
            if severity and r.get("severity") != severity:
                continue
            if category and r.get("category") != category:
                continue
            if src_ip:
                alert_src = r.get("source_alert", {}).get("src_ip", "")
                if alert_src != src_ip:
                    continue

            results.append(r)
            if len(results) >= limit:
                break

        return {
            "count": len(results),
            "results": results,
        }

    async def query_raw_alerts(self, limit: int = 20) -> dict:
        """Query raw (unanalyzed) Suricata alerts from the queue."""
        raw = await self.redis.lrange(KEY_ALERTS, 0, limit - 1)
        alerts = []
        for item in raw:
            try:
                alerts.append(json.loads(item))
            except json.JSONDecodeError:
                continue
        return {"count": len(alerts), "alerts": alerts}

    async def analyze_alert(self, alert: dict) -> dict:
        """Send an alert to HiveCoder for AI analysis."""
        # Build concise context
        alert_context = {
            "signature": alert.get("alert", {}).get("signature", ""),
            "signature_id": alert.get("alert", {}).get("signature_id", ""),
            "category": alert.get("alert", {}).get("category", ""),
            "severity": alert.get("alert", {}).get("severity", ""),
            "src_ip": alert.get("src_ip", ""),
            "src_port": alert.get("src_port", ""),
            "dest_ip": alert.get("dest_ip", ""),
            "dest_port": alert.get("dest_port", ""),
            "proto": alert.get("proto", ""),
            "timestamp": alert.get("timestamp", ""),
            "app_proto": alert.get("app_proto", ""),
        }
        if "payload_printable" in alert:
            alert_context["payload_sample"] = alert["payload_printable"][:200]

        prompt = ANALYSIS_PROMPT.format(
            alert_json=json.dumps(alert_context, indent=2)
        )

        result = await self._call_hivecoder(prompt, ANALYSIS_SYSTEM)
        if result:
            result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            result["source_alert"] = alert_context
            # Store result
            await self.redis.lpush(
                KEY_AI_RESULTS, json.dumps(result, separators=(",", ":"))
            )
            await self.redis.ltrim(KEY_AI_RESULTS, 0, 49999)
        return result or {"error": "HiveCoder analysis failed"}

    async def analyze_ip(self, ip: str, limit: int = 20) -> dict:
        """Correlate all recent alerts from a specific IP."""
        # Gather alerts for this IP from raw EVE events
        raw_events = await self.redis.lrange(KEY_EVE, 0, 4999)
        ip_alerts = []
        for raw in raw_events:
            try:
                evt = json.loads(raw)
                if evt.get("event_type") != "alert":
                    continue
                if evt.get("src_ip") == ip or evt.get("dest_ip") == ip:
                    ip_alerts.append({
                        "signature": evt.get("alert", {}).get("signature", ""),
                        "dest_ip": evt.get("dest_ip", ""),
                        "dest_port": evt.get("dest_port", ""),
                        "src_ip": evt.get("src_ip", ""),
                        "proto": evt.get("proto", ""),
                        "timestamp": evt.get("timestamp", ""),
                    })
            except json.JSONDecodeError:
                continue
            if len(ip_alerts) >= limit:
                break

        if not ip_alerts:
            return {"ip": ip, "alert_count": 0, "message": "No alerts found for this IP"}

        # Run correlation via HiveCoder
        alerts_payload = {
            "source_ip": ip,
            "alert_count": len(ip_alerts),
            "alerts": ip_alerts,
        }
        prompt = CORRELATION_PROMPT.format(
            alerts_json=json.dumps(alerts_payload, indent=2)
        )
        result = await self._call_hivecoder(prompt, ANALYSIS_SYSTEM, max_tokens=1024)
        if result:
            result["source_ip"] = ip
            result["alert_count"] = len(ip_alerts)
            result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            await self.redis.lpush(
                KEY_AI_CORRELATIONS, json.dumps(result, separators=(",", ":"))
            )
            await self.redis.ltrim(KEY_AI_CORRELATIONS, 0, 49999)
        return result or {"error": "Correlation analysis failed"}

    async def get_correlations(self, limit: int = 10) -> dict:
        """Get recent correlation analysis results."""
        raw = await self.redis.lrange(KEY_AI_CORRELATIONS, 0, limit - 1)
        results = []
        for item in raw:
            try:
                results.append(json.loads(item))
            except json.JSONDecodeError:
                continue
        return {"count": len(results), "correlations": results}

    async def get_blocks(self, limit: int = 50) -> dict:
        """Get list of AI-blocked IPs."""
        raw = await self.redis.lrange(KEY_AI_BLOCKS, 0, limit - 1)
        blocks = []
        for item in raw:
            try:
                blocks.append(json.loads(item))
            except json.JSONDecodeError:
                continue
        return {"count": len(blocks), "blocks": blocks}

    async def block_ip(self, ip: str, reason: str = "Manual block via MCP") -> dict:
        """Manually block an IP via OPNsense firewall alias."""
        # Refuse to block local IPs
        if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
            return {"success": False, "error": "Refusing to block local/private IP"}

        try:
            key, secret = self._load_opnsense_creds()
        except Exception as e:
            return {"success": False, "error": f"OPNsense creds unavailable: {e}"}

        alias_name = os.environ.get("BLOCK_ALIAS", "ai_blocklist")
        try:
            # Search for alias
            async with self.http_session.get(
                f"{OPNSENSE_URL}/firewall/alias/searchItem",
                auth=aiohttp.BasicAuth(key, secret),
                ssl=False,
            ) as resp:
                aliases = await resp.json()

            alias_uuid = None
            for row in aliases.get("rows", []):
                if row.get("name") == alias_name:
                    alias_uuid = row.get("uuid")
                    break

            if not alias_uuid:
                return {"success": False, "error": f"Alias '{alias_name}' not found on OPNsense"}

            # Get current content
            async with self.http_session.get(
                f"{OPNSENSE_URL}/firewall/alias/getItem/{alias_uuid}",
                auth=aiohttp.BasicAuth(key, secret),
                ssl=False,
            ) as resp:
                alias_data = await resp.json()

            content_raw = alias_data.get("alias", {}).get("content", {})

            # OPNsense returns content as dict: {"ip1": {"selected": 1, ...}, ...}
            # Only entries with selected=1 are actually in the alias
            if isinstance(content_raw, dict):
                existing_ips = [
                    k for k, v in content_raw.items()
                    if k and isinstance(v, dict) and v.get("selected") == 1
                ]
            elif isinstance(content_raw, str):
                existing_ips = [x.strip() for x in content_raw.split("\n") if x.strip()]
            else:
                existing_ips = []

            if ip in existing_ips:
                return {"success": True, "message": f"IP {ip} already blocked"}

            existing_ips.append(ip)
            new_content = "\n".join(existing_ips)

            async with self.http_session.post(
                f"{OPNSENSE_URL}/firewall/alias/setItem/{alias_uuid}",
                auth=aiohttp.BasicAuth(key, secret),
                json={"alias": {"content": new_content}},
                ssl=False,
            ) as resp:
                result = await resp.json()

            if result.get("result") == "saved":
                # Apply changes
                async with self.http_session.post(
                    f"{OPNSENSE_URL}/firewall/alias/reconfigure",
                    auth=aiohttp.BasicAuth(key, secret),
                    ssl=False,
                ) as resp:
                    await resp.json()

                # Log the block
                block_entry = {
                    "ip": ip,
                    "reason": reason,
                    "blocked_at": datetime.now(timezone.utc).isoformat(),
                    "source": "mcp_manual",
                }
                await self.redis.lpush(
                    KEY_AI_BLOCKS, json.dumps(block_entry, separators=(",", ":"))
                )
                await self.redis.ltrim(KEY_AI_BLOCKS, 0, 9999)

                return {"success": True, "message": f"Blocked {ip}: {reason}"}

            return {"success": False, "error": "OPNsense API returned unexpected result"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def top_talkers(self, limit: int = 10) -> dict:
        """Find top source IPs by alert volume."""
        raw = await self.redis.lrange(KEY_EVE, 0, 4999)
        ip_counts: Dict[str, int] = {}
        for item in raw:
            try:
                evt = json.loads(item)
                if evt.get("event_type") != "alert":
                    continue
                src = evt.get("src_ip", "unknown")
                ip_counts[src] = ip_counts.get(src, 0) + 1
            except json.JSONDecodeError:
                continue

        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return {
            "total_alert_events": sum(ip_counts.values()),
            "unique_sources": len(ip_counts),
            "top_talkers": [
                {"ip": ip, "alert_count": count}
                for ip, count in sorted_ips[:limit]
            ],
        }

    async def search_signature(self, pattern: str, limit: int = 20) -> dict:
        """Search alerts by signature name pattern."""
        raw = await self.redis.lrange(KEY_EVE, 0, 9999)
        matches = []
        pattern_lower = pattern.lower()
        for item in raw:
            try:
                evt = json.loads(item)
                if evt.get("event_type") != "alert":
                    continue
                sig = evt.get("alert", {}).get("signature", "")
                if pattern_lower in sig.lower():
                    matches.append({
                        "signature": sig,
                        "signature_id": evt.get("alert", {}).get("signature_id", ""),
                        "src_ip": evt.get("src_ip", ""),
                        "dest_ip": evt.get("dest_ip", ""),
                        "dest_port": evt.get("dest_port", ""),
                        "timestamp": evt.get("timestamp", ""),
                    })
            except json.JSONDecodeError:
                continue
            if len(matches) >= limit:
                break

        return {"pattern": pattern, "count": len(matches), "matches": matches}

    async def get_stats(self) -> dict:
        """Get service statistics."""
        alert_count = await self.redis.llen(KEY_ALERTS)
        eve_count = await self.redis.llen(KEY_EVE)
        result_count = await self.redis.llen(KEY_AI_RESULTS)
        corr_count = await self.redis.llen(KEY_AI_CORRELATIONS)
        block_count = await self.redis.llen(KEY_AI_BLOCKS)

        # Check HiveCoder health
        llm_status = "unknown"
        try:
            async with self.http_session.get(
                f"{HIVECODER_URL}/health", timeout=aiohttp.ClientTimeout(total=3)
            ) as resp:
                if resp.status == 200:
                    llm_status = "healthy"
                else:
                    llm_status = f"unhealthy (HTTP {resp.status})"
        except Exception:
            llm_status = "unreachable"

        # Repeat offender count
        try:
            repeat_count = await self.redis.zcard(KEY_REPEAT_OFFENDERS)
        except Exception:
            repeat_count = 0

        return {
            "redis": {
                "queued_alerts": alert_count,
                "eve_events": eve_count,
                "ai_results": result_count,
                "correlations": corr_count,
                "blocked_ips": block_count,
                "repeat_offenders": repeat_count,
            },
            "hivecoder": llm_status,
            "opnsense": OPNSENSE_URL,
        }

    async def get_trends(self, days: int = 7) -> dict:
        """Get historical daily stats for trend analysis."""
        try:
            raw = await self.redis.zrangebyscore(KEY_DAILY_STATS, "-inf", "+inf")
            all_days = []
            for item in raw:
                try:
                    all_days.append(json.loads(item))
                except json.JSONDecodeError:
                    pass
            all_days.sort(key=lambda x: x.get("date", ""))
            recent = all_days[-days:] if len(all_days) >= days else all_days

            if len(recent) < 2:
                return {"days": recent, "trend": "insufficient_data"}

            totals = [d.get("total_alerts", 0) for d in recent]
            mean = sum(totals) / len(totals)
            variance = sum((x - mean) ** 2 for x in totals) / len(totals)
            stddev = variance ** 0.5

            today_total = recent[-1].get("total_alerts", 0)
            anomaly = today_total > (mean + 2 * stddev) if stddev > 0 else False

            if len(totals) >= 3:
                first_half = sum(totals[:len(totals)//2]) / (len(totals)//2)
                second_half = sum(totals[len(totals)//2:]) / (len(totals) - len(totals)//2)
                if second_half > first_half * 1.2:
                    trend = "increasing"
                elif second_half < first_half * 0.8:
                    trend = "decreasing"
                else:
                    trend = "stable"
            else:
                trend = "insufficient_data"

            return {
                "days": recent,
                "stats": {
                    "mean": round(mean, 1),
                    "stddev": round(stddev, 1),
                    "anomaly_today": anomaly,
                    "trend": trend,
                },
            }
        except Exception as e:
            return {"error": str(e)}

    async def get_dnsbl(self, limit: int = 100) -> dict:
        """Get AI-curated domain blocklist."""
        try:
            raw = await self.redis.hgetall(KEY_DNSBL)
            entries = []
            for domain, data in raw.items():
                try:
                    d = json.loads(data)
                    d["domain"] = domain
                    entries.append(d)
                except (json.JSONDecodeError, TypeError):
                    pass
            entries.sort(key=lambda x: x.get("added_at", ""), reverse=True)
            return {
                "count": len(entries),
                "domains": entries[:limit],
                "feed_url": "http://alderlake:8080/api/dnsbl.txt",
            }
        except Exception as e:
            return {"error": str(e)}

    async def check_reputation(self, ip: str) -> dict:
        """Check IP reputation via AbuseIPDB (with Redis cache)."""
        if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
            return {"ip": ip, "error": "Private IP — no external reputation data"}

        # Check Redis cache first
        cache_key = f"abuseipdb:{ip}"
        try:
            cached = await self.redis.get(cache_key)
            if cached:
                result = json.loads(cached)
                result["cached"] = True
                return result
        except Exception:
            pass

        # Call AbuseIPDB
        api_key = os.environ.get("ABUSEIPDB_KEY", "")
        if not api_key:
            return {"ip": ip, "error": "ABUSEIPDB_KEY not configured"}

        try:
            async with self.http_session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

            raw = data.get("data", {})
            result = {
                "ip": ip,
                "abuse_score": raw.get("abuseConfidenceScore", 0),
                "total_reports": raw.get("totalReports", 0),
                "isp": raw.get("isp", ""),
                "usage_type": raw.get("usageType", ""),
                "domain": raw.get("domain", ""),
                "country": raw.get("countryCode", ""),
                "is_tor": raw.get("isTor", False),
                "last_reported": raw.get("lastReportedAt", ""),
                "cached": False,
            }

            # Cache for 24h
            try:
                await self.redis.setex(cache_key, 86400, json.dumps(result))
            except Exception:
                pass

            return result
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    async def _call_hivecoder(
        self, prompt: str, system: str = ANALYSIS_SYSTEM,
        max_tokens: int = 512,
    ) -> Optional[dict]:
        """Send a prompt to HiveCoder and parse JSON response."""
        try:
            async with self.http_session.post(
                f"{HIVECODER_URL}/v1/chat/completions",
                json={
                    "model": "hivecoder",
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.1,
                },
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

            content = data["choices"][0]["message"]["content"].strip()
            # Strip markdown code blocks
            if content.startswith("```"):
                content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse HiveCoder JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"HiveCoder call failed: {e}")
            return None

    def _load_opnsense_creds(self) -> tuple:
        """Load OPNsense API credentials."""
        creds_path = OPNSENSE_CREDS
        with open(creds_path) as f:
            creds = f.read().strip()
        key, secret = creds.split(":")
        return key, secret


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
async def main():
    logger.info("Starting AI Suricata MCP Server")

    backend = AISuricataMCP()
    await backend.connect()

    server = Server("ai-suricata")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="threat_status",
                description=(
                    "Get current network threat posture: queued alerts, "
                    "blocked IPs, daily summary, and recent critical threats."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="query_alerts",
                description=(
                    "Query AI-analyzed Suricata alert results. "
                    "Filter by severity, source IP, or attack category."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "number",
                            "description": "Max results (default 20)",
                            "default": 20,
                        },
                        "severity": {
                            "type": "string",
                            "description": "Filter: critical, high, medium, low, info",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "src_ip": {
                            "type": "string",
                            "description": "Filter by source IP address",
                        },
                        "category": {
                            "type": "string",
                            "description": "Filter: scan, exploit, c2, exfiltration, malware, dos, bruteforce, policy, info, false_positive",
                        },
                    },
                },
            ),
            Tool(
                name="query_raw_alerts",
                description="Get raw (unanalyzed) Suricata alerts waiting in the queue.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "number",
                            "description": "Max alerts to return (default 20)",
                            "default": 20,
                        },
                    },
                },
            ),
            Tool(
                name="analyze_alert",
                description=(
                    "Send a specific alert to HiveCoder for AI threat analysis. "
                    "Provide raw Suricata EVE JSON alert data."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "alert": {
                            "type": "object",
                            "description": "Raw Suricata EVE JSON alert object",
                        },
                    },
                    "required": ["alert"],
                },
            ),
            Tool(
                name="analyze_ip",
                description=(
                    "Run correlation analysis on all recent alerts from/to a specific IP. "
                    "Uses HiveCoder thinking mode to identify attack patterns and kill chain stage."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address to investigate",
                        },
                        "limit": {
                            "type": "number",
                            "description": "Max alerts to analyze (default 20)",
                            "default": 20,
                        },
                    },
                    "required": ["ip"],
                },
            ),
            Tool(
                name="get_correlations",
                description="Get recent attack correlation analysis results.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "number",
                            "description": "Max results (default 10)",
                            "default": 10,
                        },
                    },
                },
            ),
            Tool(
                name="top_talkers",
                description="Find the top source IPs by alert volume — the noisiest attackers.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "number",
                            "description": "Number of top IPs to return (default 10)",
                            "default": 10,
                        },
                    },
                },
            ),
            Tool(
                name="search_signature",
                description="Search Suricata alerts by signature name pattern (e.g., 'SSH', 'ET SCAN', 'malware').",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Signature name search pattern (case-insensitive)",
                        },
                        "limit": {
                            "type": "number",
                            "description": "Max results (default 20)",
                            "default": 20,
                        },
                    },
                    "required": ["pattern"],
                },
            ),
            Tool(
                name="get_blocks",
                description="List IPs that have been blocked by AI Suricata or manually.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "number",
                            "description": "Max results (default 50)",
                            "default": 50,
                        },
                    },
                },
            ),
            Tool(
                name="block_ip",
                description=(
                    "Manually block an IP address via OPNsense firewall alias. "
                    "Cannot block private/local IPs. Requires OPNsense API credentials."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "Public IP address to block",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for blocking",
                            "default": "Manual block via MCP",
                        },
                    },
                    "required": ["ip"],
                },
            ),
            Tool(
                name="suricata_stats",
                description="Get AI Suricata service statistics: Redis queue depths, HiveCoder health, block counts.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="get_trends",
                description="Get historical alert trend data with anomaly detection. Shows daily totals, 7-day mean/stddev, and trend direction.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days": {
                            "type": "number",
                            "description": "Number of days to return (default 7, max 90)",
                            "default": 7,
                        },
                    },
                },
            ),
            Tool(
                name="get_dnsbl",
                description="Get AI-curated domain blocklist. Domains extracted from confirmed-malicious alerts (C2, malware, exploits). Feed URL for OPNsense Unbound integration.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "number",
                            "description": "Max domains to return (default 100)",
                            "default": 100,
                        },
                    },
                },
            ),
            Tool(
                name="check_reputation",
                description="Check IP reputation via AbuseIPDB. Returns abuse score (0-100), report count, ISP, and country. Results cached for 24h.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "Public IP address to check",
                        },
                    },
                    "required": ["ip"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            if name == "threat_status":
                result = await backend.threat_status()
            elif name == "query_alerts":
                result = await backend.query_alerts(
                    limit=arguments.get("limit", 20),
                    severity=arguments.get("severity"),
                    src_ip=arguments.get("src_ip"),
                    category=arguments.get("category"),
                )
            elif name == "query_raw_alerts":
                result = await backend.query_raw_alerts(
                    limit=arguments.get("limit", 20),
                )
            elif name == "analyze_alert":
                result = await backend.analyze_alert(alert=arguments["alert"])
            elif name == "analyze_ip":
                result = await backend.analyze_ip(
                    ip=arguments["ip"],
                    limit=arguments.get("limit", 20),
                )
            elif name == "get_correlations":
                result = await backend.get_correlations(
                    limit=arguments.get("limit", 10),
                )
            elif name == "top_talkers":
                result = await backend.top_talkers(
                    limit=arguments.get("limit", 10),
                )
            elif name == "search_signature":
                result = await backend.search_signature(
                    pattern=arguments["pattern"],
                    limit=arguments.get("limit", 20),
                )
            elif name == "get_blocks":
                result = await backend.get_blocks(
                    limit=arguments.get("limit", 50),
                )
            elif name == "block_ip":
                result = await backend.block_ip(
                    ip=arguments["ip"],
                    reason=arguments.get("reason", "Manual block via MCP"),
                )
            elif name == "suricata_stats":
                result = await backend.get_stats()
            elif name == "get_trends":
                result = await backend.get_trends(
                    days=min(arguments.get("days", 7), 90),
                )
            elif name == "get_dnsbl":
                result = await backend.get_dnsbl(
                    limit=arguments.get("limit", 100),
                )
            elif name == "check_reputation":
                result = await backend.check_reputation(ip=arguments["ip"])
            else:
                result = {"error": f"Unknown tool: {name}"}

            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        except Exception as e:
            logger.error(f"Error calling tool {name}: {e}", exc_info=True)
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    logger.info("AI Suricata MCP Server ready!")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
