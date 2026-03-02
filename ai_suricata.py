#!/usr/bin/env python3
"""
AI Suricata — HiveCoder-powered threat analysis daemon.

Consumes Suricata alerts from Redis, analyzes with HiveCoder (Qwen3-14B),
stores enriched results, and optionally auto-blocks threats via OPNsense API.
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from redis.cluster import RedisCluster, ClusterNode

from analyzer import AlertAnalyzer
from opnsense_api import OPNsenseAPI

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "7000"))
REDIS_PASS = os.environ.get(
    "REDIS_PASS", "P1MC0OSpZ9Iuss5b36Bmpl2U9Yf5JwtFJTXf2Eb5WkQ="
)

# Redis keys
ALERT_KEY = "suricata:alerts"          # incoming alerts (from eve_receiver)
RESULT_KEY = "suricata:ai_results"     # enriched analysis results
CORRELATION_KEY = "suricata:ai_correlations"
SUMMARY_KEY = "suricata:ai_daily_summary"
BLOCK_LOG_KEY = "suricata:ai_blocks"   # auto-block audit log
REPEAT_KEY = "suricata:repeat_offenders"      # repeat offender scores
REPEAT_TS_KEY = "suricata:repeat_offender_ts"  # first-seen timestamps
DAILY_STATS_KEY = "suricata:daily_stats"       # historical daily stats
DNSBL_KEY = "suricata:dnsbl"                   # AI-curated domain blocklist

# Behaviour
POLL_INTERVAL = 2          # seconds between Redis polls
CORRELATION_INTERVAL = 300  # run correlation every 5 minutes
SUMMARY_HOUR = 2           # generate daily summary at 2 AM UTC
MAX_RESULTS = 50000        # keep last N results in Redis
MAX_BLOCKS = 10000

# Auto-blocking
AUTO_BLOCK_ENABLED = os.environ.get("AUTO_BLOCK", "0") == "1"
AUTO_BLOCK_CONFIDENCE = float(os.environ.get("AUTO_BLOCK_CONFIDENCE", "0.9"))
BLOCK_ALIAS = os.environ.get("BLOCK_ALIAS", "ai_blocklist")

# Repeat offender detection
REPEAT_OFFENDER_THRESHOLD = int(os.environ.get("REPEAT_THRESHOLD", "3"))
REPEAT_OFFENDER_WINDOW = int(os.environ.get("REPEAT_WINDOW", "86400"))  # 24h

# NAS storage
NAS_RESULTS_DIR = Path("/var/mnt/ai/suricata/ai_results")

# Logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ai_suricata")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
running = True


def signal_handler(sig, frame):
    global running
    logger.info("Shutdown signal received")
    running = False


def connect_redis() -> RedisCluster:
    """Connect to Redis cluster with retry."""
    while running:
        try:
            nodes = [ClusterNode(REDIS_HOST, REDIS_PORT)]
            rc = RedisCluster(
                startup_nodes=nodes,
                password=REDIS_PASS,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            rc.ping()
            logger.info("Connected to Redis cluster")
            return rc
        except Exception as e:
            logger.warning(f"Redis connect failed: {e}, retrying in 5s")
            time.sleep(5)


def store_result(rc: RedisCluster, key: str, result: dict, max_len: int):
    """Push a result to a Redis list and trim."""
    rc.lpush(key, json.dumps(result, separators=(",", ":")))
    rc.ltrim(key, 0, max_len - 1)


def write_result_to_nas(result: dict):
    """Append a result to today's NAS log file."""
    try:
        NAS_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = NAS_RESULTS_DIR / f"analysis-{today}.jsonl"
        with open(path, "a") as f:
            f.write(json.dumps(result, separators=(",", ":")) + "\n")
    except Exception as e:
        logger.warning(f"NAS write failed: {e}")


def update_repeat_offenders(rc: RedisCluster, ips: list[str]):
    """Increment correlation appearance count for each source IP."""
    now = str(time.time())
    for ip in ips:
        if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
            continue
        rc.zincrby(REPEAT_KEY, 1, ip)
        if not rc.hexists(REPEAT_TS_KEY, ip):
            rc.hset(REPEAT_TS_KEY, ip, now)


def prune_repeat_offenders(rc: RedisCluster):
    """Remove repeat offender entries older than the tracking window."""
    cutoff = time.time() - REPEAT_OFFENDER_WINDOW
    all_ts = rc.hgetall(REPEAT_TS_KEY)
    for ip_bytes, ts_bytes in all_ts.items():
        try:
            ip = ip_bytes if isinstance(ip_bytes, str) else ip_bytes.decode()
            ts = float(ts_bytes if isinstance(ts_bytes, str) else ts_bytes.decode())
            if ts < cutoff:
                rc.zrem(REPEAT_KEY, ip)
                rc.hdel(REPEAT_TS_KEY, ip)
        except (ValueError, TypeError):
            pass


def _map_category_to_abuseipdb(category: str) -> list[int]:
    """Map AI Suricata categories to AbuseIPDB category IDs."""
    mapping = {
        "scan": [14],          # Port scan
        "exploit": [15],       # Hacking
        "c2": [15, 20],        # Hacking + Exploited Host
        "exfiltration": [15],  # Hacking
        "malware": [15, 20],   # Hacking + Exploited Host
        "dos": [4],            # DDoS Attack
        "bruteforce": [18],    # Brute-Force
        "policy": [14],        # Port scan (generic)
    }
    return mapping.get(category, [14])


# Domains to never blocklist (legitimate infrastructure)
DNSBL_WHITELIST = {
    # DNS providers
    "dns.google", "dns.quad9.net", "cloudflare-dns.com", "one.one.one.one",
    # CDNs and major platforms
    "cloudflare.com", "akamai.net", "fastly.net", "amazonaws.com",
    "googlevideo.com", "gstatic.com", "google.com", "googleapis.com",
    "microsoft.com", "apple.com", "icloud.com",
    # Our infrastructure
    "opnsense.local",
}
# TLDs that are just noise (IP-based PTR records, arpa, etc.)
DNSBL_SKIP_TLDS = {".arpa", ".local", ".lan", ".internal", ".home"}
MAX_DNSBL = 10000


def extract_domains_from_alert(alert: dict) -> list[str]:
    """Extract domain indicators from a raw Suricata alert."""
    domains = []
    # TLS SNI — most reliable domain indicator
    sni = alert.get("tls", {}).get("sni", "")
    if sni:
        domains.append(sni)
    # DNS query name
    dns = alert.get("dns", {})
    rrname = dns.get("rrname", "")
    if rrname:
        domains.append(rrname.rstrip("."))
    # HTTP hostname
    http = alert.get("http", {})
    hostname = http.get("hostname", "")
    if hostname:
        domains.append(hostname)
    # Deduplicate, filter junk
    seen = set()
    clean = []
    for d in domains:
        d = d.lower().strip()
        if not d or d in seen:
            continue
        # Skip IP addresses
        if d.replace(".", "").isdigit():
            continue
        # Skip whitelisted domains and subdomains
        if any(d == w or d.endswith("." + w) for w in DNSBL_WHITELIST):
            continue
        # Skip noise TLDs
        if any(d.endswith(tld) for tld in DNSBL_SKIP_TLDS):
            continue
        # Must have at least one dot (valid domain)
        if "." not in d:
            continue
        seen.add(d)
        clean.append(d)
    return clean


def maybe_add_to_dnsbl(
    alert: dict, result: dict, rc: RedisCluster
):
    """Add domains from confirmed-malicious alerts to the DNSBL."""
    severity = result.get("severity", "info")
    confidence = result.get("confidence", 0.0)
    fp = result.get("false_positive_likelihood", "high")
    category = result.get("category", "")
    action = result.get("recommended_action", "")

    # Only blocklist domains from high-confidence malicious alerts
    if severity not in ("critical", "high"):
        return
    if confidence < 0.7:
        return
    if fp != "low":
        return
    if category in ("info", "false_positive", "scan"):
        # Scans don't have meaningful domain indicators
        return

    domains = extract_domains_from_alert(alert)
    if not domains:
        return

    now = datetime.now(timezone.utc).isoformat()
    for domain in domains:
        entry = json.dumps({
            "domain": domain,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "action": action,
            "src_ip": alert.get("src_ip", ""),
            "signature": alert.get("alert", {}).get("signature", ""),
            "added_at": now,
        }, separators=(",", ":"))
        # Use domain as hash field — auto-deduplicates
        rc.hset(DNSBL_KEY, domain, entry)

    # Trim if too large (keep newest by just capping size)
    if rc.hlen(DNSBL_KEY) > MAX_DNSBL:
        all_entries = rc.hgetall(DNSBL_KEY)
        # Sort by added_at, remove oldest
        sorted_entries = sorted(
            all_entries.items(),
            key=lambda x: json.loads(x[1]).get("added_at", ""),
            reverse=True,
        )
        to_remove = [k for k, _ in sorted_entries[MAX_DNSBL:]]
        if to_remove:
            rc.hdel(DNSBL_KEY, *to_remove)

    logger.info(f"DNSBL: added {len(domains)} domain(s): {', '.join(domains)}")


def maybe_auto_block(
    result: dict, opn: OPNsenseAPI | None, rc: RedisCluster
) -> bool:
    """Auto-block an IP if the analysis warrants it.

    Paranoia level: medium-high
    - Critical/high severity with confidence >= threshold and low FP: block
    - Medium severity with block recommendation and high confidence: block
    - Any "investigate" action on critical severity: block
    - Repeat offenders (seen 3+ times in correlation buffer): block
    """
    if not AUTO_BLOCK_ENABLED or not opn:
        return False

    action = result.get("recommended_action", "")
    confidence = result.get("confidence", 0.0)
    severity = result.get("severity", "info")
    fp = result.get("false_positive_likelihood", "high")
    category = result.get("category", "")

    src_ip = result.get("source_alert", {}).get("src_ip", "")
    if not src_ip or src_ip.startswith(("192.168.", "10.", "127.", "172.16.")):
        return False  # never block local IPs

    # Geo risk confidence boost — high-risk origins get a boost
    geo_risk = result.get("source_alert", {}).get("geo_risk", {})
    geo_score = geo_risk.get("score", 0.0)
    geo_tier = geo_risk.get("tier", "unknown")
    # Boost: critical geo = +0.15, high = +0.10, elevated = +0.05
    geo_boost = 0.0
    if geo_score >= 0.7:
        geo_boost = 0.15
    elif geo_score >= 0.5:
        geo_boost = 0.10
    elif geo_score >= 0.3:
        geo_boost = 0.05
    effective_confidence = min(confidence + geo_boost, 1.0)

    should_block = False
    reason_tag = ""

    # Tier 1: High-confidence threats
    if (
        action == "block"
        and effective_confidence >= AUTO_BLOCK_CONFIDENCE
        and severity in ("critical", "high")
        and fp == "low"
    ):
        should_block = True
        reason_tag = "high-confidence threat"

    # Tier 2: Medium severity with strong block signal
    elif (
        action == "block"
        and effective_confidence >= 0.75
        and severity == "medium"
        and fp in ("low", "medium")
        and category not in ("info", "false_positive")
    ):
        should_block = True
        reason_tag = "medium-severity block recommendation"

    # Tier 3: Critical severity with investigate recommendation
    elif (
        action == "investigate"
        and severity == "critical"
        and effective_confidence >= 0.7
        and fp == "low"
    ):
        should_block = True
        reason_tag = "critical threat requiring investigation"

    # Tier 4: Known malicious categories regardless of action
    elif (
        category in ("malware", "c2", "exfiltration", "exploit")
        and effective_confidence >= 0.7
        and fp == "low"
    ):
        should_block = True
        reason_tag = f"malicious category: {category}"

    # Tier 5: High-risk origin with any block/investigate recommendation
    elif (
        geo_score >= 0.7
        and action in ("block", "investigate")
        and severity in ("critical", "high", "medium")
        and effective_confidence >= 0.6
        and fp in ("low", "medium")
    ):
        should_block = True
        reason_tag = f"high-risk origin ({geo_tier}, geo_score={geo_score})"

    # Tier 6: Repeat offender (seen in N+ correlation windows)
    if not should_block:
        try:
            score = rc.zscore(REPEAT_KEY, src_ip)
            if score and int(score) >= REPEAT_OFFENDER_THRESHOLD:
                should_block = True
                reason_tag = f"repeat offender ({int(score)} correlation appearances)"
        except Exception:
            pass

    if should_block:
        geo_info = ""
        if geo_risk.get("factors"):
            geo_info = f" [{', '.join(geo_risk['factors'])}]"
        desc = (
            f"AI-blocked ({reason_tag}): "
            f"{result.get('description', 'threat detected')} "
            f"(confidence={confidence}"
            f"{f'+{geo_boost:.2f} geo' if geo_boost else ''}"
            f", severity={severity}){geo_info}"
        )
        success = opn.add_ip_to_alias(BLOCK_ALIAS, src_ip, desc)
        if success:
            block_entry = {
                "ip": src_ip,
                "reason": desc,
                "alert_hash": result.get("alert_hash", ""),
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "source": "auto",
            }
            store_result(rc, BLOCK_LOG_KEY, block_entry, MAX_BLOCKS)
            logger.warning(f"AUTO-BLOCKED {src_ip}: {desc}")
            # Report to AbuseIPDB if enabled
            try:
                from analyzer import abuseipdb_report
                abuse_cats = _map_category_to_abuseipdb(category)
                abuseipdb_report(src_ip, abuse_cats, desc[:1024])
            except Exception:
                pass
            return True
    return False


def main():
    global running
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("AI Suricata daemon starting")
    logger.info(f"Auto-block: {'ENABLED' if AUTO_BLOCK_ENABLED else 'disabled'}")

    # Connect to Redis
    rc = connect_redis()
    if not rc:
        return

    # Init analyzer
    analyzer = AlertAnalyzer()

    # Init OPNsense API (optional)
    opn = None
    if AUTO_BLOCK_ENABLED:
        try:
            opn = OPNsenseAPI()
            logger.info("OPNsense API client initialized")
        except Exception as e:
            logger.error(f"OPNsense API init failed: {e}")
            logger.warning("Auto-blocking disabled due to API failure")

    last_correlation = time.time()
    last_summary_date = None
    alerts_processed = 0

    logger.info(f"Polling Redis key '{ALERT_KEY}' every {POLL_INTERVAL}s")

    while running:
        try:
            # ---------------------------------------------------------------
            # 1. Consume alerts from Redis
            # ---------------------------------------------------------------
            batch_count = 0
            while batch_count < 50:  # process up to 50 alerts per cycle
                raw = rc.rpop(ALERT_KEY)
                if not raw:
                    break

                try:
                    alert = json.loads(raw)
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON alert")
                    continue

                # Only process alert-type events
                if alert.get("event_type") != "alert":
                    continue

                # Analyze with HiveCoder
                result = analyzer.analyze_alert(alert)
                if result:
                    store_result(rc, RESULT_KEY, result, MAX_RESULTS)
                    write_result_to_nas(result)
                    maybe_auto_block(result, opn, rc)
                    maybe_add_to_dnsbl(alert, result, rc)
                    alerts_processed += 1
                    batch_count += 1

                    sev = result.get("severity", "?")
                    cat = result.get("category", "?")
                    act = result.get("recommended_action", "?")
                    src = result.get("source_alert", {}).get("src_ip", "?")
                    logger.info(
                        f"Alert analyzed: {sev}/{cat} from {src} → {act}"
                    )

                # Buffer for correlation regardless
                analyzer.buffer_for_correlation(alert)

            # ---------------------------------------------------------------
            # 2. Periodic correlation analysis
            # ---------------------------------------------------------------
            now = time.time()
            if now - last_correlation >= CORRELATION_INTERVAL:
                correlations = analyzer.correlate_buffered()
                for corr in correlations:
                    store_result(rc, CORRELATION_KEY, corr, MAX_RESULTS)
                    write_result_to_nas(corr)
                    logger.info(
                        f"Correlation: {corr.get('attack_pattern', '?')} "
                        f"from {corr.get('source_ip', '?')} "
                        f"({corr.get('alert_count', 0)} alerts)"
                    )
                # Update repeat offender tracking
                corr_ips = [
                    c.get("source_ip") for c in correlations
                    if c.get("source_ip")
                ]
                if corr_ips:
                    update_repeat_offenders(rc, corr_ips)
                prune_repeat_offenders(rc)
                last_correlation = now

            # ---------------------------------------------------------------
            # 3. Daily summary
            # ---------------------------------------------------------------
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            current_hour = datetime.now(timezone.utc).hour
            if current_hour == SUMMARY_HOUR and last_summary_date != today:
                day_stats = {
                    "date": today,
                    "analyzer_stats": analyzer.stats.copy(),
                    "alerts_processed": alerts_processed,
                }
                summary = analyzer.generate_daily_summary(day_stats)
                if summary:
                    summary["generated_at"] = datetime.now(timezone.utc).isoformat()
                    rc.set(SUMMARY_KEY, json.dumps(summary))
                    write_result_to_nas(summary)
                    logger.info(
                        f"Daily summary: {summary.get('threat_level', '?')} — "
                        f"{summary.get('summary', '')}"
                    )

                # Store daily stats for historical trend analysis
                try:
                    cat_counts = {}
                    raw_results = rc.lrange(RESULT_KEY, 0, 4999)
                    for raw_r in raw_results:
                        try:
                            r = json.loads(raw_r)
                            if r.get("analyzed_at", "")[:10] == today:
                                cat = r.get("category", "unknown")
                                cat_counts[cat] = cat_counts.get(cat, 0) + 1
                        except (json.JSONDecodeError, TypeError):
                            pass
                    daily_record = {
                        "date": today,
                        "total_alerts": alerts_processed,
                        "by_severity": {
                            "critical": analyzer.stats.get("critical", 0),
                            "high": analyzer.stats.get("high", 0),
                        },
                        "by_category": cat_counts,
                        "blocked": analyzer.stats.get("blocked", 0),
                        "analyzed": analyzer.stats.get("analyzed", 0),
                        "deduplicated": analyzer.stats.get("deduplicated", 0),
                        "errors": analyzer.stats.get("errors", 0),
                    }
                    day_ts = datetime.strptime(today, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    ).timestamp()
                    rc.zadd(DAILY_STATS_KEY, {
                        json.dumps(daily_record, separators=(",", ":")): day_ts
                    })
                    # Keep 90 days
                    cutoff_ts = day_ts - (90 * 86400)
                    rc.zremrangebyscore(DAILY_STATS_KEY, "-inf", cutoff_ts)
                    logger.info("Stored daily stats for trend analysis")
                except Exception as e:
                    logger.warning(f"Failed to store daily stats: {e}")

                last_summary_date = today

            # ---------------------------------------------------------------
            # 4. Stats logging
            # ---------------------------------------------------------------
            if alerts_processed > 0 and alerts_processed % 100 == 0:
                logger.info(f"Stats: {json.dumps(analyzer.stats)}")

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Main loop error: {e}", exc_info=True)
            # Reconnect Redis if needed
            try:
                rc.ping()
            except Exception:
                logger.warning("Redis connection lost, reconnecting...")
                rc = connect_redis()
            time.sleep(POLL_INTERVAL)

    # Shutdown
    logger.info(f"Shutting down. Final stats: {json.dumps(analyzer.stats)}")
    logger.info(f"Total alerts processed: {alerts_processed}")


if __name__ == "__main__":
    main()
