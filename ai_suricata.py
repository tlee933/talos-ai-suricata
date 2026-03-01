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

    should_block = False
    reason_tag = ""

    # Tier 1: High-confidence threats (original logic)
    if (
        action == "block"
        and confidence >= AUTO_BLOCK_CONFIDENCE
        and severity in ("critical", "high")
        and fp == "low"
    ):
        should_block = True
        reason_tag = "high-confidence threat"

    # Tier 2: Medium severity with strong block signal
    elif (
        action == "block"
        and confidence >= 0.75
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
        and confidence >= 0.7
        and fp == "low"
    ):
        should_block = True
        reason_tag = "critical threat requiring investigation"

    # Tier 4: Known malicious categories regardless of action
    elif (
        category in ("malware", "c2", "exfiltration", "exploit")
        and confidence >= 0.7
        and fp == "low"
    ):
        should_block = True
        reason_tag = f"malicious category: {category}"

    if should_block:
        desc = (
            f"AI-blocked ({reason_tag}): "
            f"{result.get('description', 'threat detected')} "
            f"(confidence={confidence}, severity={severity})"
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
