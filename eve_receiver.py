#!/usr/bin/env python3
"""
Suricata EVE JSON Syslog Receiver

Listens on TCP 5140 for syslog messages from OPNsense Suricata,
extracts EVE JSON payloads, and writes them to NAS storage.
Optionally pushes to Redis when the cluster is available.
"""

import json
import logging
import os
import signal
import socket
import sys
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

# Config
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5140
NAS_EVE_DIR = Path("/var/mnt/ai/suricata/eve")
NAS_ALERT_DIR = Path("/var/mnt/ai/suricata/alerts")

# Redis config (optional, used when cluster is up)
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "7000"))
REDIS_PASS = os.environ.get("REDIS_PASS", "P1MC0OSpZ9Iuss5b36Bmpl2U9Yf5JwtFJTXf2Eb5WkQ=")
REDIS_KEY = "suricata:eve"
REDIS_ALERT_KEY = "suricata:alerts"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("eve_receiver")

# Stats
stats = {
    "received": 0,
    "parsed": 0,
    "alerts": 0,
    "errors": 0,
    "redis_pushed": 0,
    "skipped": 0,
    "connections": 0,
}
stats_lock = threading.Lock()

running = True
redis_client = None
redis_lock = threading.Lock()


def try_redis():
    """Try to connect to Redis cluster. Returns client or None."""
    try:
        from redis.cluster import RedisCluster, ClusterNode
        startup_nodes = [ClusterNode(REDIS_HOST, REDIS_PORT)]
        r = RedisCluster(startup_nodes=startup_nodes, password=REDIS_PASS, socket_timeout=2)
        r.ping()
        return r
    except Exception:
        try:
            from redis import Redis
            r = Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS, socket_timeout=2)
            r.ping()
            return r
        except Exception:
            return None


def extract_eve_json(text: str) -> dict | None:
    """Extract EVE JSON from a syslog message line."""
    text = text.strip()
    if not text:
        return None

    # Try direct JSON parse first (if no syslog wrapper)
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Find JSON object anywhere in the message (after syslog header)
    idx = text.find("{")
    if idx >= 0:
        try:
            return json.loads(text[idx:])
        except json.JSONDecodeError:
            pass

    return None


def get_log_file(base_dir: Path) -> Path:
    """Get today's log file path."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return base_dir / f"eve-{today}.json"


def write_event(event: dict):
    """Write an EVE event to NAS storage and optionally Redis."""
    global redis_client

    line = json.dumps(event, separators=(",", ":")) + "\n"
    event_type = event.get("event_type", "unknown")

    # Write to main EVE log
    log_file = get_log_file(NAS_EVE_DIR)
    with open(log_file, "a") as f:
        f.write(line)

    # Write alerts separately
    if event_type == "alert":
        with stats_lock:
            stats["alerts"] += 1
        alert_file = get_log_file(NAS_ALERT_DIR)
        with open(alert_file, "a") as f:
            f.write(line)

    # Push to Redis if available
    with redis_lock:
        rc = redis_client
    if rc:
        try:
            rc.lpush(REDIS_KEY, line.strip())
            rc.ltrim(REDIS_KEY, 0, 99999)
            if event_type == "alert":
                rc.lpush(REDIS_ALERT_KEY, line.strip())
                rc.ltrim(REDIS_ALERT_KEY, 0, 9999)
            with stats_lock:
                stats["redis_pushed"] += 1
        except Exception:
            with redis_lock:
                redis_client = None


def handle_client(conn: socket.socket, addr: tuple):
    """Handle a single TCP client connection (syslog-ng stream)."""
    global redis_client

    with stats_lock:
        stats["connections"] += 1
    logger.info(f"Connection from {addr[0]}:{addr[1]}")

    buf = b""
    retry_counter = 0

    try:
        conn.settimeout(300)  # 5 min idle timeout
        while running:
            try:
                chunk = conn.recv(8192)
                if not chunk:
                    break  # connection closed
                buf += chunk

                # Process complete lines (syslog-ng TCP uses newline framing)
                while b"\n" in buf:
                    line_bytes, buf = buf.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    # Handle octet-counted framing (RFC 6587)
                    # Format: "<length> <message>"
                    # syslog-ng with flags(syslog-protocol) may use this
                    if line[0].isdigit() and " " in line:
                        space_idx = line.index(" ")
                        possible_len = line[:space_idx]
                        if possible_len.isdigit():
                            line = line[space_idx + 1:]

                    with stats_lock:
                        stats["received"] += 1

                    event = extract_eve_json(line)
                    if event:
                        with stats_lock:
                            stats["parsed"] += 1
                        write_event(event)

                        etype = event.get("event_type", "?")
                        if etype == "alert":
                            sig = event.get("alert", {}).get("signature", "?")
                            src = event.get("src_ip", "?")
                            logger.info(f"Alert: {sig} from {src}")
                    else:
                        # Suricata fast-log lines (non-JSON alert format)
                        # are expected and not errors
                        if "[Drop]" in line or "[**]" in line or "Classification:" in line:
                            with stats_lock:
                                stats["skipped"] += 1
                        else:
                            with stats_lock:
                                stats["errors"] += 1
                                if stats["errors"] <= 10:
                                    logger.warning(f"Parse fail: {line[:300]}")

                    # Retry Redis periodically
                    retry_counter += 1
                    with redis_lock:
                        rc = redis_client
                    if not rc and retry_counter % 100 == 0:
                        new_rc = try_redis()
                        if new_rc:
                            with redis_lock:
                                redis_client = new_rc
                            logger.info("Redis reconnected")

                    # Log stats periodically
                    with stats_lock:
                        recv = stats["received"]
                    if recv % 1000 == 0 and recv > 0:
                        with stats_lock:
                            logger.info(f"Stats: {json.dumps(stats)}")

            except socket.timeout:
                continue
            except ConnectionResetError:
                break
    except Exception as e:
        logger.error(f"Client {addr[0]} error: {e}")
    finally:
        conn.close()
        logger.info(f"Connection from {addr[0]}:{addr[1]} closed")


def signal_handler(sig, frame):
    global running
    with stats_lock:
        logger.info(f"Shutting down... Stats: {json.dumps(stats)}")
    running = False
    sys.exit(0)


def main():
    global running, redis_client

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Ensure directories exist
    NAS_EVE_DIR.mkdir(parents=True, exist_ok=True)
    NAS_ALERT_DIR.mkdir(parents=True, exist_ok=True)

    # Try Redis
    redis_client = try_redis()
    redis_status = "connected" if redis_client else "unavailable (will retry)"

    # Create TCP server socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(5)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(5)

    logger.info(f"Suricata EVE receiver listening on TCP {LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"Writing to NAS: {NAS_EVE_DIR}")
    logger.info(f"Redis: {redis_status}")

    while running:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                logger.error(f"Accept error: {e}")

    srv.close()


if __name__ == "__main__":
    main()
