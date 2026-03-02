#!/usr/bin/env python3
"""
AI Suricata Metrics Dashboard

Lightweight dashboard serving EVE flow/alert/TLS data with Chart.js.
Reads from NAS EVE files and Redis AI results.
"""

import json
import os
import sys
import threading
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Paths
NAS_EVE_DIR = Path("/var/mnt/ai/suricata/eve")
NAS_ALERT_DIR = Path("/var/mnt/ai/suricata/alerts")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8080"))

# Redis config
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "7000"))
REDIS_PASS = os.environ.get("REDIS_PASS", "P1MC0OSpZ9Iuss5b36Bmpl2U9Yf5JwtFJTXf2Eb5WkQ=")


def get_redis():
    try:
        from redis.cluster import RedisCluster, ClusterNode
        rc = RedisCluster(
            startup_nodes=[ClusterNode(REDIS_HOST, REDIS_PORT)],
            password=REDIS_PASS, socket_timeout=2,
        )
        rc.ping()
        return rc
    except Exception:
        return None


def read_eve_today():
    """Read today's EVE JSON file."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = NAS_EVE_DIR / f"eve-{today}.json"
    events = []
    if path.exists():
        with open(path) as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def compute_metrics(events):
    """Compute all dashboard metrics from EVE events."""
    event_types = defaultdict(int)
    protos = defaultdict(int)
    src_bytes = defaultdict(int)
    dst_ports = defaultdict(int)
    snis = defaultdict(int)
    tls_versions = defaultdict(int)
    http_hosts = defaultdict(int)
    http_methods = defaultdict(int)
    alert_sigs = defaultdict(int)
    alert_sevs = defaultdict(int)
    alert_cats = defaultdict(int)
    hourly_bytes = defaultdict(int)
    hourly_flows = defaultdict(int)
    hourly_alerts = defaultdict(int)
    interfaces = defaultdict(int)
    total_bytes_in = 0
    total_bytes_out = 0
    dns_queries = defaultdict(int)
    dns_types = defaultdict(int)

    for e in events:
        etype = e.get("event_type", "unknown")
        event_types[etype] += 1
        iface = e.get("in_iface", "?")
        interfaces[iface] += 1

        # Extract hour for time series
        ts = e.get("timestamp", "")
        hour = "?"
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                hour = dt.strftime("%H:00")
            except (ValueError, TypeError):
                pass

        if etype == "flow":
            fl = e.get("flow", {})
            b_out = fl.get("bytes_toserver", 0)
            b_in = fl.get("bytes_toclient", 0)
            total_bytes_out += b_out
            total_bytes_in += b_in
            total = b_out + b_in

            proto = e.get("proto", "?")
            protos[proto] += 1

            src = e.get("src_ip", "?")
            src_bytes[src] += total

            dp = e.get("dest_port", 0)
            if dp:
                dst_ports[dp] += 1

            hourly_bytes[hour] += total
            hourly_flows[hour] += 1

        elif etype == "tls":
            tls = e.get("tls", {})
            sni = tls.get("sni", "")
            if sni:
                snis[sni] += 1
            ver = tls.get("version", "?")
            tls_versions[ver] += 1

        elif etype == "http":
            http = e.get("http", {})
            host = http.get("hostname", "?")
            http_hosts[host] += 1
            method = http.get("http_method", "?")
            http_methods[method] += 1

        elif etype == "alert":
            alert = e.get("alert", {})
            sig = alert.get("signature", "?")
            alert_sigs[sig] += 1
            sev = alert.get("severity", 0)
            alert_sevs[sev] += 1
            cat = alert.get("category", "?")
            alert_cats[cat] += 1
            hourly_alerts[hour] += 1

        elif etype == "dns":
            dns = e.get("dns", {})
            qtype = dns.get("type", "?")
            dns_types[qtype] += 1
            rrname = dns.get("rrname", "")
            if rrname:
                dns_queries[rrname] += 1

    def top(d, n=10):
        return dict(sorted(d.items(), key=lambda x: -x[1])[:n])

    def port_labels(d, n=15):
        port_names = {
            22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 853: "DoT",
            8080: "HTTP-Alt", 3389: "RDP", 445: "SMB", 25: "SMTP",
            993: "IMAPS", 587: "SMTP-TLS", 5060: "SIP",
        }
        items = sorted(d.items(), key=lambda x: -x[1])[:n]
        return {port_names.get(int(k), str(k)): v for k, v in items}

    hours = sorted(set(list(hourly_bytes.keys()) + list(hourly_alerts.keys())))
    hours = [h for h in hours if h != "?"]

    return {
        "summary": {
            "total_events": len(events),
            "total_flows": event_types.get("flow", 0),
            "total_alerts": event_types.get("alert", 0),
            "total_tls": event_types.get("tls", 0),
            "total_http": event_types.get("http", 0),
            "total_dns": event_types.get("dns", 0),
            "bytes_in": total_bytes_in,
            "bytes_out": total_bytes_out,
            "bytes_total": total_bytes_in + total_bytes_out,
        },
        "event_types": dict(event_types),
        "protocols": dict(protos),
        "top_talkers": top(src_bytes, 15),
        "top_ports": port_labels(dst_ports),
        "top_snis": top(snis, 15),
        "tls_versions": dict(tls_versions),
        "http_hosts": top(http_hosts, 10),
        "http_methods": dict(http_methods),
        "alert_signatures": top(alert_sigs),
        "alert_severities": {str(k): v for k, v in alert_sevs.items()},
        "alert_categories": dict(alert_cats),
        "dns_top_queries": top(dns_queries, 15),
        "dns_types": dict(dns_types),
        "interfaces": dict(interfaces),
        "time_series": {
            "hours": hours,
            "bytes": [hourly_bytes.get(h, 0) for h in hours],
            "flows": [hourly_flows.get(h, 0) for h in hours],
            "alerts": [hourly_alerts.get(h, 0) for h in hours],
        },
    }


# ---------------------------------------------------------------------------
# IP geolocation cache (ip-api.com, 45 req/min free tier)
# ---------------------------------------------------------------------------
_ip_cache = {}  # ip -> {country, countryCode, org, isp, as}
_ip_cache_lock = threading.Lock()
_PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "127.", "0.", "169.254.")


def lookup_ips(ips):
    """Batch lookup IPs via ip-api.com. Returns dict of ip -> info."""
    to_lookup = []
    with _ip_cache_lock:
        for ip in ips:
            if ip not in _ip_cache and not ip.startswith(_PRIVATE_PREFIXES):
                to_lookup.append(ip)

    # Batch lookup (max 100 per request)
    for i in range(0, len(to_lookup), 100):
        batch = to_lookup[i:i+100]
        try:
            payload = json.dumps(
                [{"query": ip, "fields": "query,country,countryCode,org,isp,as"} for ip in batch]
            ).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read())
                with _ip_cache_lock:
                    for r in results:
                        ip = r.get("query", "")
                        _ip_cache[ip] = {
                            "country": r.get("country", "?"),
                            "cc": r.get("countryCode", "??"),
                            "org": r.get("org", "?"),
                            "isp": r.get("isp", "?"),
                            "asn": r.get("as", "?"),
                        }
        except Exception:
            pass  # fail silently, IPs just won't have geo info
        time.sleep(0.5)  # rate limit safety

    result = {}
    with _ip_cache_lock:
        for ip in ips:
            if ip in _ip_cache:
                result[ip] = _ip_cache[ip]
            elif ip.startswith(_PRIVATE_PREFIXES):
                result[ip] = {"country": "Private", "cc": "—", "org": "Local network", "isp": "—", "asn": "—"}
            else:
                result[ip] = {"country": "?", "cc": "??", "org": "?", "isp": "?", "asn": "?"}
    return result


def get_blocks(events):
    """Extract blocked (dropped) alerts from EVE events with geo info."""
    blocks = []
    seen_ips = set()
    for e in events:
        if e.get("event_type") != "alert":
            continue
        alert = e.get("alert", {})
        if alert.get("action") != "blocked":
            continue
        src_ip = e.get("src_ip", "?")
        blocks.append({
            "timestamp": e.get("timestamp", ""),
            "src_ip": src_ip,
            "dest_ip": e.get("dest_ip", "?"),
            "src_port": e.get("src_port", 0),
            "dest_port": e.get("dest_port", 0),
            "proto": e.get("proto", "?"),
            "signature": alert.get("signature", "?"),
            "category": alert.get("category", "?"),
            "severity": alert.get("severity", 0),
        })
        seen_ips.add(src_ip)
        seen_ips.add(e.get("dest_ip", "?"))

    # Geo lookup for all unique IPs
    geo = lookup_ips(list(seen_ips))
    for b in blocks:
        src_geo = geo.get(b["src_ip"], {})
        b["src_country"] = src_geo.get("country", "?")
        b["src_cc"] = src_geo.get("cc", "??")
        b["src_org"] = src_geo.get("org", "?")
        b["src_asn"] = src_geo.get("asn", "?")
        dst_geo = geo.get(b["dest_ip"], {})
        b["dest_country"] = dst_geo.get("country", "?")
        b["dest_cc"] = dst_geo.get("cc", "??")
        b["dest_org"] = dst_geo.get("org", "?")

    return blocks


def get_ai_results():
    """Get AI analysis results from Redis."""
    rc = get_redis()
    if not rc:
        return []
    try:
        raw = rc.lrange("suricata:ai_results", 0, 49)
        results = []
        for r in raw:
            try:
                d = json.loads(r)
                src_geo = d.get("source_alert", {}).get("src_geo", {})
                results.append({
                    "severity": d.get("severity", "?"),
                    "category": d.get("category", "?"),
                    "confidence": d.get("confidence", 0),
                    "action": d.get("recommended_action", "?"),
                    "fp": d.get("false_positive_likelihood", "?"),
                    "description": d.get("description", ""),
                    "signature": d.get("source_alert", {}).get("signature", "?"),
                    "src_ip": d.get("source_alert", {}).get("src_ip", "?"),
                    "dest_ip": d.get("source_alert", {}).get("dest_ip", "?"),
                    "analyzed_at": d.get("analyzed_at", ""),
                    "country": src_geo.get("country", ""),
                })
            except json.JSONDecodeError:
                pass
        return results
    except Exception:
        return []


def get_ai_results_grouped():
    """Get AI results grouped by (signature, source /24 subnet)."""
    rc = get_redis()
    if not rc:
        return []
    try:
        raw = rc.lrange("suricata:ai_results", 0, 499)
        groups = {}  # (sig, subnet) -> group_data
        for r in raw:
            try:
                d = json.loads(r)
                sig = d.get("source_alert", {}).get("signature", "?")
                src_ip = d.get("source_alert", {}).get("src_ip", "?")
                # /24 subnet
                parts = src_ip.split(".")
                subnet = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else src_ip
                key = (sig, subnet)
                if key not in groups:
                    src_geo = d.get("source_alert", {}).get("src_geo", {})
                    groups[key] = {
                        "signature": sig,
                        "subnet": subnet,
                        "count": 0,
                        "unique_ips": set(),
                        "severity": d.get("severity", "?"),
                        "category": d.get("category", "?"),
                        "description": d.get("description", ""),
                        "action": d.get("recommended_action", "?"),
                        "total_confidence": 0.0,
                        "first_seen": d.get("analyzed_at", ""),
                        "last_seen": d.get("analyzed_at", ""),
                        "country": src_geo.get("country", ""),
                        "asn_org": src_geo.get("asn_org", ""),
                    }
                g = groups[key]
                g["count"] += 1
                g["unique_ips"].add(src_ip)
                g["total_confidence"] += d.get("confidence", 0)
                ts = d.get("analyzed_at", "")
                if ts and (not g["first_seen"] or ts < g["first_seen"]):
                    g["first_seen"] = ts
                if ts and (not g["last_seen"] or ts > g["last_seen"]):
                    g["last_seen"] = ts
            except (json.JSONDecodeError, TypeError):
                pass

        result = []
        for g in groups.values():
            g["unique_ips"] = len(g["unique_ips"])
            g["avg_confidence"] = round(g["total_confidence"] / g["count"], 2) if g["count"] else 0
            del g["total_confidence"]
            result.append(g)
        result.sort(key=lambda x: x["count"], reverse=True)
        return result
    except Exception:
        return []


def get_trends():
    """Get historical daily stats for trend analysis."""
    rc = get_redis()
    if not rc:
        return {"days": [], "error": "Redis unavailable"}
    try:
        raw = rc.zrangebyscore("suricata:daily_stats", "-inf", "+inf")
        days = []
        for item in raw:
            try:
                days.append(json.loads(item))
            except json.JSONDecodeError:
                pass
        days.sort(key=lambda x: x.get("date", ""))

        if len(days) < 2:
            return {"days": days, "trend": "insufficient_data"}

        # Compute 7-day stats
        recent_7 = days[-7:] if len(days) >= 7 else days
        totals = [d.get("total_alerts", 0) for d in recent_7]
        mean_7 = sum(totals) / len(totals) if totals else 0
        variance = sum((x - mean_7) ** 2 for x in totals) / len(totals) if totals else 0
        stddev_7 = variance ** 0.5

        # Anomaly: today > mean + 2*stddev
        today_total = days[-1].get("total_alerts", 0) if days else 0
        anomaly = today_total > (mean_7 + 2 * stddev_7) if stddev_7 > 0 else False

        # Trend direction
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
            "days": days,
            "stats": {
                "mean_7d": round(mean_7, 1),
                "stddev_7d": round(stddev_7, 1),
                "anomaly_today": anomaly,
                "trend": trend,
            },
        }
    except Exception:
        return {"days": [], "error": "Failed to read trends"}


def get_ai_blocks():
    """Get AI block log from Redis."""
    rc = get_redis()
    if not rc:
        return []
    try:
        raw = rc.lrange("suricata:ai_blocks", 0, 499)
        blocks = []
        for item in raw:
            try:
                blocks.append(json.loads(item))
            except json.JSONDecodeError:
                pass
        return blocks
    except Exception:
        return []


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Suricata Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0e17; color: #c9d1d9; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
.header { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); padding: 20px 30px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 22px; color: #58a6ff; font-weight: 600; }
.header .stats { display: flex; gap: 25px; }
.stat { text-align: center; }
.stat .value { font-size: 24px; font-weight: 700; color: #f0f6fc; }
.stat .label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 16px; padding: 20px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px; }
.card h3 { font-size: 14px; color: #8b949e; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.card canvas { max-height: 280px; }
.card.wide { grid-column: span 2; }
.card.full { grid-column: 1 / -1; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 10px; color: #8b949e; border-bottom: 1px solid #30363d; font-weight: 500; }
td { padding: 7px 10px; border-bottom: 1px solid #21262d; }
tr:hover { background: #1c2128; }
.sev-critical { color: #f85149; font-weight: 700; }
.sev-high { color: #f0883e; font-weight: 600; }
.sev-medium { color: #d29922; }
.sev-low { color: #58a6ff; }
.sev-info { color: #8b949e; }
.act-block { color: #f85149; }
.act-investigate { color: #f0883e; }
.act-monitor { color: #d29922; }
.act-ignore { color: #8b949e; }
.flag { font-size: 12px; margin-right: 4px; }
.block-row td { font-size: 12px; }
.asn { color: #8b949e; font-size: 11px; }
.refresh { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.refresh:hover { background: #30363d; }
.bytes { font-family: monospace; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .card.wide, .card.full { grid-column: span 1; } }
</style>
</head>
<body>
<div class="header">
  <h1>AI Suricata Dashboard</h1>
  <div class="stats">
    <div class="stat"><div class="value" id="s-events">-</div><div class="label">Events</div></div>
    <div class="stat"><div class="value" id="s-flows">-</div><div class="label">Flows</div></div>
    <div class="stat"><div class="value" id="s-alerts">-</div><div class="label">Alerts</div></div>
    <div class="stat"><div class="value" id="s-blocks" style="color:#f85149">-</div><div class="label">Blocked</div></div>
    <div class="stat"><div class="value" id="s-bytes">-</div><div class="label">Traffic</div></div>
    <button class="refresh" onclick="loadAll()">Refresh</button>
  </div>
</div>
<div class="grid" id="grid"></div>

<script>
const COLORS = ['#58a6ff','#f0883e','#3fb950','#d29922','#f85149','#bc8cff','#79c0ff','#56d364','#e3b341','#ff7b72','#d2a8ff','#a5d6ff'];
const COLORS_ALT = ['#1f6feb','#da6d28','#238636','#9e6a03','#da3633','#8957e5','#388bfd','#2ea043','#bb8009','#f85149','#a371f7','#6cb6ff'];

function fmt(n) {
  if (n >= 1e12) return (n/1e12).toFixed(1) + ' TB';
  if (n >= 1e9) return (n/1e9).toFixed(1) + ' GB';
  if (n >= 1e6) return (n/1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n/1e3).toFixed(1) + ' K';
  return n.toString();
}

function fmtBytes(n) {
  if (n >= 1e12) return (n/1e12).toFixed(2) + ' TB';
  if (n >= 1e9) return (n/1e9).toFixed(2) + ' GB';
  if (n >= 1e6) return (n/1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n/1e3).toFixed(0) + ' KB';
  return n + ' B';
}

const charts = {};

function makeChart(id, type, labels, datasets, opts={}) {
  if (charts[id]) charts[id].destroy();
  const ctx = document.getElementById(id);
  if (!ctx) return;
  const defaults = {
    responsive: true, maintainAspectRatio: true,
    plugins: {
      legend: { labels: { color: '#8b949e', font: { size: 11 } } },
    },
    scales: type === 'bar' || type === 'line' ? {
      x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
      y: { ticks: { color: '#8b949e', font: { size: 10 }, callback: v => fmt(v) }, grid: { color: '#21262d' } },
    } : undefined,
  };
  const config = { type, data: { labels, datasets }, options: { ...defaults, ...opts } };
  charts[id] = new Chart(ctx, config);
}

function pie(id, data) {
  const labels = Object.keys(data);
  const values = Object.values(data);
  makeChart(id, 'doughnut', labels, [{
    data: values, backgroundColor: COLORS.slice(0, labels.length),
    borderColor: '#161b22', borderWidth: 2,
  }], { plugins: { legend: { position: 'right', labels: { color: '#c9d1d9', font: { size: 11 }, padding: 8 } } } });
}

function bar(id, data, color=0) {
  const labels = Object.keys(data);
  const values = Object.values(data);
  makeChart(id, 'bar', labels, [{
    data: values, backgroundColor: COLORS[color] + 'cc',
    borderColor: COLORS[color], borderWidth: 1, borderRadius: 3,
  }], { plugins: { legend: { display: false } }, indexAxis: labels.length > 8 ? 'y' : 'x' });
}

function timeSeries(id, ts) {
  makeChart(id, 'line', ts.hours, [
    { label: 'Bytes', data: ts.bytes, borderColor: '#58a6ff', backgroundColor: '#58a6ff22', fill: true, tension: 0.3, yAxisID: 'y' },
    { label: 'Flows', data: ts.flows, borderColor: '#3fb950', backgroundColor: '#3fb95022', fill: true, tension: 0.3, yAxisID: 'y1' },
  ], {
    interaction: { intersect: false, mode: 'index' },
    scales: {
      x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
      y: { position: 'left', ticks: { color: '#58a6ff', callback: v => fmtBytes(v) }, grid: { color: '#21262d' } },
      y1: { position: 'right', ticks: { color: '#3fb950' }, grid: { display: false } },
    },
  });
}

function sevClass(s) { return 'sev-' + (s || 'info'); }
function actClass(a) { return 'act-' + (a || 'ignore'); }

function renderAITable(results) {
  if (!results.length) return '<p style="color:#8b949e;padding:10px;">No AI results yet</p>';
  let html = '<table><thead><tr><th>Severity</th><th>Category</th><th>Action</th><th>Conf</th><th></th><th>Src IP</th><th>Signature</th><th>Description</th></tr></thead><tbody>';
  for (const r of results) {
    const flag = ccToFlag(r.country || '');
    html += '<tr>';
    html += '<td class="' + sevClass(r.severity) + '">' + r.severity + '</td>';
    html += '<td>' + r.category + '</td>';
    html += '<td class="' + actClass(r.action) + '">' + r.action + '</td>';
    html += '<td>' + (r.confidence || 0).toFixed(1) + '</td>';
    html += '<td class="flag">' + flag + '</td>';
    html += '<td class="bytes">' + r.src_ip + '</td>';
    html += '<td>' + (r.signature || '').substring(0, 45) + '</td>';
    html += '<td>' + (r.description || '').substring(0, 80) + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}

function renderGroupedTable(groups) {
  if (!groups.length) return '<p style="color:#8b949e;padding:10px;">No grouped results yet</p>';
  let html = '<table><thead><tr><th>Count</th><th>IPs</th><th>Severity</th><th>Category</th><th>Action</th><th>Conf</th><th>Origin</th><th>Subnet</th><th>Signature</th><th>Description</th></tr></thead><tbody>';
  for (const g of groups) {
    const flag = ccToFlag(g.country || '');
    const origin = flag ? flag + ' ' + (g.asn_org || '').substring(0, 20) : (g.asn_org || '').substring(0, 20);
    html += '<tr>';
    html += '<td style="font-weight:700;color:#f0f6fc">' + g.count + '</td>';
    html += '<td>' + g.unique_ips + '</td>';
    html += '<td class="' + sevClass(g.severity) + '">' + g.severity + '</td>';
    html += '<td>' + g.category + '</td>';
    html += '<td class="' + actClass(g.action) + '">' + g.action + '</td>';
    html += '<td>' + (g.avg_confidence || 0).toFixed(2) + '</td>';
    html += '<td>' + origin + '</td>';
    html += '<td class="bytes">' + g.subnet + '</td>';
    html += '<td>' + (g.signature || '').substring(0, 45) + '</td>';
    html += '<td>' + (g.description || '').substring(0, 60) + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}

let showGrouped = true;
let cachedAI = [];
let cachedGrouped = [];

function toggleAIView() {
  showGrouped = !showGrouped;
  const btn = document.getElementById('toggle-view');
  if (btn) btn.textContent = showGrouped ? 'Show Raw' : 'Show Grouped';
  const container = document.getElementById('ai-table');
  if (container) container.innerHTML = showGrouped ? renderGroupedTable(cachedGrouped) : renderAITable(cachedAI);
}

function ccToFlag(cc) {
  if (!cc || cc === '??' || cc === '—') return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function renderBlocksTable(blocks) {
  if (!blocks.length) return '<p style="color:#8b949e;padding:10px;">No blocks yet — IPS mode active, waiting for threats</p>';
  let html = '<table><thead><tr><th>Time</th><th>Source IP</th><th>Country</th><th>Organization / ASN</th><th>Dest</th><th>Proto</th><th>Signature</th><th>Category</th></tr></thead><tbody>';
  for (const b of blocks.slice(0, 100)) {
    const t = b.timestamp ? new Date(b.timestamp).toLocaleTimeString() : '?';
    html += '<tr class="block-row">';
    html += '<td>' + t + '</td>';
    html += '<td class="bytes">' + b.src_ip + '</td>';
    html += '<td><span class="flag">' + ccToFlag(b.src_cc) + '</span>' + (b.src_country || '?') + '</td>';
    html += '<td>' + (b.src_org || '?') + '<br><span class="asn">' + (b.src_asn || '') + '</span></td>';
    html += '<td class="bytes">' + b.dest_ip + ':' + b.dest_port + '</td>';
    html += '<td>' + b.proto + '</td>';
    html += '<td>' + (b.signature || '').substring(0, 55) + '</td>';
    html += '<td>' + (b.category || '?') + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}

function renderTrendChart(trends) {
  if (!trends.days || trends.days.length < 2) return;
  const labels = trends.days.map(d => d.date ? d.date.substring(5) : '?');
  const totals = trends.days.map(d => d.total_alerts || 0);
  const critical = trends.days.map(d => (d.by_severity || {}).critical || 0);
  const blocked = trends.days.map(d => d.blocked || 0);
  makeChart('c-trends', 'line', labels, [
    { label: 'Total Alerts', data: totals, borderColor: '#58a6ff', backgroundColor: '#58a6ff22', fill: true, tension: 0.3 },
    { label: 'Critical', data: critical, borderColor: '#f85149', backgroundColor: '#f8514922', fill: false, tension: 0.3 },
    { label: 'Blocked', data: blocked, borderColor: '#3fb950', backgroundColor: '#3fb95022', fill: false, tension: 0.3 },
  ]);
}

function buildGrid(m, ai, blocks, grouped, trends) {
  const g = document.getElementById('grid');
  g.innerHTML = `
    <div class="card wide"><h3>Traffic Over Time</h3><canvas id="c-time"></canvas></div>
    <div class="card wide"><h3>Alert Trends (Daily)</h3><canvas id="c-trends"></canvas></div>
    <div class="card"><h3>Event Types</h3><canvas id="c-events"></canvas></div>
    <div class="card"><h3>Protocols</h3><canvas id="c-protos"></canvas></div>
    <div class="card"><h3>Top TLS Destinations (SNI)</h3><canvas id="c-sni"></canvas></div>
    <div class="card"><h3>Top Destination Ports</h3><canvas id="c-ports"></canvas></div>
    <div class="card"><h3>Top Talkers (by bytes)</h3><canvas id="c-talkers"></canvas></div>
    <div class="card"><h3>DNS Top Queries</h3><canvas id="c-dns"></canvas></div>
    <div class="card"><h3>TLS Versions</h3><canvas id="c-tls"></canvas></div>
    <div class="card"><h3>Interfaces</h3><canvas id="c-iface"></canvas></div>
    <div class="card full"><h3>IPS Blocked Threats</h3><div id="blocks-table"></div></div>
    <div class="card full"><h3>AI Threat Analysis <button class="refresh" id="toggle-view" onclick="toggleAIView()" style="margin-left:12px;padding:4px 12px;font-size:11px;">Show Raw</button></h3><div id="ai-table"></div></div>
  `;

  // Summary
  document.getElementById('s-events').textContent = fmt(m.summary.total_events);
  document.getElementById('s-flows').textContent = fmt(m.summary.total_flows);
  document.getElementById('s-alerts').textContent = m.summary.total_alerts;
  document.getElementById('s-bytes').textContent = fmtBytes(m.summary.bytes_total);

  // Charts
  if (m.time_series.hours.length) timeSeries('c-time', m.time_series);
  pie('c-events', m.event_types);
  pie('c-protos', m.protocols);
  const talkerLabels = {};
  for (const [k,v] of Object.entries(m.top_talkers)) talkerLabels[k] = v;
  bar('c-talkers', talkerLabels, 0);
  bar('c-sni', m.top_snis, 5);
  bar('c-ports', m.top_ports, 1);
  bar('c-dns', m.dns_top_queries, 2);
  pie('c-tls', m.tls_versions);
  pie('c-iface', m.interfaces);

  // Trend chart
  if (trends) renderTrendChart(trends);

  // Blocks table
  document.getElementById('s-blocks').textContent = blocks.length;
  document.getElementById('blocks-table').innerHTML = renderBlocksTable(blocks);

  // AI table — grouped by default
  cachedAI = ai;
  cachedGrouped = grouped || [];
  const btn = document.getElementById('toggle-view');
  if (btn) btn.textContent = showGrouped ? 'Show Raw' : 'Show Grouped';
  document.getElementById('ai-table').innerHTML = showGrouped ? renderGroupedTable(cachedGrouped) : renderAITable(ai);
}

async function loadAll() {
  try {
    const [mRes, aiRes, blkRes, grpRes, trnRes] = await Promise.all([
      fetch('/api/metrics'),
      fetch('/api/ai_results'),
      fetch('/api/blocks'),
      fetch('/api/ai_results_grouped'),
      fetch('/api/trends'),
    ]);
    const m = await mRes.json();
    const ai = await aiRes.json();
    const blocks = await blkRes.json();
    const grouped = await grpRes.json();
    const trends = await trnRes.json();
    buildGrid(m, ai, blocks, grouped, trends);
  } catch(e) { console.error('Load failed:', e); }
}

loadAll();
setInterval(loadAll, 30000);
</script>
</body>
</html>"""


class DashboardHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress access logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())

        elif path == "/api/metrics":
            events = read_eve_today()
            metrics = compute_metrics(events)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(metrics).encode())

        elif path == "/api/ai_results":
            results = get_ai_results()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(results).encode())

        elif path == "/api/blocks":
            events = read_eve_today()
            blocks = get_blocks(events)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(blocks).encode())

        elif path == "/api/ai_results_grouped":
            grouped = get_ai_results_grouped()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(grouped).encode())

        elif path == "/api/trends":
            trends = get_trends()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(trends).encode())

        elif path == "/api/blocklist.txt":
            blocks = get_ai_blocks()
            ips = sorted(set(b.get("ip", "") for b in blocks if b.get("ip")))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write("\n".join(ips).encode())

        elif path == "/api/blocklist.csv":
            blocks = get_ai_blocks()
            lines = ["ip,reason,blocked_at,source"]
            for b in blocks:
                ip = b.get("ip", "")
                reason = b.get("reason", "").replace(",", ";")
                blocked_at = b.get("blocked_at", "")
                source = b.get("source", "")
                lines.append(f"{ip},{reason},{blocked_at},{source}")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", "attachment; filename=blocklist.csv")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write("\n".join(lines).encode())

        else:
            self.send_error(404)


def main():
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler)
    print(f"AI Suricata Dashboard running on http://0.0.0.0:{DASHBOARD_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
