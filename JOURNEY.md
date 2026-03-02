# Talos AI Suricata — Project Journey

> From raw syslog to autonomous threat defense in 3 days

---

## Day 1: Foundation (February 28, 2026)

### The Problem

OPNsense runs Suricata IPS and generates thousands of alerts daily — port scans, exploit attempts, brute force probes. But alerts alone aren't actionable. Most are noise. The real threats hide in patterns that require correlation and context. Manual triage doesn't scale.

### The Solution

Build an AI-powered analysis pipeline that:
1. Receives Suricata EVE JSON via syslog
2. Classifies each alert with a local LLM
3. Correlates alerts by source IP to detect attack patterns
4. Automatically blocks confirmed threats via the OPNsense API

### What We Built

**eve_receiver.py** — TCP syslog listener on port 5140. Parses EVE JSON from OPNsense syslog messages, handles both raw JSON and syslog-wrapped formats, writes to NAS storage, and pushes alerts to Redis for AI analysis.

**ai_suricata.py** — Main analysis daemon. Polls Redis every 2 seconds, sends alerts to HiveCoder (Qwen3-14B) for classification, runs 5-minute correlation cycles to detect multi-alert attack patterns, generates daily threat summaries, and auto-blocks threats that meet confidence thresholds.

**analyzer.py** — LLM interface. Builds rich alert context (signature, flow data, metadata, payload samples), deduplicates within a 1-hour window, and parses structured JSON responses from HiveCoder.

**dashboard.py** — Chart.js metrics dashboard on port 8080. Shows alert trends, top source IPs, severity distribution, protocol breakdown, and blocked IP list.

**opnsense_api.py** — OPNsense firewall API client. Manages the `ai_blocklist` alias — adds/removes IPs, triggers firewall reconfiguration, lists current blocks.

**mcp_server.py** — Claude Code integration via MCP protocol. 11 tools for querying alerts, analyzing IPs, managing blocks, and checking system health.

### First Results

- EVE receiver successfully ingesting OPNsense syslog
- HiveCoder analyzing alerts and producing structured threat assessments
- Auto-blocking working with initial conservative thresholds (confidence >= 0.85)
- Dashboard showing live metrics

---

## Day 2: Migration to Alderlake (March 1, 2026)

### The Problem

Aurora (32GB RAM) was running AI Suricata alongside HiveCoder LLM, Redis cluster, and the training pipeline — all competing for resources. Training required stopping the LLM server. Too much contention on one box.

### The Solution

Move AI Suricata's 3 services (eve_receiver, ai_suricata, dashboard) to alderlake — an i7-12700 server with 64GB RAM sitting mostly idle. Keep the LLM and Redis on aurora where the GPU lives.

### Container Deployment

Created a `Containerfile` based on `python:3.12-slim`:
- All Python services packaged into a single container
- `entrypoint.sh` starts all 3 processes, exits if any dies
- Environment variables for all external endpoints (Redis, HiveCoder, OPNsense)
- `--network=host` for simplicity (needs ports 5140 and 8080)

Deployed as a systemd service on alderlake running under podman.

### Infrastructure Changes

- **OPNsense syslog**: Redirected from aurora (192.168.1.100) to alderlake (192.168.1.10)
- **NFS mount**: Added `/var/mnt/ai` on alderlake for persistent EVE storage
- **OPNsense creds**: Copied API key/secret to alderlake
- **Disabled aurora services**: Stopped and disabled the 3 local systemd units

### Verification

- Container receiving syslog from OPNsense
- Analyzing alerts via HiveCoder on aurora (network call adds ~0.1ms, negligible vs LLM inference)
- Dashboard accessible at alderlake:8080
- Auto-blocking working through OPNsense API

---

## Day 2 continued: Security Hardening (March 1, 2026)

### Threat Analysis

Analyzed the dashboard data: 1640 alert entries from 799 unique IPs. Identified 20+ /24 subnets responsible for 81% of all alerts — mostly hosting providers running mass scanners (Censys, Shadowserver, DigitalOcean, various Russian/Bulgarian ranges).

### CIDR Blocking

Blocked 24 scanner CIDRs at the firewall level — more effective than blocking individual IPs since scanners rotate within their subnets.

### Aggressive Auto-Block Rules

Upgraded from single-tier to 4-tier auto-blocking:

| Tier | What | Confidence |
|------|------|------------|
| 1 | High-confidence critical/high threats | >= 0.70 |
| 2 | Medium severity with block recommendation | >= 0.75 |
| 3 | Critical severity needing investigation | >= 0.70 |
| 4 | Known malicious categories (malware, C2, exfiltration, exploit) | >= 0.70 |

### Firewall Hardening

Created OPNsense rules via API:
- **Port blocking**: 24 dangerous inbound ports (SSH, Telnet, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Docker API, Modbus, MQTT, VNC, SIP)
- **ICMP blocking**: Reduces network discoverability
- **RFC1918 spoofing**: Blocks private IP ranges arriving on WAN interface

### DNS Security

- **DNSBL**: Enabled 7 blocklists in Unbound (Hagezi Multi PRO, ThreatFox, Steven Black, Fake/Scams, Threat Intelligence Feeds, DoH/VPN/TOR Bypass, Badware Hoster)
- **DNS Redirect**: NAT rule forcing all LAN DNS through OPNsense (prevents DNS bypass)

### Suricata Tuning

- Set detect profile to HIGH
- Enabled extended HTTP logging

---

## The Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    TALOS AI SURICATA                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Alderlake (Container Host)                                     │
│  ├── eve_receiver.py    — TCP 5140 syslog listener              │
│  ├── ai_suricata.py     — 4-tier threat analysis daemon         │
│  └── dashboard.py       — Chart.js metrics on :8080             │
│                                                                 │
│  Aurora (GPU + AI)                                              │
│  ├── HiveCoder LLM      — Qwen3-14B on :8090                   │
│  └── Redis Cluster       — 3 masters on 7000-7002              │
│                                                                 │
│  OPNsense (Firewall)                                            │
│  ├── Suricata IPS        — detect profile HIGH                  │
│  ├── ai_blocklist alias  — auto-populated by AI                 │
│  ├── DNSBL               — 7 security blocklists                │
│  └── DNS redirect        — force all DNS through firewall       │
│                                                                 │
│  NAS (Storage)                                                  │
│  ├── /var/mnt/ai/suricata/eve/      — raw EVE JSON logs        │
│  ├── /var/mnt/ai/suricata/alerts/   — alert-only logs          │
│  └── /var/mnt/ai/suricata/ai_results/ — LLM analysis JSONL     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Alert analysis latency | ~2-5s (LLM inference dominated) |
| Auto-block confidence threshold | 0.70 |
| Blocked CIDRs | 24+ subnets |
| Individual blocked IPs | 30+ |
| DNSBL blocklists | 7 |
| Banned inbound ports | 24 |
| MCP tools | 11 |
| Container image size | ~180 MB |
| RAM usage (container) | ~200 MB |

---

## Credits

Built with:
- HiveCoder / Qwen3-14B (local LLM inference)
- Hive-Mind (Redis cluster + AI infrastructure)
- Claude Code (Opus 4.6)
- OPNsense + Suricata IPS

**Author**: hashcat
**Date**: March 1, 2026
