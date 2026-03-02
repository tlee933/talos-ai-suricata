# Talos AI Suricata

> **AI-powered network threat analysis and automated defense for OPNsense**

An autonomous threat analysis system that consumes Suricata IDS alerts, classifies them with a local LLM (HiveCoder/Qwen3-14B), and automatically blocks confirmed threats via the OPNsense API. Runs as a single container on any Linux host with network access to OPNsense and a Redis cluster.

Named after Talos, the bronze automaton of Greek mythology who patrolled the shores of Crete — this system patrols your network perimeter.

---

## Architecture

```
Internet
  |
  v
OPNsense (Suricata IPS) --syslog--> eve_receiver (TCP 5140)
  |                                       |
  |                                       v
  |                                  Redis Cluster
  |                                       |
  |                                       v
  |                                  ai_suricata daemon
  |                                       |
  |                              HiveCoder LLM (Qwen3-14B)
  |                                       |
  |                                       v
  |                              4-tier threat classification
  |                                       |
  |   <------- OPNsense API --------  auto-block
  |                                       |
  v                                       v
Firewall (ai_blocklist alias)        dashboard (:8080)
```

### Components

| Service | Port | Role |
|---------|------|------|
| **eve_receiver** | 5140 | TCP syslog listener, parses EVE JSON, writes to NAS + Redis |
| **ai_suricata** | - | Polls Redis for alerts, sends to LLM for analysis, auto-blocks threats |
| **dashboard** | 8080 | Metrics dashboard with Chart.js (alert trends, top sources, blocks) |
| **mcp_server** | stdio | Claude Code integration — query alerts, analyze IPs, manage blocks |

### External Dependencies

| Service | Host | Role |
|---------|------|------|
| **Redis Cluster** | aurora (7000-7002) | Alert queue, analysis results, block log, correlations |
| **HiveCoder LLM** | aurora (8090) | Qwen3-14B via Hive-Mind HTTP proxy for threat classification |
| **OPNsense API** | 192.168.1.1 | Firewall alias management for IP blocking |
| **NAS** | 192.168.1.7 | Persistent EVE log and analysis result storage |

---

## Auto-Block Logic

Four-tier threat classification with escalating confidence thresholds:

| Tier | Condition | Threshold |
|------|-----------|-----------|
| **1. High-confidence threat** | action=block, severity=critical/high, fp=low | confidence >= 0.70 |
| **2. Medium-severity block** | action=block, severity=medium, fp=low/medium | confidence >= 0.75 |
| **3. Critical investigation** | action=investigate, severity=critical, fp=low | confidence >= 0.70 |
| **4. Malicious category** | category in (malware, c2, exfiltration, exploit), fp=low | confidence >= 0.70 |

RFC1918 addresses (192.168.x, 10.x, 127.x, 172.16.x) are never blocked.

---

## Deployment

### Container (recommended)

Runs all 3 services in a single podman container:

```bash
podman build -t talos-ai-suricata:latest .

podman run -d --name talos-ai-suricata \
    --network=host \
    -v /var/mnt/ai:/var/mnt/ai \
    -v /path/to/.opn_creds:/tmp/.opn_creds:ro \
    -e REDIS_HOST=192.168.1.100 \
    -e REDIS_PORT=7000 \
    -e REDIS_PASS=<redis-password> \
    -e HIVECODER_URL=http://192.168.1.100:8090/v1/chat/completions \
    -e AUTO_BLOCK=1 \
    -e AUTO_BLOCK_CONFIDENCE=0.70 \
    -e BLOCK_ALIAS=ai_blocklist \
    talos-ai-suricata:latest
```

### Systemd Service

See `ai-suricata-container.service` for a systemd unit that manages the container lifecycle.

### OPNsense Setup

1. Create a firewall alias named `ai_blocklist` (type: Host(s))
2. Create a WAN inbound block rule referencing the alias
3. Configure syslog remote destination: `<container-host>:5140` (TCP)
4. Generate API key/secret pair, save to `.opn_creds` as `key:secret`

---

## MCP Tools (Claude Code Integration)

| Tool | Description |
|------|-------------|
| `threat_status` | Current posture: queued alerts, blocked IPs, daily summary |
| `query_alerts` | Search analyzed alerts by severity, source IP, category |
| `query_raw_alerts` | View unanalyzed alerts in the queue |
| `analyze_alert` | Send a specific alert for AI analysis |
| `analyze_ip` | Correlate all alerts from/to an IP, identify attack patterns |
| `get_correlations` | View recent attack correlation results |
| `top_talkers` | Noisiest source IPs by alert volume |
| `search_signature` | Search alerts by Suricata signature name |
| `get_blocks` | List all blocked IPs |
| `block_ip` | Manually block a public IP via OPNsense |
| `suricata_stats` | Service health: Redis queues, HiveCoder status, block counts |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `127.0.0.1` | Redis cluster node address |
| `REDIS_PORT` | `7000` | Redis cluster node port |
| `REDIS_PASS` | - | Redis cluster password |
| `HIVECODER_URL` | `http://127.0.0.1:8090/v1/chat/completions` | LLM endpoint |
| `AUTO_BLOCK` | `0` | Enable auto-blocking (`1` to enable) |
| `AUTO_BLOCK_CONFIDENCE` | `0.9` | Minimum confidence for Tier 1 blocks |
| `BLOCK_ALIAS` | `ai_blocklist` | OPNsense firewall alias name |
| `DASHBOARD_PORT` | `8080` | Dashboard HTTP port |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Hardware

Currently deployed on a 2-node setup:

| Node | Role | Specs |
|------|------|-------|
| **alderlake** | Container host (eve_receiver, ai_suricata, dashboard) | i7-12700 (8P+4E, 20T), 64GB RAM, PowerColor Red Devil RX 6700 XT 12GB, Fedora CoreOS |
| **aurora** | LLM inference + Redis primary | Ryzen 9, PowerColor AI PRO R9700 32GB VRAM, ROCm 7.12, Fedora Kinoite 43 |
| **NAS** | Persistent storage | Synology, NFS, 11TB |
| **OPNsense** | Firewall + Suricata IPS | 192.168.1.1 |

---

## Project Structure

```
talos-ai-suricata/
    eve_receiver.py          # TCP 5140 syslog listener, EVE JSON parser
    ai_suricata.py           # Main analysis daemon, 4-tier auto-block
    analyzer.py              # HiveCoder LLM client, alert/correlation/summary analysis
    prompts.py               # LLM system prompts and templates
    dashboard.py             # Chart.js metrics dashboard (:8080)
    opnsense_api.py          # OPNsense firewall API client
    mcp_server.py            # Claude Code MCP integration (11 tools)
    entrypoint.sh            # Container entrypoint (starts all 3 services)
    Containerfile            # python:3.12-slim based container
    ai-suricata-container.service  # Systemd unit for podman
```

---

## Active Defenses

Beyond AI analysis, the OPNsense firewall is hardened with:

- **DNSBL** — 7 blocklists (Hagezi Pro, ThreatFox, Steven Black) via Unbound
- **DNS Redirect** — All LAN DNS forced through OPNsense (port 53 NAT redirect)
- **Port Blocking** — 24 dangerous inbound ports blocked (SSH, SMB, RDP, Redis, Docker API, etc.)
- **ICMP Blocking** — Reduces network discoverability
- **RFC1918 Spoofing** — Blocks private IP ranges arriving on WAN
- **Suricata IPS** — Detect profile set to HIGH with extended HTTP logging

---

## License

MIT

---

Built with [Hive-Mind](https://github.com/tlee933/hive-mind) and HiveCoder (Qwen3-14B)
