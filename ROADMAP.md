# Talos AI Suricata — Roadmap

*Last updated: 2026-03-02*

---

## Completed

- [x] EVE JSON syslog receiver (TCP 5140, handles both raw JSON and syslog-wrapped)
- [x] AI-powered alert analysis via HiveCoder (Qwen3-14B)
- [x] 4-tier auto-blocking (high-confidence, medium-block, critical-investigate, malicious-category)
- [x] Attack correlation engine (5-minute windows, per-source-IP grouping)
- [x] Daily threat summaries (AI-generated at 2 AM UTC)
- [x] Metrics dashboard with Chart.js (alert trends, top sources, severity, blocks)
- [x] OPNsense API integration (alias management, firewall reconfiguration)
- [x] MCP server for Claude Code (11 tools — query, analyze, block, correlate)
- [x] Container deployment (podman, python:3.12-slim, single entrypoint)
- [x] Migration to alderlake (offloaded from aurora GPU server)
- [x] CIDR-level blocking (24+ scanner subnets)
- [x] DNSBL configuration (7 security blocklists via Unbound)
- [x] DNS redirect (force all LAN DNS through OPNsense)
- [x] Port blocking (24 dangerous inbound ports)
- [x] ICMP blocking (reduce discoverability)
- [x] RFC1918 anti-spoofing rules
- [x] Suricata detect profile set to HIGH
- [x] NAS-backed persistent storage (EVE logs, alerts, AI results)
- [x] Alert deduplication (1-hour hash-based window)
- [x] Repeat offender detection (Tier 5 auto-block after 3+ correlation appearances)
- [x] GeoIP enrichment (MaxMind GeoLite2 — country, city, ASN in LLM context)
- [x] AbuseIPDB integration (IP reputation check, auto-report on block, MCP tool)
- [x] Alert fatigue reduction (grouped results by signature + /24 subnet)
- [x] Historical trend analysis (daily stats, anomaly detection, 7-day trends)
- [x] Blocklist export (plain text + CSV endpoints, AbuseIPDB sync)
- [x] 5-tier auto-blocking (added repeat offender tier)
- [x] MCP server expanded to 13 tools (+check_reputation, +get_trends)

---

## Next

### HiveCoder on alderlake 6700 XT
Deploy a local HiveCoder instance on alderlake's RX 6700 XT (12GB VRAM, RDNA2/gfx1032) for fast first-pass alert triage. ROCm doesn't officially support gfx1032, but a containerized ROCm stack with `HSA_OVERRIDE_GFX_VERSION` can force compatibility. Build a Docker/Podman image with ROCm + llama.cpp, run a small specialist model (7B Q4) for noise filtering. Route simple alerts locally, escalate ambiguous/high-severity to Qwen3-14B on aurora. This creates an MoE-like two-tier architecture without needing native RDNA2 ROCm support.

### Webhook Notifications
Send critical/high severity blocks to a webhook (Discord, Slack, ntfy). Currently the only notification path is checking the dashboard or querying via MCP.

### GeoIP Database Setup
Download and configure MaxMind GeoLite2-City and GeoLite2-ASN databases (free registration). Code is wired up and ready — just needs databases in `/var/mnt/ai/geoip/`. Set up weekly auto-update via cron/timer.

### AbuseIPDB API Key
Register for free AbuseIPDB API key and configure `ABUSEIPDB_KEY` env var. Code is wired up — enables IP reputation scoring in alert analysis and auto-reporting of blocked IPs.

### LLM Confidence Calibration
Compare HiveCoder confidence scores against AbuseIPDB abuse_score and GeoIP data to calibrate auto-block thresholds. Adjust tier confidence requirements based on observed false positive rates.

---

## Research

- **Fine-tune for IDS** — Train a LoRA adapter specifically on Suricata alert classification. The general-purpose Qwen3-14B works but a specialized model could be faster and more accurate.
- **Multi-sensor correlation** — Combine Suricata alerts with DNS logs, firewall logs, and auth logs for richer attack chain detection.
- **Honeypot integration** — Deploy low-interaction honeypots on commonly probed ports, feed interactions directly into the analysis pipeline.
- **Automated rule generation** — Use attack pattern analysis to suggest new Suricata rules for recurring threats not covered by existing rulesets.
- **ROCm on RDNA2** — Document the `HSA_OVERRIDE_GFX_VERSION=11.0.0` approach for gfx1032 cards. Test llama.cpp + ROCm in container on 6700 XT for inference viability and benchmark tok/s.
