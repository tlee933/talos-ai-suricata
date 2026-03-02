# Talos AI Suricata — Roadmap

*Last updated: 2026-03-01*

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

---

## Next

### Repeat Offender Detection
Track IPs seen across multiple correlation windows. If an IP appears in 3+ correlation cycles, auto-escalate to block regardless of individual alert confidence. The correlation buffer clears every 5 minutes — need a persistent counter in Redis.

### GeoIP Enrichment
Add country/ASN lookup to alert analysis context. Would let the LLM make better decisions (e.g., traffic from known bulletproof hosting ASNs deserves lower confidence thresholds). MaxMind GeoLite2 database, updated weekly.

### Alert Fatigue Reduction
Group similar alerts by signature + subnet and present as single entries in the dashboard. Currently 800+ unique IPs produce thousands of alerts that are mostly the same DShield/Censys scans. Need aggregation before display.

### Webhook Notifications
Send critical/high severity blocks to a webhook (Discord, Slack, ntfy). Currently the only notification path is checking the dashboard or querying via MCP.

### Historical Trend Analysis
Compare today's alert volume/distribution against 7-day and 30-day baselines. Flag anomalies (sudden spike in a category, new signature never seen before, new source country). Store daily summaries in Redis sorted set for fast lookups.

### Blocklist Sync
Export the `ai_blocklist` alias to a standard blocklist format (CSV, STIX, plain text). Allow importing community blocklists. Two-way sync with AbuseIPDB or similar reputation services.

---

## Research

- **LLM confidence calibration** — Current confidence scores come from the LLM's self-assessment. Compare against ground truth (VirusTotal, AbuseIPDB) to calibrate thresholds.
- **Fine-tune for IDS** — Train a LoRA adapter specifically on Suricata alert classification. The general-purpose Qwen3-14B works but a specialized model could be faster and more accurate.
- **Multi-sensor correlation** — Combine Suricata alerts with DNS logs, firewall logs, and auth logs for richer attack chain detection.
- **Honeypot integration** — Deploy low-interaction honeypots on commonly probed ports, feed interactions directly into the analysis pipeline.
- **Automated rule generation** — Use attack pattern analysis to suggest new Suricata rules for recurring threats not covered by existing rulesets.
