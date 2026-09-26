# Log Analyzer — Brute Force Detection

A Python script that parses SSH authentication logs and detects brute-force login attempts using time-window correlation, similar to how a SIEM detection rule works.

## What it does


- Parses log entries for failed SSH login attempts (username, IP, timestamp)
- Groups failed attempts by source IP
- Flags an IP as suspicious if it has a configurable number of failed attempts within a configurable time window (default: 3+ attempts within 5 minutes)
- Distinguishes real attack patterns (rapid repeated failures) from normal, spread-out login mistakes

## Why time-window detection matters

Counting total failed attempts alone isn't enough — 3 failed logins over a week is normal human error, while 3 failed logins in 10 seconds is a strong brute-force signal. This script correlates attempts by *time*, not just count, which is the same core logic used in real SIEM detection rules (e.g., Splunk correlation searches, Sigma rules).

## Tech stack

- Python 3
- `re` (regular expressions) for log parsing
- `datetime` for timestamp comparison
- `collections.defaultdict` for grouping

## Setup

```bash
git clone https://github.com/prashamsathapa-jpg/log-analyzer.git
cd log-analyzer
python3 analyzer.py
```

## Sample output
Total failed login attempts found: 8

Checking for 3+ failed attempts within 5 minutes:

🚨 SUSPICIOUS: 192.168.1.50 — 5 failed attempts within 5 min (possible brute force)
OK: 45.33.12.9 — 2 failed attempt(s), not within threshold window
OK: 10.0.0.20 — 1 failed attempt(s), not within threshold window

## Security concepts demonstrated

- Log parsing and pattern matching (regex) on real-world log formats
- Time-series correlation for anomaly/attack detection
- Understanding brute-force attack signatures from a defensive (blue team) perspective
- The difference between raw event counting and rate-based detection logic used in SIEM tools

## Planned improvements

- [ ] Test against real logs generated from an actual Hydra brute-force attack in a home lab
- [ ] Export findings to a CSV/report file
- [ ] Detect brute force by username across multiple source IPs (distributed attack pattern)
- [ ] Add configurable thresholds via command-line arguments

## Disclaimer

This is a learning project built to understand detection logic used in SOC/blue-team work. Sample log data included is fabricated for demonstration purposes.
