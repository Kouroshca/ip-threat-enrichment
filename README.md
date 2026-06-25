# IP Threat Enrichment Tool
A SOC triage tool that accepts any input — single IP, CSV, or log file — 
automatically extracts and enriches IPs against two threat intelligence 
sources, and produces an actionable HTML report for analysts.
Built as a portfolio project to demonstrate SOC analyst fundamentals:
multi-source threat intel fusion, honest failure handling, and operational
efficiency through caching.

## What It Does
1. **Accepts any input** — paste a single IP, upload a CSV, or drop a raw log file
2. **Cleans automatically** — deduplicates IPs, strips private/reserved ranges
3. **Enriches against two sources** — VirusTotal v3 and AbuseIPDB v2
4. **Returns an honest verdict** — Malicious / Suspicious / Clean / Unknown
5. **Caches results** — SQLite cache with 24hr TTL so re-runs don't burn quota
6. **Generates a report** — dark-themed HTML triage dashboard

## The Design Decision That Matters
Most enrichment tools return **Clean** when a lookup fails.
This tool returns **Unknown**.
A rate-limited API, an expired key, or a network timeout all produce the 
same result in a naive tool: zero scores, which look identical to a genuinely 
clean IP. This tool tracks lookup status separately from scores. If either 
VirusTotal or AbuseIPDB fails to answer, the verdict is Unknown and the 
analyst is told to re-query manually.
A tool that lies on failure is worse than no tool at all.
---
## Verdict Logic

| Condition | Verdict |
|---|---|
| Either source failed to respond | ⚪ Unknown |
| VT engines ≥ threshold OR AbuseIPDB ≥ 80% | 🔴 Malicious |
| VT engines > 0 OR AbuseIPDB ≥ 20% | 🟡 Suspicious |
| Both sources answered, both clean | 🟢 Clean |

Thresholds are configurable in `config.py` — no magic numbers in logic code.

---
## Project Structure
ip-threat-enrichment

├── parser.py       # Extracts valid IPs from any input format

├── enricher.py     # Queries VirusTotal v3 and AbuseIPDB v2

├── verdict.py      # Fuses two sources into one honest verdict

├── cache.py        # SQLite cache with TTL — preserves API quota

├── reporter.py     # Generates dark-themed HTML triage report

├── config.py       # API keys, endpoints, thresholds, TTL

├── main.py         # Entry point — wires everything together

│

├── tests/

│   └── test_verdict.py   # pytest — proves the brain can't lie

│

├── sample_data/

│   └── sample_ips.txt    # Test IPs across all verdict categories

│

├── .env                  # API keys — never committed

└── requirements.txt.

---

## Quickstart

**1. Clone the repo**
```bash
git clone https://github.com/Kouroshca/ip-threat-enrichment
cd ip-threat-enrichment
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Add your API keys**

Create a `.env` file in the project root:

Get free keys at:
- VirusTotal: https://www.virustotal.com
- AbuseIPDB: https://www.abuseipdb.com

**4. Run it**
```bash
# Single IP
python main.py 185.220.101.45

# IP list
python main.py sample_data/sample_ips.txt

# CSV file
python main.py logs/firewall_export.csv

# Log file
python main.py logs/nginx_access.log
```

**5. Open the report**

`triage_report.html` is generated in your project root. Open it in any browser.

---

## Running Tests

```bash
pytest tests/ -v
```

12 tests covering: failed lookups never produce Clean, auth errors produce 
Unknown, threshold boundaries, and action string correctness.

## Configuration

All tunable values live in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `VT_MALICIOUS_THRESHOLD` | 3 | Min VT engines to flag Malicious |
| `ABUSE_MALICIOUS_THRESHOLD` | 80 | Min AbuseIPDB % to flag Malicious |
| `ABUSE_SUSPICIOUS_THRESHOLD` | 20 | Min AbuseIPDB % to flag Suspicious |
| `CACHE_TTL_HOURS` | 24 | Hours before cached results expire |

## Tech Stack

- Python 3.11
- VirusTotal API v3
- AbuseIPDB API v2
- SQLite (via stdlib)
- Jinja2 (HTML templating)
- pandas (CSV parsing)
- pytest (verdict logic tests)
- python-dotenv (key management)

## Roadmap
- [ ] IPv6 support
- [ ] CSV export for SIEM ingestion
- [ ] Third intel source (Shodan or GreyNoise)
- [ ] Severity-sorted report — Malicious rows first
- [ ] GitHub Actions: auto-run pytest on every push
- [ ] Chrome extension frontend with Flask backend

## Limitations

- IPv4 only — IPv6 support planned
- Free API tiers: VT ~500 lookups/day, AbuseIPDB ~1000/day
- 15 second delay between API calls to respect free tier rate limits
- `.evtx` (Windows Event Log binary) not supported — plaintext logs only

# Creator: 

Kourosh Kalatian  
[github.com/Kouroshca](https://github.com/Kouroshca) | [kourosh-kalatian.com](https://kourosh-kalatian.com) | [LinkedIn](https://linkedin.com/in/kourosh-kalatian-692818271)
