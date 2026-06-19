# IP Threat Enrichment Tool #

Automated SOC triage tool that checks and classifys IPs with 2 powerfull Threat Intelligence: VirusTotal, and AbuseIPDb. 
---

## What It Does ##

1. **Ingests** IPs from a `.txt` file, `.csv` log export, or comma-separated CLI input
2. **Queries** VirusTotal API:  checks vendor detection count
3. **Queries** AbuseIPDB API:  checks abuse confidence score and report history
4. **Classifies** each IP using dual-source scoring logic
5. **Generates** a color-coded HTML report + CSV for documentation

---

## 📊 Classification Logic

| Verdict | Condition |
|---------|-----------|
| 🔴 MALICIOUS | VT flags >= 5 or AbuseIPDB score >= 50% |
| 🟡 SUSPICIOUS | VT flags >= 1 or AbuseIPDB score >= 20% |
| 🟢 CLEAN | Below all thresholds |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/Kouroshca/ip-threat-enrichment
cd ip-threat-enrichment
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set your API keys
Get free API keys from:
- [VirusTotal](https://www.virustotal.com/gui/my-apikey)
- [AbuseIPDB](https://www.abuseipdb.com/api)

```bash
export VT_API_KEY="your_virustotal_key"
export ABUSE_API_KEY="your_abuseipdb_key"
```

### 4. Run it
```bash
# Using the sample file
python enricher.py sample_data/sample_ips.txt

# Using your own file
python enricher.py /path/to/your/ips.txt

# Using a CSV from Splunk export
python enricher.py splunk_alert_export.csv

# Using comma-separated IPs directly
python enricher.py "8.8.8.8,185.220.101.45,1.1.1.1"
```

---

##  Project Structure

```
ip-threat-enrichment/
├── enricher.py              # Main tool
├── requirements.txt
├── sample_data/
│   └── sample_ips.txt       # Test IPs
└── README.md
```

---

##  Integration with Splunk IDS

This tool is designed to complement the [Python IDS with Splunk Cloud](https://github.com/Kouroshca/python-ids-splunk) project:

1. IDS detects suspicious activity => logs attacker IPs
2. Export IPs from Splunk => feed into this enrichment tool
3. Report identifies which IPs are confirmed malicious
4. Analyst escalates or blocks based on triage output

---

##  Tech Stack

- **Python 3.10+**
- **VirusTotal API v3**
- **AbuseIPDB API v2**
- **Jinja2** — HTML report templating
- **Requests** — API calls
- **Pandas** — CSV handling

---

# Creator: 

Kourosh Kalatian  
[github.com/Kouroshca](https://github.com/Kouroshca) | [kourosh-kalatian.com](https://kourosh-kalatian.com) | [LinkedIn](https://linkedin.com/in/kourosh-kalatian-692818271)
