# Threat Intelligence Aggregator

A Python-based cybersecurity tool that collects, parses, correlates, and reports on threat indicators (IOCs) from multiple sources.

Built as part of the **Unified Mentor Cybersecurity Internship** program.

---

## What This Project Does

In cybersecurity, a threat indicator (IOC) is something like a malicious IP address, a suspicious domain name, a dangerous URL, a malware file hash, or an attacker's email address. Security teams use these to block threats and protect their networks.

The problem is that these indicators come from many different sources, in many different formats, and analysts have to manually process all of it. This tool automates that work.

**Give it a folder of threat feeds → it produces cleaned blocklists and a full report.**

---

## How It Works

The tool runs in 6 steps:

1. **Load Feeds** — reads all threat feed files from a folder (CSV, TXT, JSON supported)
2. **Parse IOCs** — extracts IP addresses, domains, URLs, file hashes, and emails using regex
3. **Normalize** — validates and cleans everything; removes duplicates and invalid entries
4. **Correlate** — checks which indicators appear in multiple feeds and scores them by risk (0–100)
5. **Generate Blocklists** — writes 8 ready-to-use blocklist files for different security tools
6. **Report** — produces a full intelligence report in TXT, JSON, and CSV formats

---

## How to Run

```bash
# Basic run — processes all files in the feeds/ folder
python main.py

# Use a different folder
python main.py --feeds /path/to/your/feeds

# Only include indicators with a risk score of 30 or above in blocklists
python main.py --min-score 30

# Specify everything manually
python main.py --feeds ./feeds --output ./results --min-score 25
```

No installation needed. Uses Python 3 standard library only.

---

## Project Structure

```
ti_aggregator/
│
├── main.py                  ← Run this to start the tool
├── requirements.txt         ← No external packages needed
├── README.md
│
├── feeds/                   ← Put your threat feed files here
│   ├── feed1_ips.csv
│   ├── feed2_mixed.txt
│   └── feed3_structured.json
│
├── modules/                 ← The 5 Python modules
│   ├── parser.py            ← Reads and parses feed files
│   ├── normalizer.py        ← Cleans and validates indicators
│   ├── correlator.py        ← Cross-feed correlation + risk scoring
│   ├── blocklist_gen.py     ← Generates blocklist files
│   └── reporter.py          ← Writes the final report
│
└── output/
    ├── blocklists/
    │   ├── ip_blocklist.txt
    │   ├── domain_blocklist.txt
    │   ├── url_blocklist.txt
    │   ├── hash_blocklist.txt
    │   ├── email_blocklist.txt
    │   ├── master_blocklist.csv
    │   ├── master_blocklist.json
    │   └── high_risk_only.csv
    └── reports/
        ├── ti_report.txt
        ├── ti_report.json
        └── ioc_database.csv
```

---

## Feed Formats Supported

| Format | Extension | Notes |
|--------|-----------|-------|
| CSV | .csv | Needs columns: indicator, type, severity, source |
| Plain Text | .txt | One indicator per line, lines starting with # are ignored |
| JSON | .json | Needs a key called "indicators" with a list of objects |

---

## IOC Types the Tool Handles

| Type | Example |
|------|---------|
| IP Address | 185.220.101.45 |
| Domain | malware.evil-domain.ru |
| URL | http://malicious-site.net/payload.exe |
| File Hash (MD5/SHA1/SHA256) | 44d88612fea8a8f36de82e1278abb02f |
| Email Address | attacker@evil-domain.ru |

---

## Risk Scoring

Every indicator gets a score from 0 to 100:

- Starts with a base score based on severity (Low = 5, Medium = 15, High = 30, Critical = 40)
- Gets +10 points for every additional feed it appears in (up to +30)
- Gets +10 bonus points if it appears in 3 or more feeds
- Final score is capped at 100

**Score thresholds:** Critical ≥ 75 | High ≥ 50 | Medium ≥ 25 | Low < 25

---

## Sample Results (from test run)

- Feeds processed: 4
- Raw indicators collected: 57
- Valid unique indicators after cleaning: 35
- Indicators seen in 2+ feeds: 13
- High-risk indicators (score ≥ 50): 3
- Blocklist files created: 8
- Run time: less than 1 second

---

## Libraries Used

All from Python's standard library — no pip install required:

| Library | Used For |
|---------|----------|
| re | Regular expressions to extract IOC patterns |
| csv | Reading/writing CSV files |
| json | Reading/writing JSON files |
| os | File system navigation |
| ipaddress | IP address validation and RFC 1918 filtering |
| datetime | Adding timestamps to indicators |
| argparse | Command-line interface |

---

## Output Files

### Blocklists

| File | For Use With |
|------|-------------|
| ip_blocklist.txt | iptables, pfSense, Palo Alto firewall |
| domain_blocklist.txt | Pi-hole, DNS sinkhole |
| url_blocklist.txt | Squid proxy, Nginx |
| hash_blocklist.txt | CrowdStrike, Windows Defender, YARA |
| email_blocklist.txt | SpamAssassin, Postfix, Office 365 |
| master_blocklist.csv | All types together — SIEM import |
| master_blocklist.json | All types in JSON — API integration |
| high_risk_only.csv | Only the highest-risk indicators |

### Reports

| File | Description |
|------|-------------|
| ti_report.txt | Full human-readable summary |
| ti_report.json | Structured data for machine processing |
| ioc_database.csv | Complete spreadsheet of all indicators |

---

*Unified Mentor Internship — Cybersecurity — April 2026*
