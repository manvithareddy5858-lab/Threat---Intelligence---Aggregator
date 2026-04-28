Threat Intelligence Aggregator

A Python-based cybersecurity tool that collects, parses, correlates, and reports on threat indicators (IOCs) from multiple sources.

Built as part of the Unified Mentor Cybersecurity Internship – April 2026.

This project demonstrates how Blue Team and SOC analysts process threat intelligence feeds, identify high-risk indicators, and generate deployment-ready blocklists for defensive security tools.

Project Overview

In cybersecurity, a Threat Indicator (IOC – Indicator of Compromise) is evidence of malicious activity. Examples include:

Malicious IP addresses
Suspicious domain names
Dangerous URLs
Malware file hashes
Attacker email addresses

Security teams rely on threat intelligence feeds from multiple sources to detect and block threats.

However, these feeds often:

Come in different formats
Contain duplicate indicators
Require manual correlation
Are difficult to convert into usable blocklists

This tool automates that entire workflow.

Give it a folder of threat feeds → it produces cleaned blocklists and a full intelligence report.

Key Features
Multi-format threat feed ingestion (CSV, TXT, JSON)
Regex-based IOC extraction
Indicator validation and normalization
Cross-feed IOC correlation
Risk scoring engine (0–100)
Automated blocklist generation
Human-readable and machine-readable reports
Modular Python architecture
Uses only Python standard library (no external dependencies)
System Architecture

The tool processes threat intelligence through a 6-stage pipeline.

Threat Feeds
      │
      ▼
Feed Loader
      │
      ▼
IOC Parser
      │
      ▼
Normalization Engine
      │
      ▼
Correlation Engine
      │
      ▼
Blocklist Generator
      │
      ▼
Report Generator
      │
      ▼
Outputs (Blocklists + TI Reports)
How It Works

The tool runs in six stages:

1. Load Feeds

Reads all threat feed files from a directory.

Supported formats:

CSV
TXT
JSON
2. Parse IOCs

Extracts indicators using regular expressions:

IP addresses
Domains
URLs
File hashes
Email addresses
3. Normalize

Validates and cleans indicators:

Removes invalid entries
Removes duplicates
Filters private IP ranges
Standardizes metadata
4. Correlate

Finds indicators appearing in multiple feeds.

Indicators seen across multiple sources receive higher confidence scores.

5. Generate Blocklists

Creates ready-to-deploy blocklists for security tools such as:

Firewalls
DNS filtering systems
Web proxies
EDR tools
6. Reporting

Produces detailed intelligence reports containing:

Indicator statistics
Risk scoring results
Correlated high-risk indicators
Complete IOC database
How to Run

Basic execution:

python main.py

Processes all feeds located in the feeds/ directory.

Use a custom feed directory
python main.py --feeds /path/to/your/feeds
Only include higher-risk indicators
python main.py --min-score 30
Specify all parameters
python main.py --feeds ./feeds --output ./results --min-score 25
Example Execution Output
python main.py --feeds ./feeds

[+] Loading feeds...
[+] Parsing indicators...
[+] Normalizing data...
[+] Running correlation engine...
[+] Generating blocklists...
[+] Writing TI report...

Pipeline complete.
Project Structure
ti_aggregator/
│
├── main.py                  # Entry point for the application
├── requirements.txt         # No external packages required
├── README.md
│
├── feeds/                   # Threat feed input files
│   ├── feed1_ips.csv
│   ├── feed2_mixed.txt
│   └── feed3_structured.json
│
├── modules/                 # Core processing modules
│   ├── parser.py            # Feed parser
│   ├── normalizer.py        # Data normalization & validation
│   ├── correlator.py        # IOC correlation engine
│   ├── blocklist_gen.py     # Blocklist generation
│   └── reporter.py          # Report generation
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
    │
    └── reports/
        ├── ti_report.txt
        ├── ti_report.json
        └── ioc_database.csv
Feed Formats Supported
Format	Extension	Notes
CSV	.csv	Must include indicator, type, severity, source
Plain Text	.txt	One indicator per line
JSON	.json	Contains an indicators array
IOC Types Supported
Type	Example
IP Address	185.220.101.45
Domain	malware.evil-domain.ru
URL	http://malicious-site.net/payload.exe
File Hash	44d88612fea8a8f36de82e1278abb02f
Email Address	attacker@evil-domain.ru
Risk Scoring

Each indicator receives a score between 0 and 100.

Scoring logic:

Risk Score =
Base Severity Score
+ (10 × Additional Feed Count)  [max 30]
+ Multi-Feed Bonus (10 if indicator appears in 3+ feeds)

Severity thresholds:

Critical ≥ 75
High ≥ 50
Medium ≥ 25
Low < 25
Sample Results (Test Run)

Feeds processed: 4

Raw indicators collected: 57

Valid unique indicators after normalization: 35

Indicators appearing in multiple feeds: 13

High-risk indicators (score ≥ 50): 3

Blocklist files generated: 8

Pipeline runtime: < 1 second

Output Files
Blocklists
File	Used With
ip_blocklist.txt	iptables, pfSense, Palo Alto
domain_blocklist.txt	DNS filtering / Pi-hole
url_blocklist.txt	Web proxies
hash_blocklist.txt	EDR / Antivirus
email_blocklist.txt	Email security gateways
master_blocklist.csv	SIEM ingestion
master_blocklist.json	API integration
high_risk_only.csv	Immediate threat response
Reports
File	Description
ti_report.txt	Human-readable threat intelligence report
ti_report.json	Structured report for automation
ioc_database.csv	Full IOC dataset
Libraries Used

All modules are from the Python Standard Library.

Library	Purpose
re	IOC pattern extraction
csv	CSV parsing
json	JSON feed parsing
os	File system operations
ipaddress	IP validation
datetime	Timestamping indicators
argparse	Command line interface

No external dependencies required.

Example Screenshots

Example execution of the tool.

(Screenshots can be added here showing terminal execution and generated reports.)

Future Improvements

Potential enhancements for future development:

Support for STIX/TAXII threat intelligence feeds
Integration with SIEM platforms (Splunk, ELK)
Real-time ingestion from OSINT threat feeds
Web dashboard for IOC visualization
IOC enrichment using reputation APIs
Learning Outcomes

This project demonstrates practical knowledge of:

Threat Intelligence processing
Indicator normalization
Cross-feed correlation
Blocklist generation
SOC automation workflows
Python-based security tooling
License

Educational project developed for internship evaluation.

Unified Mentor Cybersecurity Internship — April 2026
