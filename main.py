#!/usr/bin/env python3
"""
main.py — Primary Entry Point (alias for ti_aggregator.py)
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Usage:
    python main.py
    python main.py --feeds ./feeds/ --output ./output/
    python main.py --feeds ./feeds/ --output ./output/ --min-score 50
    python main.py --help
"""

import os
import sys
import time
import argparse

# ── Path setup so modules are importable ──────────────────────────────────────
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Support both flat layout (files in root) and src/ layout
_SRC_DIR = os.path.join(_BASE_DIR, "src")
if os.path.isdir(_SRC_DIR):
    sys.path.insert(0, _SRC_DIR)
else:
    sys.path.insert(0, _BASE_DIR)

# ── Import modules (works whether they live in src/ or root) ──────────────────
try:
    from parser import load_all_feeds
    from normalizer import normalize
    from correlator import correlate
    from blocklist_gen import generate_blocklists
    from reporter import generate_reports
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[!] Make sure parser.py, normalizer.py, correlator.py,")
    print("    blocklist_gen.py, and reporter.py are present.")
    sys.exit(1)

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║   THREAT INTELLIGENCE AGGREGATOR  v1.1                      ║
║   Non-AI | Rule-Based | IOC Correlation & Blocklist Engine   ║
║   Unified Mentor Cybersecurity Internship — April 2026       ║
╚══════════════════════════════════════════════════════════════╝
"""

def parse_args():
    p = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator — IOC Correlation & Blocklist Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --feeds ./feeds/ --output ./output/
  python main.py --feeds ./feeds/ --output ./output/ --min-score 50
        """
    )
    p.add_argument(
        "--feeds",
        default="./feeds/",
        help="Directory containing IOC feed files (default: ./feeds/)"
    )
    p.add_argument(
        "--output",
        default="./output/",
        help="Directory for blocklists and reports (default: ./output/)"
    )
    p.add_argument(
        "--min-score",
        type=int,
        default=50,
        help="Minimum risk score to include in high-risk blocklist (default: 50)"
    )
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()
    start = time.time()

    # ── STEP 1: Load & Parse ──────────────────────────────────────────────
    print("─" * 60)
    print("STEP 1 / 5 — Load & Parse IOC Feeds")
    print("─" * 60)
    raw_iocs = load_all_feeds(args.feeds)
    if not raw_iocs:
        print("[✗] No IOCs loaded. Check your feeds directory.")
        sys.exit(1)

    # ── STEP 2: Normalize ─────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("STEP 2 / 5 — Normalize & Validate")
    print("─" * 60)
    normalised = normalize(raw_iocs)
    if not normalised:
        print("[✗] No valid IOCs after normalization.")
        sys.exit(1)

    # Cross-feed dedup
    seen_global = {}
    for ioc in normalised:
        key = ioc["value"].lower()
        if key not in seen_global:
            seen_global[key] = ioc
    unique_iocs = list(seen_global.values())
    print(f"[+] Unique IOCs (cross-feed dedup): {len(unique_iocs)}\n")

    # ── STEP 3: Correlate ─────────────────────────────────────────────────
    print("─" * 60)
    print("STEP 3 / 5 — Cross-Feed Correlation & Risk Scoring")
    print("─" * 60)
    correlation_result = correlate(normalised)

    # ── STEP 4: Blocklist Generation ──────────────────────────────────────
    print("─" * 60)
    print("STEP 4 / 5 — Blocklist Generation")
    print("─" * 60)
    blocklist_summary = generate_blocklists(correlation_result, args.output)

    # ── STEP 5: Reporting ─────────────────────────────────────────────────
    print("─" * 60)
    print("STEP 5 / 5 — Report Generation")
    print("─" * 60)
    generate_reports(correlation_result, blocklist_summary, args.output, args.feeds)

    elapsed = time.time() - start
    print("═" * 60)
    print(f"  ✅  Pipeline complete in {elapsed:.2f}s")
    print(f"  📁  Output directory : {os.path.abspath(args.output)}")
    print("═" * 60)


if __name__ == "__main__":
    main()
