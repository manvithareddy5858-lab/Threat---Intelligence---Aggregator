#!/usr/bin/env python3
"""
ti_aggregator.py — Main CLI Entry Point
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Usage:
    python ti_aggregator.py --feeds ./feeds/ --output ./output/
    python ti_aggregator.py --feeds ./feeds/ --output ./output/ --min-score 50
    python ti_aggregator.py --help
"""

import os
import sys
import time
import argparse

# ── Path setup so src/ modules are importable ─────────────────────────────────
_SRC_DIR = os.path.join(os.path.dirname(__file__), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from parser        import load_all_feeds
from normalizer    import normalize
from correlator    import correlate
from blocklist_gen import generate_blocklists
from reporter      import generate_reports

BANNER = r"""
 ████████╗██╗     ██████╗  █████╗  ██████╗  ██████╗ ██████╗ ███████╗ ██╗
    ██╔══╝██║    ██╔════╝ ██╔══██╗██╔════╝ ██╔════╝██╔════╝ ██╔════╝ ██║
    ██║   ██║    ███████╗ ███████║██║  ███╗██║  ███╗█████╗   ██████╗  ██║
    ██║   ██║    ╚════██║ ██╔══██║██║   ██║██║   ██║██╔══╝    ╚═══██╗ ╚═╝
    ██║   ██║    ███████║ ██║  ██║╚██████╔╝╚██████╔╝███████╗ ██████╔╝ ██╗
    ╚═╝   ╚═╝    ╚══════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═╝

  Threat Intelligence Aggregator v1.1 | Non-AI, Rule-Based | TLP:WHITE
  Unified Mentor Cybersecurity Internship — Blue Team / SOC Track
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator — IOC Correlation & Blocklist Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ti_aggregator.py --feeds ./feeds/ --output ./output/
  python ti_aggregator.py --feeds ./feeds/ --output ./output/ --min-score 50
        """
    )
    p.add_argument("--feeds",     default="./feeds/",  help="Directory containing IOC feed files (default: ./feeds/)")
    p.add_argument("--output",    default="./output/", help="Directory for blocklists and reports (default: ./output/)")
    p.add_argument("--min-score", type=int, default=50, help="Minimum risk score for high-risk filter (default: 50)")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    start = time.time()

    # ── STEP 1: Load & Parse ──────────────────────────────────────────────────
    print("─" * 60)
    print("STEP 1 / 5 — Load & Parse IOC Feeds")
    print("─" * 60)
    raw_iocs = load_all_feeds(args.feeds)
    if not raw_iocs:
        print("[✗] No IOCs loaded. Exiting.")
        sys.exit(1)

    # ── STEP 2: Normalize ─────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("STEP 2 / 5 — Normalize & Validate")
    print("─" * 60)
    normalised = normalize(raw_iocs)
    if not normalised:
        print("[✗] No valid IOCs after normalization. Exiting.")
        sys.exit(1)

    # Unique dedup across all feeds
    seen_global = {}
    for ioc in normalised:
        key = ioc["value"].lower()
        if key not in seen_global:
            seen_global[key] = ioc
    unique_iocs = list(seen_global.values())
    print(f"[+] Unique IOCs (cross-feed dedup): {len(unique_iocs)}\n")

    # ── STEP 3: Correlate ─────────────────────────────────────────────────────
    print("─" * 60)
    print("STEP 3 / 5 — Cross-Feed Correlation & Risk Scoring")
    print("─" * 60)
    correlation_result = correlate(normalised)

    # ── STEP 4: Blocklist Generation ──────────────────────────────────────────
    print("─" * 60)
    print("STEP 4 / 5 — Blocklist Generation")
    print("─" * 60)
    blocklist_summary = generate_blocklists(correlation_result, args.output)

    # ── STEP 5: Reporting ─────────────────────────────────────────────────────
    print("─" * 60)
    print("STEP 5 / 5 — Report Generation")
    print("─" * 60)
    generate_reports(correlation_result, blocklist_summary, args.output, args.feeds)

    elapsed = time.time() - start
    print("═" * 60)
    print(f"  ✅  Pipeline complete in {elapsed:.2f}s")
    print(f"  📁  Output directory: {os.path.abspath(args.output)}")
    print("═" * 60)


if __name__ == "__main__":
    main()
