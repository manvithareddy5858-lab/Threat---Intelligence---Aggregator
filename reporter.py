"""
reporter.py — Reporting Module
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Produces three report formats from the pipeline results:
  ti_report.txt       — human-readable executive summary
  ti_report.json      — machine-readable full report (SIEM / SOAR)
  ioc_database.csv    — flat CSV of all unique IOCs
"""

import os
import csv
import json
from datetime import datetime, timezone
from collections import Counter


_DIVIDER = "=" * 78
_SUBDIV  = "-" * 78


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_human():
    return datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")


# ── Text Report ───────────────────────────────────────────────────────────────

def _build_text_report(correlation_result: dict, blocklist_summary: dict,
                        feed_dir: str) -> str:
    master    = correlation_result["master_list"]
    repeated  = correlation_result["repeated"]
    high_risk = correlation_result["high_risk"]

    # Aggregate stats
    type_counts = Counter(i["type"] for i in master)
    sev_counts  = Counter(i["severity"] for i in master)
    all_sources = sorted({s for i in master for s in i["sources"]})

    lines = [
        _DIVIDER,
        "  THREAT INTELLIGENCE AGGREGATOR — FINAL REPORT",
        f"  Generated : {_now_human()}",
        f"  TLP       : WHITE",
        _DIVIDER,
        "",
        "1. EXECUTIVE SUMMARY",
        _SUBDIV,
        f"  Feed Directory     : {feed_dir}",
        f"  Feeds Processed    : {len(all_sources)}",
        f"  Total Unique IOCs  : {len(master)}",
        f"  Cross-Feed Matches : {len(repeated)}",
        f"  High-Risk (>=50)   : {len(high_risk)}",
        f"  Blocklist Files    : {len(blocklist_summary)}",
        "",
        "2. FEED SOURCES",
        _SUBDIV,
    ]
    for src in all_sources:
        src_iocs = [i for i in master if src in i["sources"]]
        lines.append(f"  • {src:<40} {len(src_iocs):>3} IOCs")

    lines += [
        "",
        "3. IOC TYPE DISTRIBUTION",
        _SUBDIV,
    ]
    for ioc_type in ("ip", "domain", "url", "hash", "email"):
        count = type_counts.get(ioc_type, 0)
        bar   = "█" * count
        lines.append(f"  {ioc_type.upper():<10} {count:>3}  {bar}")

    lines += [
        "",
        "4. SEVERITY BREAKDOWN",
        _SUBDIV,
    ]
    for sev in ("Critical", "High", "Medium", "Low"):
        count = sev_counts.get(sev, 0)
        lines.append(f"  {sev:<10} {count:>3}")

    lines += [
        "",
        "5. HIGH-RISK INDICATORS  (risk score >= 50)",
        _SUBDIV,
        f"  {'VALUE':<38}  {'TYPE':<8}  {'SCORE':>5}  {'SEV':<8}  FEEDS",
        "  " + "-" * 72,
    ]
    for ioc in high_risk:
        feeds = ", ".join(ioc["sources"])
        lines.append(
            f"  {ioc['value']:<38}  {ioc['type']:<8}  "
            f"{ioc['risk_score']:>5}  {ioc['severity']:<8}  {feeds}"
        )

    lines += [
        "",
        "6. CROSS-FEED CORRELATED IOCs  (2+ feeds)",
        _SUBDIV,
        f"  {'VALUE':<38}  {'TYPE':<8}  {'SCORE':>5}  FEEDS",
        "  " + "-" * 60,
    ]
    for ioc in repeated[:20]:
        lines.append(
            f"  {ioc['value']:<38}  {ioc['type']:<8}  "
            f"{ioc['risk_score']:>5}  {ioc['feed_count']}"
        )
    if len(repeated) > 20:
        lines.append(f"  ... and {len(repeated) - 20} more (see ioc_database.csv)")

    lines += [
        "",
        "7. BLOCKLIST FILES GENERATED",
        _SUBDIV,
    ]
    for fname, count in blocklist_summary.items():
        lines.append(f"  {fname:<40} {count:>3} entries")

    lines += [
        "",
        "8. RISK SCORING FORMULA",
        _SUBDIV,
        "  Score = Base Severity Score",
        "        + Feed Bonus  (10 pts per extra feed beyond first, max 30)",
        "        + Multi-Feed Bonus  (10 pts if seen in 3+ feeds)",
        "  [capped at 100]",
        "",
        "  Critical >= 75  |  High >= 50  |  Medium >= 25  |  Low < 25",
        "",
        _DIVIDER,
        "  END OF REPORT",
        _DIVIDER,
        "",
    ]
    return "\n".join(lines)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_reports(correlation_result: dict, blocklist_summary: dict,
                     output_dir: str, feed_dir: str = "./feeds") -> dict:
    """
    Write ti_report.txt, ti_report.json, and ioc_database.csv.
    Returns { filename: filepath }.
    """
    os.makedirs(output_dir, exist_ok=True)
    master    = correlation_result["master_list"]
    repeated  = correlation_result["repeated"]
    high_risk = correlation_result["high_risk"]
    results   = {}

    # ── 1. Text report ────────────────────────────────────────────────────────
    txt_path = os.path.join(output_dir, "ti_report.txt")
    report_text = _build_text_report(correlation_result, blocklist_summary, feed_dir)
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(report_text)
    results["ti_report.txt"] = txt_path
    print(f"[✓] ti_report.txt")

    # ── 2. JSON report ────────────────────────────────────────────────────────
    json_path = os.path.join(output_dir, "ti_report.json")
    all_sources = sorted({s for i in master for s in i["sources"]})
    type_counts = Counter(i["type"] for i in master)
    sev_counts  = Counter(i["severity"] for i in master)

    report_json = {
        "meta": {
            "generated":        _now(),
            "tlp":              "WHITE",
            "tool":             "Threat Intelligence Aggregator v1.1",
        },
        "summary": {
            "feeds_processed":   len(all_sources),
            "unique_iocs":       len(master),
            "cross_feed_matches": len(repeated),
            "high_risk_count":   len(high_risk),
            "blocklist_files":   len(blocklist_summary),
        },
        "type_distribution":     dict(type_counts),
        "severity_breakdown":    dict(sev_counts),
        "feed_sources":          all_sources,
        "high_risk_indicators":  high_risk,
        "correlated_indicators": repeated,
        "blocklist_summary":     blocklist_summary,
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report_json, fh, indent=2, default=str)
    results["ti_report.json"] = json_path
    print(f"[✓] ti_report.json")

    # ── 3. IOC database CSV ───────────────────────────────────────────────────
    csv_path = os.path.join(output_dir, "ioc_database.csv")
    fields = ["value", "type", "hash_subtype", "category", "risk_score",
              "severity", "feed_count", "sources", "description", "first_seen"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for ioc in master:
            row = dict(ioc)
            row["sources"]      = "|".join(ioc.get("sources", []))
            row["hash_subtype"] = ioc.get("hash_subtype") or ""
            writer.writerow(row)
    results["ioc_database.csv"] = csv_path
    print(f"[✓] ioc_database.csv")

    print(f"\n[✓] Generated {len(results)} report files → {output_dir}/\n")
    return results
