"""
blocklist_gen.py — Blocklist Generator
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Writes 8 deployment-ready blocklist files from correlated IOC data:
  Per-type TXT files  : ip, domain, url, hash, email
  Master CSV/JSON     : all IOC types combined
  High-risk-only CSV  : score >= 50
"""

import os
import csv
import json
from datetime import datetime, timezone


_HEADER_COMMENT = """\
# ─────────────────────────────────────────────────────────────────────────────
# Threat Intelligence Aggregator — Blocklist
# Generated : {ts}
# Entries   : {count}
# Type      : {ioc_type}
# Usage     : {usage}
# TLP       : WHITE
# ─────────────────────────────────────────────────────────────────────────────
"""

_USAGE = {
    "ip":     "iptables / pfSense / Palo Alto EDL / Cisco ACL",
    "domain": "Pi-hole / DNS sinkhole / Windows HOSTS file",
    "url":    "Squid proxy / Nginx deny_list / Web filter",
    "hash":   "CrowdStrike / Windows Defender / YARA rules",
    "email":  "Postfix / SpamAssassin / Microsoft 365 / Proofpoint",
}

_CSV_FIELDS = [
    "value", "type", "hash_subtype", "category",
    "risk_score", "severity", "feed_count", "sources",
    "description", "first_seen",
]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_txt(path: str, entries: list, ioc_type: str) -> int:
    values = [e["value"] for e in entries if e.get("type") == ioc_type]
    header = _HEADER_COMMENT.format(
        ts=_now(), count=len(values),
        ioc_type=ioc_type.upper(), usage=_USAGE.get(ioc_type, "generic")
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header)
        for v in sorted(values):
            fh.write(v + "\n")
    return len(values)


def _write_master_csv(path: str, entries: list) -> int:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            row = dict(e)
            row["sources"] = "|".join(e.get("sources", []))
            row["hash_subtype"] = e.get("hash_subtype") or ""
            writer.writerow(row)
    return len(entries)


def _write_master_json(path: str, entries: list) -> int:
    payload = {
        "generated":  _now(),
        "total":      len(entries),
        "tlp":        "WHITE",
        "indicators": entries,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return len(entries)


def _write_high_risk_csv(path: str, entries: list, min_score: int = 50) -> int:
    high = [e for e in entries if e.get("risk_score", 0) >= min_score]
    _write_master_csv(path, high)
    return len(high)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_blocklists(correlation_result: dict, output_dir: str) -> dict:
    """
    Generate all 8 blocklist files from *correlation_result* dict.
    Returns a summary dict: { filename: entry_count }.
    """
    os.makedirs(output_dir, exist_ok=True)
    master = correlation_result["master_list"]
    summary = {}

    # ── Per-type TXT files ────────────────────────────────────────────────────
    for ioc_type in ("ip", "domain", "url", "hash", "email"):
        fname = f"{ioc_type}_blocklist.txt"
        fpath = os.path.join(output_dir, fname)
        count = _write_txt(fpath, master, ioc_type)
        summary[fname] = count
        print(f"[✓] {fname:<35} ({count:>3} entries)")

    # ── Master CSV ────────────────────────────────────────────────────────────
    fname = "master_blocklist.csv"
    count = _write_master_csv(os.path.join(output_dir, fname), master)
    summary[fname] = count
    print(f"[✓] {fname:<35} ({count:>3} entries)")

    # ── Master JSON ───────────────────────────────────────────────────────────
    fname = "master_blocklist.json"
    count = _write_master_json(os.path.join(output_dir, fname), master)
    summary[fname] = count
    print(f"[✓] {fname:<35} ({count:>3} entries)")

    # ── High-risk only CSV ────────────────────────────────────────────────────
    fname = "high_risk_only.csv"
    count = _write_high_risk_csv(os.path.join(output_dir, fname), master)
    summary[fname] = count
    print(f"[✓] {fname:<35} ({count:>3} entries)")

    print(f"\n[✓] Generated {len(summary)} blocklist files → {output_dir}/\n")
    return summary
