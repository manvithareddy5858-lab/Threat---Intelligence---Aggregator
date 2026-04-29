"""
correlator.py — IOC Correlation Engine
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Groups normalised IOCs by value across all feeds.
Computes a risk score (0-100) and assigns a severity label.
Produces master_list, repeated (2+ feeds), and high_risk (score >= 50) subsets.
"""

from collections import defaultdict
from datetime import datetime, timezone

# ── Severity base scores ──────────────────────────────────────────────────────
_SEV_BASE = {
    "Critical": 75,
    "High":     50,
    "Medium":   25,
    "Low":      10,
}

# ── Score thresholds → label ──────────────────────────────────────────────────
def _score_to_severity(score: int) -> str:
    if score >= 75: return "Critical"
    if score >= 50: return "High"
    if score >= 25: return "Medium"
    return "Low"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ── Risk Scoring Formula ──────────────────────────────────────────────────────
#
#   score = base_severity_score
#         + feed_bonus   (10 pts per extra feed beyond the first, capped at 30)
#         + multi_bonus  (10 pts if seen in 3+ distinct feeds)
#   [capped at 100]
#

def _compute_score(base_severity: str, feed_count: int) -> int:
    base        = _SEV_BASE.get(base_severity, 10)
    feed_bonus  = min((feed_count - 1) * 10, 30)
    multi_bonus = 10 if feed_count >= 3 else 0
    return min(base + feed_bonus + multi_bonus, 100)


# ── Public API ────────────────────────────────────────────────────────────────

def correlate(normalised_iocs: list) -> dict:
    """
    Cross-feed correlation of normalised IOCs.

    Returns a dict with keys:
        master_list  – all unique IOCs, one entry per value
        repeated     – IOCs appearing in 2+ distinct feeds
        high_risk    – IOCs with risk score >= 50
    """
    # Group by lowercased value
    groups: dict[str, list] = defaultdict(list)
    for ioc in normalised_iocs:
        groups[ioc["value"].lower()].append(ioc)

    master_list = []

    for value_key, entries in groups.items():
        # Collect unique source feeds
        sources  = sorted({e["source"] for e in entries})
        # Pick the highest base severity across all entries
        sev_order = ["Critical", "High", "Medium", "Low"]
        best_sev  = min(
            (e["severity"] for e in entries),
            key=lambda s: sev_order.index(s) if s in sev_order else 99
        )
        # Merge descriptions (unique, non-empty)
        descs = list({e["description"] for e in entries if e["description"]})

        # Use original-case value from first entry
        canonical_value = entries[0]["value"]
        ioc_type        = entries[0]["type"]
        hash_sub        = entries[0].get("hash_subtype")
        category        = entries[0].get("category", "general")
        first_seen      = min(e.get("first_seen", _now_iso()) for e in entries)

        feed_count = len(sources)
        score      = _compute_score(best_sev, feed_count)
        severity   = _score_to_severity(score)

        correlated = {
            "value":        canonical_value,
            "type":         ioc_type,
            "hash_subtype": hash_sub,
            "category":     category,
            "sources":      sources,
            "feed_count":   feed_count,
            "base_severity": best_sev,
            "risk_score":   score,
            "severity":     severity,
            "description":  "; ".join(descs) if descs else "",
            "first_seen":   first_seen,
            "correlated_at": _now_iso(),
        }
        master_list.append(correlated)

    # Sort by risk score descending, then by value
    master_list.sort(key=lambda x: (-x["risk_score"], x["value"]))

    repeated  = [i for i in master_list if i["feed_count"] >= 2]
    high_risk = [i for i in master_list if i["risk_score"] >= 50]

    # Stats
    unique_count = len(master_list)
    print(f"[*] Running cross-feed correlation...")
    for ioc in master_list[:6]:
        feeds_str = ", ".join(ioc["sources"])
        print(f"[+] {ioc['value']:<35}  score={ioc['risk_score']:<3}  "
              f"{ioc['severity']:<8}  feeds={ioc['feed_count']}  ({feeds_str})")
    if unique_count > 6:
        print(f"    ... and {unique_count - 6} more")
    print(f"[~] {len(repeated)} total correlated across 2+ feeds")
    print(f"[✓] {len(high_risk)} high-risk indicators (score >= 50)\n")

    return {
        "master_list": master_list,
        "repeated":    repeated,
        "high_risk":   high_risk,
    }
