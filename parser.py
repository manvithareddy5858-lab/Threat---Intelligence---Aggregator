"""
parser.py — IOC Feed Parser
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Dispatches CSV / TXT / JSON feed files to format-specific parsers.
Extracts all IOC types using regular-expression pattern matching.
"""

import os
import re
import csv
import json
from datetime import datetime, timezone

# ── IOC regex patterns ────────────────────────────────────────────────────────
PATTERNS = {
    "ip":     re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "url":    re.compile(
        r"https?://[^\s\"'<>]+"
    ),
    "hash":   re.compile(
        r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
    ),
    "email":  re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
}

# Column-name variants across different CSV feed providers
_CSV_INDICATOR_COLS = {"indicator", "ioc", "value", "observable", "ip", "domain",
                       "url", "hash", "md5", "sha1", "sha256", "email", "address"}
_CSV_TYPE_COLS      = {"type", "ioc_type", "indicator_type", "category"}
_CSV_SEV_COLS       = {"severity", "risk", "confidence", "priority", "score"}
_CSV_SOURCE_COLS    = {"source", "feed", "provider", "origin"}
_CSV_DESC_COLS      = {"description", "desc", "note", "notes", "comment"}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _infer_type(value: str) -> str:
    """Return the best-match IOC type for a raw string value."""
    value = value.strip()
    if PATTERNS["url"].fullmatch(value):
        return "url"
    if PATTERNS["email"].fullmatch(value):
        return "email"
    if PATTERNS["hash"].fullmatch(value):
        return "hash"
    if PATTERNS["ip"].fullmatch(value):
        return "ip"
    if PATTERNS["domain"].fullmatch(value):
        return "domain"
    return "unknown"


def _extract_all(text: str, source: str, severity: str = "Low",
                 description: str = "") -> list:
    """Extract every IOC type from a free-form text block."""
    results = []
    seen = set()

    # URLs first (they contain IPs/domains — avoid double-counting)
    for m in PATTERNS["url"].finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append(_make_raw(v, "url", source, severity, description))

    for m in PATTERNS["email"].finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append(_make_raw(v, "email", source, severity, description))

    for m in PATTERNS["hash"].finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append(_make_raw(v, "hash", source, severity, description))

    for m in PATTERNS["ip"].finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append(_make_raw(v, "ip", source, severity, description))

    for m in PATTERNS["domain"].finditer(text):
        v = m.group()
        # Skip values already captured as IPs or parts of URLs/emails
        if v not in seen and not any(c in v for c in ("@",)):
            seen.add(v)
            results.append(_make_raw(v, "domain", source, severity, description))

    return results


def _make_raw(value, ioc_type, source, severity, description=""):
    return {
        "value":       value.strip(),
        "type":        ioc_type,
        "source":      source,
        "severity":    severity,
        "description": description,
        "first_seen":  _now_iso(),
    }


# ── Format-specific parsers ───────────────────────────────────────────────────

def parse_csv(filepath: str) -> list:
    """Parse a structured CSV threat feed."""
    source   = os.path.basename(filepath)
    results  = []

    with open(filepath, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return results

        headers  = {h.strip().lower(): h for h in reader.fieldnames if h}
        ind_col  = next((headers[k] for k in _CSV_INDICATOR_COLS if k in headers), None)
        type_col = next((headers[k] for k in _CSV_TYPE_COLS      if k in headers), None)
        sev_col  = next((headers[k] for k in _CSV_SEV_COLS       if k in headers), None)
        src_col  = next((headers[k] for k in _CSV_SOURCE_COLS    if k in headers), None)
        desc_col = next((headers[k] for k in _CSV_DESC_COLS      if k in headers), None)

        for row in reader:
            if ind_col:
                value = row.get(ind_col, "").strip()
                if not value:
                    continue
                ioc_type = (row.get(type_col, "").strip().lower()
                            if type_col else _infer_type(value))
                severity = (row.get(sev_col, "Low").strip()
                            if sev_col else "Low")
                feed_src = (row.get(src_col, source).strip()
                            if src_col else source)
                desc     = (row.get(desc_col, "").strip()
                            if desc_col else "")
                results.append(_make_raw(value, ioc_type, feed_src, severity, desc))
            else:
                # No recognized indicator column — extract from all fields
                line = " ".join(str(v) for v in row.values())
                sev  = row.get(sev_col, "Low").strip() if sev_col else "Low"
                results.extend(_extract_all(line, source, sev))

    return results


def parse_txt(filepath: str) -> list:
    """Parse a plain-text IOC feed (one indicator per line, # comments)."""
    source  = os.path.basename(filepath)
    results = []

    with open(filepath, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip inline comments
            if "  #" in line:
                line = line[:line.index("  #")].strip()
            results.extend(_extract_all(line, source))

    return results


def parse_json(filepath: str) -> list:
    """Parse a structured JSON threat feed."""
    source  = os.path.basename(filepath)
    results = []

    with open(filepath, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            print(f"[!] JSON parse error in {source}: {exc}")
            return results

    # Support both {"indicators": [...]} and flat list formats
    if isinstance(data, dict):
        indicators = data.get("indicators") or data.get("iocs") or data.get("data") or []
    elif isinstance(data, list):
        indicators = data
    else:
        return results

    for item in indicators:
        if isinstance(item, dict):
            value    = (item.get("indicator") or item.get("value") or
                        item.get("ioc")       or item.get("observable") or "").strip()
            ioc_type = (item.get("type") or item.get("ioc_type") or "").strip().lower()
            severity = (item.get("severity") or item.get("risk") or "Low").strip()
            feed_src = (item.get("source") or item.get("feed") or source).strip()
            desc     = (item.get("description") or item.get("note") or "").strip()
            if not value:
                continue
            if not ioc_type:
                ioc_type = _infer_type(value)
            results.append(_make_raw(value, ioc_type, feed_src, severity, desc))
        elif isinstance(item, str):
            results.extend(_extract_all(item.strip(), source))

    return results


# ── Public API ────────────────────────────────────────────────────────────────

def parse_feed(filepath: str) -> list:
    """Dispatch a single feed file to the correct parser."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".csv":
        return parse_csv(filepath)
    elif ext == ".json":
        return parse_json(filepath)
    else:  # .txt and everything else
        return parse_txt(filepath)


def load_all_feeds(feed_dir: str) -> list:
    """Scan *feed_dir* and parse every supported feed file found."""
    supported = {".csv", ".txt", ".json"}
    all_iocs  = []

    if not os.path.isdir(feed_dir):
        print(f"[!] Feed directory not found: {feed_dir}")
        return all_iocs

    files = sorted(
        f for f in os.listdir(feed_dir)
        if os.path.splitext(f)[1].lower() in supported
    )

    if not files:
        print(f"[!] No supported feed files found in: {feed_dir}")
        return all_iocs

    for fname in files:
        fpath = os.path.join(feed_dir, fname)
        parsed = parse_feed(fpath)
        print(f"[+] Parsed: {fname:<35} → {len(parsed):>3} raw IOCs")
        all_iocs.extend(parsed)

    print(f"[✓] Total raw IOCs collected: {len(all_iocs)}\n")
    return all_iocs
