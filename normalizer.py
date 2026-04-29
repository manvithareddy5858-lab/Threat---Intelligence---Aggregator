"""
normalizer.py — Normalization Engine
Threat Intelligence Aggregator | Unified Mentor Cybersecurity Internship

Validates, cleans, deduplicates, and enriches raw IOC dictionaries.
Filters out RFC 1918 / loopback / link-local IPs and whitelisted domains.
"""

import re
import ipaddress
from datetime import datetime, timezone

# ── Whitelists ────────────────────────────────────────────────────────────────
WHITELISTED_DOMAINS = {
    "google.com", "www.google.com", "googleapis.com",
    "microsoft.com", "windowsupdate.com", "office.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    "apple.com", "icloud.com",
    "github.com", "githubusercontent.com",
    "localhost",
}

# ── Category keyword map ──────────────────────────────────────────────────────
CATEGORY_KEYWORDS = {
    "malware":     ["malware", "trojan", "virus", "worm", "dropper", "loader",
                    "emotet", "trickbot", "ryuk", "wannacry"],
    "ransomware":  ["ransomware", "ransom", "lockbit", "darkside", "revil"],
    "c2":          ["c2", "c&c", "command", "control", "beacon", "cobalt", "empire"],
    "phishing":    ["phish", "phishing", "spear", "credential", "login", "fake"],
    "botnet":      ["botnet", "bot", "zombie", "mirai", "ddos"],
    "tor":         ["tor", "exit node", "onion"],
    "spam":        ["spam", "bulk", "mass mail"],
    "exploit":     ["exploit", "cve", "vulnerability", "zero-day", "0day"],
    "apt":         ["apt", "nation state", "advanced persistent", "targeted"],
}

# Normalise severity labels from various feed providers
_SEV_MAP = {
    "critical": "Critical", "high": "High", "med": "Medium",
    "medium": "Medium",     "low": "Low",   "info": "Low",
    "informational": "Low", "unknown": "Low",
    "3": "High", "2": "Medium", "1": "Low",
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ── Validators ────────────────────────────────────────────────────────────────

def _valid_ip(value: str) -> bool:
    try:
        obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or
                obj.is_link_local or obj.is_multicast or
                obj.is_reserved or str(obj) in ("0.0.0.0", "255.255.255.255"))


def _valid_domain(value: str) -> bool:
    v = value.lower().strip(".")
    if v in WHITELISTED_DOMAINS:
        return False
    # Must have at least one dot and a real TLD
    parts = v.split(".")
    if len(parts) < 2:
        return False
    # Reject plain IPs disguised as domains
    try:
        ipaddress.ip_address(v)
        return False
    except ValueError:
        pass
    # TLD must be 2–6 alpha chars
    tld = parts[-1]
    if not re.fullmatch(r"[a-z]{2,6}", tld):
        return False
    return True


def _valid_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value))


def _valid_url(value: str) -> bool:
    return value.startswith(("http://", "https://")) and "." in value


def _valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", value))


_VALIDATORS = {
    "ip":      _valid_ip,
    "domain":  _valid_domain,
    "hash":    _valid_hash,
    "url":     _valid_url,
    "email":   _valid_email,
}


# ── Enrichment ────────────────────────────────────────────────────────────────

def _infer_hash_subtype(value: str) -> str:
    length = len(value)
    if length == 32:  return "md5"
    if length == 40:  return "sha1"
    if length == 64:  return "sha256"
    return "hash"


def _infer_category(value: str, description: str) -> str:
    text = (value + " " + description).lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category
    return "general"


def _normalise_severity(raw: str) -> str:
    return _SEV_MAP.get(str(raw).lower().strip(), "Low")


def _normalise_type(raw: str, value: str) -> str:
    t = raw.lower().strip()
    alias = {
        "ip address": "ip", "ip_address": "ip", "ipv4": "ip", "ipv6": "ip",
        "md5": "hash", "sha1": "hash", "sha256": "hash", "sha-256": "hash",
        "file hash": "hash", "filehash": "hash",
        "fqdn": "domain", "hostname": "domain",
        "uri": "url", "link": "url",
        "email address": "email", "email_address": "email",
    }
    return alias.get(t, t) if t else "unknown"


# ── Public API ────────────────────────────────────────────────────────────────

def normalize(raw_iocs: list) -> list:
    """
    Validate, clean, deduplicate (within-feed), and enrich a list of raw IOC dicts.
    Returns a list of normalised IOC dicts.
    """
    normalised  = []
    seen        = set()          # (value_lower, source) dedup key
    invalid_cnt = 0
    dup_cnt     = 0

    for raw in raw_iocs:
        value    = str(raw.get("value", "")).strip()
        ioc_type = _normalise_type(raw.get("type", ""), value)
        source   = str(raw.get("source", "unknown")).strip()
        severity = _normalise_severity(raw.get("severity", "Low"))
        desc     = str(raw.get("description", "")).strip()

        if not value:
            invalid_cnt += 1
            continue

        # Within-feed deduplication
        dedup_key = (value.lower(), source)
        if dedup_key in seen:
            dup_cnt += 1
            continue
        seen.add(dedup_key)

        # Type inference fallback
        if ioc_type == "unknown":
            from parser import _infer_type as _inf
            ioc_type = _inf(value)

        # Validate
        validator = _VALIDATORS.get(ioc_type)
        if validator and not validator(value):
            invalid_cnt += 1
            continue

        # Enrich
        category = _infer_category(value, desc)
        hash_sub = _infer_hash_subtype(value) if ioc_type == "hash" else None

        entry = {
            "value":       value,
            "type":        ioc_type,
            "hash_subtype": hash_sub,
            "source":      source,
            "severity":    severity,
            "category":    category,
            "description": desc,
            "first_seen":  raw.get("first_seen", _now_iso()),
        }
        normalised.append(entry)

    print(f"[*] Normalizing {len(raw_iocs)} raw indicators...")
    print(f"[!] Removed: {invalid_cnt} invalid (private IP / malformed / whitelisted)")
    print(f"[!] Removed: {dup_cnt} within-feed duplicates")
    print(f"[+] Valid after normalization: {len(normalised)}")
    return normalised
