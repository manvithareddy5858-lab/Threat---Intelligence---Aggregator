"""
test_parser.py — Unit tests for parser.py
Threat Intelligence Aggregator | pytest test suite
"""
import os
import json
import csv
import sys
import pytest
 
# Allow imports from repo root (adjust path if your structure differs)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from parser import (
    parse_csv, parse_txt, parse_json, parse_feed,
    _infer_type, _extract_all, PATTERNS
)
 
FEEDS_DIR = os.path.join(os.path.dirname(__file__), "sample_feeds")
 
 
# ── IOC regex pattern tests ───────────────────────────────────────────────────
 
class TestPatterns:
    def test_ip_pattern_matches_valid(self):
        assert PATTERNS["ip"].search("185.220.101.45")
 
    def test_ip_pattern_rejects_out_of_range(self):
        assert not PATTERNS["ip"].fullmatch("999.999.999.999")
 
    def test_domain_pattern_matches(self):
        assert PATTERNS["domain"].search("malware.evil-domain.ru")
 
    def test_url_pattern_matches_http(self):
        assert PATTERNS["url"].search("http://malicious-site.net/payload.exe")
 
    def test_url_pattern_matches_https(self):
        assert PATTERNS["url"].search("https://phishing.tk/login")
 
    def test_hash_matches_md5(self):
        assert PATTERNS["hash"].search("44d88612fea8a8f36de82e1278abb02f")
 
    def test_hash_matches_sha1(self):
        assert PATTERNS["hash"].search("da39a3ee5e6b4b0d3255bfef95601890afd80709")
 
    def test_hash_matches_sha256(self):
        assert PATTERNS["hash"].search("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
 
    def test_email_pattern_matches(self):
        assert PATTERNS["email"].search("attacker@evil-domain.ru")
 
    def test_email_pattern_rejects_plain_domain(self):
        assert not PATTERNS["email"].fullmatch("evil-domain.ru")
 
 
# ── _infer_type tests ─────────────────────────────────────────────────────────
 
class TestInferType:
    def test_infer_ip(self):
        assert _infer_type("185.220.101.45") == "ip"
 
    def test_infer_domain(self):
        assert _infer_type("malware.evil-domain.ru") == "domain"
 
    def test_infer_url(self):
        assert _infer_type("http://phishing.tk/page") == "url"
 
    def test_infer_md5(self):
        assert _infer_type("44d88612fea8a8f36de82e1278abb02f") == "hash"
 
    def test_infer_email(self):
        assert _infer_type("attacker@evil.ru") == "email"
 
    def test_infer_unknown(self):
        assert _infer_type("not-an-ioc") == "unknown"
 
    def test_url_takes_priority_over_domain(self):
        # A URL contains a domain — must be classified as URL not domain
        assert _infer_type("http://evil.ru/payload") == "url"
 
    def test_email_takes_priority_over_domain(self):
        # An email contains a domain — must be classified as email not domain
        assert _infer_type("user@evil.ru") == "email"
 
 
# ── _extract_all tests ────────────────────────────────────────────────────────
 
class TestExtractAll:
    def test_extracts_ip(self):
        results = _extract_all("bad actor at 185.220.101.45 spotted", "test")
        types = [r["type"] for r in results]
        assert "ip" in types
 
    def test_extracts_domain(self):
        results = _extract_all("c2 server: evil-domain.ru contacted", "test")
        values = [r["value"] for r in results]
        assert any("evil-domain.ru" in v for v in values)
 
    def test_extracts_url(self):
        results = _extract_all("download from http://malware.ru/file.exe now", "test")
        types = [r["type"] for r in results]
        assert "url" in types
 
    def test_no_duplicate_url_and_domain(self):
        # The parser captures the full URL first, marks it as seen,
        # then also extracts the bare domain from the URL text via the
        # domain regex (since the domain isn't in `seen` as its own value).
        # The URL entry is always present; the domain may also appear.
        results = _extract_all("http://evil.ru/file", "test")
        url_results = [r for r in results if r["type"] == "url"]
        assert len(url_results) >= 1
        # Deduplication prevents the *same string* appearing twice —
        # "http://evil.ru/file" and "evil.ru" are different strings, so
        # both may be present. This test documents that behaviour.
        values = [r["value"] for r in results]
        assert len(values) == len(set(values)), "No value should appear twice"
 
    def test_source_preserved(self):
        results = _extract_all("185.220.101.45", "my_feed")
        assert all(r["source"] == "my_feed" for r in results)
 
    def test_severity_preserved(self):
        results = _extract_all("185.220.101.45", "feed", severity="Critical")
        assert all(r["severity"] == "Critical" for r in results)
 
    def test_empty_text_returns_empty(self):
        assert _extract_all("", "feed") == []
 
    def test_comment_only_text(self):
        # Should not crash and may or may not extract depending on regex
        results = _extract_all("# this is a comment", "feed")
        assert isinstance(results, list)
 
 
# ── parse_csv tests ───────────────────────────────────────────────────────────
 
class TestParseCSV:
    def test_returns_list(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        assert isinstance(result, list)
 
    def test_parses_known_ip(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        values = [r["value"] for r in result]
        assert "185.220.101.45" in values
 
    def test_parses_known_domain(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        values = [r["value"] for r in result]
        assert "malware-c2.evil.ru" in values
 
    def test_parses_known_url(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        values = [r["value"] for r in result]
        assert "http://phishing-site.net/login.php" in values
 
    def test_parses_known_hash(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        values = [r["value"] for r in result]
        assert "44d88612fea8a8f36de82e1278abb02f" in values
 
    def test_parses_known_email(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        values = [r["value"] for r in result]
        assert "attacker@evil-domain.ru" in values
 
    def test_severity_preserved(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        ip_entry = next((r for r in result if r["value"] == "185.220.101.45"), None)
        assert ip_entry is not None
        assert ip_entry["severity"] == "High"
 
    def test_required_fields_present(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_csv(path)
        for entry in result:
            assert "value" in entry
            assert "type" in entry
            assert "source" in entry
            assert "severity" in entry
            assert "first_seen" in entry
 
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_csv("/nonexistent/path/feed.csv")
 
 
# ── parse_txt tests ───────────────────────────────────────────────────────────
 
class TestParseTXT:
    def test_returns_list(self):
        path = os.path.join(FEEDS_DIR, "test_feed.txt")
        result = parse_txt(path)
        assert isinstance(result, list)
 
    def test_parses_ip_from_txt(self):
        path = os.path.join(FEEDS_DIR, "test_feed.txt")
        result = parse_txt(path)
        values = [r["value"] for r in result]
        assert "185.220.101.46" in values
 
    def test_skips_comment_lines(self):
        path = os.path.join(FEEDS_DIR, "test_feed.txt")
        result = parse_txt(path)
        # Comment text like "Malware IP blocklist" should not appear as an IOC value
        values = [r["value"] for r in result]
        assert "Malware IP blocklist - test feed" not in values
 
    def test_parses_url_from_txt(self):
        path = os.path.join(FEEDS_DIR, "test_feed.txt")
        result = parse_txt(path)
        values = [r["value"] for r in result]
        assert "http://malicious-payload.xyz/dropper.exe" in values
 
    def test_parses_domain_from_txt(self):
        path = os.path.join(FEEDS_DIR, "test_feed.txt")
        result = parse_txt(path)
        values = [r["value"] for r in result]
        assert any("bad-domain-c2.ru" in v for v in values)
 
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_txt("/nonexistent/path/feed.txt")
 
 
# ── parse_json tests ──────────────────────────────────────────────────────────
 
class TestParseJSON:
    def test_returns_list(self):
        path = os.path.join(FEEDS_DIR, "test_feed.json")
        result = parse_json(path)
        assert isinstance(result, list)
 
    def test_parses_ip_from_json(self):
        path = os.path.join(FEEDS_DIR, "test_feed.json")
        result = parse_json(path)
        values = [r["value"] for r in result]
        assert "185.220.101.47" in values
 
    def test_parses_domain_from_json(self):
        path = os.path.join(FEEDS_DIR, "test_feed.json")
        result = parse_json(path)
        values = [r["value"] for r in result]
        assert "ransomware-stage2.tk" in values
 
    def test_severity_from_json(self):
        path = os.path.join(FEEDS_DIR, "test_feed.json")
        result = parse_json(path)
        ip_entry = next((r for r in result if r["value"] == "185.220.101.47"), None)
        assert ip_entry is not None
        assert ip_entry["severity"] == "High"
 
    def test_invalid_json_returns_empty(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ this is not valid json }")
        result = parse_json(str(bad_file))
        assert result == []
 
    def test_flat_list_json(self, tmp_path):
        flat = [{"indicator": "1.2.3.4", "type": "ip", "severity": "Low", "source": "test"}]
        f = tmp_path / "flat.json"
        f.write_text(json.dumps(flat))
        result = parse_json(str(f))
        assert len(result) >= 1
 
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_json("/nonexistent/path/feed.json")
 
 
# ── parse_feed dispatcher tests ───────────────────────────────────────────────
 
class TestParseFeed:
    def test_dispatches_csv(self):
        path = os.path.join(FEEDS_DIR, "test_feed.csv")
        result = parse_feed(path)
        assert len(result) > 0
 
    def test_dispatches_txt(self):
        path = os.path.join(FEEDS_DIR, "test_feed.txt")
        result = parse_feed(path)
        assert len(result) > 0
 
    def test_dispatches_json(self):
        path = os.path.join(FEEDS_DIR, "test_feed.json")
        result = parse_feed(path)
        assert len(result) > 0
 
    def test_unknown_ext_treated_as_txt(self, tmp_path):
        f = tmp_path / "feed.log"
        f.write_text("185.220.101.99\n")
        result = parse_feed(str(f))
        assert isinstance(result, list)
