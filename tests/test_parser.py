"""
test_parser.py — Unit tests for modules/parser.py
Threat Intelligence Aggregator | pytest test suite
"""
import os, json, csv, sys, pytest
 
# ── Import path fix ───────────────────────────────────────────────────────────
# Project structure: modules/parser.py is one level up from tests/,
# inside the modules/ subfolder. We add the repo root to sys.path so
# "from modules.parser import ..." works correctly in CI.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)
 
from modules.parser import (
    parse_csv, parse_txt, parse_json, parse_feed,
    _infer_type, _extract_all, PATTERNS
)
 
FEEDS_DIR = os.path.join(os.path.dirname(__file__), "sample_feeds")
 
 
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
        assert _infer_type("http://evil.ru/payload") == "url"
    def test_email_takes_priority_over_domain(self):
        assert _infer_type("user@evil.ru") == "email"
 
 
class TestExtractAll:
    def test_extracts_ip(self):
        results = _extract_all("bad actor at 185.220.101.45 spotted", "test")
        assert "ip" in [r["type"] for r in results]
    def test_extracts_domain(self):
        results = _extract_all("c2 server: evil-domain.ru contacted", "test")
        assert any("evil-domain.ru" in r["value"] for r in results)
    def test_extracts_url(self):
        results = _extract_all("download from http://malware.ru/file.exe now", "test")
        assert "url" in [r["type"] for r in results]
    def test_no_duplicate_values(self):
        results = _extract_all("http://evil.ru/file", "test")
        values = [r["value"] for r in results]
        assert len(values) == len(set(values))
    def test_source_preserved(self):
        results = _extract_all("185.220.101.45", "my_feed")
        assert all(r["source"] == "my_feed" for r in results)
    def test_severity_preserved(self):
        results = _extract_all("185.220.101.45", "feed", severity="Critical")
        assert all(r["severity"] == "Critical" for r in results)
    def test_empty_text_returns_empty(self):
        assert _extract_all("", "feed") == []
    def test_comment_only_text(self):
        assert isinstance(_extract_all("# this is a comment", "feed"), list)
 
 
class TestParseCSV:
    def test_returns_list(self):
        assert isinstance(parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv")), list)
    def test_parses_known_ip(self):
        assert "185.220.101.45" in [r["value"] for r in parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv"))]
    def test_parses_known_domain(self):
        assert "malware-c2.evil.ru" in [r["value"] for r in parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv"))]
    def test_parses_known_url(self):
        assert "http://phishing-site.net/login.php" in [r["value"] for r in parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv"))]
    def test_parses_known_hash(self):
        assert "44d88612fea8a8f36de82e1278abb02f" in [r["value"] for r in parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv"))]
    def test_parses_known_email(self):
        assert "attacker@evil-domain.ru" in [r["value"] for r in parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv"))]
    def test_severity_preserved(self):
        result = parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv"))
        ip_entry = next((r for r in result if r["value"] == "185.220.101.45"), None)
        assert ip_entry is not None and ip_entry["severity"] == "High"
    def test_required_fields_present(self):
        for entry in parse_csv(os.path.join(FEEDS_DIR, "test_feed.csv")):
            for k in ("value","type","source","severity","first_seen"):
                assert k in entry
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_csv("/nonexistent/feed.csv")
 
 
class TestParseTXT:
    def test_returns_list(self):
        assert isinstance(parse_txt(os.path.join(FEEDS_DIR, "test_feed.txt")), list)
    def test_parses_ip_from_txt(self):
        assert "185.220.101.46" in [r["value"] for r in parse_txt(os.path.join(FEEDS_DIR, "test_feed.txt"))]
    def test_skips_comment_lines(self):
        values = [r["value"] for r in parse_txt(os.path.join(FEEDS_DIR, "test_feed.txt"))]
        assert "Malware IP blocklist - test feed" not in values
    def test_parses_url_from_txt(self):
        assert "http://malicious-payload.xyz/dropper.exe" in [r["value"] for r in parse_txt(os.path.join(FEEDS_DIR, "test_feed.txt"))]
    def test_parses_domain_from_txt(self):
        values = [r["value"] for r in parse_txt(os.path.join(FEEDS_DIR, "test_feed.txt"))]
        assert any("bad-domain-c2.ru" in v for v in values)
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_txt("/nonexistent/feed.txt")
 
 
class TestParseJSON:
    def test_returns_list(self):
        assert isinstance(parse_json(os.path.join(FEEDS_DIR, "test_feed.json")), list)
    def test_parses_ip_from_json(self):
        assert "185.220.101.47" in [r["value"] for r in parse_json(os.path.join(FEEDS_DIR, "test_feed.json"))]
    def test_parses_domain_from_json(self):
        assert "ransomware-stage2.tk" in [r["value"] for r in parse_json(os.path.join(FEEDS_DIR, "test_feed.json"))]
    def test_severity_from_json(self):
        result = parse_json(os.path.join(FEEDS_DIR, "test_feed.json"))
        entry = next((r for r in result if r["value"] == "185.220.101.47"), None)
        assert entry is not None and entry["severity"] == "High"
    def test_invalid_json_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ not valid json }")
        assert parse_json(str(bad)) == []
    def test_flat_list_json(self, tmp_path):
        f = tmp_path / "flat.json"
        f.write_text(json.dumps([{"indicator":"1.2.3.4","type":"ip","severity":"Low","source":"test"}]))
        assert len(parse_json(str(f))) >= 1
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_json("/nonexistent/feed.json")
 
 
class TestParseFeed:
    def test_dispatches_csv(self):
        assert len(parse_feed(os.path.join(FEEDS_DIR, "test_feed.csv"))) > 0
    def test_dispatches_txt(self):
        assert len(parse_feed(os.path.join(FEEDS_DIR, "test_feed.txt"))) > 0
    def test_dispatches_json(self):
        assert len(parse_feed(os.path.join(FEEDS_DIR, "test_feed.json"))) > 0
    def test_unknown_ext_treated_as_txt(self, tmp_path):
        f = tmp_path / "feed.log"
        f.write_text("185.220.101.99\n")
        assert isinstance(parse_feed(str(f)), list)
