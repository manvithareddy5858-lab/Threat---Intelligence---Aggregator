"""
test_normalizer.py — Unit tests for normalizer.py
Threat Intelligence Aggregator | pytest test suite
"""
import sys
import os
import pytest
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from normalizer import (
    normalize, _valid_ip, _valid_domain, _valid_hash,
    _valid_url, _valid_email, _normalise_severity,
    _infer_category, WHITELISTED_DOMAINS
)
 
 
# ── IP validator tests ────────────────────────────────────────────────────────
 
class TestValidIP:
    def test_public_ip_valid(self):
        assert _valid_ip("185.220.101.45") is True
 
    def test_private_10_rejected(self):
        assert _valid_ip("10.0.0.1") is False
 
    def test_private_192_rejected(self):
        assert _valid_ip("192.168.1.1") is False
 
    def test_private_172_rejected(self):
        assert _valid_ip("172.16.0.1") is False
 
    def test_loopback_rejected(self):
        assert _valid_ip("127.0.0.1") is False
 
    def test_broadcast_rejected(self):
        assert _valid_ip("255.255.255.255") is False
 
    def test_zero_rejected(self):
        assert _valid_ip("0.0.0.0") is False
 
    def test_invalid_string_rejected(self):
        assert _valid_ip("not-an-ip") is False
 
    def test_link_local_rejected(self):
        assert _valid_ip("169.254.0.1") is False
 
 
# ── Domain validator tests ────────────────────────────────────────────────────
 
class TestValidDomain:
    def test_malicious_domain_valid(self):
        assert _valid_domain("malware-c2.evil.ru") is True
 
    def test_whitelisted_google_rejected(self):
        assert _valid_domain("google.com") is False
 
    def test_whitelisted_microsoft_rejected(self):
        assert _valid_domain("microsoft.com") is False
 
    def test_localhost_rejected(self):
        assert _valid_domain("localhost") is False
 
    def test_no_tld_rejected(self):
        assert _valid_domain("nodot") is False
 
    def test_numeric_only_rejected(self):
        # IP disguised as domain
        assert _valid_domain("192.168.1.1") is False
 
    def test_valid_tld_accepted(self):
        assert _valid_domain("phishing-site.tk") is True
 
    def test_long_tld_rejected(self):
        # TLD must be 2-6 alpha chars
        assert _valid_domain("site.toolongtld") is False
 
 
# ── Hash validator tests ──────────────────────────────────────────────────────
 
class TestValidHash:
    def test_md5_valid(self):
        assert _valid_hash("44d88612fea8a8f36de82e1278abb02f") is True
 
    def test_sha1_valid(self):
        assert _valid_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True
 
    def test_sha256_valid(self):
        assert _valid_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True
 
    def test_short_hash_rejected(self):
        assert _valid_hash("abc123") is False
 
    def test_non_hex_rejected(self):
        assert _valid_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") is False
 
    def test_wrong_length_rejected(self):
        assert _valid_hash("44d88612fea8a8f36de82e1278abb02") is False  # 31 chars
 
 
# ── URL validator tests ───────────────────────────────────────────────────────
 
class TestValidURL:
    def test_http_valid(self):
        assert _valid_url("http://malware.ru/file.exe") is True
 
    def test_https_valid(self):
        assert _valid_url("https://phishing.tk/login") is True
 
    def test_no_scheme_rejected(self):
        assert _valid_url("malware.ru/file.exe") is False
 
    def test_ftp_rejected(self):
        assert _valid_url("ftp://file.ru/bad") is False
 
 
# ── Email validator tests ─────────────────────────────────────────────────────
 
class TestValidEmail:
    def test_valid_email(self):
        assert _valid_email("attacker@evil-domain.ru") is True
 
    def test_no_at_rejected(self):
        assert _valid_email("notanemail") is False
 
    def test_no_tld_rejected(self):
        assert _valid_email("user@domain") is False
 
    def test_valid_complex_email(self):
        assert _valid_email("spam.sender+tag@malware.co.uk") is True
 
 
# ── Severity normaliser tests ─────────────────────────────────────────────────
 
class TestNormaliseSeverity:
    def test_critical(self):
        assert _normalise_severity("critical") == "Critical"
 
    def test_high(self):
        assert _normalise_severity("high") == "High"
 
    def test_medium(self):
        assert _normalise_severity("medium") == "Medium"
 
    def test_med_alias(self):
        assert _normalise_severity("med") == "Medium"
 
    def test_low(self):
        assert _normalise_severity("low") == "Low"
 
    def test_info_maps_to_low(self):
        assert _normalise_severity("info") == "Low"
 
    def test_unknown_maps_to_low(self):
        assert _normalise_severity("unknown") == "Low"
 
    def test_numeric_3_maps_to_high(self):
        assert _normalise_severity("3") == "High"
 
    def test_garbage_maps_to_low(self):
        assert _normalise_severity("gibberish") == "Low"
 
    def test_case_insensitive(self):
        assert _normalise_severity("HIGH") == "High"
        assert _normalise_severity("Critical") == "Critical"
 
 
# ── Category inference tests ──────────────────────────────────────────────────
 
class TestInferCategory:
    def test_malware_keyword(self):
        assert _infer_category("payload.exe", "emotet dropper") == "malware"
 
    def test_ransomware_keyword(self):
        assert _infer_category("lockbit.ru", "") == "ransomware"
 
    def test_c2_keyword(self):
        assert _infer_category("beacon.evil.ru", "cobalt strike c2") == "c2"
 
    def test_phishing_keyword(self):
        assert _infer_category("login-page.tk", "credential phishing") == "phishing"
 
    def test_botnet_keyword(self):
        assert _infer_category("mirai.botnet.ru", "") == "botnet"
 
    def test_default_general(self):
        assert _infer_category("185.220.101.45", "") == "general"
 
 
# ── Full normalize() pipeline tests ──────────────────────────────────────────
 
class TestNormalize:
    def _make_raw(self, value, ioc_type="ip", source="feed_a", severity="High", desc=""):
        return {
            "value": value, "type": ioc_type, "source": source,
            "severity": severity, "description": desc,
            "first_seen": "2026-01-01T00:00:00+00:00"
        }
 
    def test_valid_public_ip_passes(self):
        raw = [self._make_raw("185.220.101.45")]
        result = normalize(raw)
        assert any(r["value"] == "185.220.101.45" for r in result)
 
    def test_private_ip_filtered(self):
        raw = [self._make_raw("192.168.1.1")]
        result = normalize(raw)
        assert not any(r["value"] == "192.168.1.1" for r in result)
 
    def test_whitelisted_domain_filtered(self):
        raw = [self._make_raw("google.com", "domain")]
        result = normalize(raw)
        assert not any(r["value"] == "google.com" for r in result)
 
    def test_within_feed_deduplication(self):
        raw = [
            self._make_raw("185.220.101.45"),
            self._make_raw("185.220.101.45"),  # duplicate same source
        ]
        result = normalize(raw)
        matching = [r for r in result if r["value"] == "185.220.101.45"]
        assert len(matching) == 1
 
    def test_cross_feed_not_deduplicated(self):
        raw = [
            self._make_raw("185.220.101.45", source="feed_a"),
            self._make_raw("185.220.101.45", source="feed_b"),
        ]
        result = normalize(raw)
        matching = [r for r in result if r["value"] == "185.220.101.45"]
        assert len(matching) == 2
 
    def test_severity_normalised(self):
        raw = [self._make_raw("185.220.101.45", severity="critical")]
        result = normalize(raw)
        assert result[0]["severity"] == "Critical"
 
    def test_empty_value_filtered(self):
        raw = [{"value": "", "type": "ip", "source": "feed", "severity": "Low", "description": ""}]
        result = normalize(raw)
        assert len(result) == 0
 
    def test_output_has_required_fields(self):
        raw = [self._make_raw("185.220.101.45")]
        result = normalize(raw)
        required = {"value", "type", "source", "severity", "category", "first_seen"}
        assert required.issubset(result[0].keys())
 
    def test_hash_subtype_md5(self):
        raw = [self._make_raw("44d88612fea8a8f36de82e1278abb02f", "hash")]
        result = normalize(raw)
        assert result[0]["hash_subtype"] == "md5"
 
    def test_hash_subtype_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        raw = [self._make_raw(h, "hash")]
        result = normalize(raw)
        assert result[0]["hash_subtype"] == "sha256"
 
    def test_category_enriched(self):
        raw = [self._make_raw("lockbit-stage.tk", "domain", desc="ransomware stage")]
        result = normalize(raw)
        assert result[0]["category"] == "ransomware"
 
    def test_empty_input_returns_empty(self):
        assert normalize([]) == []
