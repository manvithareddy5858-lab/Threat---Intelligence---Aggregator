"""
test_correlator.py — Unit tests for correlator.py
Threat Intelligence Aggregator | pytest test suite
"""
import sys
import os
import pytest
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from correlator import correlate, _compute_score, _score_to_severity
 
 
# ── Score formula tests ───────────────────────────────────────────────────────
 
class TestComputeScore:
    def test_critical_single_feed(self):
        # Critical base=75, feed_bonus=0, multi_bonus=0
        assert _compute_score("Critical", 1) == 75
 
    def test_high_single_feed(self):
        # High base=50
        assert _compute_score("High", 1) == 50
 
    def test_medium_single_feed(self):
        assert _compute_score("Medium", 1) == 25
 
    def test_low_single_feed(self):
        assert _compute_score("Low", 1) == 10
 
    def test_feed_bonus_two_feeds(self):
        # Low(10) + feed_bonus(10) = 20
        assert _compute_score("Low", 2) == 20
 
    def test_feed_bonus_capped_at_30(self):
        # Low(10) + capped_bonus(30) + multi_bonus(10) = 50
        assert _compute_score("Low", 5) == 50
 
    def test_multi_bonus_at_three_feeds(self):
        # Low(10) + feed_bonus(20) + multi_bonus(10) = 40
        assert _compute_score("Low", 3) == 40
 
    def test_score_capped_at_100(self):
        # Critical(75) + feed_bonus(30) + multi_bonus(10) = 115 → capped at 100
        assert _compute_score("Critical", 5) == 100
 
    def test_unknown_severity_gets_low_base(self):
        assert _compute_score("Unknown", 1) == 10
 
 
class TestScoreToSeverity:
    def test_critical_threshold(self):
        assert _score_to_severity(75) == "Critical"
        assert _score_to_severity(100) == "Critical"
 
    def test_high_threshold(self):
        assert _score_to_severity(50) == "High"
        assert _score_to_severity(74) == "High"
 
    def test_medium_threshold(self):
        assert _score_to_severity(25) == "Medium"
        assert _score_to_severity(49) == "Medium"
 
    def test_low_threshold(self):
        assert _score_to_severity(0) == "Low"
        assert _score_to_severity(24) == "Low"
 
 
# ── correlate() pipeline tests ────────────────────────────────────────────────
 
def _make_ioc(value, ioc_type="ip", source="feed_a", severity="High",
              category="general", desc=""):
    return {
        "value": value, "type": ioc_type, "source": source,
        "severity": severity, "category": category,
        "description": desc, "hash_subtype": None,
        "first_seen": "2026-01-01T00:00:00+00:00"
    }
 
 
class TestCorrelate:
    def test_returns_dict_with_required_keys(self):
        result = correlate([_make_ioc("1.2.3.4")])
        assert "master_list" in result
        assert "repeated" in result
        assert "high_risk" in result
 
    def test_single_ioc_in_master_list(self):
        result = correlate([_make_ioc("1.2.3.4")])
        assert len(result["master_list"]) == 1
 
    def test_cross_feed_merge(self):
        iocs = [
            _make_ioc("185.220.101.45", source="feed_a", severity="High"),
            _make_ioc("185.220.101.45", source="feed_b", severity="Medium"),
        ]
        result = correlate(iocs)
        # Should produce ONE merged entry
        assert len(result["master_list"]) == 1
        entry = result["master_list"][0]
        assert entry["feed_count"] == 2
        assert set(entry["sources"]) == {"feed_a", "feed_b"}
 
    def test_best_severity_wins(self):
        iocs = [
            _make_ioc("185.220.101.45", source="feed_a", severity="Low"),
            _make_ioc("185.220.101.45", source="feed_b", severity="Critical"),
        ]
        result = correlate(iocs)
        entry = result["master_list"][0]
        assert entry["base_severity"] == "Critical"
 
    def test_repeated_list_two_plus_feeds(self):
        iocs = [
            _make_ioc("1.2.3.4", source="feed_a"),
            _make_ioc("1.2.3.4", source="feed_b"),
            _make_ioc("5.6.7.8", source="feed_a"),  # single feed only
        ]
        result = correlate(iocs)
        assert len(result["repeated"]) == 1
        assert result["repeated"][0]["value"] == "1.2.3.4"
 
    def test_high_risk_score_threshold(self):
        # Critical in 1 feed = score 75 → high risk
        iocs = [_make_ioc("1.2.3.4", severity="Critical")]
        result = correlate(iocs)
        assert len(result["high_risk"]) == 1
 
    def test_low_risk_not_in_high_risk(self):
        iocs = [_make_ioc("1.2.3.4", severity="Low")]
        result = correlate(iocs)
        assert len(result["high_risk"]) == 0
 
    def test_case_insensitive_dedup(self):
        iocs = [
            _make_ioc("Evil-Domain.RU", "domain", source="feed_a"),
            _make_ioc("evil-domain.ru", "domain", source="feed_b"),
        ]
        result = correlate(iocs)
        # Should merge (same lowercase key)
        assert len(result["master_list"]) == 1
 
    def test_master_list_sorted_by_score_desc(self):
        iocs = [
            _make_ioc("1.1.1.1", severity="Low"),
            _make_ioc("2.2.2.2", severity="Critical"),
        ]
        result = correlate(iocs)
        scores = [r["risk_score"] for r in result["master_list"]]
        assert scores == sorted(scores, reverse=True)
 
    def test_multi_bonus_applied_at_three_feeds(self):
        iocs = [
            _make_ioc("1.2.3.4", source="feed_a", severity="Low"),
            _make_ioc("1.2.3.4", source="feed_b", severity="Low"),
            _make_ioc("1.2.3.4", source="feed_c", severity="Low"),
        ]
        result = correlate(iocs)
        # Low(10) + feed_bonus(20) + multi_bonus(10) = 40
        assert result["master_list"][0]["risk_score"] == 40
 
    def test_description_merging(self):
        iocs = [
            _make_ioc("1.2.3.4", source="feed_a", desc="Tor exit node"),
            _make_ioc("1.2.3.4", source="feed_b", desc="Botnet C2"),
        ]
        result = correlate(iocs)
        desc = result["master_list"][0]["description"]
        assert "Tor exit node" in desc
        assert "Botnet C2" in desc
 
    def test_empty_input(self):
        result = correlate([])
        assert result["master_list"] == []
        assert result["repeated"] == []
        assert result["high_risk"] == []
 
    def test_output_has_required_fields(self):
        result = correlate([_make_ioc("1.2.3.4")])
        entry = result["master_list"][0]
        required = {"value", "type", "sources", "feed_count", "risk_score",
                    "severity", "base_severity", "first_seen", "correlated_at"}
        assert required.issubset(entry.keys())
 
 
# ── Integration: parse → normalize → correlate ────────────────────────────────
 
class TestIntegration:
    """End-to-end pipeline test using real sample feed files."""
 
    FEEDS_DIR = os.path.join(os.path.dirname(__file__), "sample_feeds")
 
    def test_full_pipeline_csv_and_json(self):
        from parser import parse_feed
        from normalizer import normalize
 
        csv_raw = parse_feed(os.path.join(self.FEEDS_DIR, "test_feed.csv"))
        json_raw = parse_feed(os.path.join(self.FEEDS_DIR, "test_feed.json"))
        all_raw = csv_raw + json_raw
 
        normalised = normalize(all_raw)
        result = correlate(normalised)
 
        # Basic sanity
        assert len(result["master_list"]) > 0
 
        # 185.220.101.45 appears in both CSV and JSON — should be in repeated
        cross_feed = [r for r in result["repeated"] if r["value"] == "185.220.101.45"]
        assert len(cross_feed) == 1
        assert cross_feed[0]["feed_count"] >= 2
 
    def test_private_ips_never_reach_correlator(self):
        from parser import parse_feed
        from normalizer import normalize
 
        raw = parse_feed(os.path.join(self.FEEDS_DIR, "test_feed.csv"))
        normalised = normalize(raw)
        result = correlate(normalised)
 
        all_values = [r["value"] for r in result["master_list"]]
        assert "192.168.1.1" not in all_values
 
    def test_whitelisted_domains_never_reach_correlator(self):
        from parser import parse_feed
        from normalizer import normalize
 
        raw = parse_feed(os.path.join(self.FEEDS_DIR, "test_feed.csv"))
        normalised = normalize(raw)
        result = correlate(normalised)
 
        all_values = [r["value"] for r in result["master_list"]]
        assert "google.com" not in all_values
