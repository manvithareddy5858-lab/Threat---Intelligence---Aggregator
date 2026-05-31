"""
test_correlator.py — Unit tests for modules/correlator.py
Threat Intelligence Aggregator | pytest test suite
"""
import sys, os, pytest
 
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)
 
from modules.correlator import correlate, _compute_score, _score_to_severity
 
 
class TestComputeScore:
    def test_critical_single_feed(self): assert _compute_score("Critical", 1) == 75
    def test_high_single_feed(self): assert _compute_score("High", 1) == 50
    def test_medium_single_feed(self): assert _compute_score("Medium", 1) == 25
    def test_low_single_feed(self): assert _compute_score("Low", 1) == 10
    def test_feed_bonus_two_feeds(self): assert _compute_score("Low", 2) == 20
    def test_feed_bonus_capped_at_30(self): assert _compute_score("Low", 5) == 50
    def test_multi_bonus_at_three_feeds(self): assert _compute_score("Low", 3) == 40
    def test_score_capped_at_100(self): assert _compute_score("Critical", 5) == 100
    def test_unknown_severity_gets_low_base(self): assert _compute_score("Unknown", 1) == 10
 
 
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
 
 
def _make_ioc(value, ioc_type="ip", source="feed_a", severity="High", category="general", desc=""):
    return {"value":value,"type":ioc_type,"source":source,"severity":severity,
            "category":category,"description":desc,"hash_subtype":None,
            "first_seen":"2026-01-01T00:00:00+00:00"}
 
 
class TestCorrelate:
    def test_returns_dict_with_required_keys(self):
        r = correlate([_make_ioc("1.2.3.4")])
        assert "master_list" in r and "repeated" in r and "high_risk" in r
    def test_single_ioc_in_master_list(self):
        assert len(correlate([_make_ioc("1.2.3.4")])["master_list"]) == 1
    def test_cross_feed_merge(self):
        iocs = [_make_ioc("185.220.101.45",source="feed_a"), _make_ioc("185.220.101.45",source="feed_b")]
        r = correlate(iocs)
        assert len(r["master_list"]) == 1
        assert r["master_list"][0]["feed_count"] == 2
        assert set(r["master_list"][0]["sources"]) == {"feed_a","feed_b"}
    def test_best_severity_wins(self):
        iocs = [_make_ioc("1.2.3.4",source="a",severity="Low"), _make_ioc("1.2.3.4",source="b",severity="Critical")]
        assert correlate(iocs)["master_list"][0]["base_severity"] == "Critical"
    def test_repeated_list_two_plus_feeds(self):
        iocs = [_make_ioc("1.2.3.4",source="a"), _make_ioc("1.2.3.4",source="b"), _make_ioc("5.6.7.8",source="a")]
        r = correlate(iocs)
        assert len(r["repeated"]) == 1 and r["repeated"][0]["value"] == "1.2.3.4"
    def test_high_risk_score_threshold(self):
        assert len(correlate([_make_ioc("1.2.3.4",severity="Critical")])["high_risk"]) == 1
    def test_low_risk_not_in_high_risk(self):
        assert len(correlate([_make_ioc("1.2.3.4",severity="Low")])["high_risk"]) == 0
    def test_case_insensitive_dedup(self):
        iocs = [_make_ioc("Evil-Domain.RU","domain",source="a"), _make_ioc("evil-domain.ru","domain",source="b")]
        assert len(correlate(iocs)["master_list"]) == 1
    def test_master_list_sorted_by_score_desc(self):
        iocs = [_make_ioc("1.1.1.1",severity="Low"), _make_ioc("2.2.2.2",severity="Critical")]
        scores = [r["risk_score"] for r in correlate(iocs)["master_list"]]
        assert scores == sorted(scores, reverse=True)
    def test_multi_bonus_applied_at_three_feeds(self):
        iocs = [_make_ioc("1.2.3.4",source=f"feed_{x}",severity="Low") for x in "abc"]
        assert correlate(iocs)["master_list"][0]["risk_score"] == 40
    def test_description_merging(self):
        iocs = [_make_ioc("1.2.3.4",source="a",desc="Tor exit node"), _make_ioc("1.2.3.4",source="b",desc="Botnet C2")]
        desc = correlate(iocs)["master_list"][0]["description"]
        assert "Tor exit node" in desc and "Botnet C2" in desc
    def test_empty_input(self):
        r = correlate([])
        assert r["master_list"]==[] and r["repeated"]==[] and r["high_risk"]==[]
    def test_output_has_required_fields(self):
        entry = correlate([_make_ioc("1.2.3.4")])["master_list"][0]
        assert {"value","type","sources","feed_count","risk_score","severity","base_severity","first_seen","correlated_at"}.issubset(entry.keys())
 
 
class TestIntegration:
    FEEDS_DIR = os.path.join(os.path.dirname(__file__), "sample_feeds")
 
    def test_full_pipeline_csv_and_json(self):
        from modules.parser import parse_feed
        from modules.normalizer import normalize
        all_raw = parse_feed(os.path.join(self.FEEDS_DIR,"test_feed.csv")) + \
                  parse_feed(os.path.join(self.FEEDS_DIR,"test_feed.json"))
        result = correlate(normalize(all_raw))
        assert len(result["master_list"]) > 0
        cross = [r for r in result["repeated"] if r["value"]=="185.220.101.45"]
        assert len(cross) == 1 and cross[0]["feed_count"] >= 2
 
    def test_private_ips_never_reach_correlator(self):
        from modules.parser import parse_feed
        from modules.normalizer import normalize
        raw = parse_feed(os.path.join(self.FEEDS_DIR,"test_feed.csv"))
        all_vals = [r["value"] for r in correlate(normalize(raw))["master_list"]]
        assert "192.168.1.1" not in all_vals
 
    def test_whitelisted_domains_never_reach_correlator(self):
        from modules.parser import parse_feed
        from modules.normalizer import normalize
        raw = parse_feed(os.path.join(self.FEEDS_DIR,"test_feed.csv"))
        all_vals = [r["value"] for r in correlate(normalize(raw))["master_list"]]
        assert "google.com" not in all_vals
