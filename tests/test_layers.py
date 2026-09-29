"""Synthetic quality-gate tests for the Exhibit three layers.

Stdlib only. These tests exercise the deterministic machinery with
fixtures — no network, no API keys, no invented measurements. Each
layer gets a checkpoint:
  Layer A (fusion core)  — entity extraction, linking, inference, scoring
  Layer C (CT radar)    — string machinery, lookalike classification, scoring
  Layer B (sentinel)    — snapshots, diff discipline, alert budget

Run: python3 -m unittest discover tests -v
"""
import json
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workbench import analyze
from workbench import ctwatch
from workbench.store import Store


def claim(cid, tier, text, source, detail=None):
    return {"id": cid, "tier": tier, "claim": text, "source": source,
            "detail": json.dumps(detail or {})}


class TestFusionCoreEntities(unittest.TestCase):
    def test_extracts_typed_entities(self):
        ents = dict(analyze.extract_entities(
            "contact admin@example.com, server 203.0.113.7, "
            "hash " + "ab" * 32))
        self.assertIn(("email", "admin@example.com"), analyze.extract_entities(
            "contact admin@example.com"))
        self.assertIn(("ipv4", "203.0.113.7"),
                      analyze.extract_entities("server 203.0.113.7"))

    def test_rejects_invalid_ip(self):
        ents = analyze.extract_entities("bad 999.999.999.999 and 0.0.0.0")
        self.assertNotIn(("ipv4", "999.999.999.999"), ents)
        self.assertNotIn(("ipv4", "0.0.0.0"), ents)

    def test_domain_not_double_counted_inside_email(self):
        ents = analyze.extract_entities("write to admin@example.com today")
        domains = [v for t, v in ents if t == "domain"]
        self.assertNotIn("example.com", domains)


class TestFusionCoreLinks(unittest.TestCase):
    def test_shared_ip_links_two_sources(self):
        claims = [
            claim(1, "VERIFIED", "DNS: example.com A 203.0.113.7", "doh-cloudflare"),
            claim(2, "VERIFIED", "GreyNoise: 203.0.113.7 classification=benign", "greynoise"),
        ]
        links = analyze.build_links(claims, skip_values={"example.com"})
        self.assertIn(("ipv4", "203.0.113.7"), links)
        self.assertEqual(links[("ipv4", "203.0.113.7")], [1, 2])

    def test_single_source_entity_not_linked(self):
        claims = [claim(1, "VERIFIED", "DNS: example.com A 203.0.113.7", "doh-cloudflare")]
        self.assertEqual(analyze.build_links(claims), {})

    def test_target_itself_never_forms_mega_link(self):
        claims = [
            claim(1, "VERIFIED", "crt.sh: certs for example.com", "crt.sh"),
            claim(2, "VERIFIED", "urlscan: scans of example.com", "urlscan.io"),
        ]
        links = analyze.build_links(claims, skip_values={"example.com"})
        self.assertNotIn(("domain", "example.com"), links)

    def test_inferred_claim_cites_both_sources(self):
        claims = {
            1: {"source": "doh-cloudflare"}, 2: {"source": "greynoise"},
        }
        links = {("ipv4", "203.0.113.7"): [1, 2]}
        out = analyze.draft_inferred_claims(links, claims, "example.com")
        self.assertEqual(len(out), 1)
        tier, text, label, ids = out[0]
        self.assertEqual(tier, "INFERRED")
        self.assertEqual(set(ids), {1, 2})
        self.assertIn("doh-cloudflare", text)
        self.assertIn("greynoise", text)

    def test_nonprod_naming_is_guessed_not_inferred(self):
        claims = {1: {"source": "crt.sh"}, 2: {"source": "urlscan.io"}}
        links = {("domain", "staging.example.com"): [1, 2]}
        out = analyze.draft_inferred_claims(links, claims, "example.com")
        self.assertEqual(out[0][0], "GUESSED")


class TestFusionCoreScoring(unittest.TestCase):
    def test_urlscan_malicious_scores_with_citation(self):
        claims = [claim(1, "VERIFIED", "urlscan scan", "urlscan.io",
                        {"malicious_count": 2})]
        total, items, notes = analyze.score_run(claims, "example.com")
        self.assertEqual(total, 40)
        pts, reason, ids = items[0]
        self.assertEqual(pts, 40)
        self.assertEqual(ids, [1])

    def test_deterministic_same_input_same_score(self):
        claims = [
            claim(1, "VERIFIED", "urlscan scan", "urlscan.io", {"malicious_count": 1}),
            claim(2, "VERIFIED", "RDAP hold", "rdap", {"statuses": ["server hold"]}),
        ]
        self.assertEqual(analyze.score_run(claims, "example.com"),
                         analyze.score_run(claims, "example.com"))

    def test_routine_rdap_protections_not_scored(self):
        claims = [claim(1, "VERIFIED", "RDAP", "rdap",
                        {"statuses": ["client transfer prohibited",
                                       "client update prohibited"]})]
        total, items, notes = analyze.score_run(claims, "example.com")
        self.assertEqual(total, 0)

    def test_rdap_hold_is_scored(self):
        claims = [claim(1, "VERIFIED", "RDAP", "rdap", {"statuses": ["serverHold"]})]
        total, items, _ = analyze.score_run(claims, "example.com")
        self.assertEqual(total, 30)

    def test_degraded_noted_never_silent(self):
        claims = [claim(1, "DEGRADED", "crt.sh down", "crt.sh", {"error": "502"})]
        total, items, notes = analyze.score_run(claims, "example.com")
        self.assertTrue(any("crt.sh" in n and "incomplete" in n for n in notes))

    def test_clean_run_says_so(self):
        claims = [claim(1, "VERIFIED", "RDAP ok", "rdap", {"statuses": []})]
        total, items, notes = analyze.score_run(claims, "example.com")
        self.assertEqual(total, 0)
        self.assertTrue(any("No adverse signals" in n for n in notes))


class TestCTRadarStrings(unittest.TestCase):
    def test_levenshtein_basics(self):
        self.assertEqual(ctwatch.levenshtein("abc", "abc"), 0)
        self.assertEqual(ctwatch.levenshtein("abc", "abd"), 1)
        self.assertEqual(ctwatch.levenshtein("kitten", "sitting"), 3)

    def test_homoglyph_normalization(self):
        # Cyrillic а (U+0430) normalizes to latin a
        self.assertEqual(ctwatch.normalize_homoglyphs("mаrcus"), "marcus")
        self.assertEqual(ctwatch.normalize_homoglyphs("marcus"), "marcus")

    def test_registrable_naive(self):
        self.assertEqual(ctwatch.registrable("a.b.example.com"), "example.com")
        self.assertEqual(ctwatch.registrable("EXAMPLE.COM."), "example.com")


class TestCTRadarClassify(unittest.TestCase):
    BRAND = "marcusrichards.dev"

    def test_own_domain_not_lookalike(self):
        self.assertIsNone(ctwatch.classify_lookalike("www.marcusrichards.dev", self.BRAND))

    def test_unrelated_not_lookalike(self):
        self.assertIsNone(ctwatch.classify_lookalike("example-shop.com", self.BRAND))

    def test_homoglyph_detected_before_typo(self):
        kind, ev = ctwatch.classify_lookalike("mаrcusrichards.dev", self.BRAND)
        self.assertEqual(kind, "homoglyph")

    def test_edit_distance_one(self):
        kind, ev = ctwatch.classify_lookalike("marcusrichardz.dev", self.BRAND)
        self.assertEqual(kind, "edit-distance")
        self.assertIn("distance 1", ev)

    def test_edit_distance_two(self):
        kind, ev = ctwatch.classify_lookalike("mxrcusrichxrds.dev", self.BRAND)
        self.assertEqual(kind, "edit-distance")
        self.assertIn("distance 2", ev)

    def test_brand_substring(self):
        kind, ev = ctwatch.classify_lookalike("getmarcusrichards.com", self.BRAND)
        self.assertEqual(kind, "brand-substring")

    def test_distant_domain_not_lookalike(self):
        self.assertIsNone(ctwatch.classify_lookalike("marcus-richards-photography.ca", self.BRAND))


class TestCTRadarScoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Dates computed at test time: the 7-day / 30-day features are
        # windowed on "now", so fixed calendar strings drift out of
        # validity as the suite ages. A relative date never does.
        from datetime import datetime, timedelta, timezone
        fmt = "%Y-%m-%dT%H:%M:%S"
        now = datetime.now(timezone.utc)
        cls.RECENT = (now - timedelta(days=2)).strftime(fmt)
        cls.OLD = (now - timedelta(days=400)).strftime(fmt)

    def test_homoglyph_alone_below_alert_threshold(self):
        score, fired = ctwatch.score_lookalike("homoglyph", "x", self.OLD,
                                               "DigiCert Inc", self.OLD, False)
        self.assertEqual(score, 35)
        self.assertLess(score, 50)

    def test_homoglyph_plus_fresh_cert_and_free_issuer_alerts(self):
        score, fired = ctwatch.score_lookalike("homoglyph", "x", self.RECENT,
                                               "Let's Encrypt", self.RECENT, False)
        self.assertGreaterEqual(score, 50)
        self.assertIn("homoglyph", fired)
        self.assertIn("cert_last_7d", fired)

    def test_urlscan_malicious_is_strongest_single_feature(self):
        score, fired = ctwatch.score_lookalike("brand-substring", "x", self.OLD,
                                               "DigiCert", None, True)
        self.assertIn("urlscan_malicious", fired)
        self.assertGreaterEqual(score, 50)

    def test_weights_are_documented_and_summed(self):
        weights = {k: w for k, w, _ in ctwatch.FEATURES}
        score, fired = ctwatch.score_lookalike("edit-distance", "distance 1 from x",
                                               self.RECENT, "Let's Encrypt", self.RECENT, False)
        self.assertEqual(score, min(100, sum(weights[f] for f in fired)))

    def test_score_capped_at_100(self):
        score, _ = ctwatch.score_lookalike("homoglyph", "x", self.RECENT,
                                           "Let's Encrypt", self.RECENT, True)
        self.assertLessEqual(score, 100)


class TestSentinel(unittest.TestCase):
    def _verified(self, cid, source, detail):
        return claim(cid, "VERIFIED", f"{source} observation", source, detail)

    def test_snapshot_records_coverage(self):
        claims = [
            self._verified(1, "crt.sh", {"subdomains": ["a.example.com"], "issuers": ["LE"]}),
            self._verified(2, "doh-cloudflare", {"A": ["203.0.113.7"]}),
        ]
        snap = analyze.build_snapshot(claims)
        self.assertTrue(snap["coverage"]["crt.sh"])
        self.assertTrue(snap["coverage"]["doh-cloudflare"])
        self.assertFalse(snap["coverage"]["urlscan.io"])
        self.assertEqual(snap["subdomains"], ["a.example.com"])

    def test_derived_claims_not_in_snapshot(self):
        claims = [
            self._verified(1, "crt.sh", {"subdomains": ["a.example.com"]}),
            claim(2, "INFERRED", "linked", "workbench-linker", {}),
        ]
        snap = analyze.build_snapshot(claims)
        self.assertEqual(snap["subdomains"], ["a.example.com"])

    def test_stable_run_is_silent(self):
        snap = {"subdomains": ["a.example.com"], "a_records": ["203.0.113.7"],
                "issuers": ["LE"], "urlscan_malicious": 0, "ti": {},
                "coverage": {s: True for s in analyze.SNAPSHOT_SOURCES}}
        self.assertEqual(analyze.diff_snapshots(snap, snap), [])

    def test_genuine_new_subdomain_alerts(self):
        prev = {"subdomains": ["a.example.com"], "a_records": [], "issuers": [],
                "urlscan_malicious": 0, "ti": {},
                "coverage": {s: True for s in analyze.SNAPSHOT_SOURCES}}
        cur = dict(prev, subdomains=["a.example.com", "evil.example.com"],
                   coverage=dict(prev["coverage"]))
        out = analyze.diff_snapshots(prev, cur)
        alerts = [a for a in out if a[2]]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0], "new-subdomain")
        self.assertIn("evil.example.com", alerts[0][1])

    def test_recovered_source_is_note_not_alert(self):
        # crt.sh was DEGRADED (uncovered) in the baseline. When it
        # recovers, the subdomains it brings are coverage restoration —
        # recorded as an informational note, never an alert.
        prev = {"subdomains": ["a.example.com"], "a_records": [], "issuers": [],
                "urlscan_malicious": 0, "ti": {},
                "coverage": {s: (s != "crt.sh") for s in analyze.SNAPSHOT_SOURCES}}
        cur = dict(prev, subdomains=["a.example.com", "new.example.com"],
                   coverage={s: True for s in analyze.SNAPSHOT_SOURCES})
        out = analyze.diff_snapshots(prev, cur)
        alerts = [a for a in out if a[2]]
        notes = [a for a in out if not a[2]]
        self.assertEqual(alerts, [])
        self.assertTrue(any(a[0] == "source-recovered" and "crt.sh" in a[1]
                            for a in notes))

    def test_new_subdomain_still_alerts_when_source_was_covered(self):
        # crt.sh was covered in the baseline and genuinely saw a new
        # name — that IS new exposure and must alert.
        prev = {"subdomains": ["a.example.com"], "a_records": [], "issuers": [],
                "urlscan_malicious": 0, "ti": {},
                "coverage": {s: (s != "urlscan.io") for s in analyze.SNAPSHOT_SOURCES}}
        cur = dict(prev, subdomains=["a.example.com", "new.example.com"],
                   coverage={s: True for s in analyze.SNAPSHOT_SOURCES})
        out = analyze.diff_snapshots(prev, cur)
        alerts = [a for a in out if a[2]]
        self.assertTrue(any(a[0] == "new-subdomain" and a[1].endswith("new.example.com")
                            for a in alerts))

    def test_new_a_record_alerts(self):
        base = {"subdomains": [], "a_records": ["203.0.113.7"], "issuers": [],
                "urlscan_malicious": 0, "ti": {},
                "coverage": {s: True for s in analyze.SNAPSHOT_SOURCES}}
        cur = dict(base, a_records=["203.0.113.7", "198.51.100.9"],
                   coverage=dict(base["coverage"]))
        out = analyze.diff_snapshots(base, cur)
        self.assertTrue(any(a[0] == "new-a-record" and a[2] for a in out))

    def test_malicious_verdict_increase_alerts(self):
        base = {"subdomains": [], "a_records": [], "issuers": [],
                "urlscan_malicious": 0, "ti": {},
                "coverage": {s: True for s in analyze.SNAPSHOT_SOURCES}}
        cur = dict(base, urlscan_malicious=2, coverage=dict(base["coverage"]))
        out = analyze.diff_snapshots(base, cur)
        self.assertTrue(any(a[0] == "new-malicious-verdict" and a[2] for a in out))

    def test_alert_budget_counts(self):
        store = Store(":memory:")
        rid = store.new_run("example.com")
        store.add_claim(rid, "INFERRED", "NEW EXPOSURE: x", "workbench-diff",
                        "workbench://diff", "t", {"alert": True})
        store.add_claim(rid, "INFERRED", "SOURCE RECOVERED: y", "workbench-diff",
                        "workbench://diff", "t", {"alert": False})
        total, rejected, approved = analyze.alert_budget(store, "example.com")
        self.assertEqual((total, rejected, approved), (1, 0, 0))
        store.set_claim_status(1, "rejected")
        total, rejected, approved = analyze.alert_budget(store, "example.com")
        self.assertEqual((total, rejected, approved), (1, 1, 0))


class TestScopeGate(unittest.TestCase):
    def test_out_of_scope_refused_without_attestation(self):
        from workbench.cli import check_scope
        store = Store(":memory:")
        rid = store.new_run("evil.example")
        with self.assertRaises(SystemExit) as cm:
            check_scope("evil.example", None, store, rid)
        self.assertEqual(cm.exception.code, 2)

    def test_in_scope_target_passes(self):
        from workbench.cli import check_scope, load_scope
        store = Store(":memory:")
        rid = store.new_run("marcusrichards.dev")
        check_scope("marcusrichards.dev", None, store, rid)  # must not raise

    def test_attestation_logged_for_out_of_scope(self):
        from workbench.cli import check_scope
        store = Store(":memory:")
        rid = store.new_run("research.example")
        check_scope("research.example", "lawful research", store, rid)  # must not raise
        rows = store.cx.execute("SELECT text FROM attestations WHERE run_id=?",
                                (rid,)).fetchall()
        self.assertEqual(rows[0]["text"], "lawful research")


if __name__ == "__main__":
    unittest.main(verbosity=2)
