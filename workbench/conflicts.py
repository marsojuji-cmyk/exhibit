"""Conflict detection — Layer A completion.

When independent sources disagree about the same entity, the disagreement
itself is the finding. This module emits an INFERRED claim (labeled
CONFLICT:) citing both source claim IDs. It never silently merges,
never majority-votes, never drops the losing side.

RESOLUTION RULE v1 (documented, transparent, analyst-overridable):
  1. Disagreement is recorded, not resolved by the machine. The claim
     stays in the review queue until the analyst approves or rejects it.
  2. For operational priority, DIRECT OBSERVATION OF ABUSE outranks
     SCANNER CLASSIFICATION. GreyNoise "benign" describes observed scan
     behavior (what the IP does); a URLhaus/ThreatFox listing, a urlscan
     malicious verdict, VirusTotal >=3 engines, or AbuseIPDB >=75%
     confidence is direct evidence of malicious use (what the IP is used
     for). The two can both be true: a host can scan benignly AND serve
     malware. The rule therefore says "treat as malicious pending
     analyst review", not "GreyNoise was wrong".
  3. When neither side has direct-observation evidence, the conflict is
     recorded as UNRESOLVED and the analyst decides.

Falsifier (from the design brief): if cross-source conflicts turn out
rare or trivially resolvable by naive merging on real data, this layer
adds no precision over simple aggregation and should be rescoped.
"""
from __future__ import annotations

import json

ABUSEIPDB_MALICIOUS = 75   # AbuseIPDB confidence % treated as malicious-side evidence

RULE_TEXT = (
    "Resolution rule v1: direct observation of abuse (URLhaus/ThreatFox listing, "
    "urlscan malicious verdict, VirusTotal >=3 engines, AbuseIPDB >=75%) outranks "
    "GreyNoise benign-scanner classification; treat as malicious pending analyst review. "
    "Conflict stays open until the analyst approves or rejects it."
)


def _detail(claim) -> dict:
    try:
        d = json.loads(claim["detail"] or "{}")
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def detect_conflicts(claims: list) -> list[tuple[str, str, str, list[int], dict]]:
    """Returns [(tier, claim_text, source_label, claim_ids, detail), ...].
    Tier is always INFERRED; the text is prefixed CONFLICT:."""
    out: list[tuple[str, str, str, list[int], dict]] = []
    by_source: dict[str, list] = {}
    for c in claims:
        by_source.setdefault(c["source"], []).append(c)

    # Index GreyNoise verdicts by IP.
    gn: dict[str, tuple] = {}  # ip -> (claim, detail)
    for c in by_source.get("greynoise", []):
        if c["tier"] != "VERIFIED":
            continue
        d = _detail(c)
        if d.get("ip"):
            gn[d["ip"]] = (c, d)

    # Index malicious-side evidence by IP. Only IP-level conflicts exist:
    # GreyNoise and AbuseIPDB both verdict the SAME IP. URLhaus/ThreatFox/
    # VirusTotal/urlscan verdict the domain or its URLs — there is no
    # benign-side source for those entities, so no conflict shape exists;
    # they are scored as adverse evidence instead (see analyze.score_run).
    mal: dict[str, list] = {}  # ip -> [(claim, reason)]
    for c in by_source.get("abuseipdb", []):
        if c["tier"] != "VERIFIED":
            continue
        d = _detail(c)
        if d.get("ip") and int(d.get("abuse_confidence", 0) or 0) >= ABUSEIPDB_MALICIOUS:
            mal.setdefault(d["ip"], []).append(
                (c, f"AbuseIPDB confidence {d['abuse_confidence']}%"))

    for ip, (gc, gd) in sorted(gn.items()):
        if gd.get("classification") != "benign":
            continue
        hits = mal.get(ip, [])
        if not hits:
            continue
        ids = [gc["id"]] + [h[0]["id"] for h in hits]
        reasons = "; ".join(h[1] for h in hits)
        out.append((
            "INFERRED",
            f"CONFLICT: {ip} — GreyNoise classifies it a benign scanner "
            f"(noise={gd.get('noise')}, riot={gd.get('riot')}), but {reasons}. "
            f"Per resolution rule v1: treat as malicious pending analyst review.",
            "workbench-conflict",
            ids,
            {"conflict": True, "entity": ip,
             "greynoise_claim": gc["id"],
             "adverse_claims": [h[0]["id"] for h in hits],
             "rule": RULE_TEXT},
        ))

    # No domain-level conflict shape: see the mal-index comment above.
    return out
