"""Layer C: certificate-transparency early-warning radar.

Watchlist-driven. For each watchlist brand, query crt.sh for certificates
whose names contain the brand label (substring query — one query per brand,
rate-honest), classify each returned name as a lookalike or not, enrich
hits via the existing RDAP / DoH / urlscan connectors, and score phishing
likelihood with a transparent additive feature model.

Every feature and weight is documented below in FEATURES. The observation
(cert exists) is a VERIFIED claim; the phishing judgment is a GUESSED
claim citing it. Hits enter the review queue like everything else.

HONEST BOUNDARIES (documented limitations, not silent gaps):
  - The crt.sh substring query only finds names CONTAINING the brand label.
    Edit-distance-only typosquats without the brand string
    (e.g. "marcusr1chards.dev") are NOT caught. A full CT stream
    (certstream) would be needed for those — out of scope for this layer.
  - Homoglyph handling covers a fixed table of common confusables;
    full Unicode confusable coverage (UTS #39) is not implemented.
  - Scores are unvalidated until a labeled evaluation set exists;
    see README "CT radar: eval methodology".
"""
from __future__ import annotations

import json
import time
import urllib.parse

from . import connectors
from .connectors import FetchResult
from .threatintel import summarize_urlhaus  # noqa: F401  (re-export for cli)

# -- string machinery (stdlib) ------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    """Edit distance, O(min(n,m)) space."""
    if a == b:
        return 0
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, 1):
        cur = [i]
        for j, ca in enumerate(a, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Common visual confusables -> canonical ASCII. Fixed table; UTS #39
# coverage is explicitly out of scope (see module docstring).
_HOMOGLYPH_PAIRS = [
    ("0", "o"), ("1", "l"), ("1", "i"), ("5", "s"), ("8", "b"),
    ("rn", "m"), ("vv", "w"), ("cl", "d"),
    ("а", "a"), ("е", "e"), ("і", "i"), ("о", "o"), ("р", "p"),
    ("с", "c"), ("х", "x"), ("у", "y"),  # Cyrillic lookalikes
    ("ɡ", "g"), ("ո", "n"),
]
_HOMO_TABLE = str.maketrans({c: t for c, t in _HOMOGLYPH_PAIRS if len(c) == 1})


def normalize_homoglyphs(s: str) -> str:
    s = s.translate(_HOMO_TABLE)
    for multi, target in _HOMOGLYPH_PAIRS:
        if len(multi) > 1:
            s = s.replace(multi, target)
    return s


def registrable(domain: str) -> str:
    """Naive registrable domain: last two labels. (No PSL dependency.)"""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


# -- lookalike classification -------------------------------------------------
def classify_lookalike(name: str, brand_reg: str) -> tuple[str, str] | None:
    """Returns (kind, evidence) or None. Order matters: homoglyph first
    (raw edit distance would mislabel a visual spoof as a typo)."""
    nreg = registrable(name)
    brand_label = brand_reg.split(".")[0]
    if nreg == brand_reg:
        return None
    # 1. Homoglyph: normalized forms match but raw strings differ.
    if normalize_homoglyphs(nreg) == normalize_homoglyphs(brand_reg) and nreg != brand_reg:
        return ("homoglyph", f"normalizes to {normalize_homoglyphs(nreg)}")
    # 2. Edit distance on normalized registrable domains.
    d = levenshtein(normalize_homoglyphs(nreg), normalize_homoglyphs(brand_reg))
    if 1 <= d <= 2:
        return ("edit-distance", f"distance {d} from {brand_reg}")
    # 3. Brand label embedded in the registrable domain of a longer name.
    if brand_label in nreg:
        return ("brand-substring", f"contains '{brand_label}' with extra tokens")
    # 4. Brand label as a subdomain of an unrelated registrable domain.
    #    "marcusrichards.verify-login.org" is the classic phishing URL
    #    shape: the brand is bait in a label the attacker controls.
    labels = name.split(".")
    if brand_label in labels[:-2]:
        return ("brand-subdomain", f"'{brand_label}' is a subdomain label of {nreg}")
    return None


# -- transparent feature model ------------------------------------------------
# Each feature: (key, weight, why). Weights are judgment, documented here,
# not tuned — see README eval methodology for how they get validated.
FEATURES = [
    ("homoglyph", 35, "visual spoof of the brand — deliberate deception signal"),
    ("edit_distance_1", 30, "one character off the brand — classic typosquat"),
    ("edit_distance_2", 20, "two characters off the brand — weaker typosquat"),
    ("brand_substring", 25, "brand embedded in longer name, e.g. brand-login.com"),
    ("brand_subdomain", 25, "brand as a subdomain label of an unrelated registrable "
                           "domain, e.g. brand.verify-login.org — classic phishing URL shape"),
    ("cert_last_7d", 15, "certificate issued in last 7 days — phishing kits rotate fast"),
    ("free_acme_issuer", 10, "free ACME issuer — weak signal, phishers use free certs too"),
    ("rdap_created_30d", 25, "domain registered in last 30 days"),
    ("urlscan_malicious", 40, "urlscan verdicts flag the lookalike as malicious"),
]
FREE_ACME = ("let's encrypt", "letsencrypt", "zerossl", "ssl.com free", "buypass")


def score_lookalike(kind: str, evidence: str, cert_not_before: str,
                    issuer: str, rdap_created: str | None,
                    urlscan_malicious: bool) -> tuple[int, list[str]]:
    """Returns (score 0..100, [fired feature keys])."""
    fired: list[str] = []
    if kind == "homoglyph":
        fired.append("homoglyph")
    elif kind == "edit-distance":
        fired.append("edit_distance_1" if "distance 1" in evidence else "edit_distance_2")
    elif kind == "brand-substring":
        fired.append("brand_substring")
    elif kind == "brand-subdomain":
        fired.append("brand_subdomain")
    try:
        age_days = (time.time() - time.mktime(time.strptime(
            cert_not_before[:19], "%Y-%m-%dT%H:%M:%S"))) / 86400
        if age_days <= 7:
            fired.append("cert_last_7d")
    except Exception:
        pass
    if any(k in (issuer or "").lower() for k in FREE_ACME):
        fired.append("free_acme_issuer")
    if rdap_created:
        try:
            age = (time.time() - time.mktime(time.strptime(
                rdap_created[:19], "%Y-%m-%dT%H:%M:%S"))) / 86400
            if age <= 30:
                fired.append("rdap_created_30d")
        except Exception:
            pass
    if urlscan_malicious:
        fired.append("urlscan_malicious")
    weights = {k: w for k, w, _ in FEATURES}
    return min(100, sum(weights[f] for f in fired)), fired


# -- crt.sh substring query ---------------------------------------------------
def fetch_brand_certs(brand_label: str, retries: int = 2) -> FetchResult:
    """One substring query per brand: certs whose names contain the label."""
    q = urllib.parse.quote(f"%{brand_label}%")
    url = f"https://crt.sh/?q={q}&output=json"
    last = ""
    for _ in range(retries):
        status, body = connectors._get(url)
        if status == 200 and body.lstrip().startswith(("[", "{")):
            try:
                items = json.loads(body)
                items = items if isinstance(items, list) else [items]
                return FetchResult("crt.sh", url, True, json.dumps(items))
            except Exception:
                last = "unparseable JSON"
        else:
            last = body
        time.sleep(2)
    return FetchResult("crt.sh", url, False,
                       error=f"crt.sh brand query failed after {retries} tries: {last[:140]}")


def _rdap_created(domain: str) -> str | None:
    fr = connectors.fetch_rdap(domain)
    if not fr.ok:
        return None
    try:
        for ev in (fr.parsed() or {}).get("events", []) or []:
            if ev.get("eventAction") == "registration":
                return ev.get("eventDate", "")
    except Exception:
        pass
    return None


def _urlscan_malicious(domain: str) -> bool:
    fr = connectors.fetch_urlscan(domain)
    if not fr.ok:
        return False
    try:
        for r in (fr.parsed() or {}).get("results", [])[:10]:
            v = r.get("verdicts", {}) or {}
            if any((x or {}).get("malicious") for x in v.values() if isinstance(x, dict)):
                return True
    except Exception:
        pass
    return False


def run_radar(brand: str) -> list[tuple]:
    """Run the CT radar for one watchlist brand.
    Returns claim tuples: (tier, claim, source, source_url, observed_at, detail)."""
    from .store import now
    brand_reg = registrable(brand)
    brand_label = brand_reg.split(".")[0]
    claims: list[tuple] = []
    fr = fetch_brand_certs(brand_label)
    if not fr.ok:
        claims.append(("DEGRADED",
                       f"CT radar: crt.sh brand query failed for '{brand_label}' — no lookalike coverage",
                       fr.source, fr.source_url, now(), {"error": fr.error}))
        return claims
    try:
        items = json.loads(fr.raw)
    except Exception:
        items = []
    seen: set[str] = set()
    for e in items if isinstance(items, list) else []:
        for raw_name in str(e.get("name_value", "") or "").split("\n"):
            name = raw_name.strip().lower().lstrip("*.")
            if not name or name in seen or registrable(name) == brand_reg:
                continue
            seen.add(name)
            hit = classify_lookalike(name, brand_reg)
            if not hit:
                continue
            kind, evidence = hit
            nreg = registrable(name)
            # Enrich: RDAP creation date + urlscan verdict on the lookalike.
            rdap_created = _rdap_created(nreg)
            us_mal = _urlscan_malicious(nreg)
            score, fired = score_lookalike(
                kind, evidence, str(e.get("not_before", "")),
                str(e.get("issuer_name", "")), rdap_created, us_mal)
            obs_id = None  # filled by caller after insert
            claims.append(("VERIFIED",
                           f"CT radar: certificate issued for lookalike '{name}' "
                           f"({kind}: {evidence}) of watchlist brand '{brand}'",
                           "crt.sh", fr.source_url, now(),
                           {"lookalike": name, "registrable": nreg, "kind": kind,
                            "evidence": evidence, "issuer": str(e.get("issuer_name", ""))[:80],
                            "not_before": str(e.get("not_before", ""))}))
            claims.append(("GUESSED",
                           f"CT radar: '{name}' scores {score}/100 phishing likelihood "
                           f"(features: {', '.join(fired) or 'none'})",
                           "workbench-ctwatch", "workbench://ctwatch", now(),
                           {"lookalike": name, "score": score,
                            "features_fired": fired,
                            "feature_weights": {k: w for k, w, _ in FEATURES},
                            "observe_claim_ref": "previous VERIFIED claim in this run"}))
            _ = obs_id
    if not claims:
        claims.append(("VERIFIED",
                       f"CT radar: no lookalike certificates found for watchlist brand '{brand}' "
                       f"(substring query over crt.sh)",
                       "crt.sh", fr.source_url, now(),
                       {"brand": brand, "hits": 0,
                        "limitation": "substring query only; edit-distance-only typosquats without "
                                      "the brand string are not covered"}))
    return claims
