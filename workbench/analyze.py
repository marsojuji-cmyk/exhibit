"""Deterministic analysis layer — the workbench's native intelligence.

No ML black boxes: entity extraction, cross-source linking, and a
transparent risk score where every point cites the claim IDs behind it.
Anything the machine concludes is labeled INFERRED or GUESSED, never
VERIFIED. The analyst always has the last word via the review queue.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)

# Heuristic only — labeled GUESSED wherever it fires.
NONPROD_PREFIX = re.compile(r"^(dev|development|staging|stage|test|testing|qa|internal|int|vpn|admin|portal|legacy|old)[.-]", re.IGNORECASE)


def _valid_ip(v: str) -> bool:
    try:
        parts = [int(p) for p in v.split(".")]
        return len(parts) == 4 and all(0 <= p <= 255 for p in parts) and v != "0.0.0.0"
    except ValueError:
        return False


def extract_entities(text: str) -> list[tuple[str, str]]:
    """Pull typed entities out of claim text + detail blobs."""
    found: dict[tuple[str, str], bool] = {}
    for v in set(EMAIL.findall(text)):
        found[("email", v.lower())] = True
    for v in set(IPV4.findall(text)):
        if _valid_ip(v):
            found[("ipv4", v)] = True
    for v in set(SHA256.findall(text)):
        found[("sha256", v.lower())] = True
    for v in set(MD5.findall(text)):
        found[("md5", v.lower())] = True
    for v in set(DOMAIN.findall(text)):
        v = v.lower().rstrip(".")
        if not any(v == e[1].split("@")[1] for e in found if e[0] == "email"):
            found[("domain", v)] = True
    return sorted(found)


def build_links(claims, skip_values: set[str] | None = None) -> dict[tuple[str, str], list[int]]:
    """Group claim IDs by shared entity. skip_values avoids the trivial
    mega-link on the target itself."""
    skip_values = skip_values or set()
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for c in claims:
        blob = f"{c['claim']}\n{c['detail'] or ''}"
        for etype, value in extract_entities(blob):
            if value in skip_values:
                continue
            groups[(etype, value)].append(c["id"])
    return {k: sorted(set(v)) for k, v in groups.items() if len(set(v)) >= 2}


def _parse_detail(detail: str) -> dict:
    try:
        d = json.loads(detail or "{}")
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def score_run(claims, target: str) -> tuple[int, list[tuple[int, str, list[int]]], list[str]]:
    """Transparent additive scoring. Returns (total, [(points, reason, claim_ids)], notes)."""
    items: list[tuple[int, str, list[int]]] = []
    notes: list[str] = []
    by_source: dict[str, list] = defaultdict(list)
    for c in claims:
        by_source[c["source"]].append(c)

    # 1. urlscan malicious verdicts — strongest public adverse signal available.
    for c in by_source.get("urlscan.io", []):
        d = _parse_detail(c["detail"])
        n = int(d.get("malicious_count", 0) or 0)
        if n > 0:
            items.append((40, f"urlscan.io verdicts flag {n} scan(s) of {target} as malicious", [c["id"]]))

    # 2. Fresh certificates — not adverse by itself, but issuance must be authorized.
    for c in by_source.get("crt.sh", []):
        d = _parse_detail(c["detail"])
        n = int(d.get("recent_30d", 0) or 0)
        if n > 0:
            items.append((10, f"{n} certificate(s) issued in the last 30 days — confirm each was authorized", [c["id"]]))
        subs = d.get("subdomains", []) or []
        if len(subs) > 25:
            items.append((5, f"broad certificate-transparency footprint: {len(subs)} distinct subdomains", [c["id"]]))

    # 3. RDAP holds/suspensions. Routine client-side protections
    # (transfer/update/renew/delete prohibited) are normal — only flag
    # actual holds and suspensions.
    ROUTINE = ("client transfer prohibited", "client update prohibited",
               "client renew prohibited", "client delete prohibited")
    for c in by_source.get("rdap", []):
        d = _parse_detail(c["detail"])
        bad = [s for s in (d.get("statuses", []) or [])
               if s.lower() not in ROUTINE
               and any(k in s.lower() for k in ("hold", "suspend"))]
        if bad:
            items.append((30, f"RDAP shows restrictive statuses: {', '.join(bad)}", [c["id"]]))

    # 4. Public code references — informational, not scored.
    for c in by_source.get("github-api", []):
        d = _parse_detail(c["detail"])
        repos = d.get("repos", []) or []
        if repos:
            notes.append(f"GitHub: {len(repos)} public repo(s) reference '{target}' — skim for accidental exposure (claim #{c['id']}).")

    # 5. Threat-intel listings — Layer A. Direct adverse evidence.
    for c in by_source.get("urlhaus", []):
        d = _parse_detail(c["detail"])
        if d.get("listed"):
            items.append((45, f"URLhaus lists {d.get('count', '?')} malicious URL(s) for {target} "
                             f"(threats: {', '.join(d.get('threats', [])) or 'unspecified'})", [c["id"]]))
    for c in by_source.get("threatfox", []):
        d = _parse_detail(c["detail"])
        if d.get("listed"):
            items.append((40, f"ThreatFox holds {d.get('count', '?')} IoC record(s) for {target} "
                             f"({', '.join(d.get('threat_types', [])) or 'untyped'})", [c["id"]]))
    for c in by_source.get("greynoise", []):
        d = _parse_detail(c["detail"])
        if d.get("classification") == "malicious":
            items.append((30, f"GreyNoise classifies {d.get('ip', 'target IP')} as a malicious scanner "
                             f"({d.get('name', 'unnamed')})", [c["id"]]))
    for c in by_source.get("abuseipdb", []):
        d = _parse_detail(c["detail"])
        s = int(d.get("abuse_confidence", 0) or 0)
        if s >= 75:
            items.append((25, f"AbuseIPDB abuse confidence {s}% for {d.get('ip', 'target IP')} "
                             f"({d.get('total_reports', 0)} reports)", [c["id"]]))
    for c in by_source.get("virustotal", []):
        d = _parse_detail(c["detail"])
        m = int(d.get("malicious", 0) or 0)
        if m >= 3:
            items.append((30, f"VirusTotal: {m} engines flag {target} as malicious", [c["id"]]))
    for c in by_source.get("workbench-ctwatch", []):
        d = _parse_detail(c["detail"])
        s = int(d.get("score", 0) or 0)
        if s >= 50:
            items.append((s // 2, f"CT radar: lookalike '{d.get('lookalike', '?')}' scores "
                                  f"{s}/100 phishing likelihood", [c["id"]]))

    degraded = [c for c in claims if c["tier"] == "DEGRADED"]
    if degraded:
        notes.append(f"{len(degraded)} source(s) unreachable during collection — coverage is incomplete: "
                     + ", ".join(sorted({c['source'] for c in degraded})))

    total = sum(p for p, _, _ in items)
    if total == 0 and not degraded:
        notes.append("No adverse signals in the collected sources.")
    return total, items, notes


def draft_inferred_claims(links: dict, claims_by_id: dict, target: str) -> list[tuple[str, str, str, list[int]]]:
    """Propose INFERRED / GUESSED claims from link groups.
    Returns (tier, claim_text, source_label, claim_ids)."""
    out: list[tuple[str, str, str, list[int]]] = []
    for (etype, value), ids in sorted(links.items()):
        sources = sorted({claims_by_id[i]["source"] for i in ids})
        if etype == "ipv4" and len(sources) >= 2:
            out.append(("INFERRED",
                        f"{value} is shared infrastructure for {target}: observed in {', '.join(sources)}",
                        "workbench-linker", ids))
        elif etype == "email" and len(sources) >= 2:
            out.append(("INFERRED",
                        f"{value} appears as a contact point across {', '.join(sources)}",
                        "workbench-linker", ids))
        elif etype == "domain" and value != target and NONPROD_PREFIX.match(value):
            out.append(("GUESSED",
                        f"{value} matches a non-production naming pattern — may be staging/dev/test",
                        "workbench-heuristic", ids))
    return out


def recent_cert_count(detail: dict, days: int = 30) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    n = 0
    for nb in (detail.get("not_before_list", []) or []):
        try:
            dt = datetime.fromisoformat(nb.replace("Z", "+00:00"))
            if dt >= cutoff:
                n += 1
        except Exception:
            continue
    return n


# -- Layer B: temporal sentinel ---------------------------------------------
# Sources whose per-run coverage is tracked. A source is "covered" in a run
# when it produced at least one VERIFIED claim; a DEGRADED claim (or no claim
# at all) means uncovered. Diffing never alerts on data from a source that
# was uncovered in the baseline — its (re)appearance is recorded as an
# informational recovery note instead. This keeps a source outage from
# turning into a burst of false "new exposure" alerts when it recovers.
SNAPSHOT_SOURCES = ("crt.sh", "doh-cloudflare", "urlscan.io", "github",
                    "rdap", "urlhaus", "threatfox", "greynoise",
                    "abuseipdb", "virustotal", "otx")

# Which snapshot fields (and therefore which alert kinds) each source feeds.
_SOURCE_FIELDS = {
    "crt.sh": ("subdomains", "issuers"),
    "doh-cloudflare": ("a_records",),
    "urlscan.io": ("urlscan_malicious",),
    "urlhaus": ("ti.urlhaus_listed",),
    "threatfox": ("ti.threatfox_listed",),
    "greynoise": ("ti.greynoise",),
    "abuseipdb": ("ti.abuseipdb",),
    "virustotal": ("ti.vt_malicious",),
}


def build_snapshot(claims) -> dict:
    """Stable exposure surface of one run, for diffing against the next.
    Only VERIFIED observations go in — derived claims are recomputed.
    Coverage records which sources actually contributed, so the diff can
    tell "new exposure" apart from "source came back online"."""
    snap: dict = {"subdomains": [], "a_records": [], "issuers": [],
                  "urlscan_malicious": 0, "ti": {}, "coverage": {}}
    covered: set[str] = set()
    for c in claims:
        if c["tier"] == "VERIFIED":
            covered.add(c["source"])
        if c["tier"] != "VERIFIED":
            continue
        d = _parse_detail(c["detail"])
        if c["source"] == "crt.sh" and "subdomains" in d:
            snap["subdomains"] = sorted(set(d.get("subdomains", []) or []))
            snap["issuers"] = sorted(set(d.get("issuers", []) or []))
        elif c["source"] == "doh-cloudflare":
            snap["a_records"] = sorted(set(d.get("A", []) or []))
        elif c["source"] == "urlscan.io":
            snap["urlscan_malicious"] = int(d.get("malicious_count", 0) or 0)
        elif c["source"] == "urlhaus":
            snap["ti"]["urlhaus_listed"] = bool(d.get("listed"))
        elif c["source"] == "threatfox":
            snap["ti"]["threatfox_listed"] = bool(d.get("listed"))
        elif c["source"] == "greynoise" and d.get("ip"):
            snap["ti"][f"greynoise:{d['ip']}"] = d.get("classification", "unknown")
        elif c["source"] == "abuseipdb" and d.get("ip"):
            snap["ti"][f"abuseipdb:{d['ip']}"] = int(d.get("abuse_confidence", 0) or 0)
        elif c["source"] == "virustotal":
            snap["ti"]["vt_malicious"] = int(d.get("malicious", 0) or 0)
    for src in SNAPSHOT_SOURCES:
        # Covered only on positive evidence; DEGRADED or absent = uncovered.
        snap["coverage"][src] = src in covered
    return snap


def _recovered_sources(prev: dict, cur: dict) -> set[str]:
    """Sources covered now that were not covered in the baseline."""
    pcov, ccov = prev.get("coverage", {}), cur.get("coverage", {})
    return {s for s in SNAPSHOT_SOURCES
            if ccov.get(s) and not pcov.get(s)}


def diff_snapshots(prev: dict, cur: dict) -> list[tuple[str, str, bool]]:
    """Returns [(kind, description, is_alert)] — NEW exposures only.
    Removals are informational context, never alerts — the sentinel
    watches for new exposure, not churn. Data newly visible because a
    source *recovered* is recorded as an informational note (is_alert
    False), not an alert: the baseline never saw that source, so the
    "new" items are coverage restoration, not new exposure."""
    alerts: list[tuple[str, str, bool]] = []
    recovered = _recovered_sources(prev, cur)

    def consider(source: str, kind: str, desc: str):
        if source in recovered:
            return  # handled by the recovery note below
        alerts.append((kind, desc, True))

    for s in sorted(set(cur.get("subdomains", [])) - set(prev.get("subdomains", []))):
        consider("crt.sh", "new-subdomain", f"new subdomain in CT: {s}")
    for ip in sorted(set(cur.get("a_records", [])) - set(prev.get("a_records", []))):
        consider("doh-cloudflare", "new-a-record", f"new A record: {ip}")
    if cur.get("urlscan_malicious", 0) > prev.get("urlscan_malicious", 0):
        consider("urlscan.io", "new-malicious-verdict",
                 f"urlscan malicious count rose {prev.get('urlscan_malicious', 0)} → "
                 f"{cur.get('urlscan_malicious', 0)}")
    pti, cti = prev.get("ti", {}), cur.get("ti", {})
    if cti.get("urlhaus_listed") and not pti.get("urlhaus_listed"):
        consider("urlhaus", "new-ti-listing", "URLhaus newly lists the target")
    if cti.get("threatfox_listed") and not pti.get("threatfox_listed"):
        consider("threatfox", "new-ti-listing", "ThreatFox newly holds IoCs for the target")
    if (cti.get("vt_malicious", 0) or 0) > (pti.get("vt_malicious", 0) or 0):
        consider("virustotal", "new-ti-listing",
                 f"VirusTotal malicious engines rose {pti.get('vt_malicious', 0)} → "
                 f"{cti.get('vt_malicious', 0)}")
    for k, v in sorted(cti.items()):
        if k.startswith("greynoise:") and pti.get(k, "unknown") != v and v == "malicious":
            consider("greynoise", "new-ti-listing",
                     f"GreyNoise now classifies {k.split(':', 1)[1]} as malicious")
        if k.startswith("abuseipdb:") and int(v or 0) >= 75 > int(pti.get(k, 0) or 0):
            consider("abuseipdb", "new-ti-listing",
                     f"AbuseIPDB confidence for {k.split(':', 1)[1]} crossed 75% ({v}%)")

    for src in sorted(recovered):
        fields = ", ".join(_SOURCE_FIELDS.get(src, ()))
        alerts.append(("source-recovered",
                       f"{src} recovered — {fields or 'its data'} now visible; "
                       f"recorded as baseline, not alerted", False))
    return alerts


def alert_budget(store, target: str) -> tuple[int, int, int]:
    """(alerts_total, rejected, approved) for new-exposure alert claims on target.
    Rejected alerts are the false-positive numerator — the budget the
    sentinel is held to."""
    import json as _json
    total = rejected = approved = 0
    rows = store.cx.execute(
        """SELECT c.analyst_status, c.detail FROM claims c
           JOIN runs r ON r.id = c.run_id
           WHERE r.target = ? AND c.source = 'workbench-diff'""", (target,)).fetchall()
    for r in rows:
        try:
            if not _json.loads(r["detail"] or "{}").get("alert"):
                continue
        except Exception:
            continue
        total += 1
        if r["analyst_status"] == "rejected":
            rejected += 1
        elif r["analyst_status"] == "approved":
            approved += 1
    return total, rejected, approved
