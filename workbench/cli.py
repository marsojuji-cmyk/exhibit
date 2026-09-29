#!/usr/bin/env python3
"""Exhibit CLI (module: workbench.cli).

    python3 -m workbench.cli init
    python3 -m workbench.cli collect --target marcusrichards.dev
    python3 -m workbench.cli analyze --run 1
    python3 -m workbench.cli assess --run 1
    python3 -m workbench.cli review --run 1
    python3 -m workbench.cli review --approve 3
    python3 -m workbench.cli report --run 1
    python3 -m workbench.cli ctwatch
    python3 -m workbench.cli diff --run 1

Scope gate: collection runs only against targets listed in scope.yaml,
or with --attest "reason", which is written into the ledger.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import connectors
from . import threatintel
from .analyze import (alert_budget, build_links, build_snapshot,
                      diff_snapshots, draft_inferred_claims, recent_cert_count,
                      score_run)
from .assess import build_assessment, llm_polish
from .conflicts import detect_conflicts
from .ctwatch import run_radar
from .store import Store, now

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, "workbench.db")
SCOPE_PATH = os.path.join(BASE, "scope.yaml")


def _parse_scope() -> dict:
    """Minimal YAML parse — no dependency. Understands two sections:
    targets:    - name: example.com / purpose: why
    watchlist:  - name: brand.tld   / purpose: why (CT radar authorization)
    """
    out = {"targets": {}, "watchlist": {}}
    if not os.path.exists(SCOPE_PATH):
        return out
    section = None
    cur_name = None
    for line in open(SCOPE_PATH):
        s = line.strip()
        if s == "targets:":
            section = "targets"
        elif s == "watchlist:":
            section = "watchlist"
        elif s.startswith("- name:") and section:
            cur_name = s.split(":", 1)[1].strip().strip("'\"")
        elif s.startswith("purpose:") and section and cur_name:
            out[section][cur_name] = s.split(":", 1)[1].strip().strip("'\"")
            cur_name = None
    return out


def load_scope() -> dict:
    """Authorized collection targets (kept for compatibility)."""
    return _parse_scope()["targets"]


def load_watchlist() -> dict:
    """Watchlist brands authorizing the CT radar (scope.yaml: watchlist:)."""
    return _parse_scope()["watchlist"]


def check_scope(target: str, attest: str | None, store: Store, run_id: int):
    scope = load_scope()
    if target in scope:
        print(f"scope: {target} is authorized ({scope[target]})")
        return
    if attest:
        store.add_attestation(run_id, attest)
        print(f"scope: {target} NOT in scope.yaml — attestation logged to the ledger.")
        return
    print(f"REFUSED: '{target}' is not in scope.yaml.", file=sys.stderr)
    print("Add it with a stated purpose, or re-run with --attest \"<reason>\".", file=sys.stderr)
    print("The attestation is written into the ledger — the authorization is on record.", file=sys.stderr)
    sys.exit(2)


# -- collection ------------------------------------------------------------
def _summarize_crtsh(data) -> dict:
    subs, issuers, not_before = set(), set(), []
    items = data if isinstance(data, list) else []
    for e in items:
        nv = str(e.get("name_value", "") or "")
        for s in nv.split("\n"):
            s = s.strip().lower()
            if s and not s.startswith("*"):
                subs.add(s)
        issuers.add(str(e.get("issuer_name", ""))[:80])
        if e.get("not_before"):
            not_before.append(e["not_before"])
    return {"cert_count": len(items), "subdomains": sorted(subs)[:200],
            "issuers": sorted(i for i in issuers if i)[:10],
            "not_before_list": not_before}


def _summarize_urlscan(data) -> dict:
    results = (data or {}).get("results", []) if isinstance(data, dict) else []
    scans, malicious = [], 0
    for r in results[:20]:
        page = r.get("page", {}) or {}
        verdicts = r.get("verdicts", {}) or {}
        overall_mal = bool((verdicts.get("overall") or {}).get("malicious"))
        any_mal = any((v or {}).get("malicious")
                      for v in verdicts.values() if isinstance(v, dict))
        is_mal = overall_mal or any_mal
        malicious += 1 if is_mal else 0
        scans.append({"url": page.get("url", "")[:160], "date": r.get("task", {}).get("time", ""),
                      "malicious": is_mal})
    return {"scan_count": len(results), "malicious_count": malicious, "scans": scans}


def _summarize_github(data) -> dict:
    items = (data or {}).get("items", []) if isinstance(data, dict) else []
    return {"repo_count": (data or {}).get("total_count", 0),
            "repos": [{"name": i.get("full_name", ""), "url": i.get("html_url", "")} for i in items[:10]]}


def _summarize_doh(name: str) -> dict:
    out: dict[str, list] = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
        fr = connectors.fetch_doh(name, rtype)
        vals = []
        if fr.ok:
            for a in (fr.parsed() or {}).get("Answer", []) or []:
                vals.append(str(a.get("data", ""))[:160])
        out[rtype] = sorted(set(vals))
    return out


def _summarize_rdap(data) -> dict:
    d = data or {}
    return {"statuses": d.get("status", []),
            "registrar": (d.get("registrar", {}) or [{}])[0].get("name", "") if isinstance(d.get("registrar"), list) else ""}


def cmd_collect(args):
    store = Store(DB_PATH)
    run_id = store.new_run(args.target)
    check_scope(args.target, args.attest, store, run_id)
    t = args.target
    collected, degraded = 0, 0

    def put(tier, claim, source, url, observed, detail=""):
        nonlocal collected, degraded
        store.add_claim(run_id, tier, claim, source, url, observed, detail)
        collected += 1
        if tier == "DEGRADED":
            degraded += 1

    fr = connectors.fetch_crtsh(t)
    if fr.ok:
        d = _summarize_crtsh(fr.parsed())
        d["recent_30d"] = recent_cert_count(d)
        put("VERIFIED", f"Certificate Transparency: {d['cert_count']} cert(s) observed for *.{t}",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", f"crt.sh unreachable — no CT coverage this run", fr.source, fr.source_url, now(), {"error": fr.error})

    fr = connectors.fetch_urlscan(t)
    if fr.ok:
        d = _summarize_urlscan(fr.parsed())
        put("VERIFIED", f"urlscan.io: {d['scan_count']} public scan(s) reference {t} ({d['malicious_count']} malicious)",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", "urlscan.io unreachable — no scan verdicts this run", fr.source, fr.source_url, now(), {"error": fr.error})

    fr = connectors.fetch_github_repos(t)
    if fr.ok:
        d = _summarize_github(fr.parsed())
        put("VERIFIED", f"GitHub: {d['repo_count']} public repositor(ies) match '{t}'",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", "GitHub API unreachable — no repo references this run", fr.source, fr.source_url, now(), {"error": fr.error})

    d = _summarize_doh(t)
    a_recs = d.get("A", [])
    put("VERIFIED", f"DNS (DoH): {t} A → {', '.join(a_recs) if a_recs else 'none'}",
        "doh-cloudflare", f"https://cloudflare-dns.com/dns-query?name={t}", now(), d)

    fr = connectors.fetch_rdap(t)
    if fr.ok:
        d = _summarize_rdap(fr.parsed())
        put("VERIFIED", f"RDAP: {t} statuses [{', '.join(d['statuses']) or 'none listed'}]",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", "RDAP unreachable — no registration status this run", fr.source, fr.source_url, now(), {"error": fr.error})

    # -- Layer A: threat-intel connectors ----------------------------------
    fr = threatintel.fetch_urlhaus_host(t)
    if fr.ok:
        d = threatintel.summarize_urlhaus(fr.parsed())
        put("VERIFIED", f"URLhaus: {'LISTS' if d['listed'] else 'does not list'} {t} "
                        f"({d['count']} malicious URL(s))",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", f"URLhaus: {fr.error}", fr.source, fr.source_url, now(), {"error": fr.error})

    fr = threatintel.fetch_threatfox_ioc(t)
    if fr.ok:
        d = threatintel.summarize_threatfox(fr.parsed())
        put("VERIFIED", f"ThreatFox: {'holds' if d['listed'] else 'no'} IoC record(s) for {t} "
                        f"({d['count']} record(s))",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", f"ThreatFox: {fr.error}", fr.source, fr.source_url, now(), {"error": fr.error})

    for ip in a_recs:
        fr = threatintel.fetch_greynoise(ip)
        if fr.ok:
            d = threatintel.summarize_greynoise(fr.parsed())
            cached = " (cached)" if getattr(fr, "cached", False) else ""
            if d.get("observed"):
                ctext = (f"GreyNoise: {ip} classification={d['classification']} "
                         f"(noise={d['noise']}, riot={d['riot']}){cached}")
            else:
                ctext = (f"GreyNoise: {ip} not observed scanning the internet "
                         f"(no verdict — unknown, not benign){cached}")
            put("VERIFIED", ctext,
                fr.source, fr.source_url, fr.fetched_at,
                {**d, "cached": bool(getattr(fr, "cached", False))})
        else:
            put("DEGRADED", f"GreyNoise unreachable for {ip} — no scanner context this run",
                fr.source, fr.source_url, now(), {"error": fr.error})

        fr = threatintel.fetch_abuseipdb(ip)
        if fr.ok:
            d = threatintel.summarize_abuseipdb(fr.parsed())
            put("VERIFIED", f"AbuseIPDB: {ip} abuse confidence {d['abuse_confidence']}% "
                            f"({d['total_reports']} reports)",
                fr.source, fr.source_url, fr.fetched_at, d)
        else:
            put("DEGRADED", f"AbuseIPDB: {fr.error}", fr.source, fr.source_url, now(), {"error": fr.error})

    fr = threatintel.fetch_virustotal_domain(t)
    if fr.ok:
        d = threatintel.summarize_virustotal(fr.parsed())
        put("VERIFIED", f"VirusTotal: {d['malicious']} engines flag {t} as malicious "
                        f"({d['suspicious']} suspicious, {d['harmless']} harmless)",
            fr.source, fr.source_url, fr.fetched_at, d)
    else:
        put("DEGRADED", f"VirusTotal: {fr.error}", fr.source, fr.source_url, now(), {"error": fr.error})

    fr = threatintel.fetch_otx_domain(t)
    if fr.ok:
        put("VERIFIED", f"OTX: indicator record retrieved for {t}",
            fr.source, fr.source_url, fr.fetched_at, {"keys": list((fr.parsed() or {}).keys())[:12]})
    else:
        put("DEGRADED", f"OTX: {fr.error}", fr.source, fr.source_url, now(), {"error": fr.error})

    store.finish_run(run_id)
    print(f"run #{run_id}: {collected} claims ({degraded} degraded) for {t}")
    store.close()


# -- analysis --------------------------------------------------------------
def cmd_analyze(args):
    store = Store(DB_PATH)
    run = store.get_run(args.run)
    if not run:
        sys.exit(f"no run #{args.run}")
    claims = store.get_claims(args.run)
    by_id = {c["id"]: c for c in claims}
    links = build_links(claims, skip_values={run["target"].lower()})
    n_links = 0
    for (etype, value), ids in links.items():
        store.add_link(args.run, etype, value, ids)
        n_links += 1
    n_new = 0
    for tier, text, label, ids in draft_inferred_claims(links, by_id, run["target"]):
        store.add_claim(args.run, tier, text, label, "workbench://analysis", now(),
                        {"based_on_claims": ids})
        n_new += 1
    # Layer A: conflict detection — disagreement is the finding.
    n_conflicts = 0
    for tier, text, label, ids, detail in detect_conflicts(claims):
        store.add_claim(args.run, tier, text, label, "workbench://analysis", now(), detail)
        n_conflicts += 1
    total, items, notes = score_run(claims, run["target"])
    print(f"run #{args.run}: {n_links} cross-source links, {n_new} inferred/guessed claims, "
          f"{n_conflicts} conflict claim(s)")
    print(f"risk score: {total}")
    for pts, reason, ids in items:
        print(f"  +{pts}: {reason} [#{', #'.join(map(str, ids))}]")
    for note in notes:
        print(f"  note: {note}")
    store.close()


# -- assessment ------------------------------------------------------------
def cmd_assess(args):
    store = Store(DB_PATH)
    run = store.get_run(args.run)
    if not run:
        sys.exit(f"no run #{args.run}")
    claims = store.get_claims(args.run)
    links = store.get_links(args.run)
    total, items, notes = score_run(claims, run["target"])
    unreviewed = sum(1 for c in claims if c["analyst_status"] == "unreviewed")
    # Layer B: false-positive budget — alerts vs analyst dismissals.
    n_alerts, n_rej, n_appr = alert_budget(store, run["target"])
    if n_alerts:
        fp = 100.0 * n_rej / n_alerts
        notes.append(f"Alert budget for {run['target']}: {n_alerts} new-exposure alert(s) all-time, "
                     f"{n_rej} rejected by analyst → FP rate {fp:.0f}% "
                     f"({n_appr} approved, {n_alerts - n_rej - n_appr} unreviewed).")
    att = store.cx.execute(
        "SELECT text FROM attestations WHERE run_id=? ORDER BY id DESC LIMIT 1",
        (args.run,)).fetchone()
    md = build_assessment(run["target"], args.run, run["started_at"], claims,
                           links, total, items, notes, unreviewed,
                           att["text"] if att else None)
    md, polished = llm_polish(md)
    aid = store.add_assessment(args.run, md)
    path = os.path.join(BASE, f"assessment-run-{args.run}.md")
    open(path, "w").write(md)
    print(f"assessment #{aid} written to {path}" + (" (LLM-polished)" if polished else ""))
    print("--- preview ---")
    print("\n".join(md.splitlines()[:25]))
    store.close()


# -- Layer C: CT radar -------------------------------------------------------
def cmd_ctwatch(_args):
    """Watchlist-driven certificate-transparency radar. Authorization comes
    from scope.yaml's watchlist: section — each run logs an attestation."""
    store = Store(DB_PATH)
    wl = load_watchlist()
    if not wl:
        print("no watchlist entries in scope.yaml — nothing to watch")
        store.close()
        return
    for brand, purpose in wl.items():
        run_id = store.new_run(f"ctwatch:{brand}")
        store.add_attestation(run_id, f"watchlist-authorized CT radar: {purpose}")
        n = 0
        for tier, claim, source, url, observed, detail in run_radar(brand):
            store.add_claim(run_id, tier, claim, source, url, observed, detail)
            n += 1
        store.finish_run(run_id)
        print(f"ctwatch run #{run_id}: {n} claim(s) for watchlist brand '{brand}'")
    store.close()


# -- Layer B: temporal sentinel ------------------------------------------------
def cmd_diff(args):
    """Snapshot the run's exposure surface; diff against the previous
    snapshot for the same target. Only NEW exposures become alert claims —
    re-alerts are suppressed by construction."""
    store = Store(DB_PATH)
    run = store.get_run(args.run)
    if not run:
        sys.exit(f"no run #{args.run}")
    target = run["target"]
    claims = store.get_claims(args.run)
    snap = build_snapshot(claims)
    prev = store.latest_snapshot_before(target, args.run)
    if prev is None:
        store.save_snapshot(target, args.run, snap)
        print(f"run #{args.run}: baseline snapshot stored for {target} — "
              "future runs diff against this; no alerts on a baseline.")
        store.close()
        return
    import json as _json
    prev_snap = _json.loads(prev["snapshot"])
    results = diff_snapshots(prev_snap, snap)
    n_alerts = 0
    for kind, desc, is_alert in results:
        if is_alert:
            n_alerts += 1
            store.add_claim(args.run, "INFERRED",
                            f"NEW EXPOSURE: {desc} (first seen run #{args.run}; "
                            f"absent in run #{prev['run_id']})",
                            "workbench-diff", "workbench://diff", now(),
                            {"alert": True, "kind": kind, "prev_run": prev["run_id"]})
        else:
            # Source recovered after an outage: informational, never an alert.
            store.add_claim(args.run, "INFERRED",
                            f"SOURCE RECOVERED: {desc}",
                            "workbench-diff", "workbench://diff", now(),
                            {"alert": False, "kind": kind, "prev_run": prev["run_id"]})
    store.save_snapshot(target, args.run, snap)
    print(f"run #{args.run}: {n_alerts} new-exposure alert(s) vs run #{prev['run_id']}")
    for kind, desc, is_alert in results:
        print(f"  {'ALERT' if is_alert else 'NOTE'} [{kind}]: {desc}")
    store.close()


# -- review / report -------------------------------------------------------
def cmd_review(args):
    store = Store(DB_PATH)
    if args.approve:
        store.set_claim_status(args.approve, "approved")
        print(f"claim #{args.approve} approved")
    elif args.reject:
        store.set_claim_status(args.reject, "rejected")
        print(f"claim #{args.reject} rejected")
    else:
        rows = store.cx.execute(
            "SELECT id, tier, analyst_status, claim FROM claims WHERE run_id=? AND analyst_status='unreviewed' ORDER BY id",
            (args.run,)).fetchall()
        if not rows:
            print("review queue empty — every claim has an analyst verdict.")
        for r in rows:
            print(f"#{r['id']} [{r['tier']}] {r['claim'][:110]}")
    store.close()


def cmd_report(args):
    store = Store(DB_PATH)
    row = store.cx.execute(
        "SELECT markdown FROM assessments WHERE run_id=? ORDER BY id DESC LIMIT 1",
        (args.run,)).fetchone()
    print(row["markdown"] if row else f"no assessment for run #{args.run} — run assess first")
    store.close()


def cmd_init(_args):
    Store(DB_PATH).close()
    if not os.path.exists(SCOPE_PATH):
        open(SCOPE_PATH, "w").write(
            "# Authorized collection scope. The workbench collects only on these\n"
            "# targets. Anything else needs --attest \"<reason>\", logged to the ledger.\n"
            "targets:\n"
            "  - name: marcusrichards.dev\n"
            "    purpose: defensive monitoring of own domain\n")
        print(f"created {SCOPE_PATH}")
    print(f"ready. db at {DB_PATH}")


def main():
    ap = argparse.ArgumentParser(prog="workbench",
        description="Exhibit — open-source intelligence, presented as evidence. "
                    "Defensive OSINT on public sources only; every finding is a claim with provenance.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p = sub.add_parser("collect")
    p.add_argument("--target", required=True)
    p.add_argument("--attest", default=None, help="authorization reason for out-of-scope targets (logged)")
    p = sub.add_parser("analyze")
    p.add_argument("--run", type=int, required=True)
    p = sub.add_parser("assess")
    p.add_argument("--run", type=int, required=True)
    p = sub.add_parser("review")
    p.add_argument("--run", type=int, required=True)
    p.add_argument("--approve", type=int, default=None)
    p.add_argument("--reject", type=int, default=None)
    p = sub.add_parser("report")
    p.add_argument("--run", type=int, required=True)
    sub.add_parser("ctwatch")
    p = sub.add_parser("diff")
    p.add_argument("--run", type=int, required=True)
    args = ap.parse_args()
    {"init": cmd_init, "collect": cmd_collect, "analyze": cmd_analyze,
     "assess": cmd_assess, "review": cmd_review, "report": cmd_report,
     "ctwatch": cmd_ctwatch, "diff": cmd_diff}[args.cmd](args)


if __name__ == "__main__":
    main()
