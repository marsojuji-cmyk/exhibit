# Exhibit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

*open-source intelligence, presented as evidence.*

Defensive OSINT aggregation with provenance. Public sources only, every
finding a claim with a source, a timestamp, and a confidence tier.

## The one idea

Most OSINT tools show you *data*. Exhibit shows you *claims* — each with
its receipt. The analyst approves or rejects every claim; the machine
proposes, the human disposes.

**What the tiers mean, operationally:** VERIFIED is directly observed from
a named public source — act on it, and cite the claim ID. INFERRED is
derived by linking two or more VERIFIED claims — treat it as a lead and
corroborate before acting. GUESSED is a heuristic pattern match — a
hypothesis, never grounds for action on its own. DEGRADED means a source
was unreachable and the gap is recorded instead of silently missing —
never conclude "all clear" while DEGRADED claims are open. CONFLICT is not
a separate tier: it is an INFERRED claim (text prefixed `CONFLICT:`) fired
when two sources disagree about the same entity — the disagreement itself
is the finding; see the resolution rule below.

## Conflict resolution (resolution rule v1)

When GreyNoise calls an IP a benign scanner and AbuseIPDB (≥75%
confidence) flags the same IP, Exhibit emits a `CONFLICT:` claim citing
both claim IDs. The rule, documented in `workbench/conflicts.py`: direct
observation of abuse outranks scanner classification — a host can scan
benignly *and* serve malware, so the conflict resolves to "treat as
malicious pending analyst review", never to a silent majority vote. The
claim stays in the review queue until the analyst decides. Only IP-level
conflicts exist: GreyNoise and AbuseIPDB both verdict the same IP, while
URLhaus/ThreatFox/VirusTotal/urlscan verdict the domain or its URLs, for
which no benign-side source exists — those are scored as adverse evidence
instead.

## Sources (all free, all public)

Keyless, no account:
- **crt.sh** — certificate transparency: subdomains, issuance history
- **urlscan.io** — public scan verdicts for the domain
- **GitHub public API** — repositories referencing the target
- **DNS-over-HTTPS (Cloudflare)** — current DNS answers
- **RDAP** — registration status
- **GreyNoise community** — scanner classification per IP (keyless, throttled; responses cached 7 days; a 404 "not observed" is a finding, not a gap)

Key-ready — free keys, set as env vars; when unset a DEGRADED claim is
recorded, never a silent skip. No accounts were created by this project:
- **URLhaus** (`ABUSECH_AUTH_KEY`) — malware URLs per host; free Auth-Key at auth.abuse.ch
- **ThreatFox** (`ABUSECH_AUTH_KEY`) — IoC records; same free Auth-Key portal
- **AlienVault OTX** (`OTX_API_KEY`) — indicator context; free key after signup at otx.alienvault.com
- **AbuseIPDB** (`ABUSEIPDB_API_KEY`) — IP abuse confidence; free key with a free account at abuseipdb.com (1,000 checks/day)
- **VirusTotal** (`VT_API_KEY`) — multi-engine verdicts; free key in your virustotal.com profile (500 lookups/day)

Note (2026-09-29, verified against live docs): abuse.ch moved its APIs
behind a free Auth-Key. Older writeups saying "no key" are stale.

## Native intelligence (no black boxes)

1. **Entity extraction** — IPs, domains, emails, hashes pulled from raw results
2. **Cross-source linking** — the same IP in DNS answers and urlscan scans
   becomes one INFERRED claim citing both
3. **Transparent scoring** — additive risk score where every point cites
   the claim IDs behind it; the breakdown ships with the report
4. **Assessment drafting** — deterministic report with bottom line,
   findings, score breakdown, uncertainty/gaps, and a review queue
5. **Optional LLM polish** — set `WORKBENCH_LLM_URL` to a local endpoint and
   the draft gets copy-edited under a strict contract: rephrase only, never
   add facts, never drop citations. Default: off. The fence is the feature.

## Scope gate

Collection runs only against targets in `scope.yaml`. Anything else needs
`--attest "<reason>"`, written into the ledger. Out-of-scope collection
without attestation is refused, not warned. The `watchlist:` section of
`scope.yaml` authorizes the CT radar runs (each logs an attestation).

## Usage

```bash
cd ~/workspace/security/analyst-workbench
python3 -m workbench.cli init
python3 -m workbench.cli collect --target marcusrichards.dev
python3 -m workbench.cli analyze --run 1   # links, inferred claims, conflicts
python3 -m workbench.cli diff --run 1      # snapshot + new-exposure alerts
python3 -m workbench.cli assess --run 1
python3 -m workbench.cli ctwatch           # CT radar over the watchlist
python3 -m workbench.cli review --run 1        # see the queue
python3 -m workbench.cli review --approve 3    # analyst verdicts
python3 -m workbench.cli report --run 1        # full assessment
```

Or the whole pipeline for any in-scope target: `./weekly-run.sh [target]`
(ctwatch → collect → analyze → diff → assess).

Stdlib only — no installs. SQLite ledger at `workbench.db`.
Assessments render to `assessment-run-<n>.md`.

## CT radar (Layer C): how it works and how it's evaluated

For each `watchlist:` brand, Exhibit queries crt.sh once for certificates
whose names contain the brand label, classifies each name (homoglyph →
edit distance ≤2 → brand-substring → brand-in-subdomain), enriches hits
via RDAP + urlscan, and scores phishing likelihood with a transparent
additive feature model — every feature and weight is documented in
`workbench/ctwatch.py` (`FEATURES`). The observation is a VERIFIED claim;
the judgment is a GUESSED claim citing it. Known limits: the substring
query cannot catch edit-distance-only typosquats that omit the brand
string (a full CT stream would be needed); homoglyph coverage is a fixed
table, not UTS #39; the `brand-in-subdomain` kind was added 2026-09-29
after the labeled eval found the blind spot.

**Eval methodology:** precision/recall are measured against a labeled set
of known-phishing lookalikes (sourced from PhishTank/URLhaus verified
entries) plus known-benign lookalikes (CDN/reseller subdomains, defensive
registrations). The scorer runs over the set at the published weights; we
report precision/recall at the ≥50 alert threshold and a confusion matrix.
**Current status (2026-09-29):** a curated 20-fixture labeled set exists
(`eval/ct_labeled_set.json`, `eval/run_ct_eval.py`) — precision 1.000 /
recall 1.000 on it at the published weights. That measures
self-consistency, not real-world performance. A first external labeled set
now exists (`eval/ct_labeled_set_external.json`,
`eval/run_ct_eval_external.py`, report
`eval/ct-radar-external-eval-2026-09-29.md`): 269 PhishTank-verified
phishing domains plus 63 benign controls. In-scope result at ≥50: 0 TP /
14 FN / 0 FP — the canonical brand-lookalike + freshly-registered shape
scores 45 and stays silent. Only 14/269 (5.2%) of real phish wear a
recognized lookalike shape at all (coverage finding, not a weight
failure). An evidence-backed proposal (`rdap_created_30d` 20→25) is staged
in the report; **weights are unchanged pending approval.** Note:
`cert_last_7d`, `free_acme_issuer`, and `urlscan_malicious` were not
exercised by the external set.

## Temporal sentinel (Layer B): snapshots, diffs, alert budget

After each run, `diff` stores a baseline snapshot (subdomains, A records,
issuers, urlscan verdicts, threat-intel verdicts) in the ledger. The next
run diffs against it and emits INFERRED `NEW EXPOSURE` alert claims only
for *new* items — re-alerts are suppressed by construction; removals are
context, never alerts. Snapshots also record per-source *coverage*: a source
that was DEGRADED or absent in the baseline can't produce alerts when it
recovers — its returning data is logged as an informational `SOURCE
RECOVERED` note instead, so an outage never becomes a burst of false "new
exposure" alerts. The assessment surfaces the false-positive budget:
new-exposure alerts all-time vs. analyst rejections (FP rate), approvals,
and unreviewed counts. The budget is the sentinel's honesty metric —
an alert stream the analyst stops trusting is a failed instrument.

## What this is not

No stealth collection, no credentialed access, no non-public data, no
targeting of private individuals. It is an analyst's workbench for
defending your own assets and doing lawful research — the scope gate
enforces that by design.

---

## Verify it yourself

```bash
python3 -m unittest discover tests -v
```

The same command this repository's CI runs on every push. If it does not pass on a clean clone,
the CI badge is wrong and so is this README — please open an issue.

Every claim in this README is meant to be checkable by someone who does not trust it yet.
