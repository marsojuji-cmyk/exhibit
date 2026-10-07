# Exhibit — open-source intelligence, presented as evidence

**One line:** Defensive posture intelligence for infrastructure owners: know everything publicly visible about your own systems, with receipts.

**Status:** Live on GitHub (MIT). 13 assessment runs against marcusrichards.dev; 41-test stdlib suite; labeled eval harness for the CT radar; weekly pipeline via `weekly-run.sh`.

## The problem it answers

OSINT tools dump data. Analysts drown in tabs — crt.sh here, urlscan there, a DNS lookup somewhere else — and the step from "data" to "a claim I can defend" is manual, unrecorded, and un-auditable. When an AI summarizes the pile, you get fluent text with no provenance at all. In our own grounding experiment, ungrounded LLM output fabricated at 90%; grounded output at 0%. The difference wasn't the model — it was the receipts.

## The idea

Make the **evidence receipt** the primary data primitive. Every claim carries its source, exact parameters, timestamp, response status, a hash of the raw bytes, provider identifiers, a snapshot of the source's terms at fetch time, and attribution. Claims are tiered — VERIFIED / INFERRED / GUESSED / DEGRADED — each with a review date and a falsifier. A `CONFLICT:` rule handles source disagreement as an INFERRED claim: direct observation of abuse outranks a benign scanner classification — the disagreement itself is the finding, and it sits in the review queue until the analyst decides. AI proposes, summarizes, and adjudicates ambiguous matches; it never independently verifies. The machine proposes, the human disposes.

## What was built — three layers

1. **Fusion core (workbench):** 11 public sources (crt.sh, urlscan.io, GitHub code search, DNS-over-HTTPS, RDAP, GreyNoise, URLhaus, ThreatFox, OTX, AbuseIPDB, VirusTotal). Entity extraction, cross-source linking, transparent additive scoring where every point cites its claim IDs, deterministic assessment drafting, analyst review queue. Scope-gated: out-of-scope targets are refused, not warned. LLM polish is fenced behind a strict rephrase-only contract and default-off — the fence is the feature.
2. **CT radar:** certificate-transparency brand monitoring. Classifies lookalike domains (homoglyph → edit distance → brand-substring → brand-in-subdomain), scores phishing likelihood with a fully documented additive feature model. Measured against a labeled set: precision 1.000 / recall 1.000 on 20 fixtures — reported honestly as self-consistency, with external labeled data named as the prerequisite before any weight is tuned.
3. **Temporal sentinel:** snapshot diffing with per-source coverage tracking. Re-alerts suppressed by construction; removals are context, never alerts. A source recovering from DEGRADED emits `SOURCE RECOVERED`, not a false new-exposure burst.

Plus: a frozen one-page claim-receipt spec (the horizontal asset), a per-source ToS gate memo, and hash-chained SQLite ledgers under every run.

## Live evidence

13 runs against marcusrichards.dev. Risk 0; no adverse signals across reachable sources. The signature behavior: degraded sources produce DEGRADED claims, never silent gaps — the system will not say "all clear" while DEGRADED claims are open. Asked about certificate-transparency exposure while crt.sh was flapping, it answered `[DEGRADED] crt.sh unreachable — no CT coverage this run` and refused to overclaim. The refusal is the product.

## Honest limits

Free public data erodes — every connector is replaceable by design, and terms are snapshotted per receipt so a source's rule change can't silently rewrite history. The CT substring query can't catch edit-distance-only typosquats that omit the brand string; homoglyph coverage is a fixed table, not UTS #39. Re-serving urlscan verdicts commercially needs written permission. No moat in the data; the moat, if any, is the evidence discipline.

## Links

- Repo: https://github.com/marsojuji-cmyk/exhibit
- Spec: `spec/claim-receipt-spec.md` · ToS gate: `spec/tos-gate-memo.md`
