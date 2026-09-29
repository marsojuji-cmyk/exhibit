# Claim-Receipt Spec v1.0

**Status:** FROZEN 2026-09-29 · **Proposed license:** CC0 1.0 (publication is the owner's call)
**Purpose:** the unit of verifiable data. Every fact the platform holds is a *claim*;
every claim carries an *evidence receipt*. Nothing ships without both.

## 1. The claim object

| Field | Type | Required | Meaning |
|---|---|---|---|
| `claim_id` | string | yes | `cr_` + first 16 hex of SHA-256 over canonical JSON of `{claim, tier, source, provider_ids, params}`. Stable across runs for the same observation — this is the join key. |
| `claim` | string | yes | One human-readable factual statement. |
| `tier` | enum | yes | `VERIFIED` · `INFERRED` · `GUESSED` · `DEGRADED` |
| `confidence` | number 0–1 or null | no | Measured where possible (e.g. ER match probability); null where not. Never vibes. |
| `authority` | string | yes | Who/what asserts: source name, `platform-linker`, or `analyst:<name>`. |
| `observed_at` | RFC3339 UTC | yes | When the observation was made. |
| `review_date` | RFC3339 date | yes | When this claim must be re-checked. Expired = untrusted until re-observed. |
| `falsifier` | string | yes | The observation that would retire this claim. A claim without a falsifier is not finished. |
| `based_on` | claim_id[] | no | Required for INFERRED/GUESSED: the claims this was derived from. |
| `analyst_status` | enum | yes | `unreviewed` · `approved` · `rejected`. The machine proposes; the human disposes. |
| `evidence` | receipt | yes | The 8-field evidence receipt (§2). Exactly one per claim. |

**Tier definitions.** VERIFIED = directly observed from a named public source this run.
INFERRED = derived by linking ≥2 VERIFIED claims (lists `based_on`). GUESSED = heuristic
pattern match, labeled as such. DEGRADED = the source was unreachable; the *gap* is the claim.

## 2. The 8-field evidence receipt

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | `source` | string | Canonical source name, e.g. `cisa-kev`. |
| 2 | `params` | object | The exact query parameters sent. |
| 3 | `timestamp` | RFC3339 UTC | When the fetch completed. |
| 4 | `http_status` | int or null | HTTP status; null for non-HTTP transports. |
| 5 | `raw_sha256` | hex | SHA-256 of the raw response bytes. (`raw_bytes`: length; `raw_ref`: storage pointer or `omitted`.) |
| 6 | `provider_ids` | string[] | Provider-native record IDs (cert IDs, scan UUIDs, CVE IDs…). |
| 7 | `terms_snapshot` | object | `{terms_url, fetched_at, text_hash}` — the ToS as it stood when collected, so later changes can't silently re-license stored data. |
| 8 | `attribution` | string | How the source must be credited, incl. license note. |

**Chain.** Each receipt carries `prev_hash` (SHA-256 of the previous receipt, `GENESIS` for the
first) and its own `receipt_hash` = SHA-256 over canonical JSON of fields 1–8 + `prev_hash`.
Append-only: history is superseded, never edited.

## 3. Canonical JSON

UTF-8, keys sorted lexicographically, no whitespace, numbers unpadded, floats shortest
round-trip. `claim_id` / `receipt_hash` / `text_hash` are computed over this form —
anyone can recompute them. Reference implementation: `v1/platform/schema.py`.

## 4. Worked example (abridged)

```json
{
  "claim_id": "cr_9f2c…a41d",
  "claim": "CISA KEV catalog lists 1,412 entries as of 2026-09-29",
  "tier": "VERIFIED",
  "authority": "cisa-kev",
  "observed_at": "2026-09-29T12:40:00Z",
  "review_date": "2026-10-29",
  "falsifier": "a newer catalog fetch showing a different count",
  "analyst_status": "unreviewed",
  "evidence": {
    "source": "cisa-kev",
    "params": {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    "timestamp": "2026-09-29T12:40:00Z",
    "http_status": 200,
    "raw_sha256": "e3b0…",
    "provider_ids": ["catalog"],
    "terms_snapshot": {"terms_url": "https://www.cisa.gov/privacy-policy", "fetched_at": "2026-09-29", "text_hash": "a1…"},
    "attribution": "CISA Known Exploited Vulnerabilities catalog — U.S. Government work, public domain",
    "prev_hash": "GENESIS",
    "receipt_hash": "7c…"
  }
}
```

## 5. Conformance

A producer conforms iff: every emitted claim validates against §1, every claim carries a
complete §2 receipt, `claim_id`/`receipt_hash` recompute correctly, tiers are never
upgraded without a new observation, and no LLM output is labeled VERIFIED. One fabricated
citation presented as verified fails conformance permanently for that producer version.

---
*Derived from the Ektar World-View primitive: claim + provenance + authority + review date +
falsifier. This spec is the γ asset — the highest-value move is a second independent
implementer, not a longer connector list.*
