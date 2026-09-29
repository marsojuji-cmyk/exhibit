# ToS / License Design-Gate Memo — OSINT Platform v1

**Date:** 2026-09-29 · **Reviewer:** Ektar (design gate, not legal advice)
**Question:** may the platform collect from each source, store derived claims
locally, and show receipts to the analyst? And may it later re-serve that
data to third parties?

**Method:** primary ToS reads where fetchable (urlscan.io, ThreatFox,
GitHub ToS §H). Statute for CISA (17 U.S.C. §105). Public-by-design
reasoning for crt.sh / DoH / RDAP, labeled as such. OTX terms page is
JS-rendered — not directly verified.

## Verdicts

| Source | Verdict | Redistribution |
|---|---|---|
| crt.sh | **GO** | Public CT logs by design (RFC 6962); no restrictive terms published. Facts, not expression. |
| urlscan.io | **CONDITIONAL GO** | ToS (2020-07-22, VERIFIED read): personal non-commercial license; prohibits systematic DB compilation without written permission, republication, resale, and competing commercial use. **Re-serving urlscan data = NO-GO without written permission.** Local defensive analysis of own assets via documented API = acceptable use. |
| github-api | **GO** | ToS §H (eff. 2026-04-27, VERIFIED read): respect rate limits; bans API use for spam / personal-info resale. Our use (repo search, defensive, low volume) is clear. Resale of GitHub's service would need subscription. |
| doh-cloudflare | **GO** | Public resolver used for its intended purpose; DNS answers are facts. |
| rdap | **GO** | Registration data is public by ICANN mandate; rdap.org is a bootstrap. |
| cisa-kev | **GO** (strongest) | U.S. federal government work — public domain by statute. No restrictions. |
| threatfox | **CONDITIONAL GO** | FAQ (VERIFIED read): free under fair-use principles; commercial/for-profit use may require the paid enhanced API. **Commercial re-serving = NO-GO on the free tier.** Non-commercial defensive use is the stated purpose. IOCs expire from API after 6 months — do not treat absence as evidence. |
| otx | **PENDING** | Terms page not directly verifiable (JS-rendered). Connector stays OFF until a key exists AND terms are verified. No collection, no verdict. |

## Kill-criterion check (§8.1: "ToS blocks re-serving")

**Does not fire for the pilot.** The pilot collects, stores locally, and
shows receipts to the analyst — no source's ToS blocks that for own-asset
defensive use at this volume. It **does** constrain the γ path: the
claim-receipt *schema* may be published freely (it carries no third-party
data), but a public demo or product that re-serves urlscan.io verdicts or
ThreatFox IOCs needs written permission / the paid tier first. That
constraint is recorded in the `terms` table per receipt — later ToS changes
can't silently re-license stored data.

## Standing constraints for the build

1. urlscan.io: never re-serve verdicts publicly; keep query volume to documented API use; commercial use needs written permission.
2. ThreatFox: non-commercial only on the free tier; commercial path = paid enhanced API.
3. GitHub API: respect rate limits; no personal-info harvesting (not our use).
4. Every receipt carries its terms snapshot (url + fetch date + text hash) — the ledger is self-defending.
5. OTX stays OFF until key + verified terms.
