# CT radar — external labeled evaluation (2026-09-29)

Real-world validation of the published CT radar weights against
PhishTank-verified phishing domains. Run at the production threshold ≥50
with **no weight changes**.

## Corpus

Built by `eval/build_external_set.py` from the PhishTank keyless verified-online
bulk feed (`http://data.phishtank.com/data/online-valid.csv`, fetched
2026-09-29T12:55:29Z; 77,695 rows, all verified=yes and online=yes).

- **Malicious:** 269 unique registrable domains, ~45 per brand for six brands
  (amazon.com 45, facebook.com 44, microsoft.com 45, netflix.com 45,
  paypal.com 45, apple.com 45). Brand pairing from PhishTank's own `target`
  column — independent of the classifier. Full hostnames are preserved so
  subdomain labels (the brand-subdomain signal) survive; RDAP enrichment is
  per registrable domain.
- **Benign near-miss:** 23 legitimate brand infrastructure / lookalike-shaped
  domains (amazon.com, a.co, aws.amazon.com, fb.com, microsoftonline.com,
  microsoftstore.com, paypal.me, paypalobjects.com, paypal-communication.com,
  …). Two dual-use domains (`amazonaws.com`, `amazon.co.uk`) appeared as hosts
  of PhishTank-verified phishing URLs and were kept in the malicious bucket —
  the label follows the verified evidence.
- **Benign top domains:** 40 common legitimate domains, scored against every
  tracked brand at their worst score.
- **RDAP enrichment:** 174/321 unique domains returned a creation date
  (54%; many phishing domains are already dead). `cert_last_7d`,
  `free_acme_issuer`, and `urlscan_malicious` are **untested on this set**
  (no cert collection, no urlscan key) — see Limitations.

Total: 332 entries. Provenance block embedded in
`eval/ct_labeled_set_external.json`.

## Results (threshold ≥50)

### In-scope calibration — recognized lookalike shapes only

| | predicted phish | predicted benign |
|---|---|---|
| **actual phish** | TP = 0 | FN = 14 |
| **actual benign** | FP = 0 | TN = 5 |

- n = 19 (14 malicious + 5 benign near-misses with a recognized shape).
- Precision = 0.000 (0/0 — no alerts fired at all), recall = 0.000.
- The remaining 58 benign entries (18 near-miss + 40 top domains) had no
  recognized lookalike shape, fired nothing, and stayed silent — 0 false
  positives across all 63 benign entries.

Per brand (in-scope n; TP/FP/FN):

| brand | n | TP | FP | FN |
|---|---|---|---|---|
| amazon.com | 4 | 0 | 0 | 1 |
| facebook.com | 6 | 0 | 0 | 2 |
| microsoft.com | 6 | 0 | 0 | 0 |
| netflix.com | 4 | 0 | 0 | 2 |
| paypal.com | 8 | 0 | 0 | 4 |
| apple.com | 9 | 0 | 0 | 5 |

### False negatives (all 14)

Twelve brand-substring and two brand-subdomain. Twelve scored exactly 25
(shape only); two scored 45:

- `appleidmapa.com` — 45 (`brand_substring` + `rdap_created_30d`, RDAP
  2026-09-06, 23 days old at eval)
- `netflix-renovacion-pago.com` — 45 (`brand_substring` + `rdap_created_30d`)
- `baloupd-hunr.s3.amazonaws.com`, `noreplybusinessfacebook.com`,
  `netflixapp.com`, `paypalapp-auth-de.net`, `www.paylink-paypal.com`,
  `www.paypal-banking.pro`, `payme-paypal.com`, `apple-iforgetid.click`,
  `applesoporte.services`, `applemymusic.com`,
  `facebook.market-34545647656.club`, `apple.pay-wallet-review.com` — 25 each

### Coverage — the scope finding

Only **14/269 (5.2%)** of verified phishing domains wear a lookalike shape
the CT radar recognizes. The 255 declined-by-design entries are not weight
failures; they are out of the sensor's stated scope:

- ~172 compromised/unrelated domains (no brand signal in the host at all —
  e.g. `mattcomps.com`, `ejzwz.com`, generic `.pro`/`.host` throwaways);
- ~80 shortener/generic hosts;
- 5 brand-in-path-only (brand appears in the URL path, not the host —
  e.g. `facebook.market-34545647656.club` was caught at the registrable's
  full host, but `more-paypal.wixstudio.com` style entries where the stored
  registrable loses the signal are a data-shape edge);
- several sub-brand lures (`remboursement-amzprime.com`, `prime-sos.com`) —
  they target "Prime", but the watched label is "amazon". Observation only:
  a watchlist could carry sub-brand labels; that is a product change, not a
  weight change.

Coverage recall (declined counted as FN): 0.000.

### Shape distribution in the wild (14 in-scope)

brand-substring 12, brand-subdomain 2, homoglyph 0, edit-distance 0.
The heaviest published weights (homoglyph 35, edit-distance 30/20) defend
against shapes that did not appear once in 269 real phishes. That is not
evidence to lower them — the curated fixtures still exercise them — but it
is evidence about where real-world mass lands.

## Weight finding

The canonical real-world phishing shape — **brand lookalike + freshly
registered domain** — scores 25 + 20 = **45 and stays silent at ≥50**.
Two verified phishes (`appleidmapa.com`, `netflix-renovacion-pago.com`)
demonstrate this exactly.

### Candidate fixes (computed, NOT applied — awaiting approval)

| candidate | TP | TN | FP | FN |
|---|---|---|---|---|
| published weights, t=50 (baseline) | 0 | 5 | 0 | 14 |
| A: `rdap_created_30d` 20 → 25, t=50 | 2 | 5 | 0 | 12 |
| B: threshold 50 → 45 | 2 | 5 | 0 | 12 |
| C: `brand_substring` 25 → 30, t=50 | 2 | 5 | 0 | 12 |

All three candidates behave identically on this set (the only scores near
the line are the two 45s). **Recommendation: candidate A.**
It strengthens the specific conjunction the external data validates
(lookalike shape × fresh registration) instead of lowering the bar
globally (B also newly alerts edit_distance_1+cert_7d and
homoglyph+free_acme without any age signal). C is rejected: it would alert
on any old brand-substring domain with no freshness evidence, and the
benign set cannot measure that false-positive risk. None of the candidates
produce false positives on the 63-entry benign control set (all benign
scores ≤ 25).

The remaining 12 FNs score exactly 25 (shape only — old, dead, or
RDAP-silent domains). Catching them requires the untested enrichment
features: in production, `urlscan_malicious` (40) would push any
brand-substring phish to 65 ≥ 50.

## Curated vs external

| | curated (`ct_labeled_set.json`) | external (`ct_labeled_set_external.json`) |
|---|---|---|
| n | 20 (10 phish / 10 benign) | 332 (269 phish / 63 benign) |
| ground truth | hand-built fixtures | PhishTank volunteer-verified quorum |
| precision / recall | 1.000 / 1.000 | 0.000 / 0.000 (in-scope) |
| what it measures | weight arithmetic on synthetic shapes | calibration + coverage on real phish |

The curated set remains the self-consistency check. The external set is the
first real-world calibration — and it says the threshold is too high for the
shape+freshness conjunction, and the shape coverage is ~5%.

## Limitations

- `cert_last_7d`, `free_acme_issuer`, `urlscan_malicious` untested here;
  production recall with urlscan keyed will exceed this measurement.
- PhishTank labels are a volunteer-verified quorum, not absolute ground
  truth; brand pairing follows PhishTank's `target` column.
- 46% of domains returned no RDAP date (dead/parked); age features cannot
  fire on those by construction.
- Benign set is small (63); the FP risk of any weight change on
  newly-registered benign lookalikes is unmeasured.

## Reproduce

```
python3 eval/build_external_set.py <phishtank-online-valid.csv>
python3 eval/run_ct_eval_external.py
```
