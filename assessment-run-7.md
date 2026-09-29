# Exhibit — assessment: marcusrichards.dev
Run #7 · collected 2026-09-29T12:33:19Z · coverage PARTIAL (6 source(s) unreachable)

## Bottom line (analyst confidence: low)

No adverse signals in reachable sources, but coverage is incomplete. Risk score: **0** (transparent additive — see breakdown).

## Findings

### 1. Certificate Transparency: 0 cert(s) observed for *.marcusrichards.dev
Tier: [VERIFIED] · Source: crt.sh · Observed: 2026-09-29T12:33:32Z · Claim [#32]
Analyst status: unreviewed

### 2. urlscan.io: 0 public scan(s) reference marcusrichards.dev (0 malicious)
Tier: [VERIFIED] · Source: urlscan.io · Observed: 2026-09-29T12:33:35Z · Claim [#33]
Analyst status: unreviewed

### 3. GitHub: 2 public repositor(ies) match 'marcusrichards.dev'
Tier: [VERIFIED] · Source: github-api · Observed: 2026-09-29T12:33:36Z · Claim [#34]
Analyst status: unreviewed

### 4. DNS (DoH): marcusrichards.dev A → 104.21.29.136, 172.67.149.56
Tier: [VERIFIED] · Source: doh-cloudflare · Observed: 2026-09-29T12:33:39Z · Claim [#35]
Analyst status: unreviewed

### 5. RDAP: marcusrichards.dev statuses [add period, client transfer prohibited]
Tier: [VERIFIED] · Source: rdap · Observed: 2026-09-29T12:33:41Z · Claim [#36]
Analyst status: unreviewed

### 6. GreyNoise: 104.21.29.136 not observed scanning the internet (no verdict — unknown, not benign) (cached)
Tier: [VERIFIED] · Source: greynoise · Observed: 2026-09-29T12:33:41Z · Claim [#39]
Analyst status: unreviewed

### 7. GreyNoise: 172.67.149.56 not observed scanning the internet (no verdict — unknown, not benign) (cached)
Tier: [VERIFIED] · Source: greynoise · Observed: 2026-09-29T12:33:41Z · Claim [#41]
Analyst status: unreviewed

### 8. 104.21.29.136 is shared infrastructure for marcusrichards.dev: observed in doh-cloudflare, greynoise
Tier: [INFERRED] · Source: workbench-linker · Observed: 2026-09-29T12:33:43Z · Claim [#45]
Analyst status: unreviewed

### 9. 172.67.149.56 is shared infrastructure for marcusrichards.dev: observed in doh-cloudflare, greynoise
Tier: [INFERRED] · Source: workbench-linker · Observed: 2026-09-29T12:33:43Z · Claim [#46]
Analyst status: unreviewed

## Notes

- GitHub: 2 public repo(s) reference 'marcusrichards.dev' — skim for accidental exposure (claim #34).
- 6 source(s) unreachable during collection — coverage is incomplete: abuseipdb, otx, threatfox, urlhaus, virustotal

## Cross-source links

- ipv4: `104.21.29.136` → claims [#35, #39]
- ipv4: `172.67.149.56` → claims [#35, #41]

## Uncertainty and gaps

- urlhaus: URLhaus: ABUSECH_AUTH_KEY not set — urlhaus not queried; no account created, gap recorded [#37] [DEGRADED]
- threatfox: ThreatFox: ABUSECH_AUTH_KEY not set — threatfox not queried; no account created, gap recorded [#38] [DEGRADED]
- abuseipdb: AbuseIPDB: ABUSEIPDB_API_KEY not set — abuseipdb not queried; no account created, gap recorded [#40] [DEGRADED]
- abuseipdb: AbuseIPDB: ABUSEIPDB_API_KEY not set — abuseipdb not queried; no account created, gap recorded [#42] [DEGRADED]
- virustotal: VirusTotal: VT_API_KEY not set — virustotal not queried; no account created, gap recorded [#43] [DEGRADED]
- otx: OTX: OTX_API_KEY not set — otx not queried; no account created, gap recorded [#44] [DEGRADED]

## Review queue

15 claim(s) awaiting analyst review. Approve or reject each — the machine proposes, the human disposes.

## Method

Public sources only (crt.sh, urlscan.io, GitHub public API, DNS-over-HTTPS, RDAP, URLhaus, ThreatFox, GreyNoise; OTX/AbuseIPDB/VirusTotal when keys are set). VERIFIED = directly observed. INFERRED = linked across sources. GUESSED = heuristic pattern. DEGRADED = source unreachable, gap recorded. CONFLICT = sources disagree; the disagreement is the finding (INFERRED tier).