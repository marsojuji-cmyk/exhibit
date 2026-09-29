# Exhibit — assessment: marcusrichards.dev
Run #13 · collected 2026-09-29T12:41:01Z · coverage PARTIAL (6 source(s) unreachable)

## Bottom line (analyst confidence: low)

No adverse signals in reachable sources, but coverage is incomplete. Risk score: **0** (transparent additive — see breakdown).

## Findings

### 1. Certificate Transparency: 0 cert(s) observed for *.marcusrichards.dev
Tier: [VERIFIED] · Source: crt.sh · Observed: 2026-09-29T12:42:00Z · Claim [#65]
Analyst status: unreviewed

### 2. urlscan.io: 0 public scan(s) reference marcusrichards.dev (0 malicious)
Tier: [VERIFIED] · Source: urlscan.io · Observed: 2026-09-29T12:42:02Z · Claim [#66]
Analyst status: unreviewed

### 3. GitHub: 2 public repositor(ies) match 'marcusrichards.dev'
Tier: [VERIFIED] · Source: github-api · Observed: 2026-09-29T12:42:03Z · Claim [#67]
Analyst status: unreviewed

### 4. DNS (DoH): marcusrichards.dev A → 104.21.29.136, 172.67.149.56
Tier: [VERIFIED] · Source: doh-cloudflare · Observed: 2026-09-29T12:42:06Z · Claim [#68]
Analyst status: unreviewed

### 5. RDAP: marcusrichards.dev statuses [add period, client transfer prohibited]
Tier: [VERIFIED] · Source: rdap · Observed: 2026-09-29T12:42:07Z · Claim [#69]
Analyst status: unreviewed

### 6. GreyNoise: 104.21.29.136 not observed scanning the internet (no verdict — unknown, not benign) (cached)
Tier: [VERIFIED] · Source: greynoise · Observed: 2026-09-29T12:42:07Z · Claim [#72]
Analyst status: unreviewed

### 7. GreyNoise: 172.67.149.56 not observed scanning the internet (no verdict — unknown, not benign) (cached)
Tier: [VERIFIED] · Source: greynoise · Observed: 2026-09-29T12:42:07Z · Claim [#74]
Analyst status: unreviewed

### 8. 104.21.29.136 is shared infrastructure for marcusrichards.dev: observed in doh-cloudflare, greynoise
Tier: [INFERRED] · Source: workbench-linker · Observed: 2026-09-29T12:42:08Z · Claim [#78]
Analyst status: unreviewed

### 9. 172.67.149.56 is shared infrastructure for marcusrichards.dev: observed in doh-cloudflare, greynoise
Tier: [INFERRED] · Source: workbench-linker · Observed: 2026-09-29T12:42:08Z · Claim [#79]
Analyst status: unreviewed

### 10. SOURCE RECOVERED: crt.sh recovered — subdomains, issuers now visible; recorded as baseline, not alerted
Tier: [INFERRED] · Source: workbench-diff · Observed: 2026-09-29T12:42:08Z · Claim [#80]
Analyst status: unreviewed

## Notes

- GitHub: 2 public repo(s) reference 'marcusrichards.dev' — skim for accidental exposure (claim #67).
- 6 source(s) unreachable during collection — coverage is incomplete: abuseipdb, otx, threatfox, urlhaus, virustotal

## Cross-source links

- ipv4: `104.21.29.136` → claims [#68, #72]
- ipv4: `172.67.149.56` → claims [#68, #74]

## Uncertainty and gaps

- urlhaus: URLhaus: ABUSECH_AUTH_KEY not set — urlhaus not queried; no account created, gap recorded [#70] [DEGRADED]
- threatfox: ThreatFox: ABUSECH_AUTH_KEY not set — threatfox not queried; no account created, gap recorded [#71] [DEGRADED]
- abuseipdb: AbuseIPDB: ABUSEIPDB_API_KEY not set — abuseipdb not queried; no account created, gap recorded [#73] [DEGRADED]
- abuseipdb: AbuseIPDB: ABUSEIPDB_API_KEY not set — abuseipdb not queried; no account created, gap recorded [#75] [DEGRADED]
- virustotal: VirusTotal: VT_API_KEY not set — virustotal not queried; no account created, gap recorded [#76] [DEGRADED]
- otx: OTX: OTX_API_KEY not set — otx not queried; no account created, gap recorded [#77] [DEGRADED]

## Review queue

16 claim(s) awaiting analyst review. Approve or reject each — the machine proposes, the human disposes.

## Method

Public sources only (crt.sh, urlscan.io, GitHub public API, DNS-over-HTTPS, RDAP, URLhaus, ThreatFox, GreyNoise; OTX/AbuseIPDB/VirusTotal when keys are set). VERIFIED = directly observed. INFERRED = linked across sources. GUESSED = heuristic pattern. DEGRADED = source unreachable, gap recorded. CONFLICT = sources disagree; the disagreement is the finding (INFERRED tier).