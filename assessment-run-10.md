# Exhibit — assessment: marcusrichards.dev
Run #10 · collected 2026-09-29T12:34:36Z · coverage PARTIAL (7 source(s) unreachable)

## Bottom line (analyst confidence: low)

No adverse signals in reachable sources, but coverage is incomplete. Risk score: **0** (transparent additive — see breakdown).

## Findings

### 1. urlscan.io: 0 public scan(s) reference marcusrichards.dev (0 malicious)
Tier: [VERIFIED] · Source: urlscan.io · Observed: 2026-09-29T12:35:05Z · Claim [#50]
Analyst status: unreviewed

### 2. GitHub: 2 public repositor(ies) match 'marcusrichards.dev'
Tier: [VERIFIED] · Source: github-api · Observed: 2026-09-29T12:35:06Z · Claim [#51]
Analyst status: unreviewed

### 3. DNS (DoH): marcusrichards.dev A → 104.21.29.136, 172.67.149.56
Tier: [VERIFIED] · Source: doh-cloudflare · Observed: 2026-09-29T12:35:17Z · Claim [#52]
Analyst status: unreviewed

### 4. RDAP: marcusrichards.dev statuses [add period, client transfer prohibited]
Tier: [VERIFIED] · Source: rdap · Observed: 2026-09-29T12:35:18Z · Claim [#53]
Analyst status: unreviewed

### 5. GreyNoise: 104.21.29.136 not observed scanning the internet (no verdict — unknown, not benign) (cached)
Tier: [VERIFIED] · Source: greynoise · Observed: 2026-09-29T12:35:18Z · Claim [#56]
Analyst status: unreviewed

### 6. GreyNoise: 172.67.149.56 not observed scanning the internet (no verdict — unknown, not benign) (cached)
Tier: [VERIFIED] · Source: greynoise · Observed: 2026-09-29T12:35:18Z · Claim [#58]
Analyst status: unreviewed

### 7. 104.21.29.136 is shared infrastructure for marcusrichards.dev: observed in doh-cloudflare, greynoise
Tier: [INFERRED] · Source: workbench-linker · Observed: 2026-09-29T12:35:19Z · Claim [#62]
Analyst status: unreviewed

### 8. 172.67.149.56 is shared infrastructure for marcusrichards.dev: observed in doh-cloudflare, greynoise
Tier: [INFERRED] · Source: workbench-linker · Observed: 2026-09-29T12:35:19Z · Claim [#63]
Analyst status: unreviewed

## Notes

- GitHub: 2 public repo(s) reference 'marcusrichards.dev' — skim for accidental exposure (claim #51).
- 7 source(s) unreachable during collection — coverage is incomplete: abuseipdb, crt.sh, otx, threatfox, urlhaus, virustotal

## Cross-source links

- ipv4: `104.21.29.136` → claims [#52, #56]
- ipv4: `172.67.149.56` → claims [#52, #58]

## Uncertainty and gaps

- crt.sh: crt.sh unreachable — no CT coverage this run [#49] [DEGRADED]
- urlhaus: URLhaus: ABUSECH_AUTH_KEY not set — urlhaus not queried; no account created, gap recorded [#54] [DEGRADED]
- threatfox: ThreatFox: ABUSECH_AUTH_KEY not set — threatfox not queried; no account created, gap recorded [#55] [DEGRADED]
- abuseipdb: AbuseIPDB: ABUSEIPDB_API_KEY not set — abuseipdb not queried; no account created, gap recorded [#57] [DEGRADED]
- abuseipdb: AbuseIPDB: ABUSEIPDB_API_KEY not set — abuseipdb not queried; no account created, gap recorded [#59] [DEGRADED]
- virustotal: VirusTotal: VT_API_KEY not set — virustotal not queried; no account created, gap recorded [#60] [DEGRADED]
- otx: OTX: OTX_API_KEY not set — otx not queried; no account created, gap recorded [#61] [DEGRADED]

## Review queue

15 claim(s) awaiting analyst review. Approve or reject each — the machine proposes, the human disposes.

## Method

Public sources only (crt.sh, urlscan.io, GitHub public API, DNS-over-HTTPS, RDAP, URLhaus, ThreatFox, GreyNoise; OTX/AbuseIPDB/VirusTotal when keys are set). VERIFIED = directly observed. INFERRED = linked across sources. GUESSED = heuristic pattern. DEGRADED = source unreachable, gap recorded. CONFLICT = sources disagree; the disagreement is the finding (INFERRED tier).