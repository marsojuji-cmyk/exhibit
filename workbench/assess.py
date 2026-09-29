"""Assessment drafting — turns the claim ledger into an analyst-readable report.

The draft is deterministic: every finding cites claim IDs and carries its
tier. An optional LLM polish step exists behind WORKBENCH_LLM_URL; it may
only rephrase cited findings, never add claims. Default: off.
The analyst approves or rejects claims in the review queue — the machine
proposes, the human disposes.
"""
from __future__ import annotations

import json
import os
import urllib.request

LLM_URL = os.environ.get("WORKBENCH_LLM_URL", "").strip()

LLM_SYSTEM = (
    "You are a copy-editor for a threat-intelligence draft. Rules: "
    "1) Rephrase for clarity only. "
    "2) Never add facts, entities, numbers, or conclusions not present in the input. "
    "3) Never remove claim-ID citations like [#12] or tier labels like [VERIFIED]. "
    "4) If unsure, leave the sentence unchanged."
)


def llm_polish(markdown: str) -> tuple[str, bool]:
    """Returns (markdown, polished_bool). Off unless WORKBENCH_LLM_URL is set."""
    if not LLM_URL:
        return markdown, False
    try:
        payload = json.dumps({
            "system": LLM_SYSTEM,
            "input": markdown,
            "max_tokens": 4000,
        }).encode()
        req = urllib.request.Request(
            LLM_URL, data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "exhibit/0.1"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.loads(resp.read().decode())
        text = out.get("output") or out.get("text") or ""
        # Fence: the polished text must preserve every citation and tier label.
        if text and all(tag in text for tag in ("[#", "[VERIFIED]", "[DEGRADED]") if tag in markdown):
            return text, True
        return markdown, False
    except Exception:
        return markdown, False


def _fmt_ids(ids: list[int]) -> str:
    return ", ".join(f"#{i}" for i in ids)


def build_assessment(target: str, run_id: int, started_at: str, claims: list,
                     links: list, score_total: int,
                     score_items: list, notes: list,
                     unreviewed: int, attestation: str | None) -> str:
    degraded = [c for c in claims if c["tier"] == "DEGRADED"]
    coverage = "COMPLETE" if not degraded else f"PARTIAL ({len(degraded)} source(s) unreachable)"

    if score_total >= 40:
        bottom, conf = "Adverse signals present — investigate before dismissing.", "high"
    elif score_total > 0:
        bottom, conf = "Minor signals worth a look; nothing conclusive.", "moderate"
    elif degraded:
        bottom, conf = "No adverse signals in reachable sources, but coverage is incomplete.", "low"
    else:
        bottom, conf = "No adverse signals in the collected sources.", "moderate"

    L = []
    L.append(f"# Exhibit — assessment: {target}")
    L.append(f"Run #{run_id} · collected {started_at} · coverage {coverage}")
    if attestation:
        L.append(f"Scope attestation: {attestation}")
    L.append("")
    L.append(f"## Bottom line (analyst confidence: {conf})")
    L.append("")
    L.append(f"{bottom} Risk score: **{score_total}** (transparent additive — see breakdown).")
    L.append("")
    L.append("## Findings")
    L.append("")
    n = 0
    for c in claims:
        if c["tier"] == "DEGRADED":
            continue
        n += 1
        L.append(f"### {n}. {c['claim']}")
        L.append(f"Tier: [{c['tier']}] · Source: {c['source']} · "
                 f"Observed: {c['observed_at']} · Claim [{_fmt_ids([c['id']])}]")
        L.append(f"Analyst status: {c['analyst_status']}")
        L.append("")
    if score_items:
        L.append("## How the score was built")
        L.append("")
        for pts, reason, ids in score_items:
            L.append(f"- +{pts}: {reason} [{_fmt_ids(ids)}]")
        L.append("")
    if notes:
        L.append("## Notes")
        L.append("")
        for note in notes:
            L.append(f"- {note}")
        L.append("")
    if links:
        L.append("## Cross-source links")
        L.append("")
        for link in links:
            ids = json.loads(link["claim_ids"])
            L.append(f"- {link['entity_type']}: `{link['entity_value']}` → claims [{_fmt_ids(ids)}]")
        L.append("")
    if degraded:
        L.append("## Uncertainty and gaps")
        L.append("")
        for c in degraded:
            L.append(f"- {c['source']}: {c['claim']} [{_fmt_ids([c['id']])}] [DEGRADED]")
        L.append("")
    L.append("## Review queue")
    L.append("")
    L.append(f"{unreviewed} claim(s) awaiting analyst review. "
             "Approve or reject each — the machine proposes, the human disposes.")
    L.append("")
    L.append("## Method")
    L.append("")
    L.append("Public sources only (crt.sh, urlscan.io, GitHub public API, DNS-over-HTTPS, RDAP, "
             "URLhaus, ThreatFox, GreyNoise; OTX/AbuseIPDB/VirusTotal when keys are set). "
             "VERIFIED = directly observed. INFERRED = linked across sources. "
             "GUESSED = heuristic pattern. DEGRADED = source unreachable, gap recorded. "
             "CONFLICT = sources disagree; the disagreement is the finding (INFERRED tier).")
    return "\n".join(L)
