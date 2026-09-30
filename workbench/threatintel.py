"""Threat-intel connectors — Layer A of the OSINT platform.

Read-only. Public sources only. Every connector returns a FetchResult so a
failed fetch (or a missing API key) becomes a first-class gap, never a
silent hole.

Free, keyless:
  urlhaus    — abuse.ch URLhaus: is this host serving malware URLs?
  threatfox  — abuse.ch ThreatFox: IoC records for this indicator
  greynoise  — GreyNoise community: is this IP background scanner noise?
               Keyless but throttled (~50/day per source IP historically) —
               responses are cached for 7 days and 429s become DEGRADED.

Key-ready (env vars; when unset a DEGRADED claim is recorded, never a
silent skip). No accounts were created; keys are the analyst's to add:
  urlhaus    — abuse.ch URLhaus (ABUSECH_AUTH_KEY, free at auth.abuse.ch)
  threatfox  — abuse.ch ThreatFox (ABUSECH_AUTH_KEY, same portal)
  otx        — AlienVault OTX (OTX_API_KEY)
  abuseipdb  — AbuseIPDB (ABUSEIPDB_API_KEY)
  virustotal — VirusTotal (Secure Vault custom.virustotal; VT_API_KEY env fallback)
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request

from .connectors import FetchResult, USER_AGENT, TIMEOUT, MAX_BODY

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
try:
    from dynamic_credentials import add_surrogate_to_request, DynamicCredentialError
    _HAVE_VAULT = True
except ImportError:  # pragma: no cover — dev/CI without the vault helper
    _HAVE_VAULT = False

GREYNOISE_TTL = 7 * 86400
CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "greynoise-cache.json")


def _post(url: str, payload: dict, headers: dict | None = None) -> tuple:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                 **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body[:MAX_BODY]
    except Exception as exc:
        return None, f"FETCH_ERROR: {exc}"


def _get(url: str, headers: dict | None = None) -> tuple:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body[:MAX_BODY]
    except Exception as exc:
        return None, f"FETCH_ERROR: {exc}"


# -- abuse.ch: URLhaus ------------------------------------------------------
# NOTE (2026-09-29, verified against live docs): abuse.ch moved its APIs
# behind a free Auth-Key (auth.abuse.ch). The "no key" claim in older
# research is stale. The key is free; no account was created here — when
# ABUSECH_AUTH_KEY is unset a DEGRADED claim is recorded, never a silent skip.
def fetch_urlhaus_host(host: str) -> FetchResult:
    """URLhaus host lookup — malware URLs seen on this host. POST, Auth-Key.

    NOTE: URLhaus expects a form-encoded body (host=...), not JSON. A JSON
    body yields HTTP 200 with an empty response — a silent wrong answer, so
    the encoding matters here."""
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    if not key:
        return _stub("urlhaus", "ABUSECH_AUTH_KEY", url)
    data = urllib.parse.urlencode({"host": host}).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": USER_AGENT,
                 "Content-Type": "application/x-www-form-urlencoded",
                 "Auth-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            status, body = resp.status, body[:MAX_BODY]
    except Exception as exc:
        return FetchResult("urlhaus", url, False,
                           error=f"URLhaus host lookup failed: FETCH_ERROR: {exc}"[:140])
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("urlhaus", url, True, body)
    return FetchResult("urlhaus", url, False,
                       error=f"URLhaus host lookup failed: {body[:140]}")


def summarize_urlhaus(data) -> dict:
    d = data if isinstance(data, dict) else {}
    status = d.get("query_status", "")
    urls = d.get("urls", []) or []
    return {"listed": status == "ok" and bool(urls),
            "query_status": status,
            "count": len(urls),
            "threats": sorted({u.get("threat", "") for u in urls if u.get("threat")})}


# -- abuse.ch: ThreatFox ----------------------------------------------------
def fetch_threatfox_ioc(indicator: str) -> FetchResult:
    """ThreatFox IoC search — is this indicator a known IoC? POST, Auth-Key
    (same free ABUSECH_AUTH_KEY as URLhaus)."""
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    url = "https://threatfox-api.abuse.ch/api/v1/"
    if not key:
        return _stub("threatfox", "ABUSECH_AUTH_KEY", url)
    status, body = _post(url, {"query": "search_ioc", "search_term": indicator,
                               "exact_match": True}, headers={"Auth-Key": key})
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("threatfox", url, True, body)
    return FetchResult("threatfox", url, False,
                       error=f"ThreatFox search failed: {body[:140]}")


def summarize_threatfox(data) -> dict:
    d = data if isinstance(data, dict) else {}
    status = d.get("query_status", "")
    rows = d.get("data", []) or []
    # "no_result" answers carry data as a plain string, not a list of records.
    if not isinstance(rows, list):
        rows = []
    rows = [r for r in rows if isinstance(r, dict)]
    return {"listed": status == "ok" and bool(rows),
            "query_status": status,
            "count": len(rows),
            "threat_types": sorted({str(r.get("threat_type", "")) for r in rows if r.get("threat_type")}),
            "malware": sorted({str(r.get("malware_printable", "")) for r in rows if r.get("malware_printable")})}


# -- GreyNoise community ----------------------------------------------------
def _cache_load() -> dict:
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _cache_save(cache: dict):
    try:
        with open(CACHE_PATH, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


def fetch_greynoise(ip: str) -> FetchResult:
    """GreyNoise community IP context. Keyless, throttled — cached 7 days.

    A 404 is a VALID answer ("IP not observed scanning the internet"),
    not a gap: it returns ok=True with classification unknown. Only 429s
    and transport failures become DEGRADED, never silent."""
    import urllib.error
    url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}"
    cache = _cache_load()
    hit = cache.get(ip)
    if hit and time.time() - hit.get("at", 0) < GREYNOISE_TTL:
        fr = FetchResult("greynoise", url, True, json.dumps(hit["data"]))
        fr.cached = True  # type: ignore[attr-defined]
        return fr

    def _store(body: str) -> FetchResult:
        try:
            data = json.loads(body)
        except Exception:
            return FetchResult("greynoise", url, False, error="GreyNoise returned unparseable JSON")
        cache[ip] = {"at": time.time(), "data": data}
        _cache_save(cache)
        return FetchResult("greynoise", url, True, body)

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")[:MAX_BODY]
            if resp.status == 200 and body.lstrip().startswith("{"):
                return _store(body)
            return FetchResult("greynoise", url, False,
                               error=f"GreyNoise unexpected status {resp.status}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            body = e.read().decode("utf-8", "replace")[:MAX_BODY]
            if body.lstrip().startswith("{"):
                return _store(body)  # "not observed" — a finding, not a gap
            return FetchResult("greynoise", url, False, error="GreyNoise 404 with empty body")
        if e.code == 429:
            return FetchResult("greynoise", url, False,
                               error="GreyNoise rate-limited (429) — throttled community endpoint")
        return FetchResult("greynoise", url, False,
                           error=f"GreyNoise lookup failed: HTTP {e.code}")
    except Exception as exc:
        return FetchResult("greynoise", url, False, error=f"FETCH_ERROR: {exc}")


def summarize_greynoise(data) -> dict:
    d = data if isinstance(data, dict) else {}
    return {"ip": d.get("ip", ""),
            "observed": "classification" in d,
            "noise": bool(d.get("noise", False)),
            "riot": bool(d.get("riot", False)),
            "classification": str(d.get("classification", "unknown") or "unknown"),
            "name": str(d.get("name", "") or ""),
            "last_seen": str(d.get("last_seen", "") or "")}


# -- key-ready stubs --------------------------------------------------------
def _stub(name: str, env_var: str, key_url: str):
    """When the key is unset: a DEGRADED-shaped FetchResult, never silent."""
    return FetchResult(name, key_url, False,
                       error=f"{env_var} not set — {name} not queried; no account created, gap recorded")


def fetch_otx_domain(domain: str) -> FetchResult:
    """AlienVault OTX general indicator info. Key: OTX_API_KEY."""
    key = os.environ.get("OTX_API_KEY", "").strip()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/general"
    if not key:
        return _stub("otx", "OTX_API_KEY", url)
    status, body = _get(url, headers={"X-OTX-API-KEY": key})
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("otx", url, True, body)
    return FetchResult("otx", url, False, error=f"OTX query failed: {body[:140]}")


def fetch_abuseipdb(ip: str) -> FetchResult:
    """AbuseIPDB IP reputation. Key: ABUSEIPDB_API_KEY (free: 1000 checks/day)."""
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    url = ("https://api.abuseipdb.com/api/v2/check?"
           + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"}))
    if not key:
        return _stub("abuseipdb", "ABUSEIPDB_API_KEY", url)
    status, body = _get(url, headers={"Key": key, "Accept": "application/json"})
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("abuseipdb", url, True, body)
    if status == 429:
        return FetchResult("abuseipdb", url, False, error="AbuseIPDB rate-limited (429)")
    return FetchResult("abuseipdb", url, False, error=f"AbuseIPDB check failed: {body[:140]}")


def fetch_virustotal_domain(domain: str) -> FetchResult:
    """VirusTotal domain report.

    Key: Secure Vault connector custom.virustotal (Community API key;
    free: 1000 lookups/day, 4 req/min), verified live 2026-09-29.
    Falls back to VT_API_KEY env var for local/dev runs without the vault.
    The raw key never lands in logs either way.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if _HAVE_VAULT:
        try:
            # Surrogate -> authd swaps in the real key under X-Apikey.
            add_surrogate_to_request(req, "custom.virustotal",
                                     allowed_hosts=["www.virustotal.com"])
        except DynamicCredentialError:
            key = os.environ.get("VT_API_KEY", "").strip()
            if not key:
                return _stub("virustotal", "VT_API_KEY/custom.virustotal", url)
            req.add_header("x-apikey", key)
    else:
        key = os.environ.get("VT_API_KEY", "").strip()
        if not key:
            return _stub("virustotal", "VT_API_KEY", url)
        req.add_header("x-apikey", key)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            status, body = resp.status, body[:MAX_BODY]
    except Exception as exc:
        return FetchResult("virustotal", url, False,
                           error=f"VirusTotal query failed: FETCH_ERROR: {exc}"[:140])
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("virustotal", url, True, body)
    if status == 429:
        return FetchResult("virustotal", url, False, error="VirusTotal rate-limited (429)")
    if status in (401, 403):
        return FetchResult("virustotal", url, False,
                           error="VirusTotal credential rejected (401/403) — check vault connector")
    return FetchResult("virustotal", url, False, error=f"VirusTotal query failed: {body[:140]}")


def summarize_virustotal(data) -> dict:
    d = ((data or {}).get("data", {}) or {}).get("attributes", {}) or {}
    stats = d.get("last_analysis_stats", {}) or {}
    return {"malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0)}


def summarize_abuseipdb(data) -> dict:
    d = (data or {}).get("data", {}) or {}
    return {"ip": str(d.get("ipAddress", "") or ""),
            "abuse_confidence": int(d.get("abuseConfidenceScore", 0) or 0),
            "total_reports": int(d.get("totalReports", 0) or 0),
            "country": str(d.get("countryCode", "") or "")}
