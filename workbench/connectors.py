"""Read-only connectors to free public data sources.

Every connector returns a FetchResult. Nothing here authenticates,
nothing writes, nothing touches non-public data. A failed fetch is a
first-class result (ok=False) so gaps stay visible instead of silent.
"""
from __future__ import annotations

import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "exhibit/0.1 (defensive OSINT research)"
TIMEOUT = 25
MAX_BODY = 200_000


@dataclass
class FetchResult:
    source: str        # e.g. "crt.sh"
    source_url: str    # the exact URL queried
    ok: bool
    raw: str = ""      # raw body, truncated
    error: str = ""
    fetched_at: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )

    def parsed(self):
        import json

        try:
            return json.loads(self.raw)
        except Exception:
            return None


def _get(url: str, headers: dict | None = None) -> tuple:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body[:MAX_BODY]
    except Exception as exc:
        return None, f"FETCH_ERROR: {exc}"


def fetch_crtsh(domain: str, retries: int = 3) -> FetchResult:
    """Certificate Transparency via crt.sh — subdomains and issuance history.
    Queries both the apex name and %.name so apex certs aren't missed."""
    import json as _json
    queries = [urllib.parse.quote(domain), f"%25.{urllib.parse.quote(domain)}"]
    urls = [f"https://crt.sh/?q={q}&output=json" for q in queries]
    merged: list = []
    seen: set = set()
    for url in urls:
        last = ""
        for _ in range(retries):
            status, body = _get(url)
            if status == 200 and body.lstrip().startswith(("[", "{")):
                try:
                    items = _json.loads(body)
                    items = items if isinstance(items, list) else [items]
                    for e in items:
                        key = e.get("id")
                        if key not in seen:
                            seen.add(key)
                            merged.append(e)
                    break
                except Exception:
                    last = "unparseable JSON"
            else:
                last = body
            time.sleep(2)
        else:
            return FetchResult("crt.sh", " + ".join(urls), False,
                               error=f"crt.sh unavailable after {retries} tries: {last[:140]}")
    return FetchResult("crt.sh", " + ".join(urls), True, _json.dumps(merged))


def fetch_urlscan(domain: str) -> FetchResult:
    """Public urlscan.io search — who has scanned this domain and verdicts."""
    q = urllib.parse.quote(f"domain:{domain}")
    url = f"https://urlscan.io/api/v1/search/?q={q}&size=20"
    status, body = _get(url)
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("urlscan.io", url, True, body)
    return FetchResult("urlscan.io", url, False,
                       error=f"urlscan.io search failed: {body[:140]}")


def fetch_github_repos(query: str) -> FetchResult:
    """GitHub public repository search — unauthenticated, rate-limited."""
    q = urllib.parse.quote(query)
    url = f"https://api.github.com/search/repositories?q={q}&per_page=10"
    status, body = _get(url, headers={"Accept": "application/vnd.github+json"})
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("github-api", url, True, body)
    return FetchResult("github-api", url, False,
                       error=f"github search failed: {body[:140]}")


def fetch_doh(name: str, rtype: str = "A") -> FetchResult:
    """DNS-over-HTTPS via Cloudflare — current DNS answers as seen publicly."""
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    url = f"https://cloudflare-dns.com/dns-query?{params}"
    status, body = _get(url, headers={"Accept": "application/dns-json"})
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("doh-cloudflare", url, True, body)
    return FetchResult("doh-cloudflare", url, False,
                       error=f"DoH query failed: {body[:140]}")


def fetch_rdap(domain: str) -> FetchResult:
    """RDAP — public registration status for the domain."""
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    status, body = _get(url, headers={"Accept": "application/rdap+json"})
    if status == 200 and body.lstrip().startswith("{"):
        return FetchResult("rdap", url, True, body)
    return FetchResult("rdap", url, False,
                       error=f"RDAP failed: {body[:140]}")
