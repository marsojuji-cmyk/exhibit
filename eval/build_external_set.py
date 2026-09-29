"""Build the external labeled eval set for the CT radar from PhishTank's
verified online feed (keyless bulk CSV, fetched 2026-09-29).

DESIGN (honest scope):
- Malicious: verified+online PhishTank submissions whose `target` names a
  brand we track. Labels come from PhishTank's volunteer-verified quorum;
  the brand pairing comes from PhishTank's own `target` column (not from
  our classifier), so the shape taxonomy is not what selects the samples.
- What the external set validates: the FEATURE weights and the >=50 alert
  threshold on real-world phishing domains (name-shape + RDAP-age signal).
  It does NOT validate shape discovery itself: entries our classifier
  declines (compromised legit sites, shorteners, IP hosts) are counted in
  a separate "declined by design" bucket, not as weight failures.
- Benign: real, verifiable brand-infrastructure domains (several of which
  ARE lookalike-shaped, e.g. amazonaws.com, paypalobjects.com,
  googleapis.com) plus top legitimate domains as pipeline negatives.
- Meta: RDAP registration dates fetched live (polite, ~0.7s spacing).
  urlscan_malicious=False for all (no urlscan key — DEGRADED by design);
  cert_not_before="" (cert features untested on this set; documented).

Reproduce: python3 eval/build_external_set.py /path/to/online-valid.csv
"""
import csv
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workbench import ctwatch

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(HERE, "ct_labeled_set_external.json")

BRANDS = {
    "amazon.com": "Amazon.com",
    "facebook.com": "Facebook",
    "microsoft.com": "Microsoft",
    "netflix.com": "Netflix",
    "paypal.com": "PayPal",
    "apple.com": "Apple",
}
PER_BRAND = 45

# Real, verifiable brand-infrastructure / benign domains. Several are
# deliberately lookalike-shaped (brand-substring) with OLD registrations:
# the exact false-positive boundary the >=50 threshold must hold.
BENIGN_NEAR_MISS = {
    "amazon.com": ["amazon.com", "amazonaws.com", "amazon.co.uk", "a.co",
                   "aws.amazon.com"],
    "facebook.com": ["facebook.com", "fb.com", "instagram.com", "whatsapp.com"],
    "microsoft.com": ["microsoft.com", "microsoftonline.com",
                      "microsoftstore.com", "windowsupdate.com", "office.com",
                      "live.com"],
    "netflix.com": ["netflix.com", "fast.com"],
    "paypal.com": ["paypal.com", "paypal.me", "paypalobjects.com",
                   "paypal-communication.com"],
    "apple.com": ["apple.com", "icloud.com", "me.com", "mac.com"],
}
TOP_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com",
    "stackoverflow.com", "reddit.com", "twitter.com", "x.com",
    "cloudflare.com", "mozilla.org", "python.org", "nodejs.org",
    "docker.com", "kubernetes.io", "apache.org", "gnu.org",
    "bbc.com", "nytimes.com", "theguardian.com", "reuters.com",
    "cnn.com", "bloomberg.com", "forbes.com", "wsj.com",
    "ebay.com", "etsy.com", "walmart.com", "target.com",
    "craigslist.org", "yelp.com", "tripadvisor.com", "booking.com",
    "spotify.com", "discord.com", "slack.com", "zoom.us",
    "salesforce.com", "adobe.com", "oracle.com", "ibm.com",
]


def full_host(url):
    """Full hostname (lowercased, no port) — preserves subdomain labels,
    which carry the brand-subdomain phishing signal."""
    try:
        host = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return None
    if not host or "." not in host:
        return None
    return host.strip(".")


def main():
    raw_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/tmp/phishtank_online_valid.csv"
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(raw_path, encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    verified = [r for r in rows
                if r.get("verified") == "yes" and r.get("online") == "yes"]
    print(f"raw rows={len(rows)} verified+online={len(verified)}")

    target_of = {v: k for k, v in BRANDS.items()}
    per_brand_urls = {b: [] for b in BRANDS}
    for r in verified:
        b = target_of.get(r.get("target", ""))
        if b:
            per_brand_urls[b].append(r["url"])

    malicious = {}
    for brand, urls in per_brand_urls.items():
        seen, picked = set(), []
        stride = max(1, len(urls) // (PER_BRAND * 3))
        for u in urls[::stride]:
            h = full_host(u)
            if h and ctwatch.registrable(h) not in seen \
                    and ctwatch.registrable(h) != brand:
                seen.add(ctwatch.registrable(h))
                picked.append({"name": h,
                               "registrable": ctwatch.registrable(h),
                               "phishtank_url": u})
            if len(picked) >= PER_BRAND:
                break
        malicious[brand] = picked
        print(f"  {brand:16} candidates={len(urls):5} picked={len(picked)}")

    # RDAP enrichment is per registrable domain (polite, single-threaded).
    # A domain already claimed by the malicious bucket keeps its verified
    # label; benign near-misses that collide are dropped (dual-use infra
    # is labeled by the verified phishing evidence, and noted in the report).
    mal_names = {m["registrable"] for ms in malicious.values() for m in ms}
    benign_filtered = {b: [n for n in ns if ctwatch.registrable(n) not in mal_names]
                       for b, ns in BENIGN_NEAR_MISS.items()}
    dropped = {b: [n for n in ns if ctwatch.registrable(n) in mal_names]
               for b, ns in BENIGN_NEAR_MISS.items() if
               any(ctwatch.registrable(n) in mal_names for n in ns)}
    if dropped:
        print(f"  dual-use domains kept as malicious, dropped from benign: {dropped}")

    all_names = []
    for brand in BRANDS:
        all_names += [(m["registrable"], "phish") for m in malicious[brand]]
        all_names += [(ctwatch.registrable(n), "benign")
                      for n in benign_filtered[brand]]
    all_names += [(ctwatch.registrable(d), "benign-top") for d in TOP_DOMAINS]
    uniq = []
    seen_names = set()
    for n, k in all_names:
        if n not in seen_names:
            seen_names.add(n)
            uniq.append(n)
    print(f"RDAP-enriching {len(uniq)} unique domains...")
    rdap_cache, ok_count = {}, 0
    for i, n in enumerate(uniq):
        rdap_cache[n] = ctwatch._rdap_created(n)
        if rdap_cache[n]:
            ok_count += 1
        if (i + 1) % 25 == 0:
            print(f"  ...{i + 1}/{len(uniq)} (ok={ok_count})")
        time.sleep(0.7)
    print(f"RDAP ok: {ok_count}/{len(uniq)}")

    out = {
        "provenance": {
            "source": "PhishTank verified online feed (keyless bulk CSV)",
            "feed_url": "http://data.phishtank.com/data/online-valid.csv",
            "fetched_at_utc": fetched_at,
            "raw_rows": len(rows),
            "verified_online_rows": len(verified),
            "note": "Labels = PhishTank volunteer-verified quorum; brand pairing "
                    "from PhishTank's own `target` column. urlscan_malicious=False "
                    "for all entries (no urlscan key); cert dates not collected "
                    "(cert_last_7d / free_acme_issuer untested on this set).",
        },
        "brands": {},
        "top_domains": [],
    }
    for brand in BRANDS:
        out["brands"][brand] = {
            "malicious": [
                {"name": m["name"], "registrable": m["registrable"],
                 "label": "phish",
                 "phishtank_url": m["phishtank_url"],
                 "meta": {"cert_not_before": "",
                          "issuer": "",
                          "rdap_created": rdap_cache.get(m["registrable"]),
                          "urlscan_malicious": False,
                          "rdap_ok": rdap_cache.get(m["registrable"]) is not None}}
                for m in malicious[brand]
            ],
            "benign": [
                {"name": n, "label": "benign",
                 "meta": {"cert_not_before": "",
                          "issuer": "",
                          "rdap_created": rdap_cache.get(
                              ctwatch.registrable(n)),
                          "urlscan_malicious": False,
                          "rdap_ok": rdap_cache.get(
                              ctwatch.registrable(n)) is not None}}
                for n in benign_filtered[brand]
            ],
        }
    out["top_domains"] = [
        {"name": d, "label": "benign",
         "meta": {"cert_not_before": "", "issuer": "",
                  "rdap_created": rdap_cache.get(d),
                  "urlscan_malicious": False,
                  "rdap_ok": rdap_cache.get(d) is not None}}
        for d in TOP_DOMAINS
    ]
    json.dump(out, open(OUT_PATH, "w"), indent=2)
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
