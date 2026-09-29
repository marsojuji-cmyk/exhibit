"""CT radar EXTERNAL evaluation harness — Layer C weight-validation gate.

Runs the production `classify_lookalike` + `score_lookalike` over
`ct_labeled_set_external.json` (PhishTank-verified phishing domains paired
with their impersonated brands, plus real benign brand-infrastructure and
top domains) at the >=50 alert threshold.

Counting discipline (read before quoting the numbers):
- IN-SCOPE: entries where the classifier produced a kind. Precision/recall
  here validate the FEATURE weights and the threshold.
- DECLINED BY DESIGN: malicious entries where the classifier returned None
  (compromised legit sites, shorteners, IP hosts — shapes the CT radar was
  never built to catch). Reported separately as coverage scope, NOT as
  weight failures. The report also gives an all-malicious coverage number
  with declined counted as FN, clearly labeled.

Writes eval/ct-radar-eval-report-external.json.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workbench import ctwatch

HERE = os.path.dirname(os.path.abspath(__file__))
SET_PATH = os.path.join(HERE, "ct_labeled_set_external.json")
ALERT_THRESHOLD = 50


def score_fixture(name, brand_reg, meta):
    hit = ctwatch.classify_lookalike(name, brand_reg)
    if hit is None:
        return None, 0, [], None
    kind, evidence = hit
    score, fired = ctwatch.score_lookalike(
        kind, evidence,
        meta["cert_not_before"], meta["issuer"],
        meta["rdap_created"], meta["urlscan_malicious"])
    return kind, score, fired, "phish" if score >= ALERT_THRESHOLD else "benign"


def main():
    data = json.load(open(SET_PATH))
    brand_rows = {}   # brand -> list of row dicts (in-scope only)
    declined = []     # malicious entries the classifier declined
    all_rows = []
    for brand, sets in data["brands"].items():
        brand_reg = ctwatch.registrable(brand)
        rows = []
        for group in ("malicious", "benign"):
            for f in sets[group]:
                kind, score, fired, pred = score_fixture(
                    f["name"], brand_reg, f["meta"])
                row = {"name": f["name"], "brand": brand,
                       "label": f["label"], "predicted": pred,
                       "score": score, "fired": fired, "kind": kind,
                       "rdap_ok": f["meta"].get("rdap_ok")}
                if kind is None and f["label"] == "phish":
                    declined.append(row)
                else:
                    rows.append(row)
                    all_rows.append(row)
        brand_rows[brand] = rows
    top_rows = []
    for f in data["top_domains"]:
        # Pipeline negatives: must not alert against any tracked brand.
        worst = None
        for brand in data["brands"]:
            kind, score, fired, pred = score_fixture(
                f["name"], ctwatch.registrable(brand), f["meta"])
            if score > (worst[1] if worst else -1):
                worst = (brand, score, fired, pred, kind)
        brand, score, fired, pred, kind = worst
        top_rows.append({"name": f["name"], "brand": brand,
                         "label": "benign", "predicted": pred,
                         "score": score, "fired": fired, "kind": kind})
    all_rows += top_rows

    def metrics(rows):
        tp = sum(1 for r in rows if r["label"] == "phish" and r["predicted"] == "phish")
        tn = sum(1 for r in rows if r["label"] == "benign" and r["predicted"] == "benign")
        fp = sum(1 for r in rows if r["label"] == "benign" and r["predicted"] == "phish")
        fn = sum(1 for r in rows if r["label"] == "phish" and r["predicted"] == "benign")
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        return {"n": len(rows), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                "precision": round(prec, 3), "recall": round(rec, 3)}

    overall = metrics(all_rows)
    per_brand = {b: metrics(r) for b, r in brand_rows.items()}
    n_mal_total = sum(len(s["malicious"]) for s in data["brands"].values())
    coverage = {
        "malicious_total": n_mal_total,
        "in_scope": sum(len([r for r in rows if r["label"] == "phish"])
                        for rows in brand_rows.values()),
        "declined_by_design": len(declined),
        # coverage recall: declined counted as FN, labeled as such
        "coverage_recall_declined_as_fn": round(
            overall["tp"] / n_mal_total, 3) if n_mal_total else 0.0,
    }
    report = {
        "alert_threshold": ALERT_THRESHOLD,
        "provenance": data["provenance"],
        "overall_in_scope": overall,
        "per_brand_in_scope": per_brand,
        "coverage": coverage,
        "false_positive_names": [
            f"{r['name']} (vs {r['brand']}, score={r['score']}, kind={r['kind']})"
            for r in all_rows
            if r["label"] == "benign" and r["predicted"] == "phish"],
        "false_negative_names": [
            f"{r['name']} (vs {r['brand']}, score={r['score']}, kind={r['kind']}, "
            f"fired={r['fired']})"
            for r in all_rows
            if r["label"] == "phish" and r["predicted"] == "benign"],
        "declined_by_design_examples": [
            f"{r['name']} (target {r['brand']})" for r in declined[:15]],
        "note": "External ground truth (PhishTank verified). In-scope metrics "
                "validate weights/threshold; declined-by-design entries measure "
                "shape coverage scope, not weight calibration. urlscan/cert "
                "features untested on this set (no keys / no cert collection).",
    }
    out = os.path.join(HERE, "ct-radar-eval-report-external.json")
    json.dump(report, open(out, "w"), indent=2)

    print(f"EXTERNAL eval (threshold >= {ALERT_THRESHOLD})")
    print(f"  in-scope: n={overall['n']} precision={overall['precision']:.3f} "
          f"recall={overall['recall']:.3f} "
          f"(TP={overall['tp']} TN={overall['tn']} FP={overall['fp']} FN={overall['fn']})")
    for b, m in per_brand.items():
        print(f"    {b:16} n={m['n']:3} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"(TP={m['tp']} FP={m['fp']} FN={m['fn']})")
    print(f"  coverage: {coverage['in_scope']}/{coverage['malicious_total']} "
          f"malicious in scope; declined-by-design={coverage['declined_by_design']}; "
          f"coverage recall (declined=FN)={coverage['coverage_recall_declined_as_fn']:.3f}")
    if report["false_positive_names"]:
        print("  FALSE POSITIVES:")
        for n in report["false_positive_names"]:
            print(f"    {n}")
    if report["false_negative_names"]:
        print("  FALSE NEGATIVES:")
        for n in report["false_negative_names"][:20]:
            print(f"    {n}")
    print(f"report: {out}")


if __name__ == "__main__":
    main()
