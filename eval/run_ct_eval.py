"""CT radar labeled evaluation harness — Layer C quality gate.

WHAT THIS IS: a curated fixture set of lookalike domain names with
analyst-assigned labels (phish / benign) and certificate/registration
metadata, scored by the production `classify_lookalike` +
`score_lookalike` at the published ≥50 alert threshold. Reports
precision, recall, and a confusion matrix.

WHAT THIS IS NOT: external ground truth. These fixtures were curated by
the workbench author from canonical phishing patterns and benign
lookalike classes (CDN hosts, defensive registrations, the brand's own
other TLDs). No PhishTank/URLhaus labeled pull exists yet — building a
real labeled set from verified external entries is the prerequisite
before any feature weight is tuned. Until then: weights stay judgment,
and this harness measures self-consistency, not real-world precision.

The fixtures live in ct_labeled_set.json so the analyst can extend or
re-label them; re-run this script and the report regenerates.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workbench import ctwatch

HERE = os.path.dirname(os.path.abspath(__file__))
SET_PATH = os.path.join(HERE, "ct_labeled_set.json")
ALERT_THRESHOLD = 50


def days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%S")


def main():
    fixtures = json.load(open(SET_PATH))
    brand = fixtures["brand"]
    brand_reg = ctwatch.registrable(brand)
    rows = []
    skipped = 0
    for f in fixtures["fixtures"]:
        name = f["name"]
        hit = ctwatch.classify_lookalike(name, brand_reg)
        if hit is None:
            # Classifier declined — treated as a predicted negative.
            pred = "benign"
            score, fired = 0, []
        else:
            kind, evidence = hit
            meta = f["meta"]
            score, fired = ctwatch.score_lookalike(
                kind, evidence,
                meta["cert_not_before"], meta["issuer"],
                meta["rdap_created"], meta["urlscan_malicious"])
            pred = "phish" if score >= ALERT_THRESHOLD else "benign"
        rows.append({"name": name, "label": f["label"], "predicted": pred,
                     "score": score, "fired": fired, "kind": hit[0] if hit else None})
    tp = sum(1 for r in rows if r["label"] == "phish" and r["predicted"] == "phish")
    tn = sum(1 for r in rows if r["label"] == "benign" and r["predicted"] == "benign")
    fp = sum(1 for r in rows if r["label"] == "benign" and r["predicted"] == "phish")
    fn = sum(1 for r in rows if r["label"] == "phish" and r["predicted"] == "benign")
    n = len(rows)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    report = {
        "brand": brand, "alert_threshold": ALERT_THRESHOLD, "n": n,
        "true_positives": tp, "true_negatives": tn,
        "false_positives": fp, "false_negatives": fn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "confusion_matrix": {"phish_predicted_phish": tp,
                             "phish_predicted_benign": fn,
                             "benign_predicted_phish": fp,
                             "benign_predicted_benign": tn},
        "false_positive_names": [r["name"] for r in rows
                                 if r["label"] == "benign" and r["predicted"] == "phish"],
        "false_negative_names": [r["name"] for r in rows
                                 if r["label"] == "phish" and r["predicted"] == "benign"],
        "note": "Curated fixture set — measures self-consistency at published "
                "weights, not real-world precision. External labeled set (PhishTank/URLhaus "
                "verified entries) is the prerequisite for weight tuning.",
    }
    out = os.path.join(HERE, "ct-radar-eval-report.json")
    json.dump(report, open(out, "w"), indent=2)
    print(f"CT radar eval: n={n}  precision={precision:.3f}  recall={recall:.3f}")
    print(f"  TP={tp} TN={tn} FP={fp} FN={fn} (threshold ≥{ALERT_THRESHOLD})")
    for r in rows:
        mark = "ok " if r["label"] == r["predicted"] else "MISS"
        print(f"  [{mark}] {r['name']:<38} label={r['label']:<7} "
              f"pred={r['predicted']:<7} score={r['score']:>3} kind={r['kind']}")
    print(f"report: {out}")


if __name__ == "__main__":
    main()
