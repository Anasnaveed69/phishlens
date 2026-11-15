"""Collect the facts the final report quotes (test counts, rules, threats, fixtures) from the
code and the evaluation output, so the report never contains a hand-typed number.
Usage: python docs/report/make_facts.py   (then: node docs/report/build_report.js)"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from engine.features import NUMERIC_FEATURES  # noqa: E402
from engine.rules import RULES  # noqa: E402


def pytest_counts() -> tuple[int, int]:
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", out)) else 0
    failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", out)) else 0
    return passed, passed + failed


def threats() -> list[list[str]]:
    rows = []
    for line in (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*(T\d+)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|", line)
        if m:
            name = re.sub(r"\*\*", "", m.group(2))
            rows.append([m.group(1), f"{name} — {m.group(3)}", m.group(4).replace("`", "")])
    return rows


def main() -> None:
    ev = json.loads((ROOT / "reports" / "evaluation.json").read_text(encoding="utf-8"))
    passed, total = pytest_counts()
    import csv
    from engine.model import load
    from engine.pipeline import analyze
    meta = json.loads((ROOT / "models" / "model.meta.json").read_text(encoding="utf-8"))
    model = load(ROOT / "models" / "model.joblib")
    cfg = meta["recommended_config"]
    fixtures = []
    fx = ROOT / "fixtures" / "tests"
    for row in csv.DictReader((fx / "labels.csv").open(encoding="utf-8")):
        r = analyze((fx / row["filename"]).read_text(encoding="utf-8"), row["source_url"] or None, cfg, model)
        rules = [f["id"] for f in r["rules"]["fired"]]
        fixtures.append({"file": row["filename"], "expected": row["label"], "actual": r["decision"],
                         "evidence": f"score {r['score']:.2f} (ML {r['ml']['probability']:.2f}); "
                                     + (f"rules {', '.join(rules)}" if rules else "no rule fired"),
                         "pass": (r["decision"] == "benign") == (row["label"] == "benign")})
    screens = [
        ("dist/demo/step_02.png", "Normal sample: a bank login page on its own domain is classified benign"),
        ("dist/demo/step_03.png", "Adverse sample: PHISHING with the specific indicators and the model's feature contributions"),
        ("dist/demo/step_04.png", "Each fired rule shows its reason and the evidence extracted from the page"),
        ("dist/demo/step_09.png", "Side-by-side comparison of the adverse and the normal result"),
        ("dist/demo/step_11.png", "Restricted viewer: decision and reasons only"),
        ("dist/demo/step_15.png", "After the admin disables R06, a re-run records config v2 and lists R06 as disabled"),
        ("dist/demo/step_16.png", "Append-only, hash-chained audit log with the configuration change and the denied request"),
        ("dist/demo/step_17.png", "Dashboard: decisions, severity, top indicators, latency and analyst feedback"),
    ]
    facts = {
        "repo_url": "https://github.com/Anasnaveed69/phishlens",
        "report_date": date.today().strftime("%d %B %Y"),
        "n_features": len(ev.get("feature_order", NUMERIC_FEATURES)),
        "n_rules": len(RULES),
        "tests_passed": passed, "tests_total": total,
        "ci_pythons": "3.11 and 3.12",
        "threats": threats(), "n_threats": len(threats()),
        "fixture_pages": len(fixtures), "fixture_results": fixtures,
        "tfinal": [
            ["Malformed input (.exe, binary, non-HTML, empty)", "Rejected before processing, logged", "415/422, sample.upload failure event (test_malformed_and_oversized_input_rejected)"],
            ["Oversized page / zip bomb / too many files", "Rejected", "413/422 (test_zip_bomb_declared_size_rejected, test_zip_with_too_many_files_rejected)"],
            ["Unauthorized request (viewer uploads, analyst opens admin)", "Generic denial, logged, record not exposed", "403 FORBIDDEN + authz.denied event (test_viewer_cannot_upload_and_is_logged)"],
            ["Repeated submission", "Duplicate detected, fresh analysis", "same sample id, duplicate=true (test_full_workflow_and_repeated_submission)"],
            ["Safe failure: no model / tampered model", "Rules-only mode, no crash", "mode=rules_only (test_rules_only_mode_when_no_model); SHA-256 check on load"],
            ["Recovery after restart", "Data, config and audit chain intact", "chain valid after re-init (test_recovery_after_restart)"],
            ["Brute force / session fixation / cross-session CSRF", "Blocked", "429 / 401 / 403 (tests/test_security.py)"],
        ],
        "screens": [{"file": f, "caption": c} for f, c in screens if (ROOT / f).exists()],
    }
    out = ROOT / "docs" / "report" / "facts.json"
    out.write_text(json.dumps(facts, indent=2), encoding="utf-8")
    print(f"wrote {out}: {passed}/{total} tests, {len(RULES)} rules, {facts['n_features']} features, "
          f"{facts['n_threats']} threats, {len(facts['screens'])} screenshots")


if __name__ == "__main__":
    main()
