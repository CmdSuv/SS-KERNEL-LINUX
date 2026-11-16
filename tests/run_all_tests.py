#!/usr/bin/env python3
"""Master test runner + live self-audit double-check for MC SS Sentinel."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import ss_sentinel


def run_suite(live_host: bool = False) -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(PROJECT_ROOT / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        return 1

    print("\n" + "=" * 72)
    print("DOUBLE-CHECK: Isolated CLI Dry-Run & Self-False-Positive Audit")
    print("=" * 72)
    with tempfile.TemporaryDirectory() as td:
        tmp_base = Path(td)
        out_dir = tmp_base / "reports"
        cli_args = ["--no-mem-scan", "--no-deep-home", "--out-dir", str(out_dir)]
        if not live_host:
            iso_home = tmp_base / "iso_home"
            (iso_home / ".minecraft" / "mods").mkdir(parents=True, exist_ok=True)
            cli_args.extend(["--home", str(iso_home)])
        rc = ss_sentinel.main(cli_args)
        if rc != 0:
            print("FAIL: ss_sentinel CLI returned non-zero:", rc)
            return 2
        json_files = list(out_dir.glob("ss_report_*.json"))
        html_files = list(out_dir.glob("ss_report_*.html"))
        txt_files = list(out_dir.glob("ss_report_*.txt"))
        sha_files = list(out_dir.glob("ss_report_*.sha256"))
        if not (json_files and html_files and txt_files and sha_files):
            print("FAIL: Missing generated report files!")
            return 3
        payload = json.loads(json_files[0].read_text(encoding="utf-8"))
        # Verify scanner never flagged its own source files
        self_hits = [
            f for f in payload["findings"]
            if f.get("path") and str(PROJECT_ROOT) in str(f.get("path"))
        ]
        if self_hits:
            print("FAIL: Scanner flagged its own files:", self_hits)
            return 4
        print(f"CLI dry-run score: {payload['assessment']['risk_score']}/100 ({payload['assessment']['verdict_level']})")
        print(f"Findings count: {payload['assessment']['total_findings']} | Errors: {len(payload['errors'])}")
        for f in payload["findings"][:10]:
            print(f"  - [{f['severity']}] {f['rule_id']}: {f['title']}")
    print("ALL TESTS AND DOUBLE-CHECKS PASSED!")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_suite(live_host=("--live-host" in sys.argv[1:])))
