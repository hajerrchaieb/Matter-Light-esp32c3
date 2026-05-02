#!/usr/bin/env python3
"""
scripts/parse_unity_log.py
==========================
Single source of truth for parsing Unity test framework output.

Used in TWO places by the CI:
  1. Host-side test runner   (Stage 5, fast feedback path)
  2. QEMU integration runner (Stage 5, real ESP-IDF path)

Both produce identical wire-format output thanks to test_runtime/unity.h
mirroring the embedded Unity terminal format. This script reads either,
extracts per-test PASS/FAIL/IGNORE entries, and writes a structured
JSON file that downstream stages (AI agents, dashboard) consume.

Usage:
  python3 scripts/parse_unity_log.py <input.log> <output.json> <runner-name>
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path


# ── Format Unity uses on both host and QEMU UART ──────────────────
#   <file>:<line>:<test_name>:PASS
#   <file>:<line>:<test_name>:FAIL: <message>
#   <file>:<line>:<test_name>:IGNORE
#   <N> Tests <M> Failures <K> Ignored
LINE_RE    = re.compile(
    r'^([^:]+):(\d+):(test_\w+):(PASS|FAIL|IGNORE)(?::\s*(.*))?$'
)
SUMMARY_RE = re.compile(
    r'(\d+)\s+Tests?\s+(\d+)\s+Failures?\s+(\d+)\s+Ignored'
)


def parse_unity(log_text: str) -> dict:
    """Parse Unity output text and return structured results."""
    tests = []
    summary = None

    for raw in log_text.splitlines():
        line = raw.strip()
        m = LINE_RE.match(line)
        if m:
            file_, lineno, name, status, msg = m.groups()
            tests.append({
                "name":   name,
                "file":   file_,
                "line":   int(lineno),
                "status": status,
                "message": (msg or "").strip(),
            })
            continue
        m = SUMMARY_RE.search(line)
        if m:
            summary = {
                "total":    int(m.group(1)),
                "failures": int(m.group(2)),
                "ignored":  int(m.group(3)),
            }

    if summary is None:
        # No final summary line — derive from per-test entries (best effort).
        passed   = sum(1 for t in tests if t["status"] == "PASS")
        failures = sum(1 for t in tests if t["status"] == "FAIL")
        ignored  = sum(1 for t in tests if t["status"] == "IGNORE")
        summary = {
            "total":    passed + failures + ignored,
            "failures": failures,
            "ignored":  ignored,
        }

    passed = max(0, summary["total"] - summary["failures"] - summary["ignored"])

    if summary["total"] == 0:
        status = "no_output"
    elif summary["failures"] == 0:
        status = "pass"
    else:
        status = "fail"

    return {
        "status":   status,
        "total":    summary["total"],
        "passed":   passed,
        "failed":   summary["failures"],
        "ignored":  summary["ignored"],
        "tests":    tests,
    }


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write(
            "usage: parse_unity_log.py <input.log> <output.json> <runner-name>\n")
        return 2

    in_path     = Path(sys.argv[1])
    out_path    = Path(sys.argv[2])
    runner_name = sys.argv[3]

    if not in_path.exists():
        result = {
            "runner":      runner_name,
            "status":      "no_log",
            "total":       0, "passed": 0, "failed": 0, "ignored": 0,
            "tests":       [],
            "note":        f"log not found: {in_path}",
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
    else:
        log_text = in_path.read_text(errors="ignore")
        result   = parse_unity(log_text)
        result.update({
            "runner":       runner_name,
            "log_file":     str(in_path),
            "log_lines":    len(log_text.splitlines()),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"[{runner_name}] status={result['status']} "
          f"total={result['total']} "
          f"passed={result['passed']} "
          f"failed={result['failed']}")
    return 0 if result["status"] in ("pass", "no_output") else 1


if __name__ == "__main__":
    sys.exit(main())
