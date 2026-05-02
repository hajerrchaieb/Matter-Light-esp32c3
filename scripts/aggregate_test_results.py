#!/usr/bin/env python3
"""
scripts/aggregate_test_results.py
==================================
Merges the host-side runner output and the QEMU integration output
into the single `unit-test-results.json` that:

  - the AI agents (test_gen, autofix, regression) read,
  - the dashboard reads,
  - the GitHub PR comment summarises.

Aggregation rules:
  - "passed" is overall pass: BOTH runners must pass for the canonical
    status to be "pass". Either fail -> "fail". Either skip + other pass
    -> "partial". Both skipped -> "no_tests_yet".
  - per-runner numbers are preserved under the `runners` key for the
    dashboard to display side by side.
  - if a runner produced no output but the other did, status is "partial".

Usage:
  python3 scripts/aggregate_test_results.py <host.json> <qemu.json> <out.json>
"""

import json
import sys
from pathlib import Path
from datetime import datetime


def _load(p: Path) -> dict | None:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _classify(d: dict | None) -> str:
    if d is None:
        return "missing"
    return d.get("status", "missing")


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write(
            "usage: aggregate_test_results.py <host.json> <qemu.json> <out.json>\n")
        return 2

    host_p  = Path(sys.argv[1])
    qemu_p  = Path(sys.argv[2])
    out_p   = Path(sys.argv[3])

    host = _load(host_p)
    qemu = _load(qemu_p)
    h    = _classify(host)
    q    = _classify(qemu)

    # ─ Decide canonical status ────────────────────────────────────
    if h == "fail" or q == "fail":
        canonical = "fail"
    elif h == "pass" and q == "pass":
        canonical = "pass"
    elif h == "pass" and q in ("missing", "no_log", "no_output"):
        canonical = "partial"   # host OK, QEMU not run
    elif q == "pass" and h in ("missing", "no_log", "no_output"):
        canonical = "partial"   # QEMU OK, host not run
    elif h in ("missing", "no_log") and q in ("missing", "no_log"):
        canonical = "no_tests_yet"
    else:
        canonical = "partial"

    # ─ Aggregate counts (best effort) ─────────────────────────────
    def _sum(field: str) -> int:
        total = 0
        for d in (host, qemu):
            if d:
                total += int(d.get(field, 0) or 0)
        return total

    total   = _sum("total")
    passed  = _sum("passed")
    failed  = _sum("failed")
    ignored = _sum("ignored")

    # ─ Build canonical output ─────────────────────────────────────
    aggregate = {
        "status":         canonical,
        "total":          total,
        "passed":         passed,
        "failed":         failed,
        "ignored":        ignored,
        "generated_at":   datetime.utcnow().isoformat() + "Z",

        "runners": {
            "host": host or {"status": "missing"},
            "qemu": qemu or {"status": "missing"},
        },

        "summary": (
            f"host={h} qemu={q} -> canonical={canonical} "
            f"({passed}/{total} passed, {failed} failed, {ignored} ignored)"
        ),

        # Backwards-compatible fields older agents still read
        "test_lines": [],
        "note":       (host or {}).get("note") or (qemu or {}).get("note") or "",
    }

    # Concatenate per-test entries from both runners for display
    tests = []
    for runner_name, d in (("host", host), ("qemu", qemu)):
        if d and d.get("tests"):
            for t in d["tests"]:
                tests.append({**t, "runner": runner_name})
    aggregate["tests"] = tests

    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    print(aggregate["summary"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
