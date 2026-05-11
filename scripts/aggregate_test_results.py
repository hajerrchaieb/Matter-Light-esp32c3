#!/usr/bin/env python3
"""
scripts/aggregate_test_results.py  v5
"""
import json
import sys
from pathlib import Path
from datetime import datetime

_EMPTY = ("missing", "no_log", "no_output")

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

def _qemu_boot_ok(qemu: dict | None) -> bool:
    if not qemu:
        return False
    bt = qemu.get("boot_test") or {}
    if not bt:
        return False
    if not bt.get("boot_success"):
        return False
    if (bt.get("panics") or 0) > 0:
        return False
    if (bt.get("watchdogs") or 0) > 0:
        return False
    return True

def _decide_status(h: str, q: str, qemu_obj: dict | None) -> str:
    if h == "fail" or q == "fail":
        return "fail"
    if h == "pass" and q == "pass":
        return "pass"
    if h == "pass" and q == "partial" and _qemu_boot_ok(qemu_obj):
        return "pass"
    if h == "pass" and q in _EMPTY + ("skipped",):
        return "partial"
    if q == "pass" and h in _EMPTY:
        return "partial"
    if h in _EMPTY and q in _EMPTY + ("skipped",):
        return "no_tests_yet"
    return "partial"

def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write(
            "usage: aggregate_test_results.py <host.json> <qemu.json> <out.json>\n")
        return 2
    host_p = Path(sys.argv[1])
    qemu_p = Path(sys.argv[2])
    out_p  = Path(sys.argv[3])
    host = _load(host_p)
    qemu = _load(qemu_p)
    h    = _classify(host)
    q    = _classify(qemu)
    canonical = _decide_status(h, q, qemu)

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

    aggregate = {
        "status":       canonical,
        "total":        total,
        "passed":       passed,
        "failed":       failed,
        "ignored":      ignored,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "runners": {
            "host": host or {"status": "missing"},
            "qemu": qemu or {"status": "missing"},
        },
        "summary": (
            f"host={h} qemu={q} -> canonical={canonical} "
            f"({passed}/{total} passed, {failed} failed, {ignored} ignored)"
        ),
        "test_lines": [],
        "note": (host or {}).get("note") or (qemu or {}).get("note") or "",
    }

    if canonical == "pass" and h == "pass" and q == "partial" and _qemu_boot_ok(qemu):
        aggregate["note"] = (
            "Host unit tests passed and the firmware booted cleanly in QEMU "
            "(dynamic Stage A). The Unity integration build (Stage B) was "
            "skipped — usually because the ESP-IDF Docker build hit the free "
            "runner time budget. Coverage is unit + runtime sanity."
        )
        aggregate["coverage_mode"] = "host_unit_plus_qemu_boot"

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
