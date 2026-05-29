"""
tools/parse_fault_results.py
CI helper script — parses fault injection runner log and enriches
the JSON report with timing and GDB availability info.

Usage (from CI YAML):
  python3 tools/parse_fault_results.py \
    reports/fault-injection-run.log \
    reports/fault-injection-report-esp32c3.json

Called after qemu_fault_runner.py completes.
Produces: reports/fault-injection-report-esp32c3.json (enriched in-place)
"""

import json
import re
import sys
from pathlib import Path


def enrich_report(log_path: str, report_path: str) -> None:
    log_file    = Path(log_path)
    report_file = Path(report_path)

    if not report_file.exists():
        print(f"Report not found: {report_file} — nothing to enrich")
        return

    report = json.loads(report_file.read_text(encoding="utf-8"))

    # Parse timing from log
    if log_file.exists():
        log_text = log_file.read_text(errors="ignore")

        # Extract session duration
        start_match = re.search(r"TRACK D SESSION START", log_text)
        end_match   = re.search(r"TRACK D SESSION END",   log_text)
        if start_match and end_match:
            report["session_duration_note"] = "see fault-injection-run.log for timing"

        # Count GDB connections
        gdb_connects = len(re.findall(r"target remote :", log_text))
        report["gdb_connections_attempted"] = gdb_connects

        # Detect if any scenario hit actual QEMU (vs simulation)
        live_runs = len(re.findall(r"QEMU.*Starting", log_text))
        report["live_qemu_runs"] = live_runs

        # Append raw log excerpt (first 200 lines) to report
        log_lines = log_text.splitlines()[:200]
        report["run_log_excerpt"] = log_lines

    # Add quality gate thresholds to report for CI reference
    report["quality_gate_thresholds"] = {
        "critical_failures_block_pipeline": True,
        "high_failures_warn_pipeline": True,
        "minimum_pass_rate_pct": 70,
        "current_pass_rate_pct": round(
            report.get("passed", 0) / max(report.get("total_scenarios", 1), 1) * 100, 1
        ),
    }

    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report enriched: {report_file}")
    print(f"  Scenarios: {report.get('total_scenarios',0)} | "
          f"Passed: {report.get('passed',0)} | "
          f"Pass rate: {report['quality_gate_thresholds']['current_pass_rate_pct']}%")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <log_path> <report_path>")
        sys.exit(1)
    enrich_report(sys.argv[1], sys.argv[2])
