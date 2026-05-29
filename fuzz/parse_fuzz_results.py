import re, json, sys, os
from pathlib import Path

def parse(log_path: str, crash_dir: str, out_path: str) -> dict:
    log_text = ""
    if Path(log_path).exists():
        log_text = Path(log_path).read_text(errors="ignore")

    crash_dir_path = Path(crash_dir)
    crashes  = list(crash_dir_path.glob("crash-*"))   if crash_dir_path.exists() else []
    timeouts = list(crash_dir_path.glob("timeout-*")) if crash_dir_path.exists() else []
    leaks    = list(crash_dir_path.glob("leak-*"))    if crash_dir_path.exists() else []
    oom      = list(crash_dir_path.glob("oom-*"))     if crash_dir_path.exists() else []

    coverage = features = executions = exec_speed = corp_size = 0
    for line in log_text.splitlines():
        m = re.search(
            r"#(\d+)\s+\w+\s+cov:\s*(\d+)\s+ft:\s*(\d+)"
            r".*?corp:\s*(\d+)/.*?exec/s:\s*(\d+)", line)
        if m:
            executions = int(m.group(1))
            coverage   = int(m.group(2))
            features   = int(m.group(3))
            corp_size  = int(m.group(4))
            exec_speed = int(m.group(5))

    crash_types = []
    for c in crashes[:5]:
        try:
            crash_types.append({"file": c.name, "size_bytes": c.stat().st_size})
        except Exception:
            crash_types.append({"file": c.name})

    asan_errors  = [l.strip() for l in log_text.splitlines() if "ERROR: AddressSanitizer:" in l]
    ubsan_errors = [l.strip() for l in log_text.splitlines() if "runtime error:" in l]

    total_issues = len(crashes) + len(timeouts) + len(leaks) + len(oom)

    report = {
        "status":          "fail" if total_issues > 0 else "pass",
        "executions":      executions,
        "exec_per_second": exec_speed,
        "coverage_edges":  coverage,
        "features":        features,
        "corpus_size":     corp_size,
        "crashes":         {"count": len(crashes),  "files": crash_types},
        "timeouts":        {"count": len(timeouts)},
        "leaks":           {"count": len(leaks)},
        "oom":             {"count": len(oom)},
        "sanitizer_errors": {"asan": asan_errors[:10], "ubsan": ubsan_errors[:10]},
        "total_issues":    total_issues,
        "summary": (
            f"{executions:,} executions at {exec_speed:,}/s — "
            f"{coverage} edges covered — {total_issues} issue(s) found"
            if executions > 0 else "Fuzzer did not run or produced no output"
        ),
    }

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: parse_fuzz_results.py <log> <crash_dir> <out_json>")
        sys.exit(1)
    r = parse(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1 if r["status"] == "fail" else 0)
