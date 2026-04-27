"""
supervisor/orchestrator.py
==========================
Orchestrator for the DevSecOps AI-agents stage.

It calls every agent in order, stores their reports in reports/,
then asks AutoFix to:
  - generate *.patch files for issues that live IN the source code
    (these are applied automatically by Stage 4b / Stage 4c on the
     SECOND CI run);
  - produce textual instructions for issues that live OUTSIDE the
    source (CI config, secrets, dependencies, …).

It also calls Test-Gen, which deploys a Unity C++ test file into
esp-matter/examples/light/test/ — Stage 5 of the SECOND run picks
this file up and compiles + runs it as the unit-test suite.

Output: reports/pipeline-summary.json  (consumed by the CI step).
"""

import argparse
import json
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

# Make sure `agents/` and `supervisor/` are importable when running
# `python3 supervisor/orchestrator.py` from the repo root.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── Agent imports — every name matches the function defined in
#    each agent file.
from agents.security_agent         import run_security_agent
from agents.code_review_agent      import run_code_review_agent
from agents.debug_agent            import run_debug_agent
from agents.fault_analysis_agent   import run_fault_analysis_agent
from agents.optimization_agent     import run_optimization_agent
from agents.test_gen_agent         import run_test_gen_agent
from agents.release_agent          import run_release_agent
from agents.regression_detector    import run_regression_detector
from agents.autofix_agent          import run_autofix_agent   # <-- the fix


REPORTS = Path("reports")


def _safe(name: str, fn, *args, **kwargs) -> dict:
    """
    Run an agent and ALWAYS return a dict, even on failure.
    Pipeline must never crash because one agent threw.
    """
    print(f"\n========== {name} ==========")
    try:
        out = fn(*args, **kwargs) or {}
        if not isinstance(out, dict):
            out = {"raw": out}
        out.setdefault("status", "ok")
        return out
    except Exception as e:
        print(f"[Orchestrator] {name} crashed: {e}")
        traceback.print_exc()
        return {"status": "error", "error": str(e)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",  default=os.getenv("TARGET_CHIP", "esp32c3"))
    parser.add_argument("--version", default="v0.0.0")
    args = parser.parse_args()

    target = args.target
    REPORTS.mkdir(exist_ok=True)

    print(f"[Orchestrator] Target = {target}")
    print(f"[Orchestrator] Version = {args.version}")
    print(f"[Orchestrator] Started: {datetime.utcnow().isoformat()}Z")

    # ── Run every analysis agent ──────────────────────────────────
    sec   = _safe("Agent 1 — Security",        run_security_agent,        target)
    cr    = _safe("Agent 2 — Code Review",     run_code_review_agent,     target)
    dbg   = _safe("Agent 3 — Debug",           run_debug_agent,           target)
    fa    = _safe("Agent 4 — Fault Analysis",  run_fault_analysis_agent,  target)
    opt   = _safe("Agent 5 — Optimization",    run_optimization_agent,    target)

    # Test generation MUST happen before AutoFix so that, on the
    # second run, both patches and tests are picked up by Stage 5.
    tgen  = _safe("Agent 6 — Test Generation", run_test_gen_agent,        target)

    # AutoFix reads every previous report and produces patches.
    af    = _safe("Agent 7 — AutoFix",         run_autofix_agent,         target)

    # Regression + release run last, they read everything.
    reg   = _safe("Agent 8 — Regression",      run_regression_detector)
    rel   = _safe("Agent 9 — Release",         run_release_agent, target, args.version)

    # ── Aggregate scores ──────────────────────────────────────────
    def _score(d: dict, *keys) -> str:
        for k in keys:
            v = d.get(k)
            if v is not None:
                return str(v)
        return "N/A"

    summary = {
        "pipeline_passed":  af.get("status") == "ok",
        "target":           target,
        "version":          args.version,
        "generated_at":     datetime.utcnow().isoformat() + "Z",
        "stage_results": {
            "security":      {"status": sec.get("status"), "score": _score(sec, "security_score", "score")},
            "code_review":   {"status": cr.get("status"),  "score": _score(cr,  "quality_score", "score")},
            "debug":         {"status": dbg.get("status"), "issues": len(dbg.get("issues", []))},
            "fault":         {"status": fa.get("status")},
            "optimization":  {"status": opt.get("status")},
            "test_gen":      {"status": tgen.get("status"),
                              "tests_generated": tgen.get("tests_generated",
                                                          len(tgen.get("test_cases", [])))},
            "autofix":       {"status": af.get("status"),
                              "patches_generated": af.get("patches_generated", 0),
                              "manual_instructions": len(af.get("manual_instructions", []))},
            "regression":    {"status": reg.get("status")},
            "release":       {"status": rel.get("status")},
        },
    }

    out = REPORTS / "pipeline-summary.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n[Orchestrator] Summary written: {out}")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())