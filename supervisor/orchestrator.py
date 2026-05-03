"""
supervisor/orchestrator.py — DevSecOps Pipeline Orchestrator (FINAL)
======================================================================
Role:
    LangGraph-based multi-agent orchestrator. Runs all 7 AI agents
    in dependency order, aggregates their results, and writes the
    canonical pipeline-summary.json + pr-comment-body.md.

LANGGRAPH FLOW:
    code_review → security → debug → fault_analysis
                  → test_gen → optimization → autofix → summary

WHY THIS VERSION (key changes vs. previous):
    1. Defense-in-depth security score correction (Layer 4):
       Even if security_agent.py somehow returns 0 with no threats,
       this orchestrator checks again and corrects. Belt + braces.

    2. release_agent removed → its changelog generation is merged
       into optimization_agent (single agent, less LLM cost).

    3. fault_injection_result is loaded from the QEMU+GDB CI artifacts,
       not produced by an agent (it's a real measurement, not analysis).

    4. node_summary now generates a rich PR comment body (markdown)
       saved to reports/pr-comment-body.md so the CI can post it.

    5. The dynamic robustness score combines:
         robustness × 0.35  + qemu_pass × 0.25  + fuzz_pass × 0.20
         + fault_inject_pass × 0.15  + hil_pass × 0.05
"""

import json
import os
import sys
import re
from pathlib import Path
from typing import TypedDict
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

# Make the agents/ package importable when this file is executed
# directly via `python supervisor/orchestrator.py`
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.debug_agent          import run_debug_agent
from agents.security_agent       import run_security_agent
from agents.code_review_agent    import run_code_review_agent
from agents.test_gen_agent       import run_test_gen_agent
from agents.optimization_agent   import run_optimization_agent
from agents.fault_analysis_agent import run_fault_analysis_agent
from agents.autofix_agent        import run_autofix_agent

load_dotenv()

TARGET   = os.getenv("TARGET_CHIP", "esp32c3")
REPORTS  = Path("reports")
FIRMWARE = Path("firmware")


# ── LangGraph state: the dict that flows through every node ───────
class PipelineState(TypedDict):
    target: str
    source_path: str
    version: str
    code_review_result: dict
    security_result: dict
    debug_result: dict
    testgen_result: dict
    optimization_result: dict
    fault_analysis_result: dict
    autofix_result: dict
    container_scan_result: dict
    unit_test_result: dict
    slsa_hashes: dict
    ota_manifest: dict
    deploy_status: str
    feedback_issues: list
    fault_injection_result: dict
    hil_result: dict
    dynamic_score: int
    patches_generated: int
    tests_deployed: bool
    current_stage: str
    errors_found: bool
    pipeline_passed: bool
    pr_comment_body: str
    summary: str


# ════════════════════════════════════════════════════════════════════
# UTILITIES
# ════════════════════════════════════════════════════════════════════

def _load_json(path: Path) -> dict:
    """Read a JSON file or return empty dict on error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_slsa_hashes(target: str) -> dict:
    """Parse the firmware-sha256.txt produced by the SLSA stage."""
    try:
        lines = (REPORTS / "firmware-sha256.txt").read_text().strip().splitlines()
        return {p[1]: p[0] for p in (l.strip().split() for l in lines)
                if len(p) == 2}
    except Exception:
        return {}


def _load_deploy_status() -> str:
    """Read the OTA deploy status written by the release stage."""
    try:
        return (REPORTS / "deploy-status.txt").read_text().strip()
    except Exception:
        return "simulated"


def _extract_score(result: dict, *keys) -> int | str:
    """
    Try multiple JSON keys for a numeric score, then fall back to
    regex-extracting "X / 10" or "X out of 10" from free-text fields.
    Returns "N/A" if no score can be found.
    """
    for k in keys:
        v = result.get(k)
        if v is not None:
            try:
                return int(v)
            except Exception:
                pass
    for field in ("review", "summary", "score_justification"):
        text = result.get(field, "")
        if text:
            m = re.search(r"(\d+)\s*(?:out of|/)\s*10", str(text), re.I)
            if m:
                return int(m.group(1))
    return "N/A"


def _extract_build_status(d: dict) -> str:
    """Locate the build status across the various keys agents may use."""
    for k in ("build_status", "overall_health", "status", "compilation_status"):
        v = d.get(k)
        if v:
            return str(v)
    errors = d.get("compilation_errors", [])
    return "success" if isinstance(errors, list) and len(errors) == 0 else "unknown"


# ════════════════════════════════════════════════════════════════════
# CI ARTIFACT LOADER (runs once at the start of the pipeline)
# ════════════════════════════════════════════════════════════════════

def load_ci_artifacts(state: PipelineState) -> PipelineState:
    """
    Pre-load the static-analysis and dynamic-test reports produced by
    earlier CI stages. The agents will read these from disk on their
    own, but we also store them in the state for use in node_summary.
    """
    t = state["target"]
    state["container_scan_result"]  = _load_json(REPORTS / "container-scan-summary.json")
    state["unit_test_result"]       = _load_json(REPORTS / "unit-test-results.json")
    state["slsa_hashes"]            = _load_slsa_hashes(t)
    state["ota_manifest"]           = _load_json(REPORTS / "ota-manifest-signed.json")
    state["deploy_status"]          = _load_deploy_status()
    state["feedback_issues"]        = []
    state["fault_injection_result"] = _load_json(REPORTS / f"fault-injection-report-{t}.json")
    state["hil_result"]             = _load_json(REPORTS / f"hil-report-{t}.json")
    state["patches_generated"]      = 0
    state["tests_deployed"]         = False
    state["pr_comment_body"]        = ""
    return state


# ════════════════════════════════════════════════════════════════════
# AGENT NODES (one per LangGraph node)
# ════════════════════════════════════════════════════════════════════

def node_code_review(state: PipelineState) -> PipelineState:
    """Stage 1: Code Review Agent."""
    print("\n" + "=" * 60 + "\nNODE: Code Review Agent")
    state["current_stage"] = "code_review"
    try:
        result = run_code_review_agent(target=state["target"])
        score  = _extract_score(result, "quality_score", "score", "code_score")
        result["quality_score"] = score
        state["code_review_result"] = result
        if isinstance(score, int) and score < 5:
            state["errors_found"] = True
    except Exception as e:
        print(f"[Orchestrator] Code Review failed: {e}")
        state["code_review_result"] = {"error": str(e), "quality_score": "N/A"}
        state["errors_found"] = True
    return state


def node_security(state: PipelineState) -> PipelineState:
    """
    Stage 2: Security Agent.

    DEFENSE-IN-DEPTH: even though security_agent.py now has its own
    deterministic scoring, we ALSO check here. If the score arrives
    as 0/10 but no secrets and no critical CVEs were found, we force
    it back to 10/10. This guards against bugs in the agent's own
    correction logic.
    """
    print("\n" + "=" * 60 + "\nNODE: Security Agent")
    state["current_stage"] = "security"
    try:
        result  = run_security_agent(target=state["target"])
        score   = _extract_score(result, "security_score", "score")
        secrets = result.get("secrets_found",  []) or []
        n_crit  = len(result.get("critical_cves", []) or [])

        # Layer 4 of defense-in-depth scoring (in addition to the three
        # layers inside security_agent.py). If we still see 0 with no
        # threats, we override one final time at the orchestrator level.
        if score == 0 and len(secrets) == 0 and n_crit == 0:
            score = 10
            result["security_score"] = 10
            result["score_justification"] = (
                "[Orchestrator override] 0 secrets + 0 critical CVEs "
                "= 10/10. " + result.get("score_justification", "")
            )
            print("[Orchestrator] Security score 0→10 (no threats found)")

        result["security_score"] = score
        state["security_result"] = result

        # Mark errors only if real problems exist
        if (isinstance(score, int) and score < 6) or len(secrets) > 0:
            state["errors_found"] = True
    except Exception as e:
        print(f"[Orchestrator] Security failed: {e}")
        state["security_result"] = {"error": str(e), "security_score": 0}
        state["errors_found"] = True
    return state


def node_debug(state: PipelineState) -> PipelineState:
    """Stage 3: Debug Agent — root-cause analysis of build/test failures."""
    print("\n" + "=" * 60 + "\nNODE: Debug Agent")
    state["current_stage"] = "debug"
    try:
        result = run_debug_agent(target=state["target"])
        state["debug_result"] = result
        errors = result.get("compilation_errors", []) or []
        if result.get("overall_health") == "broken" or len(errors) > 0:
            state["errors_found"] = True
    except Exception as e:
        print(f"[Orchestrator] Debug failed: {e}")
        state["debug_result"] = {"error": str(e)}
        state["errors_found"] = True
    return state


def node_fault_analysis(state: PipelineState) -> PipelineState:
    """
    Stage 4: Fault Analysis Agent — analyses the QEMU+GDB fault
    injection results and produces a robustness score.

    Also computes the dynamic composite score combining:
       robustness  × 0.35
       qemu boot   × 0.25
       fuzz clean  × 0.20
       fault inj   × 0.15
       hil pass    × 0.05
    """
    print("\n" + "=" * 60 + "\nNODE: Fault Analysis Agent")
    state["current_stage"] = "fault_analysis"
    try:
        result = run_fault_analysis_agent(target=state["target"])
        state["fault_analysis_result"] = result
        score = result.get("robustness_score", 10)
        if isinstance(score, (int, float)) and score < 5:
            state["errors_found"] = True

        # Combine with the dynamic measurements
        fi     = state.get("fault_injection_result", {})
        qemu_r = _load_json(REPORTS / "qemu-dynamic-report.json")
        fuzz_r = _load_json(REPORTS / f"fuzz-report-{state['target']}.json")

        qemu_pass   = qemu_r.get("status") == "pass"
        fuzzer_pass = fuzz_r.get("total_issues", 1) == 0
        fi_pass     = fi.get("overall_status") == "pass" if fi else False
        hil_pass    = state.get("hil_result", {}).get("status") == "pass"

        try:
            ds = int(
                float(score if isinstance(score, (int, float)) else 0) * 0.35
                + (10 if qemu_pass   else 0) * 0.25
                + (10 if fuzzer_pass else 0) * 0.20
                + (10 if fi_pass     else 0) * 0.15
                + (10 if hil_pass    else 0) * 0.05
            )
        except Exception:
            ds = 0

        state["dynamic_score"] = min(ds, 10)
        print(f"[Orchestrator] Dynamic={state['dynamic_score']}/10 "
              f"(QEMU={qemu_pass} Fuzz={fuzzer_pass} FI={fi_pass})")
    except Exception as e:
        print(f"[Orchestrator] Fault Analysis failed: {e}")
        state["fault_analysis_result"] = {"error": str(e)}
        state["dynamic_score"] = 0
    return state


def node_test_gen(state: PipelineState) -> PipelineState:
    """Stage 5: Test Generation Agent — generates Unity tests."""
    print("\n" + "=" * 60 + "\nNODE: Test Generation Agent")
    state["current_stage"] = "test_gen"
    try:
        result = run_test_gen_agent(target=state["target"])
        state["testgen_result"] = result
        n      = len(result.get("test_cases", []))
        deploy = result.get("deploy_manifest", {})
        state["tests_deployed"] = deploy.get("status") in ("deployed", "partial")
        print(f"[Orchestrator] {n} test cases | "
              f"deploy={deploy.get('status', '?')}")
    except Exception as e:
        print(f"[Orchestrator] TestGen failed: {e}")
        state["testgen_result"]  = {"error": str(e)}
        state["tests_deployed"]  = False
    return state


def node_optimization(state: PipelineState) -> PipelineState:
    """
    Stage 6: Optimization + Release Agent (merged).
    Also produces release_changelog.md (formerly the release_agent's job).
    """
    print("\n" + "=" * 60 + "\nNODE: Optimization + Release Agent (merged)")
    state["current_stage"] = "optimization"
    try:
        result = run_optimization_agent(
            target  = state["target"],
            version = state["version"],
        )
        state["optimization_result"] = result
        for region in ("flash", "dram", "iram"):
            if result.get("memory_usage", {}).get(f"{region}_risk") == "critical":
                state["errors_found"] = True
    except Exception as e:
        print(f"[Orchestrator] Optimization failed: {e}")
        state["optimization_result"] = {"error": str(e)}
    return state


def node_autofix(state: PipelineState) -> PipelineState:
    """
    Stage 7: AutoFix Agent — generates .patch files from agent issues.
    Patches are NOT applied here; CI Stage 4b/4c does the apply step.
    """
    print("\n" + "=" * 60 + "\nNODE: AutoFix Agent")
    state["current_stage"] = "autofix"
    try:
        result = run_autofix_agent(
            target         = state["target"],
            apply_patches  = False,   # CI applies them, not us
        )
        state["autofix_result"]    = result
        state["patches_generated"] = result.get("patches_generated", 0)
        print(f"[Orchestrator] AutoFix: "
              f"{state['patches_generated']} patch(es)")
    except Exception as e:
        print(f"[Orchestrator] AutoFix failed: {e}")
        state["autofix_result"]    = {"error": str(e)}
        state["patches_generated"] = 0
    return state


def node_summary(state: PipelineState) -> PipelineState:
    """
    Stage 8: Aggregate everything into pipeline-summary.json AND a rich
    markdown PR comment body. This is what the dashboard reads and
    what GitHub posts on the PR.
    """
    print("\n" + "=" * 60 + "\nNODE: Pipeline Summary")
    state["current_stage"] = "summary"

    target  = state["target"]
    version = state["version"]
    _cr  = state.get("code_review_result",    {})
    _sec = state.get("security_result",       {})
    _dbg = state.get("debug_result",          {})
    _opt = state.get("optimization_result",   {})
    _fa  = state.get("fault_analysis_result", {})
    _af  = state.get("autofix_result",        {})
    _tg  = state.get("testgen_result",        {})
    _fi  = state.get("fault_injection_result", {})
    _ut  = state.get("unit_test_result",      {})

    # Pull scores defensively
    code_score = _cr.get("quality_score",  "N/A")
    if code_score == "N/A":
        code_score = _extract_score(_cr, "quality_score", "score")
    sec_score  = _sec.get("security_score", "N/A")
    if sec_score == "N/A":
        sec_score = _extract_score(_sec, "security_score", "score")

    build_ok   = _extract_build_status(_dbg)
    flash_pct  = _opt.get("memory_usage", {}).get("flash_pct", "N/A")
    rob_score  = _fa.get("robustness_score", "N/A")
    dyn_score  = state.get("dynamic_score", "N/A")
    n_cves     = len(_sec.get("critical_cves",  []) or [])
    n_secrets  = len(_sec.get("secrets_found",  []) or [])
    n_patches  = state.get("patches_generated", 0)
    tests_ok   = state.get("tests_deployed",    False)
    errors     = state.get("errors_found",      False)

    n_tests    = len(_tg.get("test_cases", []))
    if n_tests == 0 and (REPORTS / f"generated_tests_{target}.cpp").exists():
        n_tests = 1

    # Test execution stats from the canonical aggregated test file
    ut_status  = _ut.get("status",  "no_tests_yet")
    ut_passed  = _ut.get("passed",  0)
    ut_failed  = _ut.get("failed",  0)
    ut_total   = _ut.get("total",   0)
    fi_total   = _fi.get("total_scenarios", 0)
    fi_passed  = _fi.get("passed",          0)
    fi_status  = _fi.get("overall_status",  "not_run")
    patches_detail = _af.get("patches_detail", [])

    second_run_ready = n_patches > 0 or tests_ok

    # Pipeline pass criteria: no errors, OR errors but patches available
    if not errors:
        state["pipeline_passed"] = True
    elif n_patches > 0:
        state["pipeline_passed"] = True
    else:
        state["pipeline_passed"] = False
    passed = state["pipeline_passed"]

    # Console summary banner
    print("\n" + "\n".join([
        "╔══════════════════════════════════════════╗",
        f"║ Code Review : {code_score}/10",
        f"║ Security    : {sec_score}/10  CVEs={n_cves}  Secrets={n_secrets}",
        f"║ Build       : {build_ok}",
        f"║ Tests       : gen={n_tests}  run={ut_passed}/{ut_total}  {ut_status}",
        f"║ Fault Inject: {fi_passed}/{fi_total}  {fi_status}",
        f"║ Memory      : Flash {flash_pct}%",
        f"║ Robustness  : {rob_score}/10  Dynamic={dyn_score}/10",
        f"║ AutoFix     : {n_patches} patch(es)",
        f"║ Overall     : {'PASSED ✅' if passed else 'ISSUES ⚠️'}",
        "╚══════════════════════════════════════════╝",
    ]))

    # ── Rich PR comment body (markdown) ────────────────────────────
    pr_lines = [
        "## 🤖 AI Agent Analysis Report", "",
        f"**Target:** `{target}` | **Version:** `{version}` | "
        f"**Overall:** {'✅ PASSED' if passed else '⚠️ ISSUES DETECTED'}", "",
        "### 📊 Agent Scores", "",
        "| Agent | Result | Details |",
        "|-------|--------|---------|",
        f"| 🔍 Code Review | `{code_score}/10` | Static analysis of ESP-Matter C++ source |",
        f"| 🔐 Security    | `{sec_score}/10` | "
        f"{n_secrets} secret(s) · {n_cves} critical CVE(s) |",
        f"| 🔨 Build       | `{build_ok}` | ESP-IDF `idf.py build` esp32c3 |",
        f"| 💾 Memory      | Flash `{flash_pct}%` | ESP32-C3 4MB flash |",
        f"| 🛡️ Robustness  | `{rob_score}/10` | "
        f"Dynamic composite: `{dyn_score}/10` |", "",
        "### 🔧 AutoFix Patches", "",
    ]
    if patches_detail:
        pr_lines += [
            "| # | File | Severity | Method |",
            "|---|------|----------|--------|",
        ]
        for i, p in enumerate(patches_detail, 1):
            pr_lines.append(
                f"| {i} | `{p.get('file', '?').split('/')[-1]}` | "
                f"{p.get('severity', '?').upper()} | "
                f"`{p.get('fix_method', '?')}` |"
            )
        pr_lines += ["", "> 📂 Full patches in `.autofix-reports/` folder", ""]
    else:
        pr_lines += ["> ✅ No patches needed this run.", ""]

    pr_lines += [
        "### 🧪 Test Results", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Generated | {n_tests} Unity test(s) |",
        f"| Executed  | {ut_passed}/{ut_total} passed |",
        f"| Status    | `{ut_status}` |", "",
    ]

    pr_lines += [
        "### ⚡ Fault Injection (QEMU+GDB)", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Scenarios | {fi_total} |",
        f"| Passed    | {fi_passed} |",
        f"| Status    | `{fi_status}` |",
    ]
    if _fi.get("critical_failures"):
        pr_lines += [
            "",
            f"**❌ Critical failures:** "
            f"`{'`, `'.join(_fi['critical_failures'][:5])}`",
        ]
    pr_lines += [""]

    if n_secrets > 0:
        pr_lines += [
            "### 🚨 Secrets Found", "",
            "| Type | File | Action |",
            "|------|------|--------|",
        ]
        for s in _sec.get("secrets_found", [])[:5]:
            pr_lines.append(
                f"| {s.get('type', '?')} | `{s.get('file', '?')}` | "
                f"{s.get('action', 'rotate immediately')} |"
            )
        pr_lines += [""]

    pr_lines += [
        "---",
        "*Generated by 7 AI agents — Groq `llama-3.3-70b-versatile`*",
    ]
    state["pr_comment_body"] = "\n".join(pr_lines)

    # ── Persist outputs ────────────────────────────────────────────
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "pr-comment-body.md").write_text(
        state["pr_comment_body"], encoding="utf-8"
    )

    (REPORTS / "pipeline-summary.json").write_text(json.dumps({
        "target":           target,
        "version":          version,
        "pipeline_passed":  passed,
        "errors_found":     errors,
        "second_run_ready": second_run_ready,
        "stage_results": {
            "code_quality":    {
                "score":  code_score,
                "issues": len(_cr.get("issues", []) or []),
            },
            "security":        {
                "score":   sec_score,
                "cves":    n_cves,
                "secrets": n_secrets,
            },
            "build":           {"status": build_ok},
            "memory":          {"flash_pct": flash_pct},
            "tests":           {
                "generated": n_tests,
                "deployed":  tests_ok,
                "executed":  ut_total,
                "passed":    ut_passed,
                "failed":    ut_failed,
                "status":    ut_status,
            },
            "fault_injection": {
                "total":            fi_total,
                "passed":           fi_passed,
                "status":           fi_status,
                "robustness_score": rob_score,
                "dynamic_score":    dyn_score,
            },
            "autofix":         {
                "patches_generated": n_patches,
                "patch_files":       _af.get("patch_files", []),
                "issues_analyzed":   _af.get("issues_analyzed", 0),
                "status":            _af.get("status", "unknown"),
            },
            "release":         {
                "version":       version,
                "canary_deploy": state.get("deploy_status", "not_run"),
            },
        },
    }, indent=2), encoding="utf-8")
    print("[Orchestrator] pipeline-summary.json + pr-comment-body.md saved")
    return state


# ════════════════════════════════════════════════════════════════════
# GRAPH BUILDER + ENTRY POINT
# ════════════════════════════════════════════════════════════════════

def build_pipeline_graph():
    """Wire up the LangGraph DAG of agent nodes."""
    g = StateGraph(PipelineState)
    for name, fn in [
        ("code_review",     node_code_review),
        ("security",        node_security),
        ("debug",           node_debug),
        ("fault_analysis",  node_fault_analysis),
        ("test_gen",        node_test_gen),
        ("optimization",    node_optimization),
        ("autofix",         node_autofix),
        ("summary",         node_summary),
    ]:
        g.add_node(name, fn)
    g.set_entry_point("code_review")
    for a, b in [
        ("code_review",    "security"),
        ("security",       "debug"),
        ("debug",          "fault_analysis"),
        ("fault_analysis", "test_gen"),
        ("test_gen",       "optimization"),
        ("optimization",   "autofix"),
        ("autofix",        "summary"),
        ("summary",         END),
    ]:
        g.add_edge(a, b)
    return g.compile()


def run_pipeline(target: str = TARGET, version: str = "v1.0.0") -> PipelineState:
    """Programmatic entry point used by the CI."""
    REPORTS.mkdir(exist_ok=True)
    initial: PipelineState = {
        "target": target,
        "source_path": os.getenv("EXAMPLE_PATH",
                                 "esp-matter/examples/light"),
        "version": version,
        "code_review_result":    {},
        "security_result":       {},
        "debug_result":          {},
        "testgen_result":        {},
        "optimization_result":   {},
        "fault_analysis_result": {},
        "autofix_result":        {},
        "container_scan_result": {},
        "unit_test_result":      {},
        "slsa_hashes":           {},
        "ota_manifest":          {},
        "deploy_status":         "",
        "feedback_issues":       [],
        "fault_injection_result": {},
        "hil_result":            {},
        "dynamic_score":         0,
        "patches_generated":     0,
        "tests_deployed":        False,
        "current_stage":         "init",
        "errors_found":          False,
        "pipeline_passed":       False,
        "pr_comment_body":       "",
        "summary":               "",
    }
    initial = load_ci_artifacts(initial)
    return build_pipeline_graph().invoke(initial)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target",  default=os.getenv("TARGET_CHIP", TARGET))
    p.add_argument("--version", default="v1.0.0")
    a = p.parse_args()
    run_pipeline(target=a.target, version=a.version)
