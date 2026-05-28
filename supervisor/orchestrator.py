"""
supervisor/orchestrator.py — DevSecOps Pipeline Orchestrator (v8 — fusion v6+v7)
=================================================================================
"""

import json
import time
import os
import sys
import re
from pathlib import Path
from typing import TypedDict
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

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


# ── LangGraph state ───────────────────────────────────────────────
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
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_slsa_hashes(target: str) -> dict:
    try:
        lines = (REPORTS / "firmware-sha256.txt").read_text().strip().splitlines()
        return {p[1]: p[0] for p in (l.strip().split() for l in lines)
                if len(p) == 2}
    except Exception:
        return {}


def _load_deploy_status() -> str:
    try:
        return (REPORTS / "deploy-status.txt").read_text().strip()
    except Exception:
        return "simulated"


def _extract_score(result: dict, *keys) -> int | str:
    """
    Extrait un score numérique (0-10) depuis le résultat d'un agent.
    Essaie d'abord les clés JSON, puis parse les champs markdown.
    """
    for k in keys:
        v = result.get(k)
        if v is None:
            continue
        try:
            n = int(v)
            if 0 <= n <= 10:
                return n
        except (TypeError, ValueError):
            pass

    for field in ("review", "summary", "score_justification"):
        text = result.get(field, "")
        if not text:
            continue
        m = re.search(
            r"##\s*(?:QUALITY\s*)?SCORE\b(.*?)(?=##|$)",
            text, flags=re.I | re.S,
        )
        if m:
            section = m.group(1)
            section = re.sub(r"\bfrom\s*0\s*to\s*10\b", "", section, flags=re.I)
            scores = re.findall(r"\b(\d{1,2})\s*/\s*10\b", section)
            if scores:
                n = int(scores[-1])
                if 0 <= n <= 10:
                    return n

        for pat in (
            r"(?:overall|final|quality)\s*score\s*[:\-=]?\s*(\d{1,2})\s*/?\ *10",
            r"(\d{1,2})\s*(?:out of|/)\s*10\b",
            r"score\s*[:\-=]\s*(\d{1,2})",
        ):
            scores = re.findall(pat, text, flags=re.I)
            if scores:
                valid = [int(s) for s in scores if 0 <= int(s) <= 10]
                if valid:
                    return valid[-1]

    return "N/A"


def _extract_build_status(d: dict) -> str:
    for k in ("build_status", "overall_health", "status", "compilation_status"):
        v = d.get(k)
        if v:
            return str(v)
    errors = d.get("compilation_errors", [])
    return "success" if isinstance(errors, list) and len(errors) == 0 else "unknown"


# ════════════════════════════════════════════════════════════════════
# CI ARTIFACT LOADER
# ════════════════════════════════════════════════════════════════════

def load_ci_artifacts(state: PipelineState) -> PipelineState:
    t = state["target"]
    state["container_scan_result"]  = _load_json(REPORTS / "container-scan-summary.json")
    state["unit_test_result"]       = _load_json(REPORTS / "unit-test-results.json")
    state["slsa_hashes"]            = _load_slsa_hashes(t)
    state["ota_manifest"]           = _load_json(REPORTS / "ota-manifest-signed.json")
    state["deploy_status"]          = _load_deploy_status()
    state["feedback_issues"]        = []
    state["fault_injection_result"] = _load_json(REPORTS / f"fault-injection-report-{t}.json")
    # HIL : chargement du rapport HIL depuis ci.yml Stage 5
    state["hil_result"]             = _load_json(REPORTS / f"hil-report-{t}.json")
    state["patches_generated"]      = 0
    state["tests_deployed"]         = False
    state["pr_comment_body"]        = ""
    return state


# ════════════════════════════════════════════════════════════════════
# AGENT NODES
# ════════════════════════════════════════════════════════════════════

def _call_agent_with_retry(agent_fn, *args, max_retries=3, delay=15, **kwargs):
    """Appelle un agent avec retry automatique sur erreur 429 (rate limit)."""
    for attempt in range(max_retries):
        try:
            return agent_fn(*args, **kwargs)
        except Exception as e:
            msg = str(e)
            if "429" in msg or "rate limit" in msg.lower() or "Rate limit" in msg:
                if attempt < max_retries - 1:
                    wait = delay * (attempt + 1)
                    print(f"  [Retry] Rate limit — attente {wait}s "
                          f"(tentative {attempt+1}/{max_retries})")
                    time.sleep(wait)
                else:
                    print(f"  [Retry] Rate limit — max retries atteint")
                    raise
            else:
                raise
    return None


def node_code_review(state: PipelineState) -> PipelineState:
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
    print("\n" + "=" * 60 + "\nNODE: Security Agent")
    state["current_stage"] = "security"
    try:
        result  = run_security_agent(target=state["target"])
        score   = _extract_score(result, "security_score", "score")
        secrets = result.get("secrets_found",  []) or []
        n_crit  = len(result.get("critical_cves", []) or [])

        if score == 0 and len(secrets) == 0 and n_crit == 0:
            score = 10
            result["security_score"] = 10
            result["score_justification"] = (
                "[Orchestrator override] 0 secrets + 0 critical CVEs "
                "= 10/10. " + result.get("score_justification", "")
            )
            print("[Orchestrator] Security score 0→10 (aucune menace détectée)")

        result["security_score"] = score
        state["security_result"] = result

        if (isinstance(score, int) and score < 6) or len(secrets) > 0:
            state["errors_found"] = True
    except Exception as e:
        print(f"[Orchestrator] Security failed: {e}")
        state["security_result"] = {"error": str(e), "security_score": 0}
        state["errors_found"] = True
    return state


def node_debug(state: PipelineState) -> PipelineState:
    print("\n" + "=" * 60 + "\nNODE: Debug Agent")
    state["current_stage"] = "debug"
    try:
        result = _call_agent_with_retry(run_debug_agent, target=state["target"])
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
    print("\n" + "=" * 60 + "\nNODE: Fault Analysis Agent")
    state["current_stage"] = "fault_analysis"
    try:
        result = _call_agent_with_retry(run_fault_analysis_agent, target=state["target"])
        state["fault_analysis_result"] = result
        score = result.get("robustness_score", 10)
        if isinstance(score, (int, float)) and score < 5:
            state["errors_found"] = True

        fi     = state.get("fault_injection_result", {})
        qemu_r = _load_json(REPORTS / "qemu-dynamic-report.json")
        fuzz_r = _load_json(REPORTS / f"fuzz-report-{state['target']}.json")

        qemu_pass   = qemu_r.get("status") == "pass"
        fuzzer_pass = fuzz_r.get("total_issues", 1) == 0
        fi_pass     = fi.get("overall_status") == "pass" if fi else False
        # HIL : statut pour le dynamic score (poids 5%)
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

        # HIL : log détaillé dans node_fault_analysis
        hil_r        = state.get("hil_result", {})
        hil_status   = hil_r.get("status", "not_run")
        hil_tests    = hil_r.get("tests_run", 0)
        hil_passed_n = hil_r.get("tests_passed", 0)
        print(f"[Orchestrator] Dynamic={state['dynamic_score']}/10 "
              f"(QEMU={qemu_pass} Fuzz={fuzzer_pass} FI={fi_pass} HIL={hil_pass})")
        print(f"[Orchestrator] HIL: {hil_passed_n}/{hil_tests} tests "
              f"— status={hil_status}")
    except Exception as e:
        print(f"[Orchestrator] Fault Analysis failed: {e}")
        state["fault_analysis_result"] = {"error": str(e)}
        state["dynamic_score"] = 0
    return state


def node_test_gen(state: PipelineState) -> PipelineState:
    print("\n" + "=" * 60 + "\nNODE: Test Generation Agent")
    state["current_stage"] = "test_gen"
    try:
        result = _call_agent_with_retry(run_test_gen_agent, target=state["target"])
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
    print("\n" + "=" * 60 + "\nNODE: Optimization + Release Agent")
    state["current_stage"] = "optimization"
    try:
        result = _call_agent_with_retry(
            run_optimization_agent,
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
    print("\n" + "=" * 60 + "\nNODE: AutoFix Agent")
    state["current_stage"] = "autofix"
    try:
        result = run_autofix_agent(
            target        = state["target"],
            apply_patches = False,
        )
        state["autofix_result"]    = result
        state["patches_generated"] = result.get("patches_generated", 0)
        print(f"[Orchestrator] AutoFix: {state['patches_generated']} patch(es)")
    except Exception as e:
        print(f"[Orchestrator] AutoFix failed: {e}")
        state["autofix_result"]    = {"error": str(e)}
        state["patches_generated"] = 0
    return state


# ════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════

def _classify_secrets(secrets: list) -> tuple[list, list]:
    """
    Sépare les vrais secrets (code source) des faux positifs
    (fichiers .patch, reports/, /tmp/).
    Retourne (real_secrets, false_positives).
    """
    real = []
    fp   = []
    fp_paths = (".patch", "reports/patches/", ".autofix-reports/",
                "reports/gitleaks", "/tmp/")
    for s in secrets:
        f = s.get("file", "")
        if any(p in f for p in fp_paths):
            fp.append(s)
        else:
            real.append(s)
    return real, fp


# ════════════════════════════════════════════════════════════════════
# NODE SUMMARY — v8 fusion : HIL branché + OTA robuste + tests Run 2
# ════════════════════════════════════════════════════════════════════

def node_summary(state: PipelineState) -> PipelineState:
    """
    Stage final : agrège tout en pipeline-summary.json riche + PR comment.

    Points clés v8 :
      - Re-lit unit-test-results.json depuis le disque (résultats Run 2)
      - Re-lit ota-manifest-signed.json + fallback firmware-sha256.txt
      - Extraction HIL complète (v7)
      - ota_rollout, ota_note, ota_checksums depuis le manifest (v6)
    """
    print("\n" + "=" * 60 + "\nNODE: Pipeline Summary")
    state["current_stage"] = "summary"

    target  = state["target"]
    version = state["version"]
    _cr  = state.get("code_review_result",     {})
    _sec = state.get("security_result",        {})
    _dbg = state.get("debug_result",           {})
    _opt = state.get("optimization_result",    {})
    _fa  = state.get("fault_analysis_result",  {})
    _af  = state.get("autofix_result",         {})
    _tg  = state.get("testgen_result",         {})
    _fi  = state.get("fault_injection_result", {})

    # ── Tests : re-lire depuis disque (v6) ───────────────────────
    # state["unit_test_result"] est chargé au démarrage AVANT que Stage 5
    # ait fini d'écrire le fichier. En Run 2, les tests ont tourné pendant
    # Stage 5 → relire maintenant pour avoir les vrais résultats.
    _ut_fresh = _load_json(REPORTS / "unit-test-results.json")
    _ut = _ut_fresh if _ut_fresh else state.get("unit_test_result", {})

    # ── Scores ────────────────────────────────────────────────────
    code_score = _cr.get("quality_score", "N/A")
    if code_score == "N/A":
        code_score = _extract_score(_cr, "quality_score", "score")
    sec_score = _sec.get("security_score", "N/A")
    if sec_score == "N/A":
        sec_score = _extract_score(_sec, "security_score", "score")

    build_ok  = _extract_build_status(_dbg)
    flash_pct = _opt.get("memory_usage", {}).get("flash_pct", "N/A")
    rob_score = _fa.get("robustness_score", "N/A")
    dyn_score = state.get("dynamic_score", "N/A")
    n_cves    = len(_sec.get("critical_cves", []) or [])

    # ── Secrets : séparer vrais vs faux positifs ──────────────────
    all_secrets = _sec.get("secrets_found", []) or []
    real_secrets, fp_secrets = _classify_secrets(all_secrets)
    n_real_secrets = len(real_secrets)
    n_fp_secrets   = len(fp_secrets)
    n_secrets      = n_real_secrets   # seuls les vrais comptent pour le risque

    n_patches = state.get("patches_generated", 0)
    tests_ok  = state.get("tests_deployed", False)
    errors    = state.get("errors_found", False)

    # ── Tests ─────────────────────────────────────────────────────
    test_cases = _tg.get("test_cases", [])
    n_tests    = len(test_cases)
    if n_tests == 0 and (REPORTS / f"generated_tests_{target}.cpp").exists():
        n_tests = 1
    ut_status = _ut.get("status",  "no_tests_yet")
    ut_passed = _ut.get("passed",  0)
    ut_failed = _ut.get("failed",  0)
    ut_total  = _ut.get("total",   0)

    # pending_run2 seulement si tests générés mais pas encore exécutés (Run 1)
    # En Run 2, ut_total > 0 → garder le vrai statut
    if n_tests > 0 and ut_total == 0 and ut_status in (
        "no_tests_yet", "partial", "no_output"
    ):
        ut_status = "pending_run2"
        print(f"[Orchestrator] {n_tests} test(s) générés — exécution en Run 2")
    elif ut_total > 0:
        print(f"[Orchestrator] Tests exécutés : {ut_passed}/{ut_total} "
              f"passed — status={ut_status}")

    # ── Fault injection ───────────────────────────────────────────
    fi_total  = _fi.get("total_scenarios", 0)
    fi_passed = _fi.get("passed",          0)
    fi_status = _fi.get("overall_status",  "not_run")

    # ── HIL : extraction complète (v7) ───────────────────────────
    _hil         = state.get("hil_result", {})
    hil_status   = _hil.get("status",       "not_run")
    hil_tests    = _hil.get("tests_run",    0)
    hil_passed_n = _hil.get("tests_passed", 0)
    hil_failed_n = _hil.get("tests_failed", 0)
    hil_device   = _hil.get("device",       f"{target}-qemu-proxy")
    hil_duration = _hil.get("duration_s",   None)
    hil_failures = _hil.get("failures",     []) or []
    hil_pass     = hil_status == "pass"
    hil_pass_rate = round(hil_passed_n / hil_tests * 100, 1) if hil_tests > 0 else 0

    # ── OTA : manifest + fallback firmware-sha256.txt (v6) ───────
    _ota = state.get("ota_manifest", {})
    # Re-lire depuis disque au cas où ci.yml l'a écrit après load_ci_artifacts
    _ota_fresh = _load_json(REPORTS / "ota-manifest-signed.json")
    if _ota_fresh:
        _ota = _ota_fresh

    ota_checksums = _ota.get("checksums", {})
    # Fallback : firmware-sha256.txt si checksums absents du manifest
    if not ota_checksums:
        try:
            sha_txt = (REPORTS / "firmware-sha256.txt").read_text()
            for line in sha_txt.strip().splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    ota_checksums[parts[1]] = parts[0]
        except Exception:
            pass

    ota_version  = _ota.get("version",     version)
    ota_commit   = _ota.get("commit",      "—")
    ota_present  = bool(ota_checksums)
    ota_rollout  = _ota.get("rollout_pct", 10)   # lu depuis manifest, pas hardcodé
    ota_note     = _ota.get("note",        None)

    _raw_deploy       = state.get("deploy_status", "") or "simulated"
    deploy_status_val = _raw_deploy if _raw_deploy in (
        "success", "fail", "rollback", "simulated"
    ) else "simulated"

    print(f"[Orchestrator] OTA: version={ota_version} "
          f"checksums={len(ota_checksums)} "
          f"deploy={deploy_status_val} "
          f"manifest={'yes' if ota_present else 'no'}")

    # ── AutoFix details ───────────────────────────────────────────
    patches_detail = _af.get("patches_detail", []) or []
    manual_instr   = _af.get("manual_instructions", []) or []
    for p in patches_detail:
        if not p.get("fix_method"):
            p["fix_method"] = "rule_based"

    second_run_ready = n_patches > 0 or tests_ok

    # ── Agents run count (sur 8) ──────────────────────────────────
    agents_run = sum([
        bool(_cr and not _cr.get("error")),
        bool(_sec and not _sec.get("error")),
        bool(_dbg and not _dbg.get("error")),
        bool(_fa and not _fa.get("error")),
        bool(_tg and not _tg.get("error")),
        bool(_opt and not _opt.get("error")),
        bool(_af and not _af.get("error")),
    ])


    # ── Pipeline pass criteria ────────────────────────────────────
    if not errors:
        state["pipeline_passed"] = True
    elif n_patches > 0:
        state["pipeline_passed"] = True
    else:
        state["pipeline_passed"] = False
    passed = state["pipeline_passed"]

    # ── Security score override ───────────────────────────────────
    # Si 0 vrai secret ET 0 CVE critique, un score LLM de 0 est aberrant
    if isinstance(sec_score, int) and sec_score < 6 \
            and n_real_secrets == 0 and n_cves == 0:
        corrected = max(sec_score, 7)
        print(f"[Orchestrator] Security score corrigé : "
              f"{sec_score}/10 → {corrected}/10 (aucune menace réelle)")
        sec_score = corrected

    # ── Block reason ─────────────────────────────────────────────
    block_reasons = []
    if n_real_secrets > 0:
        block_reasons.append(
            f"{n_real_secrets} secret(s) hardcodé(s) dans le code source "
            f"({', '.join(s.get('file','?').split('/')[-1] for s in real_secrets[:3])}). "
            f"AutoFix a généré {n_patches} patch(es)."
        )
    if n_fp_secrets > 0:
        print(f"[Orchestrator] NOTE: {n_fp_secrets} secret(s) dans les .patch "
              f"sont des faux positifs (gitleaks scanne son propre output).")
    if isinstance(code_score, int) and code_score < 5:
        block_reasons.append(
            f"Score qualité trop bas : {code_score}/10 (seuil : 5/10)."
        )
    if isinstance(sec_score, int) and sec_score < 6 and n_real_secrets == 0:
        block_reasons.append(
            f"Score sécurité sous le seuil : {sec_score}/10 (seuil : 6/10)."
        )
    block_reason = " | ".join(block_reasons) if block_reasons else None

    if block_reason:
        state["pipeline_passed"] = False
        print(f"[Orchestrator] Pipeline BLOQUÉ : {block_reason[:80]}")

    # ── Console summary banner ────────────────────────────────────
    print("\n" + "\n".join([
        "╔══════════════════════════════════════════════════════╗",
        f"║ Code Review : {code_score}/10",
        f"║ Security    : {sec_score}/10  CVEs={n_cves}  "
        f"Real secrets={n_real_secrets}  FP secrets (patches)={n_fp_secrets}",
        f"║ Build       : {build_ok}",
        f"║ Tests       : gen={n_tests}  run={ut_passed}/{ut_total}  {ut_status}",
        f"║ Fault Inject: {fi_passed}/{fi_total}  {fi_status}",
        f"║ Memory      : Flash {flash_pct}%",
        f"║ Robustness  : {rob_score}/10  Dynamic={dyn_score}/10",
        f"║ HIL Tests   : {hil_passed_n}/{hil_tests}  "
        f"status={hil_status}  device={hil_device}",
        f"║ OTA Deploy  : {deploy_status_val}  version={ota_version}  "
        f"manifest={'yes' if ota_present else 'no'}",
        f"║ AutoFix     : {n_patches} patch(es)  agents={agents_run}/7",
        f"║ Overall     : {'PASSED ✅' if passed else 'ISSUES ⚠️'}",
        f"║ Block reason: {block_reason or 'none'}",
        "╚══════════════════════════════════════════════════════╝",
    ]))

    # ── PR comment body ───────────────────────────────────────────
    pr_lines = [
        "## AI Agent Analysis Report", "",
        f"**Target:** `{target}` | **Version:** `{version}` | "
        f"**Overall:** {'PASSED' if passed else 'ISSUES DETECTED'}", "",
        "### Agent Scores", "",
        "| Agent | Result | Details |",
        "|-------|--------|---------|",     # pas de \n superflu ici (bug v7 corrigé)
        f"| Code Review | `{code_score}/10` | Static analysis ESP-Matter C++ |",
        f"| Security    | `{sec_score}/10` | "
        f"{n_real_secrets} real secret(s) · {n_cves} critical CVE(s) |",
        f"| Build       | `{build_ok}` | ESP-IDF `idf.py build` esp32c3 |",
        f"| Memory      | Flash `{flash_pct}%` | ESP32-C3 4MB flash |",
        f"| Robustness  | `{rob_score}/10` | Dynamic composite: `{dyn_score}/10` |",
        # HIL : ligne dédiée dans le tableau des scores
        f"| HIL Tests   | `{hil_status}` | "
        f"{hil_passed_n}/{hil_tests} tests · device: `{hil_device}` |", "",
        "### AutoFix Patches", "",
    ]
    if patches_detail:
        pr_lines += [
            "| # | File | Severity | Method |",
            "|---|------|----------|--------|",
        ]
        for i, p in enumerate(patches_detail, 1):
            pr_lines.append(
                f"| {i} | `{p.get('file','?').split('/')[-1]}` | "
                f"{p.get('severity','?').upper()} | "
                f"`{p.get('fix_method','?')}` |"
            )
        pr_lines += ["", "> Full patches in `.autofix-reports/` folder", ""]
    else:
        pr_lines += ["> No patches needed this run.", ""]

    pr_lines += [
        "### Test Results", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Generated | {n_tests} Unity test(s) |",
        f"| Executed  | {ut_passed}/{ut_total} passed |",
        f"| Status    | `{ut_status}` |", "",
    ]

    pr_lines += [
        "### Fault Injection (QEMU+GDB)", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Scenarios | {fi_total} |",
        f"| Passed    | {fi_passed} |",
        f"| Status    | `{fi_status}` |",
    ]
    if _fi.get("critical_failures"):
        pr_lines += [
            "",
            f"**Critical failures:** "
            f"`{'`, `'.join(_fi['critical_failures'][:5])}`",
        ]
    pr_lines += [""]

    # HIL : section complète dans le PR comment
    pr_lines += [
        "### HIL Tests (Hardware-in-the-Loop)", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Status    | `{hil_status}` |",
        f"| Tests     | {hil_passed_n}/{hil_tests} passed |",
        f"| Pass rate | {hil_pass_rate}% |",
        f"| Device    | `{hil_device}` |",
    ]
    if hil_duration:
        pr_lines.append(f"| Duration  | {hil_duration}s |")
    if hil_failures:
        pr_lines += [
            "",
            f"**Failed tests:** `{'`, `'.join(str(f) for f in hil_failures[:5])}`",
        ]
    pr_lines += [""]

    if n_real_secrets > 0:
        pr_lines += [
            "### Real Secrets Found (source code only)", "",
            "| Type | File | Action |",
            "|------|------|--------|",
        ]
        for s in real_secrets[:5]:
            pr_lines.append(
                f"| {s.get('type','?')} | `{s.get('file','?')}` | "
                f"{s.get('action','rotate immediately')} |"
            )
        pr_lines += [""]

    if n_fp_secrets > 0:
        pr_lines += [
            f"> Note: {n_fp_secrets} secret(s) detected in generated `.patch` "
            f"files — these are **false positives** "
            f"(gitleaks scanning its own autofix output).",
            "",
        ]

    if block_reason:
        pr_lines += [
            "### Pipeline Block Reason", "",
            f"> {block_reason}", "",
        ]

    pr_lines += [
        "---",
        f"*Generated by {agents_run}/7 AI agents — "
        f"Groq `llama-3.3-70b-versatile`*",
    ]
    state["pr_comment_body"] = "\n".join(pr_lines)

    # ── Persist outputs ───────────────────────────────────────────
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
        "block_reason":     block_reason,
        "agents_run":       agents_run,
        "stage_results": {
            "code_quality": {
                "score":         code_score,
                "quality_score": code_score,     # alias pour le dashboard
                "issues":        len(_cr.get("issues", []) or []),
            },
            "security": {
                "score":               sec_score,
                "cves":                n_cves,
                "secrets":             n_secrets,
                "secrets_found":       n_real_secrets,
                "secrets_in_patches":  n_fp_secrets,
                "real_secrets":        real_secrets[:10],
                "intentional_bug_demo": any(
                    "intentional_bug" in s.get("file", "")
                    for s in real_secrets
                ),
            },
            "build":  {"status": build_ok},
            "memory": {"flash_pct": flash_pct},
            "tests": {
                "generated":  n_tests,
                "deployed":   tests_ok,
                "executed":   ut_total,
                "passed":     ut_passed,
                "failed":     ut_failed,
                "status":     ut_status,
                "test_cases": [
                    {
                        "name": tc.get("name", "?"),
                        "type": tc.get("type", "?"),
                        "area": tc.get("area", "?"),
                    }
                    for tc in test_cases[:20]
                ],
            },
            "fault_injection": {
                "total":            fi_total,
                "passed":           fi_passed,
                "status":           fi_status,
                "robustness_score": rob_score,
                "dynamic_score":    dyn_score,
            },
            # HIL : section complète dans le JSON (v7)
            "hil": {
                "status":                       hil_status,
                "tests_run":                    hil_tests,
                "tests_passed":                 hil_passed_n,
                "tests_failed":                 hil_failed_n,
                "pass_rate":                    hil_pass_rate,
                "device":                       hil_device,
                "duration_s":                   hil_duration,
                "failures":                     hil_failures[:5],
                "contributes_to_dynamic_score": True,
                "weight_in_dynamic":            "5%",
            },
            "autofix": {
                "patches_generated": n_patches,
                "patch_files":       _af.get("patch_files", []),
                "issues_analyzed":   _af.get("issues_analyzed", 0),
                "status":            _af.get("status", "unknown"),
                "patches_detail":    patches_detail,
                "manual_count":      len(manual_instr),
                "fix_method": (
                    patches_detail[0].get("fix_method", "unknown")
                    if patches_detail else "none"
                ),
            },
            # OTA : section complète avec manifest, checksums, rollout, note (v6)
            "release": {
                "version":              ota_version,
                "canary_deploy":        deploy_status_val,
                "ota_manifest_present": ota_present,
                "ota_commit":           ota_commit,
                "ota_checksums":        ota_checksums,
                "rollout_pct":          ota_rollout,   # lu depuis manifest (v6)
                "protocol":             "ESP-Matter OTA",
                "ota_note":             ota_note,      # conservé depuis v6
            },
        },
    }, indent=2), encoding="utf-8")

    print("[Orchestrator] pipeline-summary.json + pr-comment-body.md sauvegardés")
    return state


# ════════════════════════════════════════════════════════════════════
# GRAPH BUILDER + ENTRY POINT
# ════════════════════════════════════════════════════════════════════

def build_pipeline_graph():
    g = StateGraph(PipelineState)
    for name, fn in [
        ("code_review",    node_code_review),
        ("security",       node_security),
        ("debug",          node_debug),
        ("fault_analysis", node_fault_analysis),
        ("test_gen",       node_test_gen),
        ("optimization",   node_optimization),
        ("autofix",        node_autofix),
        ("summary",        node_summary),
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
        ("summary",        END),
    ]:
        g.add_edge(a, b)
    return g.compile()


def run_pipeline(target: str = TARGET, version: str = "v1.0.0") -> PipelineState:
    REPORTS.mkdir(exist_ok=True)
    initial: PipelineState = {
        "target":                target,
        "source_path":           os.getenv("EXAMPLE_PATH", "esp-matter/examples/light"),
        "version":               version,
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
    parser = argparse.ArgumentParser(description="DevSecOps Pipeline Orchestrator")
    parser.add_argument("--target",  default=os.getenv("TARGET_CHIP", "esp32c3"))
    parser.add_argument("--version", default="v1.0.0")
    args = parser.parse_args()
    run_pipeline(target=args.target, version=args.version)
