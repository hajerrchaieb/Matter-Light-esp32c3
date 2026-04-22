"""
Agent 7 — Fault Injection Analysis Agent (Track D)
Lit fault-injection-report + qemu-dynamic-report + debug/code-review.
Produit: reports/fault-analysis-report-{target}.json
Score robustesse 0-10 + fixes prioritisés.
"""
import json, os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()
TARGET  = os.getenv("TARGET_CHIP", "esp32c3")
REPORTS = Path("reports")

def _load(p: Path) -> dict:
    try:    return json.loads(p.read_text())
    except: return {}

def run_fault_analysis_agent(target: str = TARGET) -> dict:
    print(f"\n[Fault Analysis Agent] Starting for {target}")

    fault_r  = _load(REPORTS / f"fault-injection-report-{target}.json")
    qemu_r   = _load(REPORTS / "qemu-dynamic-report.json")
    debug_r  = _load(REPORTS / f"debug-report-{target}.json")
    review_r = _load(REPORTS / f"code-review-{target}.json")

    # Compact summaries for the prompt
    scenarios_txt = "\n".join(
        f"  [{('PASS' if s['passed'] else 'FAIL')}] {s['scenario_name']} | "
        f"family={s['family']} | expected={s['expected']} | actual={s['actual_reaction']} | "
        f"CWE={s.get('cwe','?')} | severity={s.get('severity','?')}"
        for s in fault_r.get("scenarios", [])
    ) or "No scenarios available."

    fault_summary = (
        f"Overall: {fault_r.get('overall_status','?').upper()} | "
        f"Passed: {fault_r.get('passed',0)}/{fault_r.get('total_scenarios',0)}\n"
        f"Critical failures: {fault_r.get('critical_failures',[])}\n"
        f"High failures: {fault_r.get('high_failures',[])}\n\n"
        f"Per-scenario:\n{scenarios_txt}"
    )
    qemu_summary = (
        f"Boot: {'OK' if qemu_r.get('boot_success') else 'FAILED'} | "
        f"Panics: {len(qemu_r.get('panics',[]))} | "
        f"Watchdog: {len(qemu_r.get('watchdog_triggers',[]))} | "
        f"Status: {qemu_r.get('status','?').upper()}"
        if qemu_r else "QEMU report not available."
    )

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1, max_tokens=3000,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Principal Embedded Security Engineer for ESP32/ESP-IDF.
Analyse fault injection results and produce actionable fixes.
SCORING (0-10):
  10 = all HANDLED, no panics
  8-9 = critical HANDLED, minor = controlled reboot
  6-7 = some high-severity unhandled but no full crashes
  4-5 = multiple high-severity failures
  0-3 = critical memory/NVS crashes without recovery
Respond with valid JSON only — no markdown, no backticks."""),
        ("human", """Target: {target}

=== FAULT INJECTION RESULTS ===
{fault_summary}

=== QEMU BASELINE (Track A) ===
{qemu_summary}

=== CODE REVIEW CONTEXT ===
{review_context}

Return exactly this JSON:
{{
  "target": "{target}",
  "robustness_score": 7,
  "score_justification": "step-by-step reasoning",
  "failed_scenarios_analysis": [
    {{
      "scenario": "malloc_exhaustion",
      "family": "memory",
      "cwe": "CWE-476",
      "root_cause": "pointer not checked for NULL after allocation",
      "fix_code": "if (!ptr) {{ ESP_LOGE(TAG, \\"NULL\\"); return ESP_ERR_NO_MEM; }}",
      "effort": "low"
    }}
  ],
  "passed_scenarios_highlights": [
    {{ "scenario": "nvs_magic_corruption", "why_good": "correctly calls nvs_flash_erase()" }}
  ],
  "family_assessments": {{
    "memory": {{ "score": 6, "verdict": "NEEDS_IMPROVEMENT", "top_recommendation": "..." }},
    "nvs":    {{ "score": 8, "verdict": "GOOD",              "top_recommendation": "..." }},
    "matter": {{ "score": 7, "verdict": "ACCEPTABLE",        "top_recommendation": "..." }}
  }},
  "priority_fixes": [
    "1. [CRITICAL] description and exact fix",
    "2. [HIGH] description and exact fix",
    "3. [MEDIUM] description and exact fix"
  ],
  "overall_verdict": "NEEDS_IMPROVEMENT",
  "summary": "2-3 sentence executive summary"
}}"""),
    ])

    raw = (prompt | llm | StrOutputParser()).invoke({
        "target":         target,
        "fault_summary":  fault_summary,
        "qemu_summary":   qemu_summary,
        "review_context": str(review_r.get("review", ""))[:600],
    })

    try:
        clean  = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        report = json.loads(clean)
    except Exception:
        report = {"target": target, "raw_response": raw, "parse_error": True}

    report["fault_runner_summary"] = {
        "total":   fault_r.get("total_scenarios", 0),
        "passed":  fault_r.get("passed", 0),
        "failed":  fault_r.get("failed", 0),
        "status":  fault_r.get("overall_status", "unknown"),
        "by_family": fault_r.get("by_family", {}),
    }
    report["analysis_timestamp"] = datetime.now().isoformat()

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"fault-analysis-report-{target}.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"[Fault Analysis Agent] Done — score={report.get('robustness_score','N/A')}/10")
    print(f"[Fault Analysis Agent] Report: {out}")
    return report

if __name__ == "__main__":
    run_fault_analysis_agent()
