"""
Agent 1 — Debug Agent  (Stage 4 + Stage 5)
Reads build log AND unit-test-results.json (new in updated CI)
and performs root cause analysis.
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

TARGET = os.getenv("TARGET_CHIP", "esp32c3")
REPORTS = Path("reports")


# ── helpers ────────────────────────────────────────────────────────

def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return default


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _summarise_unit_tests(result: dict) -> str:
    """Convert unit-test-results.json into a readable summary."""
    if not result:
        return "No unit test data available."
    status = result.get("status", "unknown")
    note   = result.get("note", "")
    passed = result.get("passed", 0)
    failed = result.get("failed", 0)
    total  = result.get("total", 0)
    if status == "no_tests_yet":
        return f"Unit tests not yet implemented. Note: {note}"
    return (
        f"Status: {status} | Passed: {passed} | Failed: {failed} | Total: {total}\n"
        f"Note: {note}"
    )


# ── main agent function ─────────────────────────────────────────────

def run_debug_agent(target: str = TARGET) -> dict:
    print(f"\n[Debug Agent] Starting analysis for target: {target}")

    build_log_path   = REPORTS / f"build-{target}.log"
    unit_test_path   = REPORTS / "unit-test-results.json"
    quality_gate_log = REPORTS / f"cppcheck-deep.xml"

    build_log    = _read(build_log_path,   default="Build log not found.")
    unit_tests   = _load_json(unit_test_path)
    quality_xml  = _read(quality_gate_log, default="cppcheck report not found.")

    unit_test_summary = _summarise_unit_tests(unit_tests)

    # Truncate logs to avoid token overflow
    if len(build_log) > 6000:
        build_log = build_log[-6000:]
        print("[Debug Agent] Build log truncated to last 6000 chars")

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1,
        max_tokens=2000,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert embedded systems engineer specialising in
ESP32 / ESP-IDF / ESP-Matter firmware debugging and CI/CD analysis.
You analyse build logs, unit test results, and static analysis reports
to identify root causes and provide actionable fixes.
Always respond with a valid JSON object only — no markdown, no backticks."""),

        ("human", """Analyse the following data for target chip: {target}

=== BUILD LOG (last 6000 chars) ===
{build_log}

=== UNIT TEST RESULTS ===
{unit_test_summary}

=== CPPCHECK QUALITY GATE (first 2000 chars) ===
{quality_xml}

Provide a JSON response with exactly this structure:
{{
  "target": "{target}",
  "build_status": "success|failed|warning",
  "compilation_errors": [
    {{
      "file": "filename.cpp",
      "line": "line number or unknown",
      "error": "exact error message",
      "root_cause": "plain-language explanation",
      "fix": "exact code or config change to apply"
    }}
  ],
  "warnings": [
    {{
      "type": "warning type",
      "description": "description",
      "impact": "low|medium|high"
    }}
  ],
  "unit_test_status": "pass|fail|not_implemented",
  "unit_test_findings": [
    {{
      "test": "test name or area",
      "result": "pass|fail|missing",
      "note": "recommendation"
    }}
  ],
  "quality_gate_errors": 0,
  "quality_gate_status": "pass|fail|not_run",
  "prioritised_actions": [
    "Action 1 — most critical",
    "Action 2",
    "Action 3"
  ],
  "overall_health": "healthy|degraded|broken",
  "summary": "2-3 sentence executive summary"
}}"""),
    ])

    chain = prompt | llm | StrOutputParser()

    print("[Debug Agent] Calling Groq LLM...")
    raw = chain.invoke({
        "target":           target,
        "build_log":        build_log,
        "unit_test_summary": unit_test_summary,
        "quality_xml":      quality_xml[:2000],
    })

    # Parse JSON
    try:
        clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        report = json.loads(clean)
    except json.JSONDecodeError:
        print("[Debug Agent] Warning: could not parse JSON — saving raw")
        report = {
            "target": target,
            "raw_response": raw,
            "parse_error": True,
        }

    # Save
    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"debug-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Debug Agent] Report saved: {out}")

    status = report.get("overall_health", "unknown")
    errors = len(report.get("compilation_errors", []))
    print(f"[Debug Agent] Done — health={status}, errors={errors}")
    return report


if __name__ == "__main__":

    report = run_debug_agent()
    print(json.dumps(report, indent=2))
