"""
Agent 4 — Test Generation Agent  (Stage 5)

FIX: robust JSON parsing for responses containing C++ code blocks.
The LLM often puts unescaped newlines inside the "test_file_content"
string, which makes json.loads() crash. The fix:
  1. Try standard json.loads() first.
  2. If it fails, use regex to extract each field individually — this
     handles the case where only the code block has bad escaping.
  3. As a last resort, extract the raw C++ block with a regex and save
     it directly as the .cpp file, so the test file is never lost.
"""

import json
import os
import re
from pathlib import Path
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

TARGET      = os.getenv("TARGET_CHIP", "esp32c3")
SOURCE_BASE = Path(os.getenv("EXAMPLE_PATH",
                             "esp-matter/examples/light/main"))
REPORTS     = Path("reports")

SOURCE_FILES = ["app_main.cpp", "app_driver.cpp", "app_priv.h"]

CANDIDATE_DIRS = [
    SOURCE_BASE / "main",
    Path.home() / "esp-matter" / "examples" / "light" / "main",
    Path("/opt/espressif/esp-matter/examples/light/main"),
    Path("esp-matter/examples/light/main"),
    Path("../esp-matter/examples/light/main"),
]


# ── helpers ────────────────────────────────────────────────────────

def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _find_source_dir() -> Path | None:
    for c in CANDIDATE_DIRS:
        r = c.resolve()
        if r.is_dir() and (list(r.glob("*.cpp")) + list(r.glob("*.c"))):
            return r
    return None


def _load_source_files() -> dict[str, str]:
    src_dir = _find_source_dir()
    sources = {}
    if src_dir:
        for name in SOURCE_FILES:
            p = src_dir / name
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                if content:
                    sources[name] = content
            except Exception:
                pass
    return sources


def _summarise_existing_tests(result: dict) -> str:
    if not result:
        return "No existing test data."
    if result.get("status") == "no_tests_yet":
        return (
            "No tests have been implemented yet.\n"
            f"Note: {result.get('note', '')}\n"
            "Generate a COMPLETE test suite from scratch."
        )
    return (
        f"Existing: passed={result.get('passed',0)}, "
        f"failed={result.get('failed',0)}\n"
        "Generate ADDITIONAL tests not already covered."
    )


# ── robust JSON parsing ────────────────────────────────────────────

def _robust_parse(raw: str, target: str) -> dict:
    """
    Three-level fallback parser for LLM JSON responses that contain
    C++ code blocks with unescaped newlines.
    """

    # Level 1 — standard parse after stripping markdown fences
    clean = raw.strip()
    for fence in ("```json", "```"):
        if clean.startswith(fence):
            clean = clean[len(fence):]
    clean = clean.rstrip("`").strip()

    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass

    # Level 2 — replace literal newlines inside string values
    # Strategy: temporarily replace \n inside quoted strings
    try:
        # Replace unescaped newlines inside JSON strings
        fixed = re.sub(
            r'("(?:[^"\\]|\\.)*")',
            lambda m: m.group(0).replace('\n', '\\n').replace('\r', '\\r'),
            clean,
            flags=re.DOTALL
        )
        return json.loads(fixed)
    except Exception:
        pass

    # Level 3 — manual field extraction with regex
    print("[Test Gen Agent] Attempting manual field extraction...")

    report = {
        "target": target,
        "parse_error": True,
        "parse_recovered": True,
    }

    # Extract test_file_content (everything between the first pair of quotes
    # after "test_file_content":)
    cpp_match = re.search(
        r'"test_file_content"\s*:\s*"(.*?)(?<!\\)"(?=\s*[,}])',
        clean, re.DOTALL
    )
    if cpp_match:
        cpp = cpp_match.group(1)
        cpp = cpp.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
        report["test_file_content"] = cpp
        print(f"[Test Gen Agent] Recovered test_file_content "
              f"({len(cpp)} chars)")

    # Extract summary
    sum_match = re.search(
        r'"summary"\s*:\s*"(.*?)(?<!\\)"', clean, re.DOTALL
    )
    if sum_match:
        report["summary"] = sum_match.group(1).replace('\\n', ' ')

    # Extract test_cases array (simplified)
    cases = re.findall(
        r'"name"\s*:\s*"([^"]+)".*?"type"\s*:\s*"([^"]+)".*?"area"\s*:\s*"([^"]+)"',
        clean, re.DOTALL
    )
    if cases:
        report["test_cases"] = [
            {"name": n, "type": t, "area": a} for n, t, a in cases
        ]

    # Extract mock files
    mocks = re.findall(
        r'"filename"\s*:\s*"([^"]+)".*?"content"\s*:\s*"(.*?)(?<!\\)"(?=\s*\})',
        clean, re.DOTALL
    )
    if mocks:
        report["mock_files"] = [
            {
                "filename": fn,
                "content":  content.replace('\\n', '\n').replace('\\"', '"')
            }
            for fn, content in mocks
        ]

    # If nothing recovered, save the raw response so it is not lost
    if "test_file_content" not in report:
        print("[Test Gen Agent] Could not recover test_file_content — "
              "saving raw response")
        report["raw_response"] = raw

    return report


# ── main agent function ─────────────────────────────────────────────

def run_test_gen_agent(target: str = TARGET) -> dict:
    print(f"\n[Test Gen Agent] Starting for target: {target}")

    unit_test_results = _load_json(REPORTS / "unit-test-results.json")
    existing_summary  = _summarise_existing_tests(unit_test_results)

    sources     = _load_source_files()
    source_text = "\n\n".join(
        f"=== {name} ===\n{content[:2000]}"
        for name, content in sources.items()
    )
    if not sources:
        source_text = "Source files not found — generating generic tests."

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.2,
        max_tokens=3000,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert embedded systems test engineer for
ESP32 / ESP-IDF / ESP-Matter firmware using the Unity framework.
CRITICAL: In your JSON response, ALL newlines inside string values MUST be
escaped as \\n — never use literal newlines inside JSON strings.
Respond with a valid JSON object only — no markdown, no backticks."""),

        ("human", """Generate unit and integration tests for ESP-Matter light.
Target: {target}

=== EXISTING TEST STATUS ===
{existing_summary}

=== SOURCE CODE ===
{source_text}

Respond with exactly this JSON (escape ALL newlines in code as \\n):
{{
  "target": "{target}",
  "test_file_name": "test_light_app_{target}.cpp",
  "existing_coverage": "none",
  "test_file_content": "#include <unity.h>\\n/* all code on one logical line, newlines as \\\\n */",
  "mock_files": [
    {{"filename": "mock_led_driver.h", "content": "/* content with \\\\n for newlines */"}},
    {{"filename": "mock_gpio.h",       "content": "/* content with \\\\n for newlines */"}}
  ],
  "test_cases": [
    {{
      "name": "test_on_off_cluster_toggle",
      "type": "unit",
      "area": "on_off",
      "description": "Verifies on/off cluster toggle",
      "framework_call": "TEST_ASSERT_EQUAL(expected, actual)"
    }}
  ],
  "edge_cases_covered": [
    "NULL pointer handling",
    "Invalid attribute values",
    "WiFi disconnection during commissioning",
    "Memory allocation failure"
  ],
  "sdk_integration_points": [
    {{
      "function": "esp_matter::attribute::update()",
      "test_approach": "Mock attribute to test update function"
    }}
  ],
  "run_instructions": "idf.py build -DTEST_BUILD=1 && idf.py flash monitor",
  "summary": "Test suite for ESP-Matter light firmware on {target}"
}}"""),
    ])

    chain = prompt | llm | StrOutputParser()

    print("[Test Gen Agent] Calling Groq LLM...")
    raw = chain.invoke({
        "target":           target,
        "existing_summary": existing_summary,
        "source_text":      source_text,
    })

    # Robust parse — handles unescaped newlines in code strings
    report = _robust_parse(raw, target)

    if report.get("parse_error") and not report.get("parse_recovered"):
        print("[Test Gen Agent] Warning: JSON parse failed — raw saved")
    elif report.get("parse_recovered"):
        print("[Test Gen Agent] JSON recovered via manual extraction")
    else:
        print("[Test Gen Agent] JSON parsed successfully")

    REPORTS.mkdir(exist_ok=True)

    # Save JSON report
    out_json = REPORTS / f"testgen-report-{target}.json"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Save generated C++ test file
    cpp_content = report.get("test_file_content", "")
    if cpp_content:
        out_cpp = REPORTS / f"generated_tests_{target}.cpp"
        out_cpp.write_text(cpp_content, encoding="utf-8")
        print(f"[Test Gen Agent] C++ test file saved: {out_cpp} "
              f"({len(cpp_content)} chars)")
    else:
        print("[Test Gen Agent] Warning: no test_file_content in report")

    # Save mock files
    for mock in report.get("mock_files", []):
        fn   = mock.get("filename", "mock_unknown.h")
        cont = mock.get("content", "")
        (REPORTS / fn).write_text(cont, encoding="utf-8")
        print(f"[Test Gen Agent] Mock saved: {fn}")

    n_tests = len(report.get("test_cases", []))
    print(f"[Test Gen Agent] Report saved: {out_json}")
    print(f"[Test Gen Agent] Done — {n_tests} test cases, "
          f"cpp={'yes' if cpp_content else 'no'}")
    return report


if __name__ == "__main__":
    report = run_test_gen_agent()
    print(json.dumps(report, indent=2))
