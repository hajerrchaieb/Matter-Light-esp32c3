"""
agents/optimization_agent.py — Agent 5 : Optimization + Release Agent
======================================================================
MERGED: Release Agent functionality integrated here.
release_agent.py is no longer needed — remove it from orchestrator imports.

FIXES vs previous version:
  FIX 1 — _parse_size_report returns realistic ESP-Matter estimates when missing
  FIX 2 — Prompt never gets flash_pct=0 (LLM was confused by zero values)
  FIX 3 — Release changelog generated here (merged from release_agent)
  FIX 4 — Enhanced prompts with concrete ESP32-C3 + Matter context
"""

import json
import os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

TARGET      = os.getenv("TARGET_CHIP", "esp32c3")
SOURCE_BASE = Path(os.getenv("EXAMPLE_PATH", "esp-matter/examples/light/main"))
REPORTS     = Path("reports")
FIRMWARE    = Path("firmware")

# ESP32-C3 hardware limits
ESP32C3_FLASH_TOTAL = 4 * 1024 * 1024   # 4 MB
ESP32C3_DRAM_TOTAL  = 400 * 1024
ESP32C3_IRAM_TOTAL  = 400 * 1024

# Typical ESP-Matter light firmware footprint (used when size report absent)
ESP_MATTER_TYPICAL = {
    "flash_used_kb": 1800,
    "dram_used_kb":  180,
    "iram_used_kb":  120,
}


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


def _load_source_snippet() -> str:
    candidates = [
        SOURCE_BASE / "app_main.cpp",
        Path("../esp-matter/examples/light/main/app_main.cpp"),
        Path("/opt/espressif/esp-matter/examples/light/main/app_main.cpp"),
    ]
    for c in candidates:
        try:
            content = c.read_text(encoding="utf-8", errors="ignore")
            if content:
                return content[:2000]
        except Exception:
            pass
    return "Source not found."


def _check_signing_status(target: str) -> tuple[bool, str]:
    fw_dir = FIRMWARE / target
    if fw_dir.exists():
        signed_bins = list(fw_dir.glob("*-signed.bin"))
        if signed_bins:
            return True, f"{len(signed_bins)} signed binary(ies) found"
    return False, "No signed binaries — Secure Boot V2 not active"


def _parse_size_report(size_txt: str) -> dict:
    """
    Parse idf.py size output.
    Returns realistic ESP-Matter estimates when report is absent.
    Never returns zeros (which confuse the LLM into outputting flash_pct=0).
    """
    if not size_txt or "not available" in size_txt.lower() or len(size_txt.strip()) < 20:
        return {
            "flash_used": ESP_MATTER_TYPICAL["flash_used_kb"] * 1024,
            "dram_used":  ESP_MATTER_TYPICAL["dram_used_kb"]  * 1024,
            "iram_used":  ESP_MATTER_TYPICAL["iram_used_kb"]  * 1024,
            "raw":        "",
            "is_estimate": True,
        }

    result = {"flash_used": 0, "dram_used": 0, "iram_used": 0,
              "raw": size_txt[:500], "is_estimate": False}

    for line in size_txt.splitlines():
        ll = line.lower()
        if "flash" in ll and ":" in line:
            try:
                result["flash_used"] = int(line.split(":")[1].strip().split()[0])
            except Exception:
                pass
        if "dram" in ll and ":" in line:
            try:
                result["dram_used"] = int(line.split(":")[1].strip().split()[0])
            except Exception:
                pass
        if "iram" in ll and ":" in line:
            try:
                result["iram_used"] = int(line.split(":")[1].strip().split()[0])
            except Exception:
                pass

    # If all zeros after parsing, use typical values
    if result["flash_used"] == 0 and result["dram_used"] == 0:
        result["flash_used"]  = ESP_MATTER_TYPICAL["flash_used_kb"] * 1024
        result["dram_used"]   = ESP_MATTER_TYPICAL["dram_used_kb"]  * 1024
        result["iram_used"]   = ESP_MATTER_TYPICAL["iram_used_kb"]  * 1024
        result["is_estimate"] = True

    return result


def _build_size_context(size_txt: str, parsed: dict) -> str:
    if parsed["is_estimate"]:
        return (
            f"SIZE REPORT: Not available from build. Using TYPICAL values for ESP-Matter Light on ESP32-C3:\n"
            f"  Flash used : ~{ESP_MATTER_TYPICAL['flash_used_kb']} KB / 4096 KB "
            f"(~{ESP_MATTER_TYPICAL['flash_used_kb']/4096*100:.1f}%)\n"
            f"  DRAM used  : ~{ESP_MATTER_TYPICAL['dram_used_kb']} KB / 400 KB "
            f"(~{ESP_MATTER_TYPICAL['dram_used_kb']/400*100:.1f}%)\n"
            f"  IRAM used  : ~{ESP_MATTER_TYPICAL['iram_used_kb']} KB / 400 KB "
            f"(~{ESP_MATTER_TYPICAL['iram_used_kb']/400*100:.1f}%)\n"
            f"Note: These are ESTIMATES — run 'idf.py size' for exact values.\n"
            f"ESP-Matter adds ~800KB overhead over basic ESP-IDF."
        )
    fk = parsed["flash_used"] // 1024
    dk = parsed["dram_used"]  // 1024
    ik = parsed["iram_used"]  // 1024
    return (
        f"SIZE REPORT (real data from idf.py size):\n"
        f"  Flash used : {fk} KB / 4096 KB ({fk/4096*100:.1f}%)\n"
        f"  DRAM used  : {dk} KB / 400 KB  ({dk/400*100:.1f}%)\n"
        f"  IRAM used  : {ik} KB / 400 KB  ({ik/400*100:.1f}%)\n"
        f"{size_txt[:1500]}"
    )


# ── MERGED RELEASE SECTION ─────────────────────────────────────────

def _generate_changelog(
    target: str,
    version: str,
    security_report: dict,
    debug_report: dict,
    optimization_report: dict,
    autofix_report: dict,
    testgen_report: dict,
    llm: ChatGroq,
) -> str:
    """Generate release changelog text (merged from release_agent)."""

    sec_score    = security_report.get("security_score", "N/A")
    n_secrets    = len(security_report.get("secrets_found", []))
    n_cves       = len(security_report.get("critical_cves", []))
    build_status = debug_report.get("build_status") or debug_report.get("overall_health", "unknown")
    n_patches    = autofix_report.get("patches_generated", 0)
    n_tests      = len(testgen_report.get("test_cases", []))
    flash_pct    = optimization_report.get("memory_usage", {}).get("flash_pct", "N/A")
    saving_kb    = optimization_report.get("total_estimated_saving_kb", 0)

    patches_detail = ""
    for p in autofix_report.get("patches_detail", []):
        patches_detail += f"  - [{p.get('severity','?').upper()}] {p.get('description','')[:100]}\n"

    changelog_prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a technical writer for embedded IoT firmware releases.
Write a professional, concrete changelog. Use emoji section headers.
Be specific about what was fixed, detected, and tested.
Return ONLY the markdown text — no JSON, no code blocks."""),

        ("human", f"""Write a CHANGELOG for firmware release {version} — target {target}

KEY METRICS:
  Security score : {sec_score}/10
  Secrets found  : {n_secrets} (0 = clean)
  Critical CVEs  : {n_cves}
  Build          : {build_status}
  AI patches     : {n_patches}
  Tests generated: {n_tests}
  Flash usage    : {flash_pct}%
  Potential saving: {saving_kb} KB

PATCHES APPLIED:
{patches_detail if patches_detail else "  No patches applied this release."}

Write sections: ✨ New Features, 🐛 Bug Fixes, 🔐 Security, ⚡ Performance, 🔍 Code Quality, ✅ Quality Gates, ⚠️ Known Issues, 🔜 Next Release
Keep each section to 3-5 bullet points. Be specific to ESP32/Matter/esp-idf context.
"""),
    ])

    try:
        changelog = (changelog_prompt | llm | StrOutputParser()).invoke({})
        return changelog
    except Exception as e:
        print(f"[Optimization Agent] Changelog generation failed: {e}")
        return f"## CHANGELOG — {version}\n\n- Build: {build_status}\n- Security score: {sec_score}/10\n- AutoFix patches: {n_patches}\n"


# ── main agent function ─────────────────────────────────────────────

def run_optimization_agent(
    target:   str = TARGET,
    version:  str = "v1.0.0",
) -> dict:
    print(f"\n[Optimization Agent] Starting for target: {target}")

    size_txt       = _read(REPORTS / f"size-{target}.txt")
    components_txt = _read(REPORTS / f"size-components-{target}.txt")
    source_snippet = _load_source_snippet()
    signed, sign_note = _check_signing_status(target)
    parsed_size    = _parse_size_report(size_txt)
    size_context   = _build_size_context(size_txt, parsed_size)

    # Load sibling agent reports for changelog (merged release functionality)
    security_report  = _load_json(REPORTS / f"security-report-{target}.json")
    debug_report     = _load_json(REPORTS / f"debug-report-{target}.json")
    autofix_report   = _load_json(REPORTS / f"autofix-report-{target}.json")
    testgen_report   = _load_json(REPORTS / f"testgen-report-{target}.json")

    signing_context = (
        f"Secure Boot V2 ACTIVE — adds ~4KB overhead per binary.\n{sign_note}"
        if signed else
        f"Secure Boot V2 NOT active.\n{sign_note}"
    )

    if len(components_txt) > 3000:
        components_txt = components_txt[:3000]

    data_source = "estimate" if parsed_size["is_estimate"] else "real_build"

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.0,
        max_tokens=2500,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert ESP32 firmware optimization engineer.
You analyse idf.py size output and provide concrete memory optimization recommendations
for ESP32-C3 running ESP-IDF + ESP-Matter (IoT smart light example).

ESP-Matter context:
- Base ESP-IDF: ~300KB flash
- Matter SDK (CHIP): adds ~800KB flash, ~60KB DRAM
- LED driver: ~10KB flash
- WiFi/BLE stack: ~200KB flash

RULES:
- NEVER output 0.0 for any percentage — use estimates if real data missing
- Mark all values as estimates when size report is not from a real build
- Provide concrete sdkconfig changes (not vague "optimize code" advice)
- Always respond with valid JSON only — no markdown, no backticks."""),

        ("human", """Analyse firmware memory for: {target}

ESP32-C3 Limits: Flash=4096KB | DRAM=400KB | IRAM=400KB

=== MEMORY DATA ({data_source}) ===
{size_context}

=== COMPONENT BREAKDOWN ===
{components_txt}

=== SECURE BOOT STATUS ===
{signing_context}

=== SOURCE CONTEXT (app_main.cpp excerpt) ===
{source_snippet}

Provide JSON with exactly this structure:
{{
  "target": "{target}",
  "data_source": "{data_source}",

  "memory_usage": {{
    "flash_used_kb": 1800,
    "flash_total_kb": 4096,
    "flash_pct": 43.9,
    "flash_risk": "ok",

    "dram_used_kb": 180,
    "dram_total_kb": 400,
    "dram_pct": 45.0,
    "dram_risk": "ok",

    "iram_used_kb": 120,
    "iram_total_kb": 400,
    "iram_pct": 30.0,
    "iram_risk": "ok"
  }},

  "signing_overhead": {{
    "active": false,
    "overhead_kb": 4,
    "note": "Secure Boot V2 adds ~4KB per binary"
  }},

  "top_components": [
    {{
      "name": "esp-matter (CHIP SDK)",
      "flash_kb": 800,
      "dram_kb": 60,
      "reducible": true,
      "how_to_reduce": "Disable unused clusters in menuconfig: CONFIG_ENABLE_CHIP_SHELL=n"
    }},
    {{
      "name": "esp-wifi",
      "flash_kb": 200,
      "dram_kb": 50,
      "reducible": false,
      "how_to_reduce": "Required for Matter over WiFi"
    }}
  ],

  "optimisation_recommendations": [
    {{
      "title": "Enable compiler size optimisation",
      "change": "CONFIG_COMPILER_OPTIMIZATION_SIZE=y in sdkconfig.defaults",
      "estimated_saving_kb": 30,
      "effort": "low",
      "risk": "none"
    }},
    {{
      "title": "Enable newlib nano format",
      "change": "CONFIG_NEWLIB_NANO_FORMAT=y",
      "estimated_saving_kb": 15,
      "effort": "low",
      "risk": "none"
    }},
    {{
      "title": "Disable unused Matter clusters",
      "change": "Set CONFIG_ENABLE_SCENES_CLUSTER=n, CONFIG_ENABLE_TIME_CLUSTER=n in menuconfig",
      "estimated_saving_kb": 50,
      "effort": "medium",
      "risk": "low"
    }}
  ],

  "sdkconfig_flags": [
    "CONFIG_COMPILER_OPTIMIZATION_SIZE=y",
    "CONFIG_NEWLIB_NANO_FORMAT=y",
    "CONFIG_ENABLE_CHIP_SHELL=n",
    "CONFIG_CHIP_LOG_FILTERING=y"
  ],

  "total_estimated_saving_kb": 95,
  "ota_partition_feasible": true,
  "ota_recommendation": "With 1800KB app size and 4MB flash, dual OTA partitions are feasible (2×2048KB layout).",

  "summary": "2-3 sentence summary of memory health and top optimization wins"
}}"""),
    ])

    chain = prompt | llm | StrOutputParser()

    print("[Optimization Agent] Calling Groq LLM for memory analysis...")
    raw = chain.invoke({
        "target":          target,
        "data_source":     data_source,
        "size_context":    size_context,
        "components_txt":  components_txt or "Component breakdown not available.",
        "signing_context": signing_context,
        "source_snippet":  source_snippet,
    })

    try:
        clean  = raw.strip()
        for fence in ("```json", "```"):
            if clean.startswith(fence):
                clean = clean[len(fence):]
        clean  = clean.rstrip("`").strip()
        report = json.loads(clean)
    except json.JSONDecodeError:
        print("[Optimization Agent] Warning: JSON parse failed — using fallback")
        fk = parsed_size["flash_used"] // 1024
        dk = parsed_size["dram_used"]  // 1024
        ik = parsed_size["iram_used"]  // 1024
        report = {
            "target":      target,
            "data_source": data_source,
            "memory_usage": {
                "flash_used_kb": fk, "flash_total_kb": 4096,
                "flash_pct":     round(fk / 4096 * 100, 1),
                "flash_risk":    "ok",
                "dram_used_kb":  dk, "dram_total_kb": 400,
                "dram_pct":      round(dk / 400 * 100, 1),
                "dram_risk":     "ok",
                "iram_used_kb":  ik, "iram_total_kb": 400,
                "iram_pct":      round(ik / 400 * 100, 1),
                "iram_risk":     "ok",
            },
            "optimisation_recommendations": [{
                "title": "Enable compiler size optimisation",
                "change": "CONFIG_COMPILER_OPTIMIZATION_SIZE=y",
                "estimated_saving_kb": 30, "effort": "low", "risk": "none",
            }],
            "sdkconfig_flags":          ["CONFIG_COMPILER_OPTIMIZATION_SIZE=y"],
            "total_estimated_saving_kb": 30,
            "ota_partition_feasible":    True,
            "summary":                  f"Estimates: Flash {fk}KB/{round(fk/4096*100,1)}% DRAM {dk}KB. Run idf.py size for exact values.",
            "parse_error":              True,
        }

    # ══ Generate changelog (merged from release_agent) ═════════════
    print("[Optimization Agent] Generating release changelog...")
    changelog = _generate_changelog(
        target, version, security_report, debug_report,
        report, autofix_report, testgen_report, llm,
    )

    # Save changelog
    REPORTS.mkdir(exist_ok=True)
    changelog_path = REPORTS / f"CHANGELOG-{version}.md"
    changelog_path.write_text(changelog, encoding="utf-8")

    # Build release report (replaces release_agent output)
    release_info = {
        "version":          version,
        "target":           target,
        "generated_at":     datetime.utcnow().isoformat() + "Z",
        "changelog":        changelog,
        "changelog_file":   str(changelog_path),
        "security_score":   security_report.get("security_score", "N/A"),
        "build_status":     debug_report.get("build_status") or debug_report.get("overall_health", "unknown"),
        "patches_applied":  autofix_report.get("patches_generated", 0),
        "tests_generated":  len(testgen_report.get("test_cases", [])),
        "flash_pct":        report.get("memory_usage", {}).get("flash_pct", "N/A"),
        "canary_deploy":    "simulated",
    }

    # Save release report
    release_out = REPORTS / f"release-report-{target}.json"
    release_out.write_text(json.dumps(release_info, indent=2), encoding="utf-8")

    # Add release info to optimization report
    report["release"] = release_info
    report["agent"]   = "optimization_agent"

    out = REPORTS / f"optimization-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    flash_pct = report.get("memory_usage", {}).get("flash_pct", "N/A")
    saving    = report.get("total_estimated_saving_kb", 0)
    print(f"[Optimization Agent] Done — flash={flash_pct}% | saving={saving}KB | changelog saved")
    return report


if __name__ == "__main__":
    report = run_optimization_agent()
    print(json.dumps({k: v for k, v in report.items() if k != "release"}, indent=2))
