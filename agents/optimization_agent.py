"""
CORRECTION pour agents/optimization_agent.py
Remplace la fonction _parse_size_report ET le bloc prompt principal.

PROBLÈME : quand size report absent, le LLM reçoit "Size data not available"
et retourne flash_pct=0.0 au lieu d'estimer depuis les composants.

CORRECTION :
  1. _parse_size_report retourne des valeurs par défaut réalistes pour ESP-Matter
  2. Le prompt indique explicitement au LLM d'estimer quand les données manquent
  3. Un fallback_mode est injecté dans le prompt
"""

import json
import os
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

# ESP32-C3 memory limits
ESP32C3_FLASH_TOTAL = 4 * 1024 * 1024   # 4 MB
ESP32C3_DRAM_TOTAL  = 400 * 1024         # 400 KB
ESP32C3_IRAM_TOTAL  = 400 * 1024         # 400 KB

# Valeurs typiques ESP-Matter light (utilisées comme fallback)
ESP_MATTER_TYPICAL = {
    "flash_used_kb": 1800,   # ESP-Matter utilise ~1.7-2.0 MB typiquement
    "dram_used_kb":  180,    # ~180 KB DRAM
    "iram_used_kb":  120,    # ~120 KB IRAM
}


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
    main = SOURCE_BASE / "app_main.cpp"
    # Chercher dans plusieurs endroits
    candidates = [
        main,
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


def _check_signing_status(target: str) -> tuple:
    fw_dir = FIRMWARE / target
    if fw_dir.exists():
        signed_bins = list(fw_dir.glob("*-signed.bin"))
        if signed_bins:
            return True, f"{len(signed_bins)} signed binary(ies) found"
    return False, "No signed binaries — Secure Boot V2 not active"


def _parse_size_report(size_txt: str) -> dict:
    """
    Parse idf.py size output.
    CORRECTION: retourne des valeurs typiques ESP-Matter si le rapport est absent,
    au lieu de 0 qui induit le LLM en erreur.
    """
    if not size_txt or "not available" in size_txt.lower():
        # Valeurs typiques pour ESP-Matter light sur ESP32-C3
        return {
            "flash_used": ESP_MATTER_TYPICAL["flash_used_kb"] * 1024,
            "dram_used":  ESP_MATTER_TYPICAL["dram_used_kb"]  * 1024,
            "iram_used":  ESP_MATTER_TYPICAL["iram_used_kb"]  * 1024,
            "raw":        size_txt[:200],
            "is_estimate": True,   # Flag pour le LLM
        }

    result = {
        "flash_used": 0,
        "dram_used":  0,
        "iram_used":  0,
        "raw":        size_txt[:500],
        "is_estimate": False,
    }
    for line in size_txt.splitlines():
        line_lower = line.lower()
        if "flash" in line_lower and ":" in line:
            try:
                result["flash_used"] = int(line.split(":")[1].strip().split()[0])
            except Exception:
                pass
        if "dram" in line_lower and ":" in line:
            try:
                result["dram_used"] = int(line.split(":")[1].strip().split()[0])
            except Exception:
                pass
        if "iram" in line_lower and ":" in line:
            try:
                result["iram_used"] = int(line.split(":")[1].strip().split()[0])
            except Exception:
                pass

    # Si parse a échoué (tous à 0), utiliser les valeurs typiques
    if result["flash_used"] == 0 and result["dram_used"] == 0:
        result["flash_used"] = ESP_MATTER_TYPICAL["flash_used_kb"] * 1024
        result["dram_used"]  = ESP_MATTER_TYPICAL["dram_used_kb"]  * 1024
        result["iram_used"]  = ESP_MATTER_TYPICAL["iram_used_kb"]  * 1024
        result["is_estimate"] = True

    return result


def run_optimization_agent(target: str = TARGET) -> dict:
    print(f"\n[Optimization Agent] Starting for target: {target}")

    size_txt       = _read(REPORTS / f"size-{target}.txt")
    components_txt = _read(REPORTS / f"size-components-{target}.txt")
    source_snippet = _load_source_snippet()
    signed, sign_note = _check_signing_status(target)
    parsed_size    = _parse_size_report(size_txt)

    is_estimate = parsed_size.get("is_estimate", False)

    signing_context = (
        f"Secure Boot V2 ACTIVE — adds ~4KB overhead per binary.\n{sign_note}"
        if signed else
        f"Secure Boot V2 NOT active.\n{sign_note}"
    )

    # CORRECTION: message explicite pour le LLM quand données absentes
    if not size_txt or "not available" in size_txt.lower():
        print("[Optimization Agent] Size report not found — using typical ESP-Matter values")
        size_context = (
            f"SIZE REPORT: Not available (build not run locally).\n"
            f"Using TYPICAL values for ESP-Matter Light on ESP32-C3:\n"
            f"  Flash used: ~{ESP_MATTER_TYPICAL['flash_used_kb']} KB / 4096 KB (~44%)\n"
            f"  DRAM used:  ~{ESP_MATTER_TYPICAL['dram_used_kb']} KB / 400 KB (~45%)\n"
            f"  IRAM used:  ~{ESP_MATTER_TYPICAL['iram_used_kb']} KB / 400 KB (~30%)\n"
            f"Use these estimates in your analysis. Mark all values as estimates.\n"
            f"Note: ESP-Matter adds significant overhead (~800KB) over basic ESP-IDF."
        )
    else:
        flash_kb = parsed_size["flash_used"] // 1024
        dram_kb  = parsed_size["dram_used"]  // 1024
        iram_kb  = parsed_size["iram_used"]  // 1024
        size_context = (
            f"SIZE REPORT (from idf.py size):\n"
            f"  Flash used: {flash_kb} KB / 4096 KB ({flash_kb/4096*100:.1f}%)\n"
            f"  DRAM used:  {dram_kb} KB / 400 KB ({dram_kb/400*100:.1f}%)\n"
            f"  IRAM used:  {iram_kb} KB / 400 KB ({iram_kb/400*100:.1f}%)\n"
            f"{size_txt[:1500]}"
        )

    if len(components_txt) > 3000:
        components_txt = components_txt[:3000]

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1,
        max_tokens=2500,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert ESP32 firmware optimization engineer.
You analyse idf.py size output and provide concrete memory optimization recommendations.
When exact data is unavailable, use typical ESP-Matter values and mark them as estimates.
IMPORTANT: Never output 0.0 for flash_pct — use the provided estimates if real data missing.
Always respond with a valid JSON object only — no markdown, no backticks."""),

        ("human", """Analyse firmware memory usage for: {target}

ESP32-C3 Memory Limits:
- Flash total: 4096 KB
- DRAM total:  400 KB
- IRAM total:  400 KB

=== MEMORY DATA ===
{size_context}

=== COMPONENT BREAKDOWN ===
{components_txt}

=== SECURE BOOT STATUS ===
{signing_context}

=== SOURCE CONTEXT ===
{source_snippet}

DATA AVAILABILITY: {data_availability}

Provide JSON with exactly this structure:
{{
  "target": "{target}",
  "data_source": "real_build|estimate",

  "memory_usage": {{
    "flash_used_kb": 1800,
    "flash_total_kb": 4096,
    "flash_pct": 43.9,
    "flash_risk": "ok|warning|critical",

    "dram_used_kb": 180,
    "dram_total_kb": 400,
    "dram_pct": 45.0,
    "dram_risk": "ok|warning|critical",

    "iram_used_kb": 120,
    "iram_total_kb": 400,
    "iram_pct": 30.0,
    "iram_risk": "ok|warning|critical"
  }},

  "signing_overhead": {{
    "active": false,
    "overhead_kb": 4,
    "note": "Secure Boot V2 adds ~4KB per binary"
  }},

  "top_components": [
    {{
      "name": "esp-matter",
      "flash_kb": 800,
      "dram_kb": 50,
      "reducible": true,
      "how_to_reduce": "Disable unused clusters in menuconfig"
    }}
  ],

  "optimisation_recommendations": [
    {{
      "title": "Enable compiler size optimisation",
      "change": "CONFIG_COMPILER_OPTIMIZATION_SIZE=y in sdkconfig",
      "estimated_saving_kb": 20,
      "effort": "low",
      "risk": "none"
    }}
  ],

  "sdkconfig_flags": [
    "CONFIG_COMPILER_OPTIMIZATION_SIZE=y",
    "CONFIG_NEWLIB_NANO_FORMAT=y"
  ],

  "total_estimated_saving_kb": 20,
  "ota_partition_feasible": true,
  "ota_recommendation": "OTA requires 2×app partition. With current size, feasible with 4MB flash.",

  "summary": "2-3 sentence summary of memory health and top optimization wins"
}}"""),
    ])

    chain = prompt | llm | StrOutputParser()

    print("[Optimization Agent] Calling Groq LLM...")
    raw = chain.invoke({
        "target":          target,
        "size_context":    size_context,
        "components_txt":  components_txt if components_txt else "Component breakdown not available.",
        "signing_context": signing_context,
        "source_snippet":  source_snippet,
        "data_availability": "ESTIMATES (build not run locally)" if is_estimate else "REAL DATA from idf.py size",
    })

    try:
        clean  = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        report = json.loads(clean)
    except json.JSONDecodeError:
        print("[Optimization Agent] Warning: JSON parse failed — using fallback report")
        # Fallback manuel avec les valeurs typiques
        report = {
            "target":      target,
            "data_source": "estimate",
            "memory_usage": {
                "flash_used_kb":  ESP_MATTER_TYPICAL["flash_used_kb"],
                "flash_total_kb": 4096,
                "flash_pct":      round(ESP_MATTER_TYPICAL["flash_used_kb"] / 4096 * 100, 1),
                "flash_risk":     "ok",
                "dram_used_kb":   ESP_MATTER_TYPICAL["dram_used_kb"],
                "dram_total_kb":  400,
                "dram_pct":       round(ESP_MATTER_TYPICAL["dram_used_kb"] / 400 * 100, 1),
                "dram_risk":      "ok",
                "iram_used_kb":   ESP_MATTER_TYPICAL["iram_used_kb"],
                "iram_total_kb":  400,
                "iram_pct":       round(ESP_MATTER_TYPICAL["iram_used_kb"] / 400 * 100, 1),
                "iram_risk":      "ok",
            },
            "optimisation_recommendations": [
                {
                    "title":               "Enable compiler size optimisation",
                    "change":              "CONFIG_COMPILER_OPTIMIZATION_SIZE=y",
                    "estimated_saving_kb": 20,
                    "effort":              "low",
                    "risk":                "none",
                }
            ],
            "sdkconfig_flags":          ["CONFIG_COMPILER_OPTIMIZATION_SIZE=y"],
            "total_estimated_saving_kb": 20,
            "ota_partition_feasible":    True,
            "summary":                  "Memory estimates based on typical ESP-Matter light firmware. Run 'idf.py size' for exact values.",
            "parse_error":              True,
        }

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"optimization-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Optimization Agent] Report saved: {out}")
    saving = report.get("total_estimated_saving_kb", 0)
    flash_pct = report.get("memory_usage", {}).get("flash_pct", "N/A")
    print(f"[Optimization Agent] Done — flash={flash_pct}% | saving={saving}KB")
    return report


if __name__ == "__main__":
    report = run_optimization_agent()
    print(json.dumps(report, indent=2))
