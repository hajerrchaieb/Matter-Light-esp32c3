# ================================================================
# 🔵 CODE REVIEW AGENT — Stage 1: Qualité du code ESP32 Matter
# ================================================================
# ORIGINAL structure preserved — PromptTemplate + Markdown output
# ADDED: multi-path source resolution so it works both locally
#        (~/esp-matter/) and in CI (/opt/espressif/esp-matter/)
# ================================================================
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv
import json, os
from datetime import datetime

load_dotenv()

llm = ChatGroq(
    model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0
)

prompt = PromptTemplate(
    input_variables=["app_main", "app_driver", "app_priv", "target"],
    template="""
You are a senior ESP32 firmware engineer doing a code review.
Target chip: {target}
Framework: ESP-IDF + ESP-Matter (IoT smart light example)

=== app_main.cpp ===
{app_main}

=== app_driver.cpp ===
{app_driver}

=== app_priv.h ===
{app_priv}

## CODE QUALITY ISSUES
List all quality problems (complexity, naming, structure, comments).

## SECURITY ISSUES
Unsafe functions, buffer risks, memory leaks, hardcoded values.

## ESP32 BEST PRACTICES VIOLATIONS
ESP-IDF specific issues:
- Task stack sizes
- Heap usage
- ISR safety
- Error handling (esp_err_t checks)
- NVS usage

## ESP-MATTER SPECIFIC ISSUES
Matter protocol issues:
- Attribute handling
- Cluster configuration
- Commissioning flow

## SUGGESTED IMPROVEMENTS
Concrete code improvements with examples.

## QUALITY SCORE
Score from 0 to 10 with justification.
"""
)

chain = prompt | llm | StrOutputParser()


def read_file(path: str) -> str:
    if os.path.exists(path):
        with open(path, "r", errors="ignore") as f:
            content = f.read()
            print(f"  ✅ Read: {path} ({len(content)} chars)")
            return content
    print(f"  ⚠️  Not found: {path}")
    return f"// File not found: {path}"


def resolve_source_path(source_path: str) -> str:
    """
    Try the given path first, then fall back to known locations.
    This covers:
      - local VirtualBox: ~/esp-matter/examples/light/main
      - CI Docker runner: /opt/espressif/esp-matter/examples/light/main
      - repo submodule:   ./esp-matter/examples/light/main
    """
    candidates = [
        source_path,
        os.path.expanduser("~/esp-matter/examples/light/main"),
        "/opt/espressif/esp-matter/examples/light/main",
        os.path.join(os.getcwd(), "esp-matter/examples/light/main"),
        os.path.join(os.getcwd(), "../esp-matter/examples/light/main"),
    ]

    for candidate in candidates:
        if os.path.isdir(candidate):
            cpp_files = [
                f for f in os.listdir(candidate)
                if f.endswith(".cpp") or f.endswith(".c")
            ]
            if cpp_files:
                print(f"  📁 Source found at: {candidate}")
                return candidate

    # None found — return original so caller handles gracefully
    print(f"  ⚠️  Source not found in any candidate path")
    return source_path


def run_code_review_agent(
    source_path: str = "../esp-matter/examples/light/main",
    target: str = "esp32c3"
) -> dict:
    print(f"\n{'='*55}")
    print(f"🔵 CODE REVIEW AGENT — Stage 1")
    print(f"📁 Source : {source_path}")
    print(f"🎯 Target : {target}")
    print(f"{'='*55}")

    # Resolve actual path
    resolved_path = resolve_source_path(source_path)

    print("\n📖 Reading source files...")
    app_main   = read_file(os.path.join(resolved_path, "app_main.cpp"))
    app_driver = read_file(os.path.join(resolved_path, "app_driver.cpp"))
    app_priv   = read_file(os.path.join(resolved_path, "app_priv.h"))

    print("\n⚡ Reviewing code with Groq...\n")

    result = chain.invoke({
        "app_main":   app_main[:2000],
        "app_driver": app_driver[:2000],
        "app_priv":   app_priv[:1000],
        "target":     target
    })

    print("📋 CODE REVIEW RESULT:")
    print("-" * 55)
    print(result)
    print("-" * 55)

    # ── Same JSON structure as original — "review" key preserved ──
    report = {
        "agent":          "code_review_agent",
        "timestamp":      datetime.now().isoformat(),
        "target":         target,
        "source_path":    resolved_path,
        "files_reviewed": ["app_main.cpp", "app_driver.cpp", "app_priv.h"],
        "review":         result,   # ← release_agent reads this key
        "status":         "completed"
    }

    os.makedirs("reports", exist_ok=True)
    with open(f"reports/code-review-{target}.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Report saved: reports/code-review-{target}.json")
    return report


if __name__ == "__main__":
    run_code_review_agent(
        source_path=os.getenv(
            "EXAMPLE_PATH",
            os.path.expanduser("~/esp-matter/examples/light/main")
        ),
        target=os.getenv("TARGET_CHIP", "esp32c3")
    )
