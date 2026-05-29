# ================================================================
# CODE REVIEW AGENT — Stage 1
# CORRECTION v7 : ajoute quality_score (entier 0-10) directement
# dans le JSON — le backend n'a plus besoin d'extraire depuis markdown.
# ================================================================
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv
import json, os, re
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
Example format: "Quality Score: 6/10"
"""
)

chain = prompt | llm | StrOutputParser()


def _extract_score(text: str) -> int | None:
    """
    Extrait le score numérique (0-10) depuis le markdown.
    Cherche : "6/10", "Score: 6", "score: 6 out of 10", "Quality Score: 6/10".
    Retourne None si non trouvé.
    """
    # Section ## QUALITY SCORE
    m = re.search(
        r"##\s*QUALITY\s*SCORE\b(.*?)(?=##|$)",
        text, flags=re.I | re.S
    )
    if m:
        section = re.sub(r"\bfrom\s*0\s*to\s*10\b", "", m.group(1), flags=re.I)
        scores = re.findall(r"\b(\d{1,2})\s*/\s*10\b", section)
        if scores:
            n = int(scores[-1])
            if 0 <= n <= 10:
                return n

    # Patterns génériques
    for pat in (
        r"(?:quality|overall|final)\s*score\s*[:\-=]?\s*(\d{1,2})\s*(?:/\s*10)?",
        r"(\d{1,2})\s*(?:out of|/)\s*10\b",
        r"score\s*[:\-=]\s*(\d{1,2})\b",
    ):
        matches = re.findall(pat, text, flags=re.I)
        if matches:
            valid = [int(s) for s in matches if 0 <= int(s) <= 10]
            if valid:
                return valid[-1]
    return None


def read_file(path: str) -> str:
    if os.path.exists(path):
        with open(path, "r", errors="ignore") as f:
            content = f.read()
            print(f"  ✅ Read: {path} ({len(content)} chars)")
            return content
    print(f"  ⚠️  Not found: {path}")
    return f"// File not found: {path}"


def resolve_source_path(source_path: str) -> str:
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

    # ── CORRECTION : extraire quality_score comme entier ──────────
    quality_score = _extract_score(result)
    if quality_score is None:
        quality_score = 5   # valeur par défaut si LLM ne donne pas de score
        print(f"  ⚠️  Score not found in markdown — defaulting to {quality_score}/10")
    else:
        print(f"  ✅ Quality score extracted: {quality_score}/10")

    report = {
        "agent":          "code_review_agent",
        "timestamp":      datetime.now().isoformat(),
        "target":         target,
        "source_path":    resolved_path,
        "files_reviewed": ["app_main.cpp", "app_driver.cpp", "app_priv.h"],
        "review":         result,         # texte markdown complet
        "quality_score":  quality_score,  # ← NOUVEAU : entier 0-10 direct
        "score":          quality_score,  # ← alias pour compatibilité orchestrateur
        "issues":         [],             # ← NOUVEAU : liste vide (pas d'issues structurées)
        "status":         "completed"
    }

    os.makedirs("reports", exist_ok=True)
    out_path = f"reports/code-review-{target}.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Report saved: {out_path}")
    return report


if __name__ == "__main__":
    run_code_review_agent(
        source_path=os.getenv(
            "EXAMPLE_PATH",
            os.path.expanduser("~/esp-matter/examples/light/main")
        ),
        target=os.getenv("TARGET_CHIP", "esp32c3")
    )
