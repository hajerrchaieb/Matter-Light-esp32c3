"""
agents/autofix_agent.py  —  Agent 8 : Auto-Fix Agent

Rôle :
  Lit tous les rapports des agents précédents et génère automatiquement
  des patches C++ appliquables avec `git apply` pour corriger les bugs
  identifiés. Priorise les CRITICAL et HIGH.

Inputs :
  reports/debug-report-{target}.json
  reports/code-review-{target}.json
  reports/security-report-{target}.json
  reports/fault-analysis-report-{target}.json

Outputs :
  reports/autofix-report-{target}.json
  reports/patches/fix_{scenario_name}.patch   (appliquable avec git apply)
  reports/patches/APPLY_ALL.sh                (script pour tout appliquer)

Usage :
  python3 agents/autofix_agent.py
  python3 agents/autofix_agent.py --apply    (applique les patches directement)
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

TARGET  = os.getenv("TARGET_CHIP", "esp32c3")
REPORTS = Path("reports")
PATCHES = Path("reports/patches")

# ── Helpers ────────────────────────────────────────────────────────

def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_source_file(filename: str) -> str:
    """Lit un fichier source ESP-Matter depuis les chemins connus."""
    candidates = [
        Path(f"../esp-matter/examples/light/main/{filename}"),
        Path(f"esp-matter/examples/light/main/{filename}"),
        Path(f"/opt/espressif/esp-matter/examples/light/main/{filename}"),
    ]
    for c in candidates:
        try:
            content = c.read_text(encoding="utf-8", errors="ignore")
            if content:
                return content
        except Exception:
            pass
    return ""


def _collect_issues(target: str) -> list[dict]:
    """
    Collecte tous les problèmes CRITICAL et HIGH depuis les rapports
    des agents précédents. Retourne une liste dédupliquée.
    """
    issues = []

    # Debug agent — erreurs de compilation
    debug = _load_json(REPORTS / f"debug-report-{target}.json")
    for err in debug.get("compilation_errors", []):
        issues.append({
            "source":    "debug_agent",
            "severity":  "critical",
            "file":      err.get("file", "unknown"),
            "location":  err.get("line", "?"),
            "problem":   err.get("error", err.get("root_cause", "?")),
            "fix_hint":  err.get("fix", ""),
            "cwe":       "",
        })

    # Code review — issues HIGH+
    review = _load_json(REPORTS / f"code-review-{target}.json")
    for issue in review.get("issues", []):
        if issue.get("severity") in ("critical", "high"):
            issues.append({
                "source":    "code_review",
                "severity":  issue.get("severity", "high"),
                "file":      issue.get("file", "app_main.cpp"),
                "location":  issue.get("location", "unknown"),
                "problem":   issue.get("description", ""),
                "fix_hint":  issue.get("good_code", ""),
                "cwe":       issue.get("cwe", ""),
            })

    # Fault analysis — scénarios échoués
    fault = _load_json(REPORTS / f"fault-analysis-report-{target}.json")
    for sc in fault.get("failed_scenarios_analysis", []):
        issues.append({
            "source":    "fault_analysis",
            "severity":  "high",
            "file":      sc.get("affected_file", "app_main.cpp"),
            "location":  "see fault scenario",
            "problem":   sc.get("root_cause", ""),
            "fix_hint":  sc.get("fix_code", ""),
            "cwe":       sc.get("cwe", ""),
        })

    # Security — CVEs et secrets
    security = _load_json(REPORTS / f"security-report-{target}.json")
    for secret in security.get("secrets_found", []):
        issues.append({
            "source":    "security",
            "severity":  "critical",
            "file":      secret.get("file", "unknown"),
            "location":  "hardcoded credential",
            "problem":   f"Hardcoded {secret.get('type','secret')} detected",
            "fix_hint":  secret.get("action", "Move to NVS or environment variable"),
            "cwe":       "CWE-798",
        })

    return issues


# ── Génération des patches via LLM ─────────────────────────────────

def run_autofix_agent(target: str = TARGET, apply_patches: bool = False) -> dict:
    print(f"\n{'='*55}")
    print(f"Agent 8 — Auto-Fix Agent")
    print(f"Target: {target}")
    print(f"{'='*55}")

    PATCHES.mkdir(parents=True, exist_ok=True)

    issues = _collect_issues(target)
    if not issues:
        print("[AutoFix] Aucun problème critique/high trouvé — rien à patcher")
        report = {
            "target":          target,
            "patches_generated": 0,
            "issues_found":    0,
            "summary":         "No critical or high issues found — no patches needed.",
            "status":          "clean",
        }
        (REPORTS / f"autofix-report-{target}.json").write_text(
            json.dumps(report, indent=2)
        )
        return report

    print(f"[AutoFix] {len(issues)} problème(s) à corriger")

    # Charger le code source
    app_main_src   = _read_source_file("app_main.cpp")
    app_driver_src = _read_source_file("app_driver.cpp")
    app_priv_src   = _read_source_file("app_priv.h")

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1,
        max_tokens=3000,
    )

    # Grouper les issues par fichier pour optimiser les tokens
    issues_by_file: dict[str, list] = {}
    for issue in issues[:8]:  # Limiter à 8 pour rester dans les tokens
        f = issue.get("file", "app_main.cpp")
        issues_by_file.setdefault(f, []).append(issue)

    all_patches = []

    for filename, file_issues in issues_by_file.items():
        # Choisir le bon source
        if "app_main" in filename:
            src = app_main_src[:3000]
        elif "app_driver" in filename:
            src = app_driver_src[:3000]
        elif "app_priv" in filename:
            src = app_priv_src[:1500]
        else:
            src = "Source not available"

        issues_txt = "\n".join([
            f"  Issue {i+1}: [{iss['severity'].upper()}] {iss['problem']}\n"
            f"    Location: {iss.get('location','?')}\n"
            f"    Hint: {iss.get('fix_hint','')[:200]}\n"
            f"    CWE: {iss.get('cwe','')}"
            for i, iss in enumerate(file_issues)
        ])

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert ESP32/ESP-IDF firmware engineer.
Generate unified diff patches (git diff format) to fix the identified issues.
Each patch must be syntactically correct C++ that compiles with ESP-IDF.

RULES:
- Patches must be in unified diff format (--- a/file, +++ b/file, @@ lines)
- Keep changes minimal — only fix what is identified
- Never break existing functionality
- All new code must follow ESP-IDF conventions (esp_err_t, ESP_LOGE, etc.)
- Respond with valid JSON only — no markdown, no backticks."""),

            ("human", """Generate fix patches for: {filename}

=== ISSUES TO FIX ===
{issues_txt}

=== CURRENT SOURCE CODE ===
{source_code}

Return exactly this JSON:
{{
  "filename": "{filename}",
  "patches": [
    {{
      "issue_id": 1,
      "title": "Add NULL check after get_light_endpoint()",
      "severity": "high",
      "cwe": "CWE-476",
      "patch_content": "--- a/main/{filename}\\n+++ b/main/{filename}\\n@@ -42,6 +42,10 @@\\n esp_matter_endpoint_t *ep = get_light_endpoint();\\n+if (!ep) {{\\n+    ESP_LOGE(TAG, \\"Light endpoint is NULL\\");\\n+    return ESP_ERR_INVALID_STATE;\\n+}}\\n esp_matter_attr_val_t val;",
      "explanation": "Prevents NULL dereference when endpoint is not initialized",
      "compilable": true
    }}
  ],
  "total_fixes": 1,
  "estimated_effort": "30 minutes to apply and test all patches"
}}"""),
        ])

        print(f"[AutoFix] Génération patch pour {filename} ({len(file_issues)} issues)...")
        raw = (prompt | llm | StrOutputParser()).invoke({
            "filename":    filename,
            "issues_txt":  issues_txt,
            "source_code": src,
        })

        try:
            clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            result = json.loads(clean)
            all_patches.append(result)

            # Sauvegarder chaque patch comme fichier .patch
            for patch in result.get("patches", []):
                patch_content = patch.get("patch_content", "")
                if patch_content:
                    # Nettoyer les \n échappés
                    patch_content = patch_content.replace("\\n", "\n")
                    patch_name = patch.get("title", "fix").replace(" ", "_")[:40]
                    patch_file = PATCHES / f"fix_{patch_name}.patch"
                    patch_file.write_text(patch_content, encoding="utf-8")
                    print(f"  [AutoFix] Patch sauvegardé: {patch_file.name}")

        except json.JSONDecodeError:
            print(f"  [AutoFix] Parse JSON failed pour {filename}")
            all_patches.append({
                "filename": filename,
                "patches":  [],
                "parse_error": True,
                "raw": raw[:200],
            })

    # Générer le script APPLY_ALL.sh
    apply_script_lines = [
        "#!/bin/bash",
        "# Auto-Fix — applique tous les patches générés",
        f"# Généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "# Usage: bash reports/patches/APPLY_ALL.sh",
        "",
        "set -e",
        "",
        "ESP_MATTER_MAIN='../esp-matter/examples/light/main'",
        "",
        "echo '=== Application des patches Auto-Fix ==='",
        "",
    ]
    patch_files = list(PATCHES.glob("*.patch"))
    for pf in patch_files:
        apply_script_lines.append(f"echo '→ Application: {pf.name}'")
        apply_script_lines.append(
            f"git apply --directory='$ESP_MATTER_MAIN' '{pf.resolve()}' || "
            f"echo '  [WARNING] Patch failed — peut-être déjà appliqué'"
        )
        apply_script_lines.append("")

    apply_script_lines.extend([
        "echo ''",
        "echo '=== Vérification compilation après patches ==='",
        "cd \"$ESP_MATTER_MAIN\"",
        "idf.py build 2>&1 | tail -5",
        "echo 'done'",
    ])

    apply_script = PATCHES / "APPLY_ALL.sh"
    apply_script.write_text("\n".join(apply_script_lines))
    apply_script.chmod(0o755)
    print(f"[AutoFix] Script généré: {apply_script}")

    # Appliquer les patches si demandé
    if apply_patches and patch_files:
        print("[AutoFix] Application des patches...")
        for pf in patch_files:
            try:
                result = subprocess.run(
                    ["git", "apply", "--check", str(pf)],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    subprocess.run(["git", "apply", str(pf)])
                    print(f"  [AutoFix] ✓ {pf.name} appliqué")
                else:
                    print(f"  [AutoFix] ⚠ {pf.name} inapplicable: {result.stderr[:100]}")
            except Exception as e:
                print(f"  [AutoFix] Erreur: {e}")

    # Rapport final
    total_patches = sum(len(p.get("patches", [])) for p in all_patches)
    report = {
        "agent":           "autofix_agent",
        "target":          target,
        "timestamp":       datetime.now().isoformat(),
        "issues_analyzed": len(issues),
        "patches_generated": total_patches,
        "patch_files":     [str(p) for p in patch_files],
        "apply_script":    str(apply_script),
        "patches_by_file": all_patches,
        "status":          "patches_generated" if total_patches > 0 else "no_patches",
        "summary": (
            f"{total_patches} patch(es) générés pour {len(issues_by_file)} fichier(s). "
            f"Pour appliquer: bash {apply_script}"
        ),
    }

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"autofix-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[AutoFix] {total_patches} patch(es) générés")
    print(f"[AutoFix] Pour appliquer: bash reports/patches/APPLY_ALL.sh")
    print(f"[AutoFix] Rapport: {out}")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",  default=TARGET)
    parser.add_argument("--apply",   action="store_true",
                        help="Appliquer les patches via git apply")
    args = parser.parse_args()
    run_autofix_agent(target=args.target, apply_patches=args.apply)
