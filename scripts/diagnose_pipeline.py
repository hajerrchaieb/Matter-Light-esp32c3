#!/usr/bin/env python3
"""
scripts/diagnose_pipeline.py
============================
Script de diagnostic à lancer manuellement ou via CI pour comprendre
pourquoi les agents AI retournent N/A et les patches = 0.

Usage local :
  python3 scripts/diagnose_pipeline.py

Usage dans ci.yml (ajouter comme step dans ai-agents) :
  - name: Diagnose AI agents
    run: python3 scripts/diagnose_pipeline.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPORTS = Path(os.getenv("REPORTS_DIR", "reports"))
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):  print(f"  {GREEN}OK{RESET}  {msg}")
def fail(msg): print(f"  {RED}FAIL{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}WARN{RESET} {msg}")
def section(title): print(f"\n{BOLD}{'='*60}{RESET}\n{BOLD}{title}{RESET}\n{'='*60}")


# ── 1. Vérification des secrets / env vars ────────────────────────
section("1. Environment Variables & Secrets")

groq_key = os.getenv("GROQ_API_KEY", "")
if not groq_key:
    fail("GROQ_API_KEY is EMPTY — agents LLM cannot call Groq API")
    print("      → Ajoute le secret dans : GitHub repo → Settings → Secrets → Actions")
    print("        Nom : GROQ_API_KEY   Valeur : gsk_xxxxxxxxxxxxxxxx")
elif groq_key.startswith("gsk_"):
    ok(f"GROQ_API_KEY présent ({groq_key[:8]}...)")
else:
    warn(f"GROQ_API_KEY présent mais format inhabituel : {groq_key[:6]}...")

pat = os.getenv("PAT_TOKEN", "")
if not pat:
    warn("PAT_TOKEN absent — Stage 4c (push branche autofix) ne fonctionnera pas")
    print("      → Créer un PAT : GitHub → Settings → Developer settings")
    print("        → Personal access tokens → Tokens (classic)")
    print("        → Permissions : repo (all) + workflow")
    print("        → Ajouter comme secret : PAT_TOKEN")
else:
    ok(f"PAT_TOKEN présent ({pat[:6]}...)")

target = os.getenv("TARGET_CHIP", "esp32c3")
ok(f"TARGET_CHIP = {target}")

example_path = os.getenv("EXAMPLE_PATH", "esp-matter/examples/light")
ok(f"EXAMPLE_PATH = {example_path}")


# ── 2. Vérification des fichiers requis ───────────────────────────
section("2. Fichiers requis dans le repo")

required_files = [
    ("supervisor/orchestrator.py",          "Orchestrateur LangGraph"),
    ("agents/debug_agent.py",               "Agent 1 — Debug"),
    ("agents/security_agent.py",            "Agent 2 — Security"),
    ("agents/code_review_agent.py",         "Agent 3 — Code Review"),
    ("agents/test_gen_agent.py",            "Agent 4 — Test Gen"),
    ("agents/optimization_agent.py",        "Agent 5 — Optimization"),
    ("agents/release_agent.py",             "Agent 6 — Release"),
    ("agents/fault_analysis_agent.py",      "Agent 7 — Fault Analysis"),
    ("agents/autofix_agent.py",             "Agent 8 — AutoFix"),
    ("agents/regression_detector.py",       "Regression Detector"),
    ("fuzz/fuzz_matter_attr.cpp",           "Fuzzer harness"),
    ("fuzz/parse_fuzz_results.py",          "Fuzzer result parser"),
]

missing = []
for filepath, desc in required_files:
    p = Path(filepath)
    if p.exists():
        ok(f"{filepath} ({desc})")
    else:
        fail(f"{filepath} MANQUANT — {desc}")
        missing.append(filepath)

if missing:
    print(f"\n  {RED}→ {len(missing)} fichier(s) manquant(s) !{RESET}")
    print("    Utilise les fichiers générés dans les artefacts de la conversation Claude.")


# ── 3. Vérification des dépendances Python ────────────────────────
section("3. Dépendances Python")

packages = [
    ("langchain",        "LangChain core"),
    ("langchain_groq",   "LangChain Groq provider"),
    ("langgraph",        "LangGraph orchestration"),
    ("chromadb",         "ChromaDB (mémoire agents)"),
    ("dotenv",           "python-dotenv"),
    ("pydantic",         "Pydantic validation"),
]

for pkg, desc in packages:
    try:
        __import__(pkg)
        ok(f"{pkg} ({desc})")
    except ImportError:
        fail(f"{pkg} NON INSTALLÉ — {desc}")
        print(f"      → pip install {pkg}")


# ── 4. Vérification des rapports CI ───────────────────────────────
section("4. Rapports CI disponibles pour les agents")

ci_reports = [
    (f"build-esp32c3.log",               "Stage 4 — Build log (pour debug_agent)"),
    (f"size-esp32c3.txt",                "Stage 4 — Size report (pour optimization_agent)"),
    (f"unit-test-results.json",          "Stage 5 — Unit tests (pour debug_agent)"),
    (f"qemu-dynamic-report.json",        "Stage 5 — QEMU report (pour fault_analysis_agent)"),
    (f"cppcheck-deep.xml",               "Stage 5 — cppcheck (pour debug_agent)"),
    (f"sbom-spdx.json",                  "Stage 2 — SBOM (pour security_agent)"),
    (f"gitleaks-report.json",            "Stage 2 — Gitleaks (pour security_agent)"),
    (f"grype-report.json",               "Stage 2 — CVEs (pour security_agent)"),
    (f"container-scan-summary.json",     "Stage 3 — Container scan (pour security_agent)"),
    (f"firmware-sha256.txt",             "Stage 6 — SLSA hashes (pour security_agent)"),
    (f"fault-injection-report-esp32c3.json", "Track D — Fault injection (pour fault_analysis_agent)"),
]

missing_reports = []
for filename, desc in ci_reports:
    p = REPORTS / filename
    if p.exists():
        size = p.stat().st_size
        if size > 10:
            ok(f"{filename} ({size} bytes) — {desc}")
        else:
            warn(f"{filename} VIDE ({size} bytes) — {desc}")
    else:
        warn(f"{filename} absent — {desc}")
        missing_reports.append(filename)

if missing_reports:
    print(f"\n  {YELLOW}→ {len(missing_reports)} rapport(s) absent(s){RESET}")
    print("    Normal au premier run — les agents utilisent des valeurs par défaut.")


# ── 5. Vérification du pipeline-summary.json ─────────────────────
section("5. Pipeline Summary (résultat des agents)")

summary_path = REPORTS / "pipeline-summary.json"
if not summary_path.exists():
    fail("pipeline-summary.json ABSENT")
    print("      → L'orchestrateur n'a pas terminé correctement")
    print("      → Vérifie le log : reports/orchestrator-run.log")
else:
    try:
        summary = json.loads(summary_path.read_text())
        ok(f"pipeline-summary.json trouvé")

        sr = summary.get("stage_results", {})

        # Code quality
        cq = sr.get("code_quality", {})
        score = cq.get("score", "N/A")
        if score == "N/A" or score is None:
            fail(f"code_quality.score = N/A → code_review_agent n'a pas scoré")
        else:
            ok(f"code_quality.score = {score}/10")

        # Security
        sec = sr.get("security", {})
        sec_score = sec.get("score", "N/A")
        if sec_score == "N/A" or sec_score is None:
            fail(f"security.score = N/A → security_agent n'a pas scoré")
        else:
            ok(f"security.score = {sec_score}/10")

        # AutoFix
        af = sr.get("autofix", {})
        patches = af.get("patches_generated", 0)
        if patches == 0:
            warn(f"autofix.patches_generated = 0")
            print("      → Normal si aucune issue critique trouvée par les agents")
            print("      → Ou l'agent autofix n'est pas dans l'orchestrateur")
        else:
            ok(f"autofix.patches_generated = {patches}")

        # Pipeline passed
        passed = summary.get("pipeline_passed", False)
        if passed:
            ok(f"pipeline_passed = True")
        else:
            warn(f"pipeline_passed = False (erreurs détectées)")

    except Exception as e:
        fail(f"Impossible de parser pipeline-summary.json : {e}")


# ── 6. Vérification de l'orchestrator-run.log ────────────────────
section("6. Orchestrator Run Log (cherche les erreurs)")

log_path = REPORTS / "orchestrator-run.log"
if not log_path.exists():
    fail("orchestrator-run.log ABSENT")
    print("      → L'orchestrateur n'a pas produit de logs")
else:
    log_text = log_path.read_text(errors="ignore")
    lines    = log_text.splitlines()
    ok(f"orchestrator-run.log trouvé ({len(lines)} lignes)")

    # Chercher les erreurs clés
    error_patterns = [
        ("GROQ_API_KEY",      "Clé API Groq manquante ou invalide"),
        ("AuthenticationError", "Authentification Groq échouée"),
        ("RateLimitError",    "Rate limit Groq atteint"),
        ("ImportError",       "Module Python manquant"),
        ("ModuleNotFoundError", "Module Python introuvable"),
        ("JSONDecodeError",   "Réponse LLM non-JSON"),
        ("parse_error",       "Parsing JSON échoué dans un agent"),
        ("failed:",           "Agent a échoué"),
        ("Exception",         "Exception non gérée"),
        ("Traceback",         "Stack trace Python"),
    ]

    errors_found = []
    for pattern, desc in error_patterns:
        matching = [l for l in lines if pattern.lower() in l.lower()]
        if matching:
            errors_found.append((pattern, desc, matching[0]))

    if not errors_found:
        ok("Aucune erreur critique dans orchestrator-run.log")
    else:
        for pattern, desc, example in errors_found:
            fail(f"'{pattern}' trouvé — {desc}")
            print(f"      Exemple : {example[:120]}")

    # Chercher les agents qui ont tourné
    print("\n  Agents détectés dans les logs :")
    agent_markers = [
        ("NODE: Code Review Agent",    "Agent 3 — Code Review"),
        ("NODE: Security Agent",       "Agent 2 — Security"),
        ("NODE: Debug Agent",          "Agent 1 — Debug"),
        ("NODE: Fault Analysis Agent", "Agent 7 — Fault Analysis"),
        ("NODE: Test Generation",      "Agent 4 — Test Gen"),
        ("NODE: Optimization Agent",   "Agent 5 — Optimization"),
        ("NODE: Release Agent",        "Agent 6 — Release"),
        ("NODE: AutoFix Agent",        "Agent 8 — AutoFix"),
        ("NODE: Pipeline Summary",     "Summary"),
    ]
    for marker, label in agent_markers:
        if marker in log_text:
            ok(f"{label} a tourné")
        else:
            warn(f"{label} NON TROUVÉ dans les logs")


# ── 7. Vérification des rapports agents ──────────────────────────
section("7. Rapports produits par les agents")

agent_reports = [
    (f"debug-report-esp32c3.json",         "Agent 1"),
    (f"security-report-esp32c3.json",      "Agent 2"),
    (f"code-review-esp32c3.json",          "Agent 3"),
    (f"testgen-report-esp32c3.json",       "Agent 4"),
    (f"optimization-report-esp32c3.json",  "Agent 5"),
    (f"release-report-esp32c3.json",       "Agent 6"),
    (f"fault-analysis-report-esp32c3.json","Agent 7"),
    (f"autofix-report-esp32c3.json",       "Agent 8"),
]

for filename, agent in agent_reports:
    p = REPORTS / filename
    if p.exists():
        try:
            data = json.loads(p.read_text())
            if data.get("parse_error"):
                warn(f"{filename} ({agent}) — parse_error=True (LLM response invalide)")
            elif data.get("error"):
                fail(f"{filename} ({agent}) — error: {str(data['error'])[:80]}")
            else:
                ok(f"{filename} ({agent}) — OK")
        except Exception as e:
            fail(f"{filename} ({agent}) — JSON invalide: {e}")
    else:
        warn(f"{filename} ({agent}) — ABSENT (agent n'a pas tourné ou a échoué)")


# ── 8. Vérification patches AutoFix ──────────────────────────────
section("8. Patches AutoFix")

patches_dir = REPORTS / "patches"
if not patches_dir.exists():
    warn("reports/patches/ absent — AutoFix n'a généré aucun patch")
    print("      → Causes possibles :")
    print("        1. Aucune issue CRITICAL/HIGH trouvée par les agents")
    print("        2. autofix_agent.py absent du repo")
    print("        3. L'orchestrateur n'appelle pas run_autofix_agent()")
    print("      → Vérification dans orchestrator.py:")
    print("        Cherche 'from agents.autofix_agent import run_autofix_agent'")
    print("        Cherche 'node_autofix' dans build_pipeline_graph()")
else:
    patches = list(patches_dir.glob("*.patch"))
    apply_script = patches_dir / "APPLY_ALL.sh"
    if patches:
        ok(f"{len(patches)} patch(es) trouvés dans reports/patches/")
        for p in patches:
            ok(f"  {p.name} ({p.stat().st_size} bytes)")
    else:
        warn("reports/patches/ existe mais aucun .patch trouvé")

    if apply_script.exists():
        ok("APPLY_ALL.sh présent")
    else:
        warn("APPLY_ALL.sh absent")


# ── 9. Vérification source ESP-Matter ────────────────────────────
section("9. Source ESP-Matter (pour les agents)")

src_candidates = [
    Path("esp-matter/examples/light/main"),
    Path("../esp-matter/examples/light/main"),
    Path("/opt/espressif/esp-matter/examples/light/main"),
]

src_found = False
for c in src_candidates:
    if c.exists():
        cpp_files = list(c.glob("*.cpp"))
        if cpp_files:
            ok(f"Source trouvée : {c} ({len(cpp_files)} fichiers .cpp)")
            src_found = True
            break
        else:
            warn(f"{c} existe mais aucun .cpp trouvé")

if not src_found:
    warn("Source ESP-Matter introuvable")
    print("      → Le step 'Expose ESP-Matter source for agents' n'a pas copié les fichiers")
    print("      → Vérifie que le Docker image contient /opt/espressif/esp-matter/")


# ── Résumé ────────────────────────────────────────────────────────
section("RÉSUMÉ & ACTIONS REQUISES")

print("""
Pour corriger "Sec:N/A/10 Qual:N/A/10" dans le pipeline :

CAUSE 1 (la plus probable) : GROQ_API_KEY manquant ou invalide
  → GitHub repo → Settings → Secrets and variables → Actions
  → New repository secret → Nom: GROQ_API_KEY, Valeur: gsk_xxx
  → Obtenir une clé gratuite sur : https://console.groq.com

CAUSE 2 : autofix_agent.py absent ou orchestrator.py ancien
  → Remplacer supervisor/orchestrator.py par la version avec Agent 8
  → Ajouter agents/autofix_agent.py dans le repo

CAUSE 3 : agents/*.py absents du repo
  → Vérifier que tous les fichiers agents/ sont dans le repo
  → git status pour voir ce qui manque

Pour corriger "Patches = 0" :
  → D'abord corriger le GROQ_API_KEY (les patches nécessitent
    que les agents détectent des issues)
  → Si GROQ_API_KEY OK mais patches=0 : aucune issue critique
    trouvée (c'est possible si le code est propre)

Pour corriger "Node.js 20 deprecated" warnings :
  → Mettre à jour actions/checkout@v4 → actions/checkout@v4
  → Mettre à jour actions/download-artifact@v4 (déjà v4, OK)
  → Ces warnings n'affectent pas le fonctionnement
""")

print(f"{BOLD}Script terminé.{RESET}")
print(f"Logs détaillés dans : {REPORTS}/orchestrator-run.log")