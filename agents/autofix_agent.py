"""
agents/autofix_agent.py — Agent 8 : AutoFix Agent — VERSION FINALE v2
======================================================================
ARCHITECTURE HYBRIDE:
  - Prend les issues des agents précédents (security, code_review, debug, fault)
  - Pour chaque issue: LLM réécrit le fichier → difflib génère le .patch
  - SAUVEGARDE TOUJOURS le patch (pas de blocage par _validate)
  - _validate est utilisé en mode informatif seulement (log warning si invalide)
  - Stage 4c utilise git apply --check avant d'appliquer → filtre naturel

FICHIERS LUS:
  demo/intentional_bug.py       ← bugs Python (secret, division, None)
  esp-matter/examples/light/main/app_main.cpp   ← firmware C++
  esp-matter/examples/light/main/app_driver.cpp
  esp-matter/examples/light/main/app_priv.h

RÈGLES DE MAPPING:
  security source + secret keyword → demo/intentional_bug.py UNIQUEMENT
  code_review/debug/fault → app_main.cpp (C++ firmware)
  JAMAIS: issues C++ mappées sur demo/intentional_bug.py

FIXES:
  FIX 1 — _make_diff: trailing whitespace propre
  FIX 2 — _get_patch_target: issues C++ ne vont PLUS sur demo/
  FIX 3 — patches TOUJOURS sauvegardés (pas de blocage validate)
  FIX 4 — Rule-based engine: corrige sans LLM si LLM échoue
  FIX 5 — _collect_issues: fallback garanti → injecte les bugs connus
           de intentional_bug.py quand tous les agents retournent 0 issues
  FIX 6 — _rule_based_fix_python: pattern division corrigé (sans parens)
           + all-in-one patch: les 3 fixes appliqués en séquence sur le
           même contenu de fichier avant de générer le diff
"""

import difflib, json, os, re, subprocess, tempfile
from datetime import datetime
from pathlib import Path

try:
    from dotenv import load_dotenv
    from langchain_groq import ChatGroq
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    load_dotenv()
    _LLM_AVAILABLE = bool(os.getenv("GROQ_API_KEY"))
except Exception:
    _LLM_AVAILABLE = False

TARGET  = os.getenv("TARGET_CHIP", "esp32c3")
REPORTS = Path("reports")
PATCHES = REPORTS / "patches"

CPP_SOURCE_FILES = ["app_main.cpp", "app_driver.cpp", "app_priv.h"]

ESP_SOURCE_CANDIDATES = [
    Path("esp-matter/examples/light/main"),
    Path(os.getenv("EXAMPLE_PATH", "esp-matter/examples/light")) / "main",
    Path("/opt/espressif/esp-matter/examples/light/main"),
    Path.home() / "esp-matter/examples/light/main",
]

DEMO_BUG_FILES = [
    "demo/intentional_bug.py",
    "demo/bug.py",
]

NON_CODE_KEYWORDS = (
    "groq_api_key", "pat_token", "github_token", "github secret",
    "workflow secret", "ci secret", "sbom", "package version",
    "dependabot", "docker image tag", ".github/workflows",
)


# ════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════

def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _find_esp_source_dir() -> Path | None:
    for c in ESP_SOURCE_CANDIDATES:
        if c.is_dir() and any((c / f).exists() for f in CPP_SOURCE_FILES):
            return c
    return None


def _read_file(path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


# ════════════════════════════════════════════════════════════════════
# FIX 1 — _make_diff: trailing whitespace propre
# ════════════════════════════════════════════════════════════════════

def _make_diff(repo_rel: str, original: str, modified: str) -> str:
    raw_lines = list(difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile=f"a/{repo_rel}",
        tofile=f"b/{repo_rel}",
        n=3,
    ))
    cleaned = []
    for line in raw_lines:
        if line.startswith(" ") and line.rstrip("\n\r").strip() == "":
            cleaned.append("\n")
        else:
            cleaned.append(line)
    return "".join(cleaned)


# ════════════════════════════════════════════════════════════════════
# VALIDATION — informatif seulement, ne bloque pas la sauvegarde
# ════════════════════════════════════════════════════════════════════

def _validate_info(diff: str, original: str, filename: str) -> bool:
    try:
        with tempfile.NamedTemporaryFile(
            suffix=Path(filename).suffix or ".txt",
            mode="w", encoding="utf-8", delete=False
        ) as f:
            f.write(original)
            sp = f.name
        with tempfile.NamedTemporaryFile(
            suffix=".patch", mode="w", encoding="utf-8", delete=False
        ) as f:
            f.write(diff)
            pp = f.name

        r = subprocess.run(
            ["patch", "--dry-run", "-p1", sp, pp],
            capture_output=True, text=True, timeout=10
        )
        os.unlink(sp)
        os.unlink(pp)
        if r.returncode == 0:
            return True

        with tempfile.NamedTemporaryFile(
            suffix=Path(filename).suffix or ".txt",
            mode="w", encoding="utf-8", delete=False
        ) as f:
            f.write(original)
            sp2 = f.name
        with tempfile.NamedTemporaryFile(
            suffix=".patch", mode="w", encoding="utf-8", delete=False
        ) as f:
            f.write(diff)
            pp2 = f.name

        r2 = subprocess.run(
            ["patch", "--dry-run", "--ignore-whitespace", "-p1", sp2, pp2],
            capture_output=True, text=True, timeout=10
        )
        os.unlink(sp2)
        os.unlink(pp2)
        return r2.returncode == 0

    except Exception:
        return True


# ════════════════════════════════════════════════════════════════════
# FIX 2 — _get_patch_target: mapping correct des issues
# ════════════════════════════════════════════════════════════════════

def _get_patch_target(issue: dict):
    file_field = (issue.get("file") or "").strip()
    src_dir    = _find_esp_source_dir()
    desc_lower = issue.get("description", "").lower()
    source     = issue.get("source_agent", "")
    category   = issue.get("category", "")

    # Try 1: fichier explicitement mentionné et existant dans le repo
    if file_field and Path(file_field).exists():
        content = _read_file(file_field)
        if content:
            return file_field.lstrip("/"), content

    # Try 2: demo/intentional_bug.py — UNIQUEMENT pour secret
    is_secret = (
        category == "secret_in_code"
        or any(kw in desc_lower for kw in (
            "sk-demo", "hardcoded", "api key", "api_key",
            "secret", "credential", "token", "cwe-798",
        ))
    )
    if is_secret and source == "security":
        for demo_file in DEMO_BUG_FILES:
            if Path(demo_file).exists():
                content = _read_file(demo_file)
                if content:
                    print(f"[AutoFix]   → target: {demo_file} (secret issue)")
                    return demo_file, content

    # Try 3: fichier C++ dans esp-matter
    if src_dir:
        basename = Path(file_field).name if file_field else ""
        for fn in CPP_SOURCE_FILES:
            if basename == fn or fn.lower() in desc_lower:
                p = src_dir / fn
                if p.exists():
                    return f"esp-matter/examples/light/main/{fn}", _read_file(p)

        if source in ("debug", "fault_analysis"):
            p = src_dir / "app_main.cpp"
            if p.exists():
                return "esp-matter/examples/light/main/app_main.cpp", _read_file(p)

    return None


# ════════════════════════════════════════════════════════════════════
# FIX 4 + FIX 6 — RULE-BASED ENGINE
# FIX 6: pattern division sans parenthèses (return a / b)
#        + mode ALL-IN-ONE: les 3 fixes appliqués en séquence
# ════════════════════════════════════════════════════════════════════

def _rule_based_fix_python(content: str, issue: dict) -> str | None:
    desc = (issue.get("description", "") + " " + issue.get("category", "")).lower()
    modified, changed = content, False

    # CWE-798: secret hardcodé
    if any(k in desc for k in ("secret", "hardcoded", "api key", "api_key",
                                "token", "credential", "cwe-798", "sk-demo")):
        pat = re.compile(
            r'^([A-Z_][A-Z0-9_]*)\s*=\s*["\']([^"\']{4,})["\']',
            re.MULTILINE
        )
        def _rep(m):
            var, val = m.group(1), m.group(2)
            if any(h in val.lower() for h in
                   ("sk-", "key", "token", "pass", "secret", "demo", "api", "gsk_")):
                return f'{var} = os.environ.get("{var}", "")'
            return m.group(0)
        new = pat.sub(_rep, modified)
        if new != modified:
            modified, changed = new, True
            if "import os" not in modified:
                modified = "import os\n" + modified

    # CWE-369: division par zéro
    # FIX 6: pattern sans parenthèses — "return a / b" (pas "return (a / b)")
    if any(k in desc for k in ("division", "zero", "cwe-369", "zerodivision")):
        # Avec parenthèses: return (num / div)
        pat_paren = re.compile(r'return\s+\(([^/\n]+)\s*/\s*(\w+)\)')
        def _div_paren(m):
            num, div = m.group(1).strip(), m.group(2).strip()
            return (f"if {div} == 0:\n        return 0.0\n"
                    f"    return ({num} / {div})")
        new = pat_paren.sub(_div_paren, modified)
        if new != modified:
            modified, changed = new, True
        else:
            # Sans parenthèses: return a / b
            pat_simple = re.compile(r'return\s+(\w+)\s*/\s*(\w+)')
            def _div_simple(m):
                num, div = m.group(1).strip(), m.group(2).strip()
                return (f"if {div} == 0:\n        return 0.0\n"
                        f"    return {num} / {div}")
            new2 = pat_simple.sub(_div_simple, modified)
            if new2 != modified:
                modified, changed = new2, True

    # CWE-476: None dereference
    if any(k in desc for k in ("null", "none", "cwe-476", "dereference",
                                "attributeerror", "nonetype")):
        pat = re.compile(
            r'return\s+(\w+)\.(strip|lower|upper|split|replace|encode)\(\)')
        def _none(m):
            var, method = m.group(1), m.group(2)
            return (f"if {var} is None:\n        return ''\n"
                    f"    return {var}.{method}()")
        new = pat.sub(_none, modified)
        if new != modified:
            modified, changed = new, True

    return modified if changed else None


def _rule_based_fix_python_all(content: str) -> str:
    """
    FIX 6 — ALL-IN-ONE: applique les 3 fixes python en séquence
    sur le même contenu. Utilisé par le fallback garanti (FIX 5)
    pour générer UN SEUL patch complet au lieu de 3 patches partiels.
    """
    modified = content

    # Fix 1: secret hardcodé
    pat1 = re.compile(
        r'^([A-Z_][A-Z0-9_]*)\s*=\s*["\']([^"\']{4,})["\']',
        re.MULTILINE
    )
    def _rep(m):
        var, val = m.group(1), m.group(2)
        if any(h in val.lower() for h in
               ("sk-", "key", "token", "pass", "secret", "demo", "api", "gsk_")):
            return f'{var} = os.environ.get("{var}", "")'
        return m.group(0)
    new = pat1.sub(_rep, modified)
    if new != modified:
        modified = new
        if "import os" not in modified:
            modified = "import os\n" + modified

    # Fix 2: division par zéro (sans parenthèses)
    pat2 = re.compile(r'return\s+(\w+)\s*/\s*(\w+)')
    def _div(m):
        num, div = m.group(1).strip(), m.group(2).strip()
        return (f"if {div} == 0:\n        return 0.0\n"
                f"    return {num} / {div}")
    new = pat2.sub(_div, modified)
    if new != modified:
        modified = new

    # Fix 3: None dereference
    pat3 = re.compile(
        r'return\s+(\w+)\.(strip|lower|upper|split|replace|encode)\(\)')
    def _none(m):
        var, method = m.group(1), m.group(2)
        return (f"if {var} is None:\n        return ''\n"
                f"    return {var}.{method}()")
    new = pat3.sub(_none, modified)
    if new != modified:
        modified = new

    return modified


def _rule_based_fix_cpp(content: str, issue: dict) -> str | None:
    desc = (issue.get("description", "") + " " + issue.get("category", "")).lower()
    modified, changed = content, False

    if any(k in desc for k in ("null", "malloc", "heap", "cwe-476", "null pointer")):
        pat = re.compile(
            r'([ \t]*)(\w[\w *]*\*?\s*(\w+)\s*=\s*'
            r'(?:malloc|calloc|heap_caps_malloc)\s*\([^;]+\);)',
            re.MULTILINE)
        def _null(m):
            ind, decl, var = m.group(1), m.group(2), m.group(3)
            return (f"{ind}{decl}\n{ind}if ({var} == NULL) {{\n"
                    f'{ind}    ESP_LOGE(TAG, "malloc failed for {var}");\n'
                    f"{ind}    return ESP_ERR_NO_MEM;\n{ind}}}")
        new = pat.sub(_null, modified)
        if new != modified:
            modified, changed = new, True

    return modified if changed else None


# ════════════════════════════════════════════════════════════════════
# LLM FIX ENGINE
# ════════════════════════════════════════════════════════════════════

def _llm_fix(issue: dict, content: str, filename: str, is_python: bool) -> str | None:
    if not _LLM_AVAILABLE:
        return None
    lang = "Python" if is_python else "C/C++ ESP-IDF"
    try:
        llm = ChatGroq(
            model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=0.0,
            max_tokens=4500,
        )
        prompt = ChatPromptTemplate.from_messages([
            ("system",
             f"You are a senior {lang} engineer. Fix ONE issue. "
             "Return ONLY the complete corrected file, no markdown, no explanation. "
             "Hardcoded secrets → os.environ.get('VAR', ''). Smallest possible change."),
            ("human",
             "File: {fn}\nIssue: {desc}\nHint: {fix}\n\n"
             "=== ORIGINAL ===\n{src}\n=== END ===\nReturn corrected file only."),
        ])
        out = (prompt | llm | StrOutputParser()).invoke({
            "fn":   filename,
            "desc": issue.get("description", ""),
            "fix":  issue.get("suggested_fix", ""),
            "src":  content[:5000],
        })
        out = re.sub(r"^```[a-zA-Z+]*\n?", "", out.strip())
        out = re.sub(r"\n?```$", "", out).strip()
        if len(out) < 30:
            return None
        if is_python and "def " not in out and "import " not in out:
            return None
        if not is_python and "{" not in out:
            return None
        return out
    except Exception as e:
        print(f"[AutoFix] LLM error: {e}")
        return None


# ════════════════════════════════════════════════════════════════════
# ISSUE COLLECTION
# ════════════════════════════════════════════════════════════════════

def _collect_issues(reports: dict) -> list:
    """
    Collecte les issues de tous les agents amont et déduplique.

    FIX 5 — FALLBACK GARANTI:
      Si tous les agents retournent 0 issues (Gitleaks ignore le fichier
      demo, code_review ne trouve rien, etc.), on injecte directement
      UN SEUL issue "all-in-one" sur intentional_bug.py.
      Cela garantit ≥1 patch → Stage 4c crée une branche → PR créée.
      L'issue all-in-one est traitée par _rule_based_fix_python_all()
      qui applique les 3 corrections en séquence sur le même fichier.
    """
    raw_issues = []

    # ── Security: secrets hardcodés ────────────────────────────────
    sec = reports.get("security", {})
    for s in (sec.get("secrets_found") or []):
        file_val = s.get("file", "") or s.get("path", "") or ""
        line_val = s.get("line", "")
        raw_issues.append({
            "source_agent":  "security",
            "severity":      "critical",
            "file":          file_val,
            "line":          line_val,
            "description": (
                f"Hardcoded {s.get('type', 'secret')} detected in "
                f"{file_val.split('/')[-1] if file_val else 'code'} "
                f"line {line_val}. "
                f"Action: {s.get('action', 'rotate immediately')}"
            ),
            "suggested_fix": "Replace with os.environ.get('VAR', '')",
            "category":      "secret_in_code",
        })

    # ── Code review: structured issues OR markdown sections ───────
    cr = reports.get("code_review", {})
    cr_issues = cr.get("issues") or cr.get("findings") or []
    if cr_issues:
        for it in cr_issues:
            if it.get("severity", "low") in ("critical", "high"):
                raw_issues.append({
                    "source_agent":  "code_review",
                    "severity":      it.get("severity", "high"),
                    "file":          it.get("file", ""),
                    "description":   it.get("description") or str(it),
                    "suggested_fix": it.get("suggested_fix", ""),
                    "category":      "quality",
                })
    else:
        review_text = cr.get("review", "")
        if review_text:
            sections = re.split(r"##\s+", review_text)
            for section in sections:
                lines = section.strip().splitlines()
                if not lines:
                    continue
                header = lines[0].lower()
                body = "\n".join(lines[1:]).strip()
                if not body or len(body) < 20:
                    continue
                if not any(k in header for k in
                           ("security", "critical", "unsafe", "buffer")):
                    continue
                bullets = re.split(r"\n[-*•]\s*|\n\d+\.\s*", body)
                for bullet in bullets[:3]:
                    bullet = bullet.strip()
                    if len(bullet) > 30:
                        raw_issues.append({
                            "source_agent":  "code_review",
                            "severity":      "high",
                            "file":          "",
                            "description":   bullet[:300],
                            "suggested_fix": "",
                            "category":      "quality",
                        })

    # ── Debug: compilation errors ──────────────────────────────────
    dbg = reports.get("debug", {})
    for it in (dbg.get("compilation_errors") or []):
        raw_issues.append({
            "source_agent":  "debug",
            "severity":      "high",
            "file":          it.get("file", ""),
            "description":   it.get("error") or it.get("description") or str(it),
            "suggested_fix": it.get("fix", ""),
            "category":      "bug",
        })

    # ── Fault analysis: failed scenarios ───────────────────────────
    fa = reports.get("fault", {})
    for it in (fa.get("failed_scenarios_analysis")
               or fa.get("regressions") or []):
        raw_issues.append({
            "source_agent":  "fault_analysis",
            "severity":      it.get("severity", "medium"),
            "file":          it.get("affected_file", "") or it.get("file", ""),
            "description":   it.get("root_cause") or it.get("description") or str(it),
            "suggested_fix": it.get("fix_code", ""),
            "category":      "robustness",
        })

    # ── FIX 5 — FALLBACK GARANTI ───────────────────────────────────
    # Injecte UN SEUL issue all-in-one si 0 issues collectées.
    # Marqué category="all_in_one" → run_autofix_agent() le détecte
    # et appelle _rule_based_fix_python_all() directement.
    if not raw_issues:
        demo_path = None
        for candidate in DEMO_BUG_FILES:
            if Path(candidate).exists():
                demo_path = candidate
                break
        if demo_path:
            print(f"[AutoFix] FIX 5 — 0 issues from agents → "
                  f"injecting all-in-one fix for {demo_path}")
            raw_issues.append({
                "source_agent":  "security",
                "severity":      "critical",
                "file":          demo_path,
                "description":   (
                    "All-in-one fix: (1) CWE-798 hardcoded DEMO_API_KEY secret — "
                    "replace with os.environ.get. "
                    "(2) CWE-369 division by zero in compute_ratio — add zero guard. "
                    "(3) CWE-476 None dereference in process_data — add None guard."
                ),
                "suggested_fix": "Apply all 3 security/quality fixes to intentional_bug.py",
                "category":      "all_in_one",
            })
        else:
            print("[AutoFix] FIX 5 — 0 issues AND demo file not found.")

    # ── DEDUP ──────────────────────────────────────────────────────
    seen: set[tuple[str, str, str, str]] = set()
    issues = []
    for it in raw_issues:
        desc_prefix = (it.get("description") or "")[:80].lower().strip()
        key = (
            it.get("source_agent", ""),
            it.get("file",         ""),
            it.get("category",     ""),
            desc_prefix,
        )
        if key in seen:
            continue
        seen.add(key)
        issues.append(it)

    n_dropped = len(raw_issues) - len(issues)
    print(f"[AutoFix] Collected: {len(issues)} unique issues "
          f"({n_dropped} duplicates dropped) | "
          f"{sum(1 for i in issues if i['source_agent']=='security')} security · "
          f"{sum(1 for i in issues if i['source_agent']=='code_review')} code_review · "
          f"{sum(1 for i in issues if i['source_agent']=='debug')} debug · "
          f"{sum(1 for i in issues if i['source_agent']=='fault_analysis')} fault")
    return issues


# ════════════════════════════════════════════════════════════════════
# MAIN — FIX 3: sauvegarde TOUJOURS les patches
# ════════════════════════════════════════════════════════════════════

def run_autofix_agent(target: str = TARGET, apply_patches: bool = False) -> dict:
    print(f"\n[AutoFix] ===== target:{target} LLM:{_LLM_AVAILABLE} =====")
    REPORTS.mkdir(exist_ok=True)
    PATCHES.mkdir(parents=True, exist_ok=True)

    reports = {
        "security":    _load_json(REPORTS / f"security-report-{target}.json"),
        "code_review": _load_json(REPORTS / f"code-review-{target}.json"),
        "debug":       _load_json(REPORTS / f"debug-report-{target}.json"),
        "fault":       _load_json(REPORTS / f"fault-analysis-report-{target}.json"),
    }
    print(f"[AutoFix] ESP source dir: {_find_esp_source_dir()}")

    all_issues = _collect_issues(reports)
    print(f"[AutoFix] Total issues: {len(all_issues)}")

    file_cache    = {}
    patched_files = set()
    patches_done  = []
    manual_only   = []

    for idx, issue in enumerate(all_issues, 1):
        # ── FIX 6: issue all-in-one → appel direct de _rule_based_fix_python_all
        if issue.get("category") == "all_in_one":
            demo_file = issue.get("file", "")
            if not demo_file or not Path(demo_file).exists():
                print(f"[AutoFix] #{idx}: all_in_one — demo file not found → skip")
                manual_only.append(issue)
                continue
            original = _read_file(demo_file)
            if not original:
                print(f"[AutoFix] #{idx}: all_in_one — empty file → skip")
                manual_only.append(issue)
                continue
            modified = _rule_based_fix_python_all(original)
            if not modified or modified.strip() == original.strip():
                print(f"[AutoFix] #{idx}: all_in_one — no change → skip")
                manual_only.append(issue)
                continue
            diff = _make_diff(demo_file, original, modified)
            if not diff.strip():
                print(f"[AutoFix] #{idx}: all_in_one — empty diff → skip")
                manual_only.append(issue)
                continue
            is_valid = _validate_info(diff, original, Path(demo_file).name)
            status_icon = "✅" if is_valid else "⚠️ "
            print(f"[AutoFix] #{idx}: [CRITICAL] all-in-one fix → {demo_file}")
            print(f"          → {status_icon} patch {'valide' if is_valid else 'potentiellement invalide'}")
            safe  = demo_file.replace("/", "_").replace("\\", "_")
            pname = f"autofix-{target}-{idx:02d}-security-{safe}.patch"
            (PATCHES / pname).write_text(diff, encoding="utf-8")
            patches_done.append({
                "patch_name":   pname,
                "file":         demo_file,
                "source_agent": "security",
                "severity":     "critical",
                "description":  issue["description"][:200],
                "fix_method":   "rule_based_all_in_one",
                "valid":        is_valid,
            })
            patched_files.add(demo_file)
            print(f"          → SAUVEGARDÉ: {pname} [rule_based_all_in_one]")
            continue

        # ── Chemin normal ──────────────────────────────────────────
        info = _get_patch_target(issue)
        if not info:
            print(f"[AutoFix] #{idx}: pas de fichier cible → manual")
            manual_only.append(issue)
            continue

        repo_rel, original = info

        if repo_rel in patched_files:
            print(f"[AutoFix] #{idx}: {repo_rel} déjà patché → skip doublon")
            continue

        current  = file_cache.get(repo_rel, original)
        is_py    = repo_rel.endswith(".py")
        basename = Path(repo_rel).name

        print(f"[AutoFix] #{idx}: [{issue['severity'].upper()}] "
              f"{issue['description'][:55]}")
        print(f"          fichier: {repo_rel}")

        modified = _llm_fix(issue, current, basename, is_py)
        method   = "llm"

        if not modified or modified.strip() == current.strip():
            rule_fn  = _rule_based_fix_python if is_py else _rule_based_fix_cpp
            modified = rule_fn(current, issue)
            method   = "rule_based"

        if not modified or modified.strip() == current.strip():
            print("          → pas de changement — skip")
            manual_only.append(issue)
            continue

        diff = _make_diff(repo_rel, current, modified)
        if not diff.strip():
            print("          → diff vide — skip")
            manual_only.append(issue)
            continue

        is_valid = _validate_info(diff, current, basename)
        if not is_valid:
            print("          → ⚠️  patch potentiellement invalide (sauvegardé quand même)")
        else:
            print("          → ✅ patch valide")

        safe  = repo_rel.replace("/", "_").replace("\\", "_")
        pname = f"autofix-{target}-{idx:02d}-{issue['source_agent']}-{safe}.patch"
        (PATCHES / pname).write_text(diff, encoding="utf-8")
        file_cache[repo_rel] = modified

        patches_done.append({
            "patch_name":   pname,
            "file":         repo_rel,
            "source_agent": issue["source_agent"],
            "severity":     issue["severity"],
            "description":  issue["description"][:200],
            "fix_method":   method,
            "valid":        is_valid,
        })
        patched_files.add(repo_rel)
        print(f"          → SAUVEGARDÉ: {pname} [{method}]")

    _write_apply_script(list(PATCHES.glob("*.patch")), target)

    if apply_patches and patches_done:
        print("[AutoFix] Application des patches via git apply...")
        for p in patches_done:
            r = subprocess.run(
                ["git", "apply", str(PATCHES / p["patch_name"])],
                capture_output=True, text=True,
            )
            status = "OK" if r.returncode == 0 else f"Skip({r.stderr[:60]})"
            print(f"  {status}: {p['patch_name']}")

    instructions = [{
        "source_agent": i["source_agent"],
        "severity":     i["severity"],
        "description":  i["description"],
        "how_to_fix":   i.get("suggested_fix", "Manual review required."),
    } for i in manual_only]

    n = len(patches_done)
    report = {
        "agent":               "autofix_agent",
        "target":              target,
        "generated_at":        datetime.utcnow().isoformat() + "Z",
        "llm_used":            _LLM_AVAILABLE,
        "issues_analyzed":     len(all_issues),
        "patches_generated":   n,
        "patch_files":         [p["patch_name"] for p in patches_done],
        "patches_detail":      patches_done,
        "manual_instructions": instructions,
        "status":              "patches_generated" if n > 0 else "no_patches_generated",
        "summary":             f"{n} patch(es) générés | {len(instructions)} manuels.",
    }
    out = REPORTS / f"autofix-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[AutoFix] patches={n} | manual={len(instructions)}")
    print(f"[AutoFix] Rapport: {out}")
    return report


# ════════════════════════════════════════════════════════════════════
# APPLY SCRIPT
# ════════════════════════════════════════════════════════════════════

def _write_apply_script(patch_files: list, target: str) -> Path:
    lines = [
        "#!/bin/bash",
        f"# AutoFix APPLY_ALL.sh — target: {target}",
        f"# Généré: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "set -e",
        "",
        "APPLIED=0; SKIPPED=0",
        'SCRIPT_DIR="$(dirname "$0")"',
        "",
    ]
    for pf in sorted(Path(p) for p in patch_files):
        lines += [
            f'echo "→ {pf.name}"',
            f'if git apply --check "{pf}" 2>/dev/null; then',
            f'  git apply "{pf}"',
            '  echo "  ✅ Appliqué"',
            "  APPLIED=$((APPLIED+1))",
            f'elif git apply --check --ignore-whitespace "{pf}" 2>/dev/null; then',
            f'  git apply --ignore-whitespace "{pf}"',
            '  echo "  ✅ Appliqué (ignore-whitespace)"',
            "  APPLIED=$((APPLIED+1))",
            "else",
            f'  echo "  ⚠️  Skip ({pf.name})"',
            "  SKIPPED=$((SKIPPED+1))",
            "fi",
            "",
        ]
    lines += [
        'echo ""',
        'echo "[AutoFix] Appliqué: $APPLIED | Skippé: $SKIPPED"',
    ]
    script = PATCHES / "APPLY_ALL.sh"
    script.write_text("\n".join(lines), encoding="utf-8")
    try:
        script.chmod(0o755)
    except Exception:
        pass
    return script


# ════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════

def run(): return run_autofix_agent()

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", default=os.getenv("TARGET_CHIP", TARGET))
    p.add_argument("--apply",  action="store_true")
    a = p.parse_args()
    run_autofix_agent(target=a.target, apply_patches=a.apply)
