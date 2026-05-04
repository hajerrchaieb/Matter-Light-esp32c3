"""
agents/security_agent.py — v5 (DEDUP + DEFENSE-IN-DEPTH SCORING)
==================================================================
Same role as v4 but adds two important fixes that surfaced when we
observed the dashboard reporting "9 secrets" for what is really
ONE secret in demo/intentional_bug.py.

ROOT CAUSE OF THE 9-SECRETS BUG
-------------------------------
Gitleaks runs once per commit history page. When the same secret
appears multiple times in the git history (because we have rotated
the demo secret several times during development), Gitleaks reports
it once per occurrence — not once per current location. The previous
agent counted EACH occurrence as a separate secret, so 1 real secret
in 9 commits → 9 "secrets_found" entries → -27 points → score 0.

FIX
---
Layer 0 (NEW) — Deduplicate by (file, line) BEFORE counting.
                A secret at demo/intentional_bug.py:2 is ONE secret
                even if it shows up in 9 commit snapshots.

Layers 1-3 same as v4 (deterministic + injection + post-validation).

Layer 4 (orchestrator) is unchanged.

EXPECTED RESULT FOR YOUR DEMO
-----------------------------
1 real hardcoded secret in demo/intentional_bug.py
  → after dedup: secrets_found = [1 entry]
  → deterministic score: 10 - 3 = 7
  → dashboard displays Security 7/10 (warn tone)
  → AutoFix produces 1 patch on that file
  → second run shows Security 10/10 because the secret was patched
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

TARGET  = os.getenv("TARGET_CHIP", "esp32c3")
REPORTS = Path("reports")


# ── helpers ────────────────────────────────────────────────────────

def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return default


def _load_json(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _summarise_sbom(sbom: dict) -> str:
    if not sbom:
        return "SBOM not available."
    packages      = sbom.get("packages", [])
    relationships = sbom.get("relationships", [])
    pkg_names     = [
        p.get("name", "?") + " " + p.get("versionInfo", "")
        for p in packages[:20]
    ]
    return (
        f"Total packages: {len(packages)} | Relationships: {len(relationships)}\n"
        f"Top packages: {', '.join(pkg_names)}"
    )


# ════════════════════════════════════════════════════════════════════
# LAYER 0 (NEW) — DEDUPLICATE GITLEAKS OUTPUT
# ════════════════════════════════════════════════════════════════════
def _parse_gitleaks(leaks: dict | list) -> tuple[str, list]:
    """
    Parse Gitleaks output and return (summary_text, secrets_list).

    NEW v5: Deduplicates by (file, line, rule). Multiple commits
    referencing the same secret location are collapsed into ONE entry.
    """
    if not leaks:
        return "No secrets found — gitleaks report empty or not available.", []

    if isinstance(leaks, list):
        if len(leaks) == 0:
            return "No secrets detected by Gitleaks — clean repository.", []

        # ── Dedup by (file, line, rule) ────────────────────────────
        seen: set[tuple[str, str, str]] = set()
        unique_secrets = []

        for leak in leaks:
            rule  = leak.get("RuleID",     leak.get("rule",  "?"))
            fpath = leak.get("File",       leak.get("file",  "?"))
            line  = leak.get("StartLine",  leak.get("line",  "?"))
            key   = (str(fpath), str(line), str(rule))

            if key in seen:
                continue   # same secret seen earlier in another commit
            seen.add(key)

            unique_secrets.append({
                "type":   rule,
                "rule":   rule,
                "file":   fpath,
                "line":   line,
                "match":  leak.get("Match", "[REDACTED]")[:40],
                "risk":   "critical",
                "action": "Remove from code, rotate the secret, "
                          "use env var via os.environ.get('VAR', '')",
            })

        # Build the summary lines
        summary_lines = []
        for s in unique_secrets[:10]:
            summary_lines.append(
                f"  Rule={s['rule']} | File={s['file']} | "
                f"Line={s['line']} | Match=[REDACTED]"
            )

        n_raw    = len(leaks)
        n_unique = len(unique_secrets)
        prefix   = (
            f"SECRETS FOUND ({n_unique} unique"
            + (f", {n_raw} raw matches across history" if n_raw != n_unique else "")
            + "):\n"
        )
        return prefix + "\n".join(summary_lines), unique_secrets

    return str(leaks)[:500], []


def _summarise_grype(grype: dict) -> str:
    if not grype:
        return "Grype CVE report not available."
    matches = grype.get("matches", [])
    if not matches:
        return "No CVEs found by Grype."
    critical = [m for m in matches
                if m.get("vulnerability", {}).get("severity") == "Critical"]
    high     = [m for m in matches
                if m.get("vulnerability", {}).get("severity") == "High"]

    lines = [
        f"Total CVEs: {len(matches)} | "
        f"Critical: {len(critical)} | High: {len(high)}"
    ]
    for m in (critical + high)[:10]:
        v   = m.get("vulnerability", {})
        art = m.get("artifact", {})
        lines.append(
            f"  {v.get('severity', '?')} | {v.get('id', '?')} | "
            f"pkg={art.get('name', '?')} {art.get('version', '?')} | "
            f"fix={v.get('fix', {}).get('versions', ['none'])}"
        )
    return "\n".join(lines)


def _summarise_container_scan(scan: dict) -> str:
    if not scan:
        return "Container scan summary not available."
    image   = scan.get("image",     "unknown")
    digest  = scan.get("digest",    "unknown")
    date    = scan.get("scan_date", "unknown")
    mutable = "@sha256:" not in image
    warning = (" ⚠️  MUTABLE TAG — supply chain risk"
               if mutable else " ✅ Digest pinned")
    return (
        f"Image: {image}{warning}\n"
        f"Digest: {digest}\n"
        f"Scanned: {date}"
    )


def _summarise_slsa_hashes(hashes_txt: str) -> str:
    if not hashes_txt or "not found" in hashes_txt.lower():
        return "SLSA firmware hashes not available."
    lines = [l.strip() for l in hashes_txt.strip().splitlines() if l.strip()]
    return (
        f"Firmware SHA256 hashes ({len(lines)} binaries):\n"
        + "\n".join(f"  {l}" for l in lines)
    )


# ════════════════════════════════════════════════════════════════════
# LAYER 1 — DETERMINISTIC SCORING (ground truth)
# ════════════════════════════════════════════════════════════════════
def _compute_score_from_data(
    n_secrets: int,
    n_critical_cves: int,
    n_high_cves: int,
    mutable_tag: bool,
    slsa_available: bool,
) -> int:
    """
    Deduction table (from a perfect 10):
        - Each unique secret      : -3 (capped at -9)
        - Each Critical CVE       : -2 (capped at -6)
        - Each High CVE           : -1 (capped at -3)
        - Mutable Docker tag      : -1
        - SLSA hashes missing     : -1
    Floor at 0.
    """
    score = 10
    if n_secrets > 0:
        score -= 3 * min(n_secrets, 3)
    if n_critical_cves > 0:
        score -= 2 * min(n_critical_cves, 3)
    if n_high_cves > 0:
        score -= 1 * min(n_high_cves, 3)
    if mutable_tag:
        score -= 1
    if not slsa_available:
        score -= 1
    return max(0, min(10, score))


# ════════════════════════════════════════════════════════════════════
# MAIN AGENT
# ════════════════════════════════════════════════════════════════════
def run_security_agent(target: str = TARGET) -> dict:
    print(f"\n[Security Agent] Starting analysis for target: {target}")

    sbom_raw      = _load_json(REPORTS / "sbom-spdx.json")
    gitleaks_raw  = _load_json(REPORTS / "gitleaks-report.json")
    grype_raw     = _load_json(REPORTS / "grype-report.json")
    container_raw = _load_json(REPORTS / "container-scan-summary.json")
    slsa_txt      = _read(REPORTS / "firmware-sha256.txt")

    sbom_summary                   = _summarise_sbom(sbom_raw)
    gitleaks_summary, raw_secrets  = _parse_gitleaks(gitleaks_raw)
    grype_summary                  = _summarise_grype(grype_raw)
    container_summary              = _summarise_container_scan(container_raw)
    slsa_summary                   = _summarise_slsa_hashes(slsa_txt)

    # ── Layer 1 — deterministic ground truth ───────────────────────
    n_secrets   = len(raw_secrets)
    n_crit_cves = len([
        m for m in (grype_raw.get("matches", [])
                    if isinstance(grype_raw, dict) else [])
        if m.get("vulnerability", {}).get("severity") == "Critical"
    ])
    n_high_cves = len([
        m for m in (grype_raw.get("matches", [])
                    if isinstance(grype_raw, dict) else [])
        if m.get("vulnerability", {}).get("severity") == "High"
    ])
    mutable_tag = (
        "@sha256:" not in container_raw.get("image", "")
        if container_raw else True
    )
    slsa_available = bool(
        slsa_txt and "not found" not in slsa_txt.lower()
    )

    deterministic_score = _compute_score_from_data(
        n_secrets, n_crit_cves, n_high_cves, mutable_tag, slsa_available
    )

    print(
        f"[Security Agent] Deterministic score: {deterministic_score}/10  "
        f"(unique_secrets={n_secrets} critCVE={n_crit_cves} "
        f"highCVE={n_high_cves} mutableTag={mutable_tag} "
        f"slsa={slsa_available})"
    )

    # ── Layer 2 — inject expected score into the LLM prompt ────────
    score_guidance = f"""
SCORING RULES — you MUST output security_score = {deterministic_score}.
This number was computed deterministically from the raw scanner data.
Your job is to write the human-readable justification, not to choose
a different number.

Deduction table:
  Start at 10.
  - Each UNIQUE hardcoded secret       :  -3 points (max -9)
  - Each Critical CVE                  :  -2 points (max -6)
  - Each High CVE                      :  -1 point  (max -3)
  - Mutable Docker tag (no @sha256:)   :  -1 point
  - SLSA hashes missing                :  -1 point
  - Score floor: 0

Current data (deduplicated):
  unique_secrets = {n_secrets}
  critical_cves  = {n_crit_cves}
  high_cves      = {n_high_cves}
  mutable_tag    = {mutable_tag}
  slsa_available = {slsa_available}

REQUIRED OUTPUT  : security_score = {deterministic_score}
"""

    llm = ChatGroq(
        model       = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key     = os.getenv("GROQ_API_KEY"),
        temperature = 0.0,
        max_tokens  = 2500,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a senior DevSecOps security engineer specialising
in embedded IoT supply chain security. CRITICAL: the security_score is
computed deterministically and given to you in the prompt — you MUST
output that exact value. Always respond with valid JSON only, no markdown."""),

        ("human", """Analyse the security posture for target: {target}

=== SBOM SUMMARY ===
{sbom_summary}

=== SECRET SCAN (Gitleaks, deduplicated) ===
{gitleaks_summary}

=== CVE SCAN (Grype) ===
{grype_summary}

=== CONTAINER IMAGE SCAN ===
{container_summary}

=== FIRMWARE SLSA HASHES ===
{slsa_summary}

{score_guidance}

Provide a JSON response with EXACTLY this structure
(security_score MUST equal {deterministic_score}):
{{
  "target": "{target}",
  "security_score": {deterministic_score},
  "score_justification": "step-by-step: started at 10, deducted X for Y unique secrets, Z for ...",
  "critical_cves": [],
  "secrets_found": [
    {{
      "type": "API key type",
      "file": "file path",
      "line": "line number",
      "risk": "critical",
      "action": "what to do immediately"
    }}
  ],
  "container_security": {{
    "image": "image name",
    "digest_pinned": true,
    "mutable_tag_risk": false,
    "recommendation": "pin image to digest"
  }},
  "slsa_provenance": {{
    "hashes_available": true,
    "binary_count": 3,
    "integrity_status": "verified",
    "recommendation": "add SLSA L2 attestation"
  }},
  "recommendations": [
    "1. [CRITICAL] Rotate exposed key immediately",
    "2. [HIGH] Pin Docker image to digest",
    "3. [LOW] Add SLSA L2 attestation"
  ],
  "summary": "2-3 sentence executive summary"
}}"""),
    ])

    chain = prompt | llm | StrOutputParser()

    print("[Security Agent] Calling Groq LLM...")
    raw = chain.invoke({
        "target":              target,
        "sbom_summary":        sbom_summary,
        "gitleaks_summary":    gitleaks_summary,
        "grype_summary":       grype_summary,
        "container_summary":   container_summary,
        "slsa_summary":        slsa_summary,
        "score_guidance":      score_guidance,
        "deterministic_score": deterministic_score,
    })

    # ── Parse LLM response ─────────────────────────────────────────
    try:
        clean = raw.strip()
        for fence in ("```json", "```"):
            if clean.startswith(fence):
                clean = clean[len(fence):]
        clean  = clean.rstrip("`").strip()
        report = json.loads(clean)
    except json.JSONDecodeError:
        print("[Security Agent] Warning: LLM returned invalid JSON — "
              "using deterministic fallback")
        report = {
            "target":               target,
            "security_score":       deterministic_score,
            "score_justification":  (
                f"Deterministic fallback: {n_secrets} unique secret(s), "
                f"{n_crit_cves} critical CVE(s), {n_high_cves} high CVE(s), "
                f"mutable_tag={mutable_tag}, slsa_available={slsa_available}."
            ),
            "critical_cves":  [],
            "secrets_found":  raw_secrets,
            "parse_error":    True,
            "raw_response":   raw[:500],
        }

    # ── Layer 3 — post-LLM validation ──────────────────────────────
    llm_score = report.get("security_score")

    if not isinstance(llm_score, (int, float)):
        report["security_score"] = deterministic_score
        print(f"[Security Agent] OVERRIDE: LLM score non-numeric "
              f"→ {deterministic_score}/10")

    elif llm_score == 0 and deterministic_score >= 4:
        report["security_score"] = deterministic_score
        report["score_justification"] = (
            f"[Auto-corrected from LLM 0/10 to {deterministic_score}/10] "
            + report.get("score_justification", "")
        )
        print(f"[Security Agent] OVERRIDE: LLM 0/10 → "
              f"{deterministic_score}/10 (gt-truth)")

    # CRITICAL: never let LLM override the deterministic score upward
    elif llm_score > deterministic_score + 1:
        print(f"[Security Agent] OVERRIDE: LLM said {llm_score}/10 "
              f"but ground truth is {deterministic_score}/10 → using gt")
        report["security_score"] = deterministic_score

    # ── Always inject deduplicated secrets list ────────────────────
    # (don't trust the LLM to enumerate them correctly)
    if raw_secrets:
        report["secrets_found"] = raw_secrets
        print(f"[Security Agent] Injected {n_secrets} deduplicated "
              f"secret(s) into report")
    elif not report.get("secrets_found"):
        report["secrets_found"] = []

    # ── Save ───────────────────────────────────────────────────────
    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"security-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Security Agent] Report saved: {out}")

    score   = report.get("security_score", "N/A")
    n_cves  = len(report.get("critical_cves", []))
    secrets = len(report.get("secrets_found", []))
    print(f"[Security Agent] Done — score={score}/10 "
          f"| CVEs={n_cves} | secrets={secrets}")
    return report


if __name__ == "__main__":
    report = run_security_agent()
    print(json.dumps(report, indent=2))
