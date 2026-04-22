"""
Agent 2 — Security Agent  (Stage 2 + Stage 3 + Stage 6)
Updated inputs from new CI/CD:
  - reports/sbom-spdx.json           (Stage 2 — unchanged)
  - reports/gitleaks-report.json     (Stage 2 — unchanged)
  - reports/grype-report.json        (Stage 2 — unchanged)
  - reports/container-scan-summary.json  (Stage 3 — NEW)
  - reports/firmware-sha256.txt          (Stage 6 — NEW: SLSA hashes)
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
    packages = sbom.get("packages", [])
    relationships = sbom.get("relationships", [])
    pkg_names = [p.get("name", "?") + " " + p.get("versionInfo", "") for p in packages[:20]]
    return (
        f"Total packages: {len(packages)} | Relationships: {len(relationships)}\n"
        f"Top packages: {', '.join(pkg_names)}"
    )


def _summarise_gitleaks(leaks: dict | list) -> str:
    if not leaks:
        return "No secrets found OR report empty."
    if isinstance(leaks, list):
        if len(leaks) == 0:
            return "No secrets detected — clean."
        items = []
        for l in leaks[:10]:
            items.append(
                f"  Rule={l.get('RuleID','?')} | File={l.get('File','?')} "
                f"| Line={l.get('StartLine','?')} | Match=[REDACTED]"
            )
        return f"SECRETS FOUND ({len(leaks)} total):\n" + "\n".join(items)
    return str(leaks)[:500]


def _summarise_grype(grype: dict) -> str:
    if not grype:
        return "Grype CVE report not available."
    matches = grype.get("matches", [])
    if not matches:
        return "No CVEs found."
    critical = [m for m in matches if m.get("vulnerability", {}).get("severity") == "Critical"]
    high     = [m for m in matches if m.get("vulnerability", {}).get("severity") == "High"]

    lines = [f"Total CVEs: {len(matches)} | Critical: {len(critical)} | High: {len(high)}"]
    for m in (critical + high)[:10]:
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        lines.append(
            f"  {v.get('severity','?')} | {v.get('id','?')} | "
            f"pkg={art.get('name','?')} {art.get('version','?')} | "
            f"fix={v.get('fix', {}).get('versions', ['none'])}"
        )
    return "\n".join(lines)


def _summarise_container_scan(scan: dict) -> str:
    if not scan:
        return "Container scan summary not available."
    image  = scan.get("image", "unknown")
    digest = scan.get("digest", "unknown")
    date   = scan.get("scan_date", "unknown")
    mutable = "@sha256:" not in image
    warning = " ⚠️  MUTABLE TAG — supply chain risk" if mutable else " ✅ Digest pinned"
    return (
        f"Image: {image}{warning}\n"
        f"Digest: {digest}\n"
        f"Scanned: {date}"
    )


def _summarise_slsa_hashes(hashes_txt: str) -> str:
    if not hashes_txt or "not found" in hashes_txt.lower():
        return "SLSA firmware hashes not available."
    lines = [l.strip() for l in hashes_txt.strip().splitlines() if l.strip()]
    return f"Firmware SHA256 hashes ({len(lines)} binaries):\n" + "\n".join(f"  {l}" for l in lines)


# ── main agent function ─────────────────────────────────────────────

def run_security_agent(target: str = TARGET) -> dict:
    print(f"\n[Security Agent] Starting analysis for target: {target}")

    sbom_raw      = _load_json(REPORTS / "sbom-spdx.json")
    gitleaks_raw  = _load_json(REPORTS / "gitleaks-report.json")
    grype_raw     = _load_json(REPORTS / "grype-report.json")
    container_raw = _load_json(REPORTS / "container-scan-summary.json")  # NEW
    slsa_txt      = _read(REPORTS / "firmware-sha256.txt")               # NEW

    sbom_summary      = _summarise_sbom(sbom_raw)
    gitleaks_summary  = _summarise_gitleaks(gitleaks_raw)
    grype_summary     = _summarise_grype(grype_raw)
    container_summary = _summarise_container_scan(container_raw)
    slsa_summary      = _summarise_slsa_hashes(slsa_txt)

    llm = ChatGroq(
        model=os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1,
        max_tokens=2500,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a senior DevSecOps security engineer specialising in
embedded IoT supply chain security, firmware security, and CVE analysis for
ESP32 / Matter devices. You analyse SBOM reports, secret scans, CVE databases,
container scan results, and SLSA provenance hashes.
Always respond with a valid JSON object only — no markdown, no backticks."""),

        ("human", """Analyse the security posture for target: {target}

=== SBOM SUMMARY ===
{sbom_summary}

=== SECRET SCAN (Gitleaks) ===
{gitleaks_summary}

=== CVE SCAN (Grype) ===
{grype_summary}

=== CONTAINER IMAGE SCAN (Stage 3 - NEW) ===
{container_summary}

=== FIRMWARE SLSA HASHES (Stage 6 - NEW) ===
{slsa_summary}

Provide a JSON response with exactly this structure:
{{
  "target": "{target}",
  "security_score": 7,
  "score_justification": "explanation of score 0-10",

  "critical_cves": [
    {{
      "cve_id": "CVE-XXXX-XXXXX",
      "severity": "Critical|High",
      "package": "package name and version",
      "description": "what it does",
      "remediation": "exact fix — upgrade to X.X.X or apply patch"
    }}
  ],

  "secrets_found": [
    {{
      "type": "API key / credential type",
      "file": "file path",
      "risk": "high|medium|low",
      "action": "what to do immediately"
    }}
  ],

  "container_security": {{
    "image": "image name",
    "digest_pinned": true,
    "mutable_tag_risk": false,
    "recommendation": "action if needed"
  }},

  "slsa_provenance": {{
    "hashes_available": true,
    "binary_count": 0,
    "integrity_status": "verified|missing|partial",
    "recommendation": "next steps for SLSA L2/L3"
  }},

  "supply_chain_risks": [
    {{
      "component": "component name",
      "risk": "description of supply chain risk",
      "mitigation": "concrete mitigation step"
    }}
  ],

  "dependency_risks": [
    {{
      "package": "name",
      "version": "version",
      "risk": "description",
      "recommended_version": "safe version"
    }}
  ],

  "prioritised_actions": [
    "Action 1 — most critical",
    "Action 2",
    "Action 3",
    "Action 4"
  ],

  "compliance_notes": "Any SPDX/CycloneDX / SBOM compliance observations",
  "summary": "2-3 sentence executive summary of security posture"
}}"""),
    ])

    chain = prompt | llm | StrOutputParser()

    print("[Security Agent] Calling Groq LLM...")
    raw = chain.invoke({
        "target":            target,
        "sbom_summary":      sbom_summary,
        "gitleaks_summary":  gitleaks_summary,
        "grype_summary":     grype_summary,
        "container_summary": container_summary,
        "slsa_summary":      slsa_summary,
    })

    try:
        clean  = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        report = json.loads(clean)
    except json.JSONDecodeError:
        print("[Security Agent] Warning: could not parse JSON — saving raw")
        report = {"target": target, "raw_response": raw, "parse_error": True}

    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"security-report-{target}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Security Agent] Report saved: {out}")

    score   = report.get("security_score", "N/A")
    n_cves  = len(report.get("critical_cves", []))
    secrets = len(report.get("secrets_found", []))
    print(f"[Security Agent] Done — score={score}/10, CVEs={n_cves}, secrets={secrets}")
    return report


if __name__ == "__main__":
    report = run_security_agent()
    print(json.dumps(report, indent=2))
