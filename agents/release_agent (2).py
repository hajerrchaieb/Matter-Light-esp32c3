# ================================================================
# 🚀 RELEASE AGENT — Stage 7: Changelog et release notes
# ================================================================
# ORIGINAL structure preserved — PromptTemplate + Markdown output
# FIXED: read_report() now reads ALL known keys, not just 3
# ADDED: container_scan, slsa_hashes, deploy_status, ota_manifest
#        testgen_report — fixes "Tests Generated: Failed" in CHANGELOG
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
    input_variables=[
        "git_log",
        "debug_report",
        "security_report",
        "code_review_report",
        "optimization_report",
        "container_scan",
        "slsa_hashes",
        "deploy_status",
        "ota_manifest",
        "testgen_report",          # ← ADDED (was missing — caused "Failed" in CHANGELOG)
        "version",
        "target",
        "date",
    ],
    template="""
You are a technical writer for ESP32 Matter firmware releases.
Version : {version}
Target  : {target}
Date    : {date}

GIT COMMIT HISTORY:
{git_log}

DEBUG AGENT FINDINGS:
{debug_report}

SECURITY AGENT FINDINGS:
{security_report}

CODE REVIEW FINDINGS:
{code_review_report}

OPTIMIZATION AGENT FINDINGS:
{optimization_report}

CONTAINER IMAGE SCAN (Stage 3):
{container_scan}

FIRMWARE SLSA HASHES (Stage 6):
{slsa_hashes}

OTA MANIFEST CHECKSUMS (Stage 7):
{ota_manifest}

CANARY DEPLOYMENT RESULT (Stage 9):
{deploy_status}

TEST GENERATION AGENT (Stage 5):
{testgen_report}

Generate a complete professional release document:

## CHANGELOG — {version}

### ✨ New Features
List new features extracted from git commits.

### 🐛 Bug Fixes
List all bugs fixed based on debug agent findings.

### 🔐 Security Updates
List security improvements from security agent.
Include container image digest and SLSA hash status.

### ⚡ Performance Improvements
List memory and performance optimizations found.

### 🔍 Code Quality
Summary of code review findings and improvements.

---

## 📋 RELEASE NOTES
Professional summary for end users (2-3 paragraphs).

---

## 💾 MEMORY FOOTPRINT
| Memory | Used   | Available | Status |
|--------|--------|-----------|--------|
| Flash  | ?KB    | 4096KB    | ?      |
| DRAM   | ?KB    | 400KB     | ?      |
| IRAM   | ?KB    | 128KB     | ?      |

---

## ⚡ FLASH INSTRUCTIONS
```bash
# Flash the firmware
esptool.py --chip {target} --port /dev/ttyUSB0 write_flash @flasher_args.json

# Or flash manually
esptool.py --chip {target} --port /dev/ttyUSB0 write_flash \\
  0x0     bootloader.bin \\
  0x8000  partition-table.bin \\
  0x10000 light.bin
```

---

## ✅ QUALITY GATES
| Check               | Status |
|---------------------|--------|
| Build               | ?      |
| Security Scan       | ?      |
| Code Review Score   | ?/10   |
| Memory Usage        | ?      |
| Tests Generated     | ?      |
| Container Scan      | ?      |
| SLSA Provenance     | ?      |
| Canary Deployment   | {deploy_status} |

---

## ⚠️ KNOWN ISSUES
List any remaining issues from all agent reports.

---

## 🔜 NEXT RELEASE
Recommended improvements for next version based on all findings.
"""
)

chain = prompt | llm | StrOutputParser()


def read_report(path: str) -> str:
    """
    Read a JSON report and extract its text content.
    Tries all known keys used by the different agent versions:
      "review"   — code_review_agent (original)
      "analysis" — debug/security agents (original)
      "tests"    — test_gen_agent (original)
      "changelog"— release_agent own output
      "summary"  — orchestrator summary
    Falls back to dumping the whole JSON if no known key found.
    """
    if not os.path.exists(path):
        print(f"  ⚠️  Not found: {path}")
        return f"Report not available: {path}"

    with open(path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"  ⚠️  Invalid JSON: {path}")
            return f"Invalid JSON in: {path}"

    # Try all known content keys in order
    for key in ("review", "analysis", "tests", "changelog", "summary"):
        if key in data and data[key]:
            content = str(data[key])
            print(f"  ✅ Read: {path} (key='{key}', {len(content)} chars)")
            return content[:800]

    # Fallback: dump the whole dict as a readable string
    content = json.dumps(data, indent=2)
    print(f"  ✅ Read: {path} (full JSON fallback, {len(content)} chars)")
    return content[:800]


def read_new_ci_artifact(path: str, label: str) -> str:
    """Read new CI artifacts added after the ci.yml update."""
    if not os.path.exists(path):
        return f"{label}: not available (Stage may not have run yet)"

    # Plain text files (e.g. firmware-sha256.txt, deploy-status.txt)
    if path.endswith(".txt"):
        with open(path, "r") as f:
            content = f.read().strip()
        print(f"  ✅ Read: {path} ({len(content)} chars)")
        return f"{label}:\n{content}"

    # JSON files
    with open(path, "r") as f:
        try:
            data = json.load(f)
            content = json.dumps(data, indent=2)
            print(f"  ✅ Read: {path}")
            return f"{label}:\n{content[:500]}"
        except Exception:
            return f"{label}: unreadable"


def run_release_agent(
    version: str = "v1.0.0",
    target:  str = "esp32c3"
) -> dict:
    print(f"\n{'='*55}")
    print(f"🚀 RELEASE AGENT — Stage 7")
    print(f"📦 Version : {version}")
    print(f"🎯 Target  : {target}")
    print(f"{'='*55}")
    print("\n📖 Reading all agent reports...")

    # ── Original agent reports (same keys as before) ───────────────
    debug_report        = read_report(f"reports/debug-report-{target}.json")
    security_report     = read_report(f"reports/security-report-{target}.json")
    code_review_report  = read_report(f"reports/code-review-{target}.json")
    optimization_report = read_report(f"reports/optimization-report-{target}.json")

    # ── Test generation report ─────────────────────────────────────
    # Reads testgen-report-{target}.json to get the real test count.
    # This fixes "Tests Generated: Failed" in the CHANGELOG — the LLM
    # was guessing because it had no info about the test agent output.
    testgen_path   = f"reports/testgen-report-{target}.json"
    testgen_report = "Test generation report not available."
    if os.path.exists(testgen_path):
        try:
            with open(testgen_path) as f:
                tg = json.load(f)
            n_cases    = len(tg.get("test_cases", []))
            cpp_exists = os.path.exists(
                f"reports/generated_tests_{target}.cpp"
            )
            mocks   = [m.get("filename", "") for m in tg.get("mock_files", [])]
            summary = tg.get("summary", "")
            testgen_report = (
                f"{n_cases} test cases generated — "
                f"C++ file: {'saved' if cpp_exists else 'missing'} — "
                f"Mocks: {', '.join(mocks) if mocks else 'none'}\n"
                f"Summary: {summary}"
            )
            print(f"  ✅ Read: {testgen_path} ({n_cases} test cases)")
        except Exception as e:
            testgen_report = f"Could not read testgen report: {e}"
            print(f"  ⚠️  {testgen_report}")
    else:
        print(f"  ⚠️  Not found: {testgen_path}")

    # ── New CI artifacts added in updated ci.yml ───────────────────
    print("\n📖 Reading new CI artifacts...")
    container_scan = read_new_ci_artifact(
        "reports/container-scan-summary.json", "Container image scan"
    )
    slsa_hashes = read_new_ci_artifact(
        "reports/firmware-sha256.txt", "Firmware SHA256 hashes"
    )
    ota_manifest = read_new_ci_artifact(
        "reports/ota-manifest-signed.json", "OTA manifest with checksums"
    )
    deploy_status = read_new_ci_artifact(
        "reports/deploy-status.txt", "Canary deployment result"
    )

    # ── Git log ────────────────────────────────────────────────────
    print("  📝 Reading git log...")
    git_log = os.popen(
        "git log --oneline -15 2>/dev/null || echo 'No git history available'"
    ).read().strip()

    print("\n⚡ Generating release notes with Groq...\n")

    result = chain.invoke({
        "git_log":             git_log,
        "debug_report":        debug_report,
        "security_report":     security_report,
        "code_review_report":  code_review_report,
        "optimization_report": optimization_report,
        "container_scan":      container_scan,
        "slsa_hashes":         slsa_hashes,
        "ota_manifest":        ota_manifest,
        "deploy_status":       deploy_status,
        "testgen_report":      testgen_report,   # ← ADDED
        "version":             version,
        "target":              target,
        "date":                datetime.now().strftime("%Y-%m-%d"),
    })

    print("📋 RELEASE NOTES:")
    print("-" * 55)
    print(result)
    print("-" * 55)

    # ── Save Markdown changelog ────────────────────────────────────
    os.makedirs("reports", exist_ok=True)
    changelog_file = f"reports/CHANGELOG-{version}.md"
    with open(changelog_file, "w") as f:
        f.write(f"# ESP32 Matter Light Firmware — {version}\n")
        f.write(f"**Target:** {target}  \n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}  \n")
        f.write(f"**Generated by:** AI Release Agent  \n\n")
        f.write("---\n\n")
        f.write(result)

    # ── Save JSON report (same structure as original) ──────────────
    report = {
        "agent":          "release_agent",
        "timestamp":      datetime.now().isoformat(),
        "version":        version,
        "target":         target,
        "changelog":      result,
        "changelog_file": changelog_file,
        "sources": {
            "debug":          f"reports/debug-report-{target}.json",
            "security":       f"reports/security-report-{target}.json",
            "code_review":    f"reports/code-review-{target}.json",
            "optimization":   f"reports/optimization-report-{target}.json",
            "testgen":        f"reports/testgen-report-{target}.json",  # ← ADDED
            "container_scan": "reports/container-scan-summary.json",
            "slsa_hashes":    "reports/firmware-sha256.txt",
            "ota_manifest":   "reports/ota-manifest-signed.json",
            "deploy_status":  "reports/deploy-status.txt",
        },
        "status": "completed"
    }

    with open(f"reports/release-report-{target}.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Changelog saved : {changelog_file}")
    print(f"✅ Report saved    : reports/release-report-{target}.json")
    return report


if __name__ == "__main__":
    run_release_agent(
        version=os.getenv("RELEASE_VERSION", "v1.0.0"),
        target=os.getenv("TARGET_CHIP", "esp32c3")
    )
