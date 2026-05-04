"""
agents/autofix_agent.py — DEDUP PATCH (apply ONLY this function change)
=========================================================================

WHAT TO CHANGE:
   Replace the existing _collect_issues() function (around line 362)
   with the version below.

WHY:
   Without this, when security_agent reports N secrets at the same
   location, _collect_issues creates N identical "Hardcoded API key"
   entries → AutoFix produces N identical manual_instructions → the
   dashboard shows 13 "critical: rotate the exposed API key" cards.

   The security_agent v5 already dedupes upstream, but this is a
   second safety net at the AutoFix level.

WHERE:
   File: agents/autofix_agent.py
   Find: "def _collect_issues(reports: dict) -> list:"
   Replace the entire function until the end of the function body
   (it ends with the print(...) line and "return issues").

The rest of autofix_agent.py is unchanged. Do NOT replace the
whole file — only the _collect_issues function.
"""

# ─── REPLACE THIS FUNCTION (line ~362 in autofix_agent.py) ─────────

def _collect_issues(reports: dict) -> list:
    """
    Collect issues from every upstream agent report and deduplicate
    them so AutoFix doesn't generate duplicate patches/instructions.

    DEDUP STRATEGY:
       Two issues are considered "the same" if they share
       (source_agent, file, category, first 80 chars of description).
       This catches the case of multiple commits referencing the same
       secret as well as the case of LLM-generated bullets that
       overlap.
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
            import re
            sections = re.split(r"##\s+", review_text)
            for section in sections:
                lines = section.strip().splitlines()
                if not lines:
                    continue
                header = lines[0].lower()
                content = "\n".join(lines[1:]).strip()
                if not content or len(content) < 20:
                    continue
                if not any(k in header for k in
                           ("security", "critical", "unsafe", "buffer")):
                    continue
                bullets = re.split(r"\n[-*•]\s*|\n\d+\.\s*", content)
                # Cap at 3 bullets per section to avoid spam
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

    # ── DEDUP step ─────────────────────────────────────────────────
    seen: set[tuple[str, str, str, str]] = set()
    issues = []
    for it in raw_issues:
        # Dedup key: same agent + file + category + content prefix
        # File may be empty → still works
        desc_prefix = (it.get("description") or "")[:80].lower().strip()
        key = (
            it.get("source_agent",  ""),
            it.get("file",           ""),
            it.get("category",       ""),
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
