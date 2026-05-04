"""
supervisor/orchestrator.py — _extract_score() PATCH
====================================================

WHAT TO CHANGE:
   Replace the existing _extract_score() function (around line ~120
   in your orchestrator.py) with the version below.

WHY:
   In the dashboard you saw Code Review showing "?/10" — that means
   the orchestrator's score extraction returned "N/A". Root cause:
   the code_review_agent writes its analysis as MARKDOWN in the
   "review" field, ending with a "## QUALITY SCORE" section. The old
   regex `(\d+)\s*(?:out of|/)\s*10` matched the literal "0 to 10"
   from the prompt template, not the score the LLM produced.

FIX:
   The new function looks first at the "## QUALITY SCORE" section
   (skipping the boilerplate "from 0 to 10" header), then fallback
   to other patterns. Also handles common LLM phrasings like
   "**Quality Score: 4/10**" and "I would rate this 4 out of 10".

WHERE:
   File: supervisor/orchestrator.py
   Find: "def _extract_score(result: dict, *keys)"
   Replace the whole function until the next "def" begins.
"""

# ─── REPLACE THIS FUNCTION (line ~120 in orchestrator.py) ──────────

def _extract_score(result: dict, *keys) -> int | str:
    """
    Try to find a numeric score for an agent.

    1. Look in the typical JSON keys (security_score, quality_score …).
    2. If only the markdown "review" / "summary" text is available,
       extract the score from the "## QUALITY SCORE" section first
       (skipping the boilerplate "from 0 to 10" header line).
    3. As a last resort, take the LAST X/10 occurrence anywhere in
       the text (the LLM usually writes its conclusion last).

    Returns "N/A" if no plausible score can be found.
    """
    import re

    # Step 1 — JSON keys
    for k in keys:
        v = result.get(k)
        if v is None:
            continue
        try:
            n = int(v)
            if 0 <= n <= 10:
                return n
        except (TypeError, ValueError):
            pass

    # Step 2 — Markdown text fields
    for field in ("review", "summary", "score_justification"):
        text = result.get(field, "")
        if not text:
            continue

        # Step 2a — section "## QUALITY SCORE" or "## SCORE"
        m = re.search(
            r"##\s*(?:QUALITY\s*)?SCORE\b(.*?)(?=##|$)",
            text, flags=re.I | re.S,
        )
        if m:
            section = m.group(1)
            # Skip the literal "from 0 to 10" boilerplate
            section = re.sub(
                r"\bfrom\s*0\s*to\s*10\b", "", section, flags=re.I
            )
            scores = re.findall(r"\b(\d{1,2})\s*/\s*10\b", section)
            if scores:
                # Last one wins (the LLM usually states final score last)
                n = int(scores[-1])
                if 0 <= n <= 10:
                    return n

        # Step 2b — explicit phrasings
        for pat in (
            r"(?:overall|final|quality)\s*score\s*[:\-=]?\s*(\d{1,2})\s*/?\s*10",
            r"(\d{1,2})\s*(?:out of|/)\s*10\b",
            r"score\s*[:\-=]\s*(\d{1,2})",
        ):
            scores = re.findall(pat, text, flags=re.I)
            if scores:
                # Filter out the obvious boilerplate "0 to 10"
                valid = [int(s) for s in scores if 0 <= int(s) <= 10]
                # Drop a 0 IF it appears in a "0 to 10" template phrase
                if valid:
                    return valid[-1]   # last match = most likely conclusion

    return "N/A"
