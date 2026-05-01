#!/bin/bash
# AutoFix APPLY_ALL.sh — target: esp32c3
# Généré: 2026-05-01 11:31
set -e

APPLIED=0; SKIPPED=0
SCRIPT_DIR="$(dirname "$0")"

# Appliquer les patches Python directement (git apply)
# Appliquer les patches C++ dans esp-matter/

echo "→ autofix-esp32c3-01-security-demo_intentional_bug.py.patch"
if git apply --check "reports/patches/autofix-esp32c3-01-security-demo_intentional_bug.py.patch" 2>/dev/null; then
  git apply "reports/patches/autofix-esp32c3-01-security-demo_intentional_bug.py.patch"
  echo "  ✅ Appliqué"
  APPLIED=$((APPLIED+1))
elif git apply --check --ignore-whitespace "reports/patches/autofix-esp32c3-01-security-demo_intentional_bug.py.patch" 2>/dev/null; then
  git apply --ignore-whitespace "reports/patches/autofix-esp32c3-01-security-demo_intentional_bug.py.patch"
  echo "  ✅ Appliqué (ignore-whitespace)"
  APPLIED=$((APPLIED+1))
else
  echo "  ⚠️  Skip (autofix-esp32c3-01-security-demo_intentional_bug.py.patch)"
  SKIPPED=$((SKIPPED+1))
fi

echo ""
echo "[AutoFix] Appliqué: $APPLIED | Skippé: $SKIPPED"