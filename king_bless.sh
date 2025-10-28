#!/usr/bin/env sh
# king_bless.sh
# Defensive helper for Termux: heuristically scans a codebase for patterns that may indicate SQL injection risk.
# WARNING: This is a heuristic scanner. It will produce false positives and false negatives.
# Use it to find suspicious code, then manually review and fix with parameterized queries.

set -e

TARGET_DIR="${1:-.}"

if ! command -v grep >/dev/null 2>&1; then
  echo "This script requires grep. Install it in Termux with: pkg install grep"
  exit 1
fi

echo "king_bless: scanning ${TARGET_DIR} for risky SQL patterns (heuristic)..."
echo

# Patterns: direct query functions, concatenation near SQL keywords, use of string interpolation with execute/cursor
grep -RIn --binary-files=without-match --exclude-dir=node_modules \
  -e "mysql_query\s*\(" \
  -e "pg_query\s*\(" \
  -e "sqlite3\.execute\(" \
  -e "cursor\.execute\s*\(" \
  -e "\.query\s*\(" \
  -e "exec\(" \
  -e "execute\(" \
  "${TARGET_DIR}" || true

echo
echo "Checking for likely string concatenation near SQL keywords (PHP '.' or JS/Python '+')..."
# PHP concatenation with dot near SQL words (very fuzzy)
grep -RIn --binary-files=without-match --exclude-dir=node_modules --include='*.php' \
  -E "(SELECT|INSERT|UPDATE|DELETE).*\." "${TARGET_DIR}" || true

# JS/Python concatenation with + near SQL keywords (very fuzzy)
grep -RIn --binary-files=without-match --exclude-dir=node_modules --include='*.js' -E "(SELECT|INSERT|UPDATE|DELETE).*\+" "${TARGET_DIR}" || true
grep -RIn --binary-files=without-match --exclude-dir=node_modules --include='*.py' -E "(SELECT|INSERT|UPDATE|DELETE).*\+" "${TARGET_DIR}" || true

echo
echo "Checking for string interpolation patterns that may be unsafe (PHP \"\${}\", Python f-strings, JS template literals with variables)..."
grep -RIn --binary-files=without-match --exclude-dir=node_modules --include='*.php' -E "\$\{?[A-Za-z0-9_]+\}?" "${TARGET_DIR}" || true
grep -RIn --binary-files=without-match --exclude-dir=node_modules --include='*.py' -E "f\".*\{.*\}.*\"" "${TARGET_DIR}" || true
grep -RIn --binary-files=without-match --exclude-dir=node_modules --include='*.js' -E "`.*\\$\\{.*\\}.*`" "${TARGET_DIR}" || true

echo
echo "Scan complete. Notes:"
echo "- Results are heuristics. Manually review each flagged line."
echo "- Prefer parameterized queries / prepared statements. Do not build SQL by concatenating untrusted input."
echo "- To fix issues, sanitize inputs and use DB drivers' parameter APIs."