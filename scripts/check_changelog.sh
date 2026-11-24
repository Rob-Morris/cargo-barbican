#!/bin/sh
# Shared canonical version-note/index contract for commits and tag publication.
set -eu
version=${1-}
fail() { printf >&2 'changelog-check: %s\n' "$*"; exit 1; }
case "$version" in ''|*[!0-9.]*) fail 'exact version required' ;; esac
file="docs/changelog/v$version.md"
[ -f "$file" ] && [ ! -L "$file" ] || fail "missing regular $file"
summary=$(awk '/^\*\*Summary\*\* / {sub(/^\*\*Summary\*\* /, ""); print}' "$file")
[ -n "$summary" ] || fail "$file is missing the canonical Summary"
case "$summary" in *'
'*) fail 'multiple canonical Summaries' ;; esac
[ -n "$(printf '%s' "$summary" | tr -d '[:space:]')" ] || fail 'empty canonical Summary'
link="[v$version](changelog/v$version.md)"
awk -F'|' -v link="$link" -v expected="$summary" '
  function trim(s) {gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s}
  /^\|/ {if (trim($2) == link) {versions++; if (trim($4) == expected) matching++}}
  END {exit(versions == 1 && matching == 1 ? 0 : 1)}
' docs/CHANGELOG.md || fail 'missing or ambiguous matching version/index Summary'
printf '%s\n' "$summary"
