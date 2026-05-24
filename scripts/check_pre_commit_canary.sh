#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
CANARY_DEF="$REPO_ROOT/.canaries/pre-commit.md"
CANARY_LOG="$REPO_ROOT/.canary--pre-commit"
STAGED_CANARY=$(git diff --cached --name-only --diff-filter=ACMR -- .canary--pre-commit || true)

if [ ! -f "$CANARY_DEF" ]; then
  printf '%s\n' "pre-commit: .canaries/pre-commit.md not found - skipping canary check"
  exit 0
fi

if [ -n "$STAGED_CANARY" ]; then
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "pre-commit: .canary--pre-commit is staged for commit."
  printf >&2 '%s\n' "pre-commit: the canary receipt is transient local state and must remain untracked."
  printf >&2 '%s\n' "pre-commit: unstage it with 'git restore --staged .canary--pre-commit' and try again."
  printf >&2 '%s\n' ""
  exit 1
fi

TASKS_SECTION=$(awk '/^## Tasks$/{f=1;next}/^## Log$/{f=0}f' "$CANARY_DEF")
EXPECTED_IDS=$(printf '%s\n' "$TASKS_SECTION" | grep -oE '\[[0-9]+[a-z]?\]' | sort -u || true)

if [ -z "$EXPECTED_IDS" ]; then
  printf '%s\n' "pre-commit: no bracket IDs found in .canaries/pre-commit.md - skipping"
  exit 0
fi

if [ ! -f "$CANARY_LOG" ]; then
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "pre-commit: .canary--pre-commit not found."
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "Read .canaries/pre-commit.md and write .canary--pre-commit"
  printf >&2 '%s\n' "confirming you've followed each task. Format:"
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "  [1] Label: done"
  printf >&2 '%s\n' "  [2] Label: skip, reason"
  printf >&2 '%s\n' ""
  exit 1
fi

MISSING=""
for ID in $EXPECTED_IDS; do
  if ! grep -qF "$ID" "$CANARY_LOG" 2>/dev/null; then
    MISSING="$MISSING  $ID\n"
  fi
done

if [ -n "$MISSING" ]; then
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "pre-commit: .canary--pre-commit is missing these tasks:"
  printf >&2 "$MISSING"
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "Mark each as '[id] Label: done' or '[id] Label: skip, reason'."
  exit 1
fi

BAD=""
while IFS= read -r LINE || [ -n "$LINE" ]; do
  TRIMMED=$(printf '%s' "$LINE" | sed -E 's/^[[:space:]]+//')
  case "$TRIMMED" in
    \[[0-9]*\]*)
      if ! printf '%s' "$TRIMMED" | grep -qE '^\[[0-9]+[a-z]?\] .+: (done([, ] ?.+)?|skip, ?.+)$'; then
        BAD="$BAD  $LINE\n"
      fi
      ;;
  esac
done < "$CANARY_LOG"

if [ -n "$BAD" ]; then
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "pre-commit: these lines have invalid format:"
  printf >&2 "$BAD"
  printf >&2 '%s\n' ""
  printf >&2 '%s\n' "Expected: [id] Label: done  or  [id] Label: skip, reason"
  exit 1
fi

rm -f "$CANARY_LOG"
