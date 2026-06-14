#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

MSG_FILE="${1:-}"
BRANCH="${2:-$(git branch --show-current 2>/dev/null || true)}"

if [ -z "$MSG_FILE" ] || [ ! -f "$MSG_FILE" ]; then
  printf >&2 '%s\n' "commit-msg: expected commit message file path"
  exit 1
fi

subject=$(
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    { print; exit }
  ' "$MSG_FILE"
)

if [ -z "$subject" ]; then
  printf >&2 '%s\n' "commit-msg: empty commit subject"
  exit 1
fi

subject_len=$(printf '%s' "$subject" | wc -c | tr -d '[:space:]')
if [ "$subject_len" -gt 72 ]; then
  printf >&2 '%s\n' "commit-msg: subject is too long ($subject_len > 72)"
  exit 1
fi

all_staged=$(git diff --cached --name-only --diff-filter=ACMR || true)
if git diff --cached -U0 -- crates/barbican/Cargo.toml crates/cargo-barbican/Cargo.toml | grep -qE '^[+-]version = "'; then
  version_bump_staged=1
else
  version_bump_staged=0
fi

if printf '%s\n' "$all_staged" | grep -Eq '^docs/CHANGELOG\.md$|^docs/changelog/'; then
  changelog_staged=1
else
  changelog_staged=0
fi

read_version() {
  awk -F'"' '
    $1 ~ /^version = / { print $2; exit }
  ' "$1"
}

version_a=$(read_version crates/barbican/Cargo.toml)
version_b=$(read_version crates/cargo-barbican/Cargo.toml)
head_subject=$(git log -1 --format=%s 2>/dev/null || true)

if [ "$version_a" != "$version_b" ]; then
  printf >&2 '%s\n' "commit-msg: crate manifest versions diverge ($version_a vs $version_b)"
  exit 1
fi

if printf '%s' "$subject" | grep -qE '^(docs:|test:|chore:) .+'; then
  if [ "$version_bump_staged" -eq 1 ] || [ "$changelog_staged" -eq 1 ]; then
    printf >&2 '%s\n' "commit-msg: support-only subjects cannot carry version-bundle changes"
    exit 1
  fi
  exit 0
fi

if printf '%s' "$subject" | grep -qE '^WIP: .+'; then
  if [ "$BRANCH" = "main" ]; then
    printf >&2 '%s\n' "commit-msg: WIP commits are not allowed on main"
    exit 1
  fi
  if [ "$version_bump_staged" -eq 1 ] || [ "$changelog_staged" -eq 1 ]; then
    printf >&2 '%s\n' "commit-msg: WIP subjects cannot carry version-bundle changes"
    exit 1
  fi
  exit 0
fi

parsed=$(printf '%s\n' "$subject" | sed -nE 's/^(.*) \(v([0-9]+\.[0-9]+\.[0-9]+)\)$/\1\
\2/p')

if [ -n "$parsed" ]; then
  summary=$(printf '%s\n' "$parsed" | sed -n '1p')
  version=$(printf '%s\n' "$parsed" | sed -n '2p')

  if [ "$version" != "$version_a" ]; then
    printf >&2 '%s\n' "commit-msg: crate manifests are at v$version_a but subject says v$version"
    exit 1
  fi

  changelog_file="docs/changelog/v$version.md"
  if [ ! -f "$changelog_file" ]; then
    printf >&2 '%s\n' "commit-msg: missing $changelog_file"
    exit 1
  fi

  canonical_summary=$(
    awk '
      /^\*\*Summary\*\*/ {
        sub(/^\*\*Summary\*\* /, "")
        print
        exit
      }
    ' "$changelog_file"
  )

  if [ -z "$canonical_summary" ]; then
    printf >&2 '%s\n' "commit-msg: $changelog_file is missing the top-line **Summary**"
    exit 1
  fi

  if [ "$summary" != "$canonical_summary" ]; then
    printf >&2 '%s\n' "commit-msg: subject Summary does not match the canonical $changelog_file Summary"
    printf >&2 '  subject:   %s\n' "$summary"
    printf >&2 '  canonical: %s\n' "$canonical_summary"
    exit 1
  fi

  changelog_link="[v$version](changelog/v$version.md)"

  if ! awk -F'|' -v link="$changelog_link" -v expected="$summary" '
    function trim(s) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
      return s
    }
    /^\|/ {
      version_col = trim($2)
      summary_col = trim($4)
      if (version_col == link && summary_col == expected) {
        found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  ' docs/CHANGELOG.md; then
    printf >&2 '%s\n' "commit-msg: docs/CHANGELOG.md is missing the matching v$version row for the canonical Summary"
    exit 1
  fi

  head_matches_version=0
  if [ "$BRANCH" != "main" ] && [ -n "$head_subject" ] && printf '%s' "$head_subject" | grep -qE "\\(v$version\\)$"; then
    head_matches_version=1
  fi

  if [ "$version_bump_staged" -ne 1 ] && [ "$head_matches_version" -ne 1 ]; then
    printf >&2 '%s\n' "commit-msg: versioned subjects require a staged crate-manifest version bump; only non-main branches may amend the current v$version commit without one"
    exit 1
  fi

  if [ "$changelog_staged" -ne 1 ] && [ "$head_matches_version" -ne 1 ]; then
    printf >&2 '%s\n' "commit-msg: versioned subjects require staged changelog updates; only non-main branches may amend the current v$version commit without them"
    exit 1
  fi

  exit 0
fi

printf >&2 '%s\n' "commit-msg: subject must be '<Summary> (vX.Y.Z)', 'docs: ...', 'test: ...', 'chore: ...', or 'WIP: ...'"
exit 1
