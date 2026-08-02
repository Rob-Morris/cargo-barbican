#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

MODE=${1:---worktree}

case "$MODE" in
  --worktree | --staged) ;;
  *)
    printf >&2 '%s\n' "usage: scripts/check_doc_versions.sh [--worktree|--staged]"
    exit 2
    ;;
esac

fail() {
  printf >&2 '%s\n' "doc-version-check: $1"
  exit 1
}

# Reads a file from the worktree or the staged snapshot, failing hard if it is
# absent. Callers must capture the output into a variable rather than piping
# read_file directly: an `exit` from inside a pipe only kills the subshell, so
# a read failure mid-pipeline would otherwise be silently swallowed.
read_file() {
  path=$1

  if [ "$MODE" = "--staged" ]; then
    git show ":$path" 2>/dev/null || fail "$path is not present in the staged snapshot"
  else
    cat "$path" 2>/dev/null || fail "$path is not present in the worktree"
  fi
}

read_crate_version() {
  awk -F'"' '
    $1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
  '
}

crate_manifest=$(read_file crates/barbican/Cargo.toml)
cargo_barbican_manifest=$(read_file crates/cargo-barbican/Cargo.toml)

crate_version=$(printf '%s\n' "$crate_manifest" | read_crate_version)
cargo_barbican_version=$(printf '%s\n' "$cargo_barbican_manifest" | read_crate_version)
sync_header="Synced from cargo-barbican v$crate_version"

if [ "$crate_version" != "$cargo_barbican_version" ]; then
  fail "crate manifest versions diverge ($crate_version vs $cargo_barbican_version)"
fi

if [ -z "$crate_version" ]; then
  fail "unable to read version from crates/barbican/Cargo.toml"
fi

toolchain=$(read_file rust-toolchain.toml)
rust_version=$(
  printf '%s\n' "$toolchain" | awk -F'"' '
    /^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }
  '
)

if [ -z "$rust_version" ]; then
  fail "unable to read rust-toolchain.toml channel"
fi

assert_contains() {
  file=$1
  expected=$2
  label=$3

  content=$(read_file "$file")
  if ! printf '%s\n' "$content" | grep -qF -- "$expected"; then
    fail "$file is missing $label: $expected"
  fi
}

assert_not_contains() {
  file=$1
  unexpected=$2
  label=$3

  content=$(read_file "$file")
  if printf '%s\n' "$content" | grep -qF -- "$unexpected"; then
    fail "$file still contains $label: $unexpected"
  fi
}

assert_contains README.md "badge/version-$crate_version-blue" "current version badge"
assert_contains README.md "--tag v$crate_version" "immutable release install tag"
assert_contains README.md "badge/Rust-$rust_version-" "current Rust badge"
assert_contains README.md "cargo-deny@0.19.6 cargo-audit@0.22.1" "reviewed delegate versions"
assert_contains docs/user/integration.md "--tag v$crate_version" "immutable release install tag"
assert_contains docs/user/integration.md "cargo-deny@0.19.6 cargo-audit@0.22.1" "reviewed delegate versions"
assert_contains docs/user/ci.md "--tag v$crate_version" "immutable release install tag"
assert_contains docs/user/ci.md "cargo-deny@0.19.6 cargo-audit@0.22.1" "reviewed delegate versions"
assert_contains docs/user/ci.md "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" "pinned checkout action"
assert_contains crates/cargo-barbican/src/commands/policy.rs "--tag v$crate_version" "generated immutable release install tag"
assert_contains crates/cargo-barbican/src/commands/policy.rs "cargo-deny@0.19.6" "generated reviewed cargo-deny version"
assert_contains crates/cargo-barbican/src/commands/policy.rs "cargo-audit@0.22.1" "generated reviewed cargo-audit version"
assert_not_contains README.md "--branch main" "mutable release install branch"
assert_not_contains docs/user/integration.md "--branch main" "mutable release install branch"
assert_not_contains docs/user/ci.md "--branch main" "mutable release install branch"
assert_not_contains docs/user/ci.md "actions/checkout@v" "mutable checkout action tag"
assert_contains docs/user/integration.md "$sync_header" "template sync-header example"
assert_contains templates/README.md "$sync_header" "template sync-header convention"

if [ "$MODE" = "--staged" ]; then
  template_files=$(
    git ls-files --stage -- templates \
      | awk '$2 != "0000000000000000000000000000000000000000"' \
      | sed 's/^[^	]*	//' \
      | grep -v '^templates/README.md$' \
      | sort
  )
else
  template_files=$(
    find templates -type f ! -path 'templates/README.md' | sort
  )
fi

# Split only on newlines so paths containing spaces survive. A piped
# `while read` loop would run in a subshell, where assert_contains's `fail`
# could not abort the script, so keep the for-loop in the main shell.
old_ifs=$IFS
IFS='
'
for template in $template_files; do
  assert_contains "$template" "$sync_header" "template sync header"
done
IFS=$old_ifs
