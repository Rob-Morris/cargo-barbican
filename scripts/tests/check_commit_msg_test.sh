#!/bin/sh
# Behaviour tests for scripts/check_commit_msg.sh.
#
# The script under test reads real repository state (the crate manifests, the
# changelog bundle, the HEAD subject, and the staged index), so each case is
# driven against a throwaway git repo with fixture files rather than mocking
# git. We exercise the observable contract: which subjects/branches/staged
# states are accepted and which are rejected.
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
SCRIPT="$REPO_ROOT/scripts/check_commit_msg.sh"

WORK=$(mktemp -d)
MSG=$(mktemp)
trap 'rm -rf "$WORK" "$MSG"' EXIT

VERSION=1.0.0
SUMMARY="Add a feature"

PASS=0
FAIL=0

git_in() {
  git -C "$WORK" -c user.name=test -c user.email=test@example.com -c core.hooksPath= "$@"
}

write_manifest() { # $1=relative path  $2=version
  mkdir -p "$WORK/$(dirname "$1")"
  cat >"$WORK/$1" <<EOF
[package]
name = "x"
version = "$2"
edition = "2024"
EOF
}

write_bundle() { # $1=version  $2=summary  (working-tree changelog files)
  mkdir -p "$WORK/docs/changelog"
  printf '**Summary** %s\n' "$2" >"$WORK/docs/changelog/v$1.md"
  cat >"$WORK/docs/CHANGELOG.md" <<EOF
# Changelog

| Version | Date | Summary |
| --- | --- | --- |
| [v$1](changelog/v$1.md) | 2026-01-01 | $2 |
EOF
}

setup_base() {
  rm -rf "$WORK"
  mkdir -p "$WORK"
  git_in init -q
  write_manifest crates/barbican/Cargo.toml "$VERSION"
  write_manifest crates/cargo-barbican/Cargo.toml "$VERSION"
  write_bundle "$VERSION" "$SUMMARY"
  git_in add -A
  git_in commit -q --no-verify -m "$SUMMARY (v$VERSION)"
}

msg() { # $1=subject line
  printf '%s\n' "$1" >"$MSG"
}

run() { # $1=branch
  (cd "$WORK" && sh "$SCRIPT" "$MSG" "$1")
}

expect_pass() { # $1=description  $2=branch
  if run "$2" >/dev/null 2>&1; then
    PASS=$((PASS + 1))
    printf 'ok   - %s\n' "$1"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected exit 0)\n' "$1"
  fi
}

expect_fail() { # $1=description  $2=branch
  if run "$2" >/dev/null 2>&1; then
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected nonzero exit)\n' "$1"
  else
    PASS=$((PASS + 1))
    printf 'ok   - %s\n' "$1"
  fi
}

# --- Amend exemption: the branch this suite was added to guard ---------------

# A body-only amend of the current version's commit stages no changelog, but is
# permitted off main because HEAD already carries the matching (vX.Y.Z).
setup_base
msg "$SUMMARY (v$VERSION)"
expect_pass "amend current-version commit on dev with nothing staged" dev

# The same amend on main must NOT be exempted.
setup_base
msg "$SUMMARY (v$VERSION)"
expect_fail "amend current-version commit on main is rejected" main

# --- The amend exemption must not weaken the real new-version gate -----------

# A genuine new version (HEAD still at the previous version) with the manifest
# bump staged but the changelog NOT staged must still be rejected.
setup_base
write_manifest crates/barbican/Cargo.toml 1.1.0
write_manifest crates/cargo-barbican/Cargo.toml 1.1.0
write_bundle 1.1.0 "New thing"
git_in add crates/barbican/Cargo.toml crates/cargo-barbican/Cargo.toml
msg "New thing (v1.1.0)"
expect_fail "new version with manifest bump but no staged changelog is rejected" dev

# The same new version with the full bundle staged is accepted.
setup_base
write_manifest crates/barbican/Cargo.toml 1.1.0
write_manifest crates/cargo-barbican/Cargo.toml 1.1.0
write_bundle 1.1.0 "New thing"
git_in add -A
msg "New thing (v1.1.0)"
expect_pass "new version with full bundle staged" dev

# --- Content checks still run on amends --------------------------------------

# Subject Summary must match the canonical changelog Summary, even when the
# amend exemption would otherwise let the staging gates pass.
setup_base
msg "Different summary (v$VERSION)"
expect_fail "versioned subject whose Summary mismatches the changelog" dev

# Subject version must match the crate manifests.
setup_base
msg "$SUMMARY (v9.9.9)"
expect_fail "versioned subject whose version does not match the manifests" dev

# Crate manifests must agree with each other.
setup_base
write_manifest crates/barbican/Cargo.toml 1.2.0
msg "$SUMMARY (v$VERSION)"
expect_fail "diverging crate manifest versions" dev

# --- Support / WIP prefixes --------------------------------------------------

setup_base
git_in add -A # no-op; nothing changed
msg "docs: clarify wording"
expect_pass "docs prefix with nothing staged" dev

# Support prefixes may not carry a version bundle.
setup_base
write_manifest crates/barbican/Cargo.toml 1.1.0
write_manifest crates/cargo-barbican/Cargo.toml 1.1.0
git_in add crates/barbican/Cargo.toml crates/cargo-barbican/Cargo.toml
msg "chore: bump versions"
expect_fail "chore prefix carrying a version bump" dev

setup_base
msg "WIP: experiment"
expect_pass "WIP on dev with nothing staged" dev

setup_base
msg "WIP: experiment"
expect_fail "WIP on main" main

# --- Malformed subjects ------------------------------------------------------

setup_base
msg "This commit subject is intentionally far too long to fit within the seventy two character ceiling"
expect_fail "subject longer than 72 characters" dev

setup_base
: >"$MSG"
expect_fail "empty subject" dev

setup_base
msg "random subject with neither a prefix nor a version suffix"
expect_fail "subject with neither a support prefix nor a version suffix" dev

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
