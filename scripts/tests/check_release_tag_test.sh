#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
SCRIPT="$REPO_ROOT/scripts/check_release_tag.sh"
TEST_REPO=$(mktemp -d)
OUT=$(mktemp)
ERR=$(mktemp)
trap 'rm -rf "$TEST_REPO" "$OUT" "$ERR"' EXIT

mkdir -p "$TEST_REPO/crates/barbican" "$TEST_REPO/crates/cargo-barbican"

write_manifest_versions() {
  barbican_version=$1
  cargo_barbican_version=$2
  printf '%s\n' '[package]' 'name = "barbican"' \
    "version = \"$barbican_version\"" >"$TEST_REPO/crates/barbican/Cargo.toml"
  printf '%s\n' '[package]' 'name = "cargo-barbican"' \
    "version = \"$cargo_barbican_version\"" \
    >"$TEST_REPO/crates/cargo-barbican/Cargo.toml"
}

write_manifest_versions 1.2.3 1.2.3

git -C "$TEST_REPO" init -q
git -C "$TEST_REPO" add crates
git -C "$TEST_REPO" -c user.name=Test -c user.email=test@example.com \
  commit -q -m initial

PASS=0
FAIL=0

expect_pass() {
  description=$1
  if (cd "$TEST_REPO" && sh "$SCRIPT") >"$OUT" 2>"$ERR"; then
    PASS=$((PASS + 1))
    printf 'ok   - %s\n' "$description"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected exit 0)\n' "$description"
  fi
}

expect_fail() {
  description=$1
  expected=$2
  if (cd "$TEST_REPO" && sh "$SCRIPT") >"$OUT" 2>"$ERR"; then
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected nonzero exit)\n' "$description"
  elif grep -qF "$expected" "$ERR"; then
    PASS=$((PASS + 1))
    printf 'ok   - %s\n' "$description"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected diagnostic not found)\n' "$description"
  fi
}

write_manifest_versions '' 1.2.3
expect_fail "missing barbican manifest version is rejected" \
  "unable to read version from crates/barbican/Cargo.toml"

write_manifest_versions 1.2.3 1.2.4
expect_fail "diverging crate manifest versions are rejected" \
  "crate manifest versions diverge (1.2.3 vs 1.2.4)"

write_manifest_versions 1.2.3 1.2.3
expect_fail "missing release tag is rejected" \
  "v1.2.3 does not exist or does not resolve to a commit"

git -C "$TEST_REPO" tag v1.2.3
expect_pass "release tag at HEAD passes"

printf '%s\n' changed >"$TEST_REPO/change.txt"
git -C "$TEST_REPO" add change.txt
git -C "$TEST_REPO" -c user.name=Test -c user.email=test@example.com \
  commit -q -m changed
expect_fail "release tag on an older commit is rejected" "v1.2.3 resolves to"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
