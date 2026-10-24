#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"
DENY_VERSION=0.19.6
if ! DENY_BANNER=$(cargo deny --version 2>&1); then
  printf >&2 '%s\n' "verify-adoption: cargo-deny $DENY_VERSION is required; no tests were skipped" "$DENY_BANNER"
  printf >&2 '%s\n' "Install the reviewed scanner: cargo install --locked cargo-deny@$DENY_VERSION"
  exit 1
fi
case "$DENY_BANNER" in
  "cargo-deny $DENY_VERSION" | "cargo-deny $DENY_VERSION "*) ;;
  *) printf >&2 '%s\n' "verify-adoption: expected cargo-deny $DENY_VERSION; found: $DENY_BANNER"; exit 1 ;;
esac

export BARBICAN_TEST_ADOPTION_DENY_VERSION=$DENY_VERSION
adoption_log=$(mktemp)
trap 'rm -f "$adoption_log"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if cargo test --locked -p cargo-barbican --test adoption_e2e -- --ignored --nocapture > "$adoption_log" 2>&1; then
  cat "$adoption_log"
else
  cat "$adoption_log" >&2
  exit 1
fi
# An ignored target discovered on an unsupported platform or accidentally
# filtered to zero tests is not proof that the scanner-backed journey ran.
if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' "$adoption_log"; then
  printf >&2 '%s\n' 'verify-adoption: expected executed adoption tests with no skips or filters'
  exit 1
fi
