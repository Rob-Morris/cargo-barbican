#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

NEXTEST_VERSION=0.9.146
# The reviewed fixture route excludes ambient user config and recording.
export NEXTEST_USER_CONFIG_FILE=none
export NEXTEST_EXPERIMENTAL_RECORD=0
if ! NEXTEST_BANNER=$(cargo nextest --version 2>&1); then
  printf >&2 '%s\n' "verify-nextest: cargo-nextest $NEXTEST_VERSION is required; no tests were skipped" "$NEXTEST_BANNER"
  printf >&2 '%s\n' "Install the reviewed test tool: cargo install --locked --no-default-features cargo-nextest@$NEXTEST_VERSION"
  exit 1
fi

case "$NEXTEST_BANNER" in
  "cargo-nextest $NEXTEST_VERSION "* | "cargo-nextest $NEXTEST_VERSION") ;;
  *)
    printf >&2 '%s\n' "verify-nextest: expected cargo-nextest $NEXTEST_VERSION; found: $NEXTEST_BANNER"
    exit 1
    ;;
esac

export BARBICAN_TEST_NEXTEST_VERSION=$NEXTEST_VERSION
nextest_log=$(mktemp)
trap 'rm -f "$nextest_log"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if cargo test --locked -p cargo-barbican --test nextest -- --ignored > "$nextest_log" 2>&1; then
  cat "$nextest_log"
else
  cat "$nextest_log" >&2
  exit 1
fi
# An empty, ignored or filtered fixture target is not real-runner proof.
if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' "$nextest_log"; then
  printf >&2 '%s\n' 'verify-nextest: expected executed nextest tests with no skips or filters'
  exit 1
fi
