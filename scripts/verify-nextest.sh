#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

NEXTEST_VERSION=0.9.146
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
cargo test --locked -p cargo-barbican --test nextest -- --ignored
