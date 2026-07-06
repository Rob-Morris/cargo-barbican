#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

BRANCH=${VERIFY_BRANCH_OVERRIDE-$(git branch --show-current 2>/dev/null || true)}
MODE=barbican
SKIP_REASON=

usage() {
  cat <<'USAGE'
usage: scripts/verify.sh [--barbican|--vanilla|--skip REASON]

Default:
  --barbican  Run cargo-barbican's own audit and verify commands.

Escape hatches:
  --vanilla   Off main only. Run raw cargo/audit/deny commands instead.
              Record the explicit reason in .canary--pre-commit.
  --skip      Off main only. Record an explicit skip reason and exit 0.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --barbican)
      MODE=barbican
      shift
      ;;
    --vanilla)
      MODE=vanilla
      shift
      ;;
    --skip)
      shift
      if [ "$#" -eq 0 ] || [ -z "$1" ]; then
        printf >&2 '%s\n' "verify: --skip requires a reason"
        exit 2
      fi
      MODE=skip
      SKIP_REASON=$1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf >&2 'verify: unknown argument: %s\n' "$1"
      usage >&2
      exit 2
      ;;
  esac
done

off_main() {
  [ -n "$BRANCH" ] && [ "$BRANCH" != "main" ]
}

# The escape-hatch branch guard runs before anything else — including the
# commit-message tests and clippy below — so a rejected `--vanilla`/`--skip`
# on main never runs any of this script's other checks first.
if { [ "$MODE" = vanilla ] || [ "$MODE" = skip ]; } && ! off_main; then
  printf >&2 'verify: --%s is allowed only on a known non-main branch\n' "$MODE"
  exit 1
fi

if [ "$MODE" != skip ]; then
  sh scripts/tests/check_commit_msg_test.sh
  # verify_branch_guard_test.sh drives this very script (including its
  # off-main `--vanilla` success path), so it sets this sentinel on its own
  # nested invocations to stop them re-entering this block and recursing.
  if [ -z "${VERIFY_BRANCH_GUARD_TEST_RUNNING-}" ]; then
    sh scripts/tests/verify_branch_guard_test.sh
  fi
  cargo clippy --workspace --all-targets --locked -- -D warnings
fi

case "$MODE" in
  barbican)
    cargo run --locked --bin cargo-barbican -- audit
    cargo run --locked --bin cargo-barbican -- verify
    ;;
  vanilla)
    printf '%s\n' "verify: vanilla fallback on ${BRANCH:-unknown branch}; record the reason in .canary--pre-commit"
    cargo audit
    cargo deny check advisories bans sources
    cargo build --locked
    cargo test --locked
    ;;
  skip)
    printf '%s\n' "verify: skipped on ${BRANCH:-unknown branch}: $SKIP_REASON"
    ;;
esac
