#!/bin/sh
# Behaviour tests for the escape-hatch branch guard in scripts/verify.sh.
#
# The guard is what stands between a contributor on `main` and the
# `--vanilla`/`--skip` escape hatches, so a regression here is a fail-open
# bug: it would let main's stricter checks be bypassed. VERIFY_BRANCH_OVERRIDE
# exists precisely so this suite can drive the real script deterministically,
# without depending on which branch happens to be checked out.
#
# This script is itself driven by scripts/verify.sh (see the guard there
# around VERIFY_BRANCH_GUARD_TEST_RUNNING), so every nested invocation of
# verify.sh below exports that sentinel to stop the nested run from trying to
# re-enter this suite and recursing.
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
SCRIPT="$REPO_ROOT/scripts/verify.sh"

STUB_BIN=$(mktemp -d)
OUT=$(mktemp)
ERR=$(mktemp)
trap 'rm -rf "$STUB_BIN" "$OUT" "$ERR"' EXIT

# Stands in for `cargo` on the off-main `--vanilla` case below, so that case
# exercises the real branch-guard-then-proceed control flow without paying
# for a real `cargo audit`/`cargo deny check`/`cargo build`/`cargo test`.
cat >"$STUB_BIN/cargo" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$STUB_BIN/cargo"

PASS=0
FAIL=0

run_with_override() { # $1=branch  (remaining args passed to verify.sh)
  branch=$1
  shift
  (
    cd "$REPO_ROOT"
    VERIFY_BRANCH_OVERRIDE=$branch
    VERIFY_BRANCH_GUARD_TEST_RUNNING=1
    export VERIFY_BRANCH_OVERRIDE VERIFY_BRANCH_GUARD_TEST_RUNNING
    sh "$SCRIPT" "$@"
  )
}

expect_rejected_before_running_anything() { # $1=description  $2=branch  (remaining args)
  description=$1
  branch=$2
  shift 2
  if run_with_override "$branch" "$@" >"$OUT" 2>"$ERR"; then
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected nonzero exit)\n' "$description"
    return
  fi
  if [ -s "$OUT" ]; then
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected no stdout before the guard fires)\n' "$description"
    return
  fi
  if ! grep -q "allowed only on a known non-main branch" "$ERR"; then
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected the branch-guard message on stderr)\n' "$description"
    return
  fi
  PASS=$((PASS + 1))
  printf 'ok   - %s\n' "$description"
}

expect_proceeds() { # $1=description  $2=branch  (remaining args)
  description=$1
  branch=$2
  shift 2
  if run_with_override "$branch" "$@" >"$OUT" 2>"$ERR"; then
    if grep -q "allowed only on a known non-main branch" "$ERR"; then
      FAIL=$((FAIL + 1))
      printf 'FAIL - %s (branch guard fired but should not have)\n' "$description"
    else
      PASS=$((PASS + 1))
      printf 'ok   - %s\n' "$description"
    fi
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL - %s (expected exit 0)\n' "$description"
  fi
}

# --- On main, both escape hatches are rejected before anything else runs ----

expect_rejected_before_running_anything \
  "--skip on main is rejected before running anything" main --skip "reason"
expect_rejected_before_running_anything \
  "--vanilla on main is rejected before running anything" main --vanilla

# --- Off main, both escape hatches proceed -----------------------------------

expect_proceeds "--skip off main proceeds" a-feature-branch --skip "reason"

PATH="$STUB_BIN:$PATH"
export PATH
expect_proceeds "--vanilla off main proceeds (expensive phase stubbed)" a-feature-branch --vanilla

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
