#!/bin/sh
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"
sh scripts/check_vendored_source.sh

# The ordinary suite remains offline. This required native journey deliberately
# fetches current advisory data and exercises the installed reviewed scanners.
tool_policy_log=$(mktemp)
trap 'rm -f "$tool_policy_log"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
run_native_test() {
  if BARBICAN_TOOL_POLICY_NATIVE=1 BARBICAN_TOOL_APPLY_NATIVE=1 \
    cargo test --release --locked -p cargo-barbican --lib "$1" \
    -- --exact --nocapture > "$tool_policy_log" 2>&1; then
    cat "$tool_policy_log"
  else
    cat "$tool_policy_log" >&2
    exit 1
  fi
  if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;' "$tool_policy_log"; then
    printf >&2 '%s\n' "verify-cargo-tools: expected required native journey to execute: $1"
    exit 1
  fi
}

run_native_test tool_intake::policy::tests::native_policy_scanners_preserve_review_identity_and_reject_root_license
run_native_test tool_intake::policy::native_tests::native_policy_matrix_preserves_sources_closure_advisories_and_refuses_bad_coverage
run_native_test tool_intake::apply_tests::lifecycle::native_application_owners_accept_install_check_admit_and_retain_failure_effects
