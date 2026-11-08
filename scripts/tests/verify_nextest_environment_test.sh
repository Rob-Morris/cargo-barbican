#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/bin"
cat > "$work/bin/cargo" <<'SH'
#!/bin/sh
set -eu
[ "$NEXTEST_USER_CONFIG_FILE" = none ]
[ "$NEXTEST_EXPERIMENTAL_RECORD" = 0 ]
printf '%s\n' "$*" >> "$CONTROL_CARGO_CALLS"
case "$*" in
  'nextest --version') printf '%s\n' 'cargo-nextest 0.9.146 (authored control)' ;;
  'test --locked -p cargo-barbican --test nextest -- --ignored')
    [ "$BARBICAN_TEST_NEXTEST_VERSION" = 0.9.146 ]
    printf '%s\n' "$CONTROL_TEST_SUMMARY"
    exit "$CONTROL_TEST_EXIT" ;;
  *) exit 1 ;;
esac
SH
chmod 700 "$work/bin/cargo"
printf '%s\n' 'nextest --version' 'test --locked -p cargo-barbican --test nextest -- --ignored' > "$work/expected"
run_control() {
  : > "$work/calls"
  PATH="$work/bin:$PATH" CONTROL_CARGO_CALLS="$work/calls" \
    CONTROL_TEST_SUMMARY="$1" CONTROL_TEST_EXIT="$2" \
    NEXTEST_USER_CONFIG_FILE=/unreviewed/user-config.toml NEXTEST_EXPERIMENTAL_RECORD=1 \
    sh "$repo_root/scripts/verify-nextest.sh" > "$work/output" 2>&1
}

passing='test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
run_control "$passing" 0
cmp "$work/expected" "$work/calls"
grep -F "$passing" "$work/output" > /dev/null

for summary in \
  'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' \
  'test result: ok. 0 passed; 0 failed; 14 ignored; 0 measured; 0 filtered out;' \
  'test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;' \
  'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out;' \
  'test result: FAILED. 13 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;' \
  'no test summary'; do
  if run_control "$summary" 0; then
    printf >&2 'verify-nextest accepted incomplete proof: %s\n' "$summary"
    exit 1
  fi
  cmp "$work/expected" "$work/calls"
  grep -F 'expected executed nextest tests with no skips or filters' "$work/output" > /dev/null
done
# Even a successful-looking summary must not mask a failed Cargo process.
if run_control "$passing" 1; then
  printf >&2 '%s\n' 'verify-nextest accepted a failed Cargo process'
  exit 1
fi
cmp "$work/expected" "$work/calls"
printf '%s\n' 'Nextest verification environment and execution controls: PASS'
