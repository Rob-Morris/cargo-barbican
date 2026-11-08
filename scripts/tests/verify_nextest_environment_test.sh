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
    [ "$BARBICAN_TEST_NEXTEST_VERSION" = 0.9.146 ] ;;
  *) exit 1 ;;
esac
SH
chmod 700 "$work/bin/cargo"
PATH="$work/bin:$PATH" CONTROL_CARGO_CALLS="$work/calls" \
  NEXTEST_USER_CONFIG_FILE=/unreviewed/user-config.toml NEXTEST_EXPERIMENTAL_RECORD=1 \
  sh "$repo_root/scripts/verify-nextest.sh"
printf '%s\n' 'nextest --version' 'test --locked -p cargo-barbican --test nextest -- --ignored' > "$work/expected"
cmp "$work/expected" "$work/calls"
printf '%s\n' 'Nextest verification environment controls: PASS'
