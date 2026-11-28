#!/bin/sh
# Exercise the real branch guard and observe which verification commands it dispatches.
set -eu

REPO_ROOT=$(CDPATH= cd "$(dirname "$0")/../.." && pwd)
. "$REPO_ROOT/scripts/tests/isolate_git_fixture.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/bin"

for tool in sh python3 cargo; do
  cat >"$WORK/bin/$tool" <<'STUB'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$BARBICAN_VERIFY_CALLS"
STUB
  chmod +x "$WORK/bin/$tool"
done

run_with_override() {
  branch=$1
  shift
  : > "$WORK/calls"
  (
    cd "$REPO_ROOT"
    PATH="$WORK/bin:$PATH" BARBICAN_VERIFY_CALLS="$WORK/calls" VERIFY_BRANCH_OVERRIDE="$branch" \
      /bin/sh "$REPO_ROOT/scripts/verify.sh" "$@"
  ) >"$WORK/out" 2>"$WORK/err"
}

rejects_before_dispatch() {
  if run_with_override "$@"; then
    printf >&2 'FAIL: expected refusal for %s on branch %s\n' "$2" "$1"
    exit 1
  fi
  grep -q 'allowed only on a known non-main branch' "$WORK/err"
  test ! -s "$WORK/out"
  test ! -s "$WORK/calls"
  printf 'ok - %s refuses before dispatch on branch %s\n' "$2" "$1"
}

rejects_before_dispatch main --skip reason
rejects_before_dispatch main --vanilla
rejects_before_dispatch '' --skip reason
rejects_before_dispatch '' --vanilla

run_with_override feature --skip reason
grep -q 'skipped on feature: reason' "$WORK/out"
test ! -s "$WORK/calls"
printf '%s\n' 'ok - off-main skip dispatches no verification commands'

run_with_override feature --vanilla
cat >"$WORK/expected" <<'EXPECTED'
sh scripts/check_vendored_source.sh
sh scripts/tests/check_vendored_source_test.sh
sh scripts/tests/check_commit_msg_test.sh
sh scripts/tests/check_release_tag_test.sh
python3 -B scripts/tests/install_barbican_test.py
python3 -B scripts/tests/release_protocol_test.py
sh scripts/tests/verify_branch_guard_test.sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo audit
cargo deny check advisories bans sources
cargo build --locked
cargo test --locked
EXPECTED
diff -u "$WORK/expected" "$WORK/calls"
printf '%s\n' 'ok - off-main vanilla dispatches verification once in order'
