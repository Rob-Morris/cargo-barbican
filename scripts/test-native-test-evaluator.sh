#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { printf >&2 'usage: %s REVIEWED_BOTTLE\n' "$0"; exit 1; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/barbican-evaluator-controls.XXXXXX")
work=$(cd "$work" && pwd -P)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

selected=$(sh "$script_dir/provision-native-test-evaluator.sh" "$work/selected evaluator" "$1")
[ "$selected" = "$work/selected evaluator/rustup" ]
[ -x "$selected" ] && [ ! -L "$selected" ]

expect_failure() {
  expected=$1
  shift
  if sh "$script_dir/provision-native-test-evaluator.sh" "$work/refused" "$@" > "$work/output" 2>&1; then
    printf >&2 'provisioner unexpectedly accepted %s\n' "$expected"
    exit 1
  fi
  grep -F "$expected" "$work/output" > /dev/null
  [ ! -e "$work/refused" ]
}

expect_failure 'regular file' "$work/absent"
printf 'short archive' > "$work/short"
expect_failure 'bottle size mismatch' "$work/short"

cp "$1" "$work/corrupt.tar.gz"
printf 'X' | dd of="$work/corrupt.tar.gz" bs=1 seek=0 conv=notrunc 2>/dev/null
mkdir "$work/tools"
cat > "$work/tools/tar" <<'SH'
#!/bin/sh
touch "$CONTROL_TAR_CALLED"
cat "$CONTROL_TAR_OUTPUT"
SH
chmod 700 "$work/tools/tar"
export CONTROL_TAR_CALLED="$work/tar-called"
export CONTROL_TAR_OUTPUT="$work/wrong-evaluator"
export PATH="$work/tools:$PATH"
expect_failure 'bottle SHA256 mismatch' "$work/corrupt.tar.gz"
[ ! -e "$CONTROL_TAR_CALLED" ]

# Model an extractor returning incorrect bytes: the independent binary check
# must still refuse even when the outer archive has the approved identity.
cp "$selected" "$CONTROL_TAR_OUTPUT"
chmod 600 "$CONTROL_TAR_OUTPUT"
printf 'X' | dd of="$CONTROL_TAR_OUTPUT" bs=1 seek=0 conv=notrunc 2>/dev/null
expect_failure 'evaluator SHA256 mismatch' "$1"
[ -e "$CONTROL_TAR_CALLED" ]
printf 'short evaluator' > "$CONTROL_TAR_OUTPUT"
expect_failure 'evaluator size mismatch' "$1"

printf '%s\n' 'Native evaluator provisioning controls: PASS (no evaluator executed)'
