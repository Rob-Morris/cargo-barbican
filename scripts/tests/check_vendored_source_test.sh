#!/bin/sh
set -eu
REPO_ROOT=$(git rev-parse --show-toplevel)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM
mkdir -p "$SCRATCH/scripts" "$SCRATCH/vendor/rpgpie/src" "$SCRATCH/docs/dependency-reviews"
cp "$REPO_ROOT/scripts/check_vendored_source.sh" "$SCRATCH/scripts/"
cp "$REPO_ROOT/scripts/verify.sh" "$SCRATCH/scripts/"
git -C "$SCRATCH" init -q
cd "$SCRATCH"
printf 'reviewed source\n' > vendor/rpgpie/src/lib.rs
if command -v sha256sum >/dev/null 2>&1; then
  HASH=$(sha256sum vendor/rpgpie/src/lib.rs)
else
  HASH=$(shasum -a 256 vendor/rpgpie/src/lib.rs)
fi
printf '%s  src/lib.rs\n' "${HASH%% *}" > docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
cp docs/dependency-reviews/rpgpie-0.12.0-tree.sha256 receipt.backup
reject() {
  if sh scripts/check_vendored_source.sh > output 2>&1; then
    printf >&2 'FAIL: %s\n' "$1"; exit 1
  fi
  printf 'ok - %s\n' "$1"
}
sh scripts/check_vendored_source.sh
printf 'changed\n' > vendor/rpgpie/src/lib.rs
reject 'changed bytes'
printf 'reviewed source\n' > vendor/rpgpie/src/lib.rs
printf 'unreviewed\n' > vendor/rpgpie/build.rs
reject 'extra build script'
rm vendor/rpgpie/build.rs
mv vendor/rpgpie/src/lib.rs saved.rs
reject 'missing source'
ln -s ../../../saved.rs vendor/rpgpie/src/lib.rs
reject 'source symlink'
rm vendor/rpgpie/src/lib.rs
mkdir vendor/rpgpie/src/lib.rs
reject 'directory replacing file'
rmdir vendor/rpgpie/src/lib.rs
mv saved.rs vendor/rpgpie/src/lib.rs
mv vendor/rpgpie/src source.saved
ln -s ../../source.saved vendor/rpgpie/src
reject 'symlinked source directory'
rm vendor/rpgpie/src
mv source.saved vendor/rpgpie/src
printf '%s  ../escape\n' "${HASH%% *}" > docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
reject 'receipt traversal'
cp receipt.backup docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
cat receipt.backup >> docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
reject 'duplicate receipt entry'
cp receipt.backup docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
mkfifo vendor/rpgpie/unreviewed-pipe
reject 'special source file'
rm vendor/rpgpie/unreviewed-pipe
printf '%s  src/lib.rs' "${HASH%% *}" > docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
printf 'changed\n' > vendor/rpgpie/src/lib.rs
reject 'changed bytes with unterminated receipt line'
mkdir stub-bin
cat > stub-bin/cargo <<'STUB'
#!/bin/sh
touch cargo-was-executed
exit 0
STUB
chmod +x stub-bin/cargo
if PATH="$SCRATCH/stub-bin:$PATH" sh scripts/verify.sh > output 2>&1; then
  printf >&2 '%s\n' 'FAIL: verification accepted changed source'; exit 1
fi
[ ! -e cargo-was-executed ]
printf '%s\n' 'ok - source refusal precedes Cargo execution'
printf 'reviewed source\n' > vendor/rpgpie/src/lib.rs
cp receipt.backup docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
sh scripts/check_vendored_source.sh
cmp -s receipt.backup docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
printf '%s\n' 'vendored source behaviour tests: PASS'
