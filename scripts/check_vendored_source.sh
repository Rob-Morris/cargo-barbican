#!/bin/sh
# Static one-writer checkout check; the reviewed receipt is never regenerated.
set -eu
export LC_ALL=C
REPO_ROOT=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
cd "$REPO_ROOT"
SOURCE=vendor/rpgpie
RECEIPT=docs/dependency-reviews/rpgpie-0.12.0-tree.sha256
fail() { printf >&2 'vendored source: %s\n' "$1"; exit 1; }
[ "$#" -eq 0 ] || fail 'no arguments accepted'
for directory in vendor "$SOURCE" docs docs/dependency-reviews; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || fail "not a real directory: $directory"
done
[ -f "$RECEIPT" ] && [ ! -L "$RECEIPT" ] || fail 'missing regular review receipt'
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM
# Confine every receipt entry before opening it, including option-like names.
awk '
  length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
  substr($0, 65, 2) != "  " { exit 1 }
  {
    path = substr($0, 67)
    if (path !~ /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/) exit 1
    n = split(path, parts, "/")
    for (i = 1; i <= n; i++) if (parts[i] == "." || parts[i] == "..") exit 1
    if (seen[path]++) exit 1
    print path
  }
  END { if (NR == 0) exit 1 }
' "$RECEIPT" > "$SCRATCH/expected" || fail 'invalid review receipt'
find "$SOURCE" ! -type d ! -type f -print > "$SCRATCH/wrong-types"
[ ! -s "$SCRATCH/wrong-types" ] || fail 'symlink or unsupported source entry'
find "$SOURCE" -type f -print > "$SCRATCH/files"
sed "s|^$SOURCE/||" "$SCRATCH/files" | sort > "$SCRATCH/actual"
sort "$SCRATCH/expected" > "$SCRATCH/sorted"
cmp -s "$SCRATCH/sorted" "$SCRATCH/actual" || fail 'missing or extra source file'
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 "$1"; }
else
  fail 'requires OS sha256sum or shasum'
fi
while IFS= read -r line || [ -n "$line" ]; do
  expected=${line%% *}
  path=${line#*  }
  actual=$(digest "$SOURCE/$path") || fail "cannot hash: $path"
  [ "${actual%% *}" = "$expected" ] || fail "changed source: $path"
done < "$RECEIPT"
printf '%s\n' 'vendored source: PASS'
