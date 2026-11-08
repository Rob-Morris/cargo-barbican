#!/bin/sh
set -eu
umask 077

fail() { printf >&2 'native test evaluator: %s\n' "$*"; exit 1; }
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail "usage: $0 NEW_DIRECTORY [REVIEWED_BOTTLE]"
[ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || fail 'requires macOS ARM64; native coverage must not be skipped'

destination=$1
case "$destination" in /*) ;; *) fail 'NEW_DIRECTORY must be absolute' ;; esac
mkdir -m 700 "$destination" || fail 'NEW_DIRECTORY must not already exist'
destination=$(cd "$destination" && pwd -P)
complete=false
trap 'if [ "$complete" != true ]; then rm -rf "$destination"; fi' EXIT
trap 'exit 1' HUP INT TERM

# Identity and member were reviewed before execution; see the dated CI record.
bottle_sha=040e2eb689f99acefa1849bd9c5f7591ba100fda29323901859b7a86e68d6bf5
binary_sha=16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496
bottle="$destination/bottle.tar.gz"
if [ "$#" -eq 2 ]; then
  [ -f "$2" ] && [ ! -L "$2" ] || fail 'REVIEWED_BOTTLE must be a regular file'
  [ "$(wc -c < "$2" | tr -d ' ')" = 4863566 ] || fail 'bottle size mismatch'
  cp "$2" "$bottle"
else
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 30 --max-time 180 --max-filesize 4863566 \
    -H 'Authorization: Bearer QQ==' \
    "https://ghcr.io/v2/homebrew/core/rustup/blobs/sha256:$bottle_sha" -o "$bottle"
fi
[ "$(wc -c < "$bottle" | tr -d ' ')" = 4863566 ] || fail 'bottle size mismatch'
actual=$(shasum -a 256 "$bottle")
[ "${actual%% *}" = "$bottle_sha" ] || fail 'bottle SHA256 mismatch; no archive member extracted'

# The whole fixed-size archive is authenticated before tar sees it. Extraction
# to stdout cannot publish the bottle's wrappers, links or installer metadata.
tar -xOf "$bottle" rustup/1.29.0_1/libexec/bin/rustup > "$destination/rustup"
[ "$(wc -c < "$destination/rustup" | tr -d ' ')" = 11031216 ] || fail 'evaluator size mismatch'
actual=$(shasum -a 256 "$destination/rustup")
[ "${actual%% *}" = "$binary_sha" ] || fail 'evaluator SHA256 mismatch; nothing made executable'
chmod 500 "$destination/rustup"
complete=true
printf '%s\n' "$destination/rustup"
