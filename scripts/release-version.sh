#!/bin/sh
set -eu
fail() { printf >&2 'release-version: %s\n' "$*"; exit 1; }

read_version() {
  awk -F'"' '
    $1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
  ' "$1"
}

library=$(read_version crates/barbican/Cargo.toml)
binary=$(read_version crates/cargo-barbican/Cargo.toml)
[ -n "$library" ] || fail 'unable to read version from crates/barbican/Cargo.toml'
[ "$library" = "$binary" ] || fail "crate manifest versions diverge ($library vs $binary)"
printf '%s\n' "$library" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  fail 'canonical stable version required'
printf '%s\n' "$library"
