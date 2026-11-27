#!/bin/sh
set -eu
fail() { printf >&2 'release-source: %s\n' "$*"; exit 1; }

[ "${GITHUB_REPOSITORY-}" = Rob-Morris/cargo-barbican ] &&
  [ "${GITHUB_REPOSITORY_ID-}" = 1276595321 ] &&
  [ "${GITHUB_REPOSITORY_OWNER_ID-}" = 2587163 ] || fail 'canonical repository/owner IDs required'
source=${GITHUB_SHA-}
[ "${#source}" = 40 ] || fail 'expected full event commit'
case "$source" in *[!0-9a-f]*) fail 'invalid event commit' ;; esac
[ "$(git rev-parse HEAD)" = "$source" ] || fail 'checkout differs from captured event commit'
version=$(sh scripts/release-version.sh)
sh scripts/check_changelog.sh "$version" >/dev/null || fail 'changelog bundle is incoherent'
printf '%s\n' "$version"
