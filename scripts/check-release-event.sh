#!/bin/sh
set -eu
fail() { printf >&2 'release-event: %s\n' "$*"; exit 1; }
[ "${GITHUB_REPOSITORY-}" = Rob-Morris/cargo-barbican ] && [ "${GITHUB_REPOSITORY_ID-}" = 1276595321 ] && [ "${GITHUB_REPOSITORY_OWNER_ID-}" = 2587163 ] || fail 'canonical repository/owner IDs required'
[ "${GITHUB_EVENT_NAME-}" = push ] && [ "${GITHUB_REF_TYPE-}" = tag ] || fail 'tag push required'
[ "${GITHUB_REF_PROTECTED-}" = true ] || fail 'protected version tag required'
tag=${GITHUB_REF_NAME-}
printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || fail 'canonical stable version tag required'
case "$tag" in *[!v0-9.]*) fail 'invalid tag characters' ;; esac
source=${GITHUB_SHA-}
[ "${#source}" = 40 ] || fail 'expected full event commit'
case "$source" in *[!0-9a-f]*) fail 'invalid event commit' ;; esac
[ "$(git cat-file -t "refs/tags/$tag")" = commit ] || fail 'only lightweight version tags are qualified'
[ "$(git rev-parse HEAD)" = "$source" ] || fail 'checkout differs from captured event commit'
git merge-base --is-ancestor "$source" refs/remotes/origin/main || fail 'release commit must be on main'
sh scripts/check_release_tag.sh "$source"
version=${tag#v}
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
sh "$script_dir/check_changelog.sh" "$version" >/dev/null || fail 'changelog bundle is incoherent'
[ "$(awk -F'"' '/^[[:space:]]*version[[:space:]]*=/ {print $2; exit}' crates/barbican/Cargo.toml)" = "$version" ] || fail 'event tag differs from manifest version'
printf 'version=%s\nsource=%s\n' "$version" "$source"
if [ -n "${GITHUB_OUTPUT-}" ]; then printf 'version=%s\nsource=%s\n' "$version" "$source" >> "$GITHUB_OUTPUT"; fi
