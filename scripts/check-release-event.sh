#!/bin/sh
set -eu
fail() { printf >&2 'release-event: %s\n' "$*"; exit 1; }
[ "${GITHUB_EVENT_NAME-}" = push ] && [ "${GITHUB_REF_TYPE-}" = tag ] || fail 'tag push required'
[ "${GITHUB_REF_PROTECTED-}" = true ] || fail 'protected version tag required'
version=$(sh scripts/check-release-source.sh)
tag="v$version"
[ "${GITHUB_REF_NAME-}" = "$tag" ] || fail 'event tag differs from manifest version'
source=$GITHUB_SHA
[ "$(git cat-file -t "refs/tags/$tag")" = commit ] || fail 'only lightweight version tags are qualified'
[ "$(git rev-parse "refs/tags/$tag")" = "$source" ] || fail 'tag differs from captured event commit'
git merge-base --is-ancestor "$source" refs/remotes/origin/main || fail 'release commit must be on main'
printf 'version=%s\nsource=%s\n' "$version" "$source"
if [ -n "${GITHUB_OUTPUT-}" ]; then printf 'version=%s\nsource=%s\n' "$version" "$source" >> "$GITHUB_OUTPUT"; fi
