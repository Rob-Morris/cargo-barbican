#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

EXPECTED_REF=${1:-HEAD}

fail() {
  printf >&2 '%s\n' "release-tag-check: $1"
  exit 1
}

crate_version=$(sh "$SCRIPT_DIR/release-version.sh")
tag="v$crate_version"
tag_commit=$(git rev-parse --verify "refs/tags/$tag^{commit}" 2>/dev/null) \
  || fail "$tag does not exist or does not resolve to a commit"
expected_commit=$(git rev-parse --verify "$EXPECTED_REF^{commit}" 2>/dev/null) \
  || fail "expected ref $EXPECTED_REF does not resolve to a commit"

if [ "$tag_commit" != "$expected_commit" ]; then
  fail "$tag resolves to $tag_commit, expected $expected_commit from $EXPECTED_REF"
fi

printf '%s\n' "release-tag-check: $tag resolves to $expected_commit"
