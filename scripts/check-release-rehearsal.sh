#!/bin/sh
set -eu
fail() { printf >&2 'release-rehearsal: %s\n' "$*"; exit 1; }

commit=${1-}
[ "$#" = 1 ] && [ "${#commit}" = 40 ] || fail 'supply the full candidate commit SHA'
case "$commit" in *[!0-9a-f]*) fail 'invalid candidate SHA' ;; esac

endpoint="repos/Rob-Morris/cargo-barbican/actions/workflows/release-rehearsal.yml/runs?event=push&head_sha=$commit&per_page=1"
run=$(gh api --hostname github.com "$endpoint" --jq '
  .workflow_runs[0] |
  select(.event == "push" and .repository.id == 1276595321 and
         .head_repository.id == 1276595321 and
         (.head_branch | startswith("release-candidate/"))) |
  [.id, .head_sha, .status, (.conclusion // "pending")] | @tsv
') || fail 'unable to read rehearsal runs from GitHub'
[ -n "$run" ] || fail "no rehearsal for $commit; push it to a release-candidate/ branch"
read -r id source status conclusion <<EOF_RUN
$run
EOF_RUN
case "$id" in ''|*[!0-9]*) fail 'invalid run ID' ;; esac
[ "$source" = "$commit" ] || fail 'rehearsal does not match the exact candidate commit'
url="https://github.com/Rob-Morris/cargo-barbican/actions/runs/$id"
[ "$status" = completed ] && [ "$conclusion" = success ] ||
  fail "latest rehearsal is $status/$conclusion: $url"
printf 'release-rehearsal: %s passed %s\n' "$commit" "$url"
