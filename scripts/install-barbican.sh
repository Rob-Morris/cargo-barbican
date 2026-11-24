#!/bin/sh
# Static single-writer publication; this is not a sandbox for verified programs.
set -eu
umask 077
export LC_ALL=C GH_HOST=github.com GH_PROMPT_DISABLED=1 GH_PAGER=cat

usage() {
  cat <<'USAGE'
Usage: install-barbican.sh --version N.N.N --install-dir DIR

Install an exact verified GitHub.com Barbican release into DIR/bin, retaining
DIR/LICENSES.txt. DIR is an owned version root, not a shared bin directory.
Its parent must exist and be owned by you without group/other write access.
Requires trusted gh (first tested baseline 2.100.0), read-only GitHub auth,
network access to GitHub/Sigstore trust services, and ordinary Unix utilities.
Supports macOS 15+ ARM64 and GNU Linux x86-64 glibc 2.35+ with libgcc_s.so.1.
No compiler, sudo, shell configuration changes or source fallback. Existing
conflicting or symlink destinations are refused. Fresh verification is always
required, including an identical existing installation. Source installation
remains an explicit alternative documented in docs/user/integration.md.
Exit: 0 success; 2 input/prerequisite/unsupported; 1 verification/runtime/I/O;
130 interrupted; 143 terminated. A late signal may leave a complete install.
USAGE
}
fail() { printf >&2 'install-barbican: %s\n' "$*"; exit 1; }
invalid() { printf >&2 'install-barbican: %s\n' "$*"; exit 2; }
version= destination=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] && [ -z "$version" ] || invalid 'supply --version once'; version=$2; shift 2 ;;
    --install-dir) [ "$#" -ge 2 ] && [ -z "$destination" ] || invalid 'supply --install-dir once'; destination=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) invalid "unknown argument: $1 (see --help)" ;;
  esac
done
[ -n "$version" ] && [ -n "$destination" ] || invalid 'both --version and --install-dir are required'
case "$version" in *[!0-9.]*) invalid 'version must be canonical N.N.N' ;; esac
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || invalid 'version must be canonical N.N.N'
case "$destination" in *'
'*) invalid 'installation path contains a control character' ;; esac
if printf '%s' "$destination" | grep -q '[[:cntrl:]]'; then
  invalid 'installation path contains a control character'
fi
for utility in gh uname od tr awk grep sed cut wc cmp cp chmod mkdir mktemp mv rm stat id env ls; do
  command -v "$utility" >/dev/null 2>&1 || invalid "missing prerequisite: $utility"
done
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  invalid 'install a trusted SHA256 utility (sha256sum or shasum)'
fi
os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
  Darwin/arm64)
    command -v sw_vers >/dev/null 2>&1 || invalid 'missing sw_vers'
    os_version=$(sw_vers -productVersion) || invalid 'cannot establish macOS version'
    printf '%s\n' "$os_version" | awk -F. '$1 ~ /^[0-9]+$/ && $1 >= 15 {ok=1} END {exit !ok}' || invalid 'macOS 15+ required'
    target=aarch64-apple-darwin
    metadata() { stat -f '%u %Lp' "$1"; }
    ;;
  Linux/x86_64)
    command -v getconf >/dev/null 2>&1 || invalid 'missing getconf'
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || invalid 'GNU glibc 2.35+ required; musl is unsupported'
    printf '%s\n' "$libc" | awk '$1 == "glibc" {split($2,v,"."); if (v[1] > 2 || (v[1] == 2 && v[2] >= 35)) ok=1} END {exit !ok}' || invalid 'GNU glibc 2.35+ required'
    target=x86_64-unknown-linux-gnu
    metadata() { stat -c '%u %a' "$1"; }
    ;;
  *) invalid "unsupported host $os/$arch; see --help" ;;
esac

# Resolve the parent before staging; never follow a destination symlink.
case "$destination" in /*) ;; *) destination="$PWD/$destination" ;; esac
parent=${destination%/*}
leaf=${destination##*/}
case "$leaf" in ''|.|..) invalid 'installation root must name a directory' ;; esac
[ -d "$parent" ] || invalid 'installation parent must already exist'
parent=$(cd "$parent" && pwd -P) || invalid 'cannot resolve installation parent'
destination="$parent/$leaf"
uid=$(id -u)
set -- $(metadata "$parent")
[ "$1" = "$uid" ] || invalid 'installation parent must be owned by the current user'
case "$2" in *[2367][0-7]|*[0-7][2367]) invalid 'installation parent must not be group/other writable' ;; esac
[ ! -L "$destination" ] || invalid 'destination is a symlink; choose a fresh owned version root'
[ ! -e "$destination" ] || [ -d "$destination" ] || invalid 'destination is not a directory'
check_gh() {
  group=$1 operation=$2
  shift 2
  help=$(gh "$group" "$operation" --help 2>/dev/null) || invalid 'trusted gh lacks required verification commands; first tested baseline is 2.100.0'
  for flag in "$@"; do
    printf '%s\n' "$help" | grep -Eq -- "$flag([[:space:]=]|$)" || invalid "trusted gh $group $operation lacks $flag; first tested baseline is 2.100.0"
  done
}
check_gh release verify --format --jq --repo
check_gh release verify-asset --format --jq --repo
check_gh attestation verify --bundle --hostname --repo --cert-identity --cert-oidc-issuer \
  --source-ref --source-digest --signer-digest --deny-self-hosted-runners --predicate-type --format --jq
gh auth token --hostname github.com >/dev/null 2>&1 || invalid 'configure trusted gh read-only authentication for github.com (GH_TOKEN or gh auth login)'

stage=$(mktemp -d "$parent/.barbican-install.XXXXXXXX") || fail 'cannot create private sibling stage'
published=false
cleanup() {
  status=$?
  trap - 0
  rm -rf "$stage"
  exit "$status"
}
cancel() {
  if [ "$published" = true ] || { [ ! -d "$stage/ready" ] && [ -d "$destination" ]; }; then
    printf >&2 'install-barbican: interrupted after publication; complete install may remain at %s\n' "$destination"
  else
    printf >&2 'install-barbican: interrupted; no installation published\n'
  fi
  exit "$1"
}
trap cleanup 0
trap 'cancel 130' INT
trap 'cancel 143' TERM
trap 'cancel 129' HUP
mkdir "$stage/download" "$stage/scratch" "$stage/ready" "$stage/ready/bin"
tag="v$version"
repo=Rob-Morris/cargo-barbican
uri="https://github.com/$repo"
mac="cargo-barbican-$tag-aarch64-apple-darwin"
linux="cargo-barbican-$tag-x86_64-unknown-linux-gnu"
notice="cargo-barbican-$tag-LICENSES.txt"
bundle="cargo-barbican-$tag-provenance.sigstore.jsonl"
asset="cargo-barbican-$tag-$target"

# This query runs only on gh's cryptographically verified result, never API JSON.
release_query='
  .verificationResult.statement |
  select(._type == "https://in-toto.io/Statement/v1" and
    .predicateType == "https://in-toto.io/attestation/release/v0.2" and
    .predicate.repository == "'"$repo"'" and
    .predicate.repositoryId == "1276595321" and .predicate.ownerId == "2587163" and
    .predicate.tag == "'"$tag"'" and .predicate.purl == "pkg:github/'"$repo@$tag"'") |
  .subject as $subjects |
  [$subjects[] | select(.uri == "pkg:github/'"$repo@$tag"'")] |
  select(length == 1) | .[0].digest.sha1 as $source |
  select($source | test("^[0-9a-f]{40}$")) |
  ["'"$mac"'", "'"$linux"'", "'"$notice"'", "'"$bundle"'"] |
  map(. as $name | [$subjects[] | select(.name == $name)] |
    select(length == 1) | .[0].digest.sha256 | select(test("^[0-9a-f]{64}$"))) |
  select(length == 4) | [$source] + . | join(" ")'
gh release verify "$tag" --repo "github.com/$repo" --format json --jq "$release_query" > "$stage/release" || fail 'release verification failed; check trusted gh, read-only authentication and network access'
[ "$(wc -l < "$stage/release" | tr -d ' ')" = 1 ] || fail 'missing or ambiguous canonical signed release/source/assets'
read -r source mac_sha linux_sha notice_sha bundle_sha extra < "$stage/release"
[ -z "$extra" ] && [ -n "$bundle_sha" ] || fail 'unsupported verified release result'
case "$target" in aarch64-apple-darwin) asset_sha=$mac_sha ;; *) asset_sha=$linux_sha ;; esac
printf 'Verifying %s from %s (%s), target %s\n' "$tag" "$repo" "$source" "$target"
gh release download "$tag" --repo "github.com/$repo" --dir "$stage/download" \
  --pattern "$asset" --pattern "$notice" --pattern "$bundle" || fail 'release download failed; nothing activated'
for name in "$asset" "$notice" "$bundle"; do
  file="$stage/download/$name"
  [ -f "$file" ] && [ ! -L "$file" ] && [ -s "$file" ] || fail "missing regular payload: $name"
  case "$name" in "$asset") expected=$asset_sha ;; "$notice") expected=$notice_sha ;; *) expected=$bundle_sha ;; esac
  [ "$(digest "$file")" = "$expected" ] || fail "signed name/digest mismatch: $name"
  gh release verify-asset "$tag" "$file" --repo "github.com/$repo" --format json --jq "$release_query" > "$stage/membership" || fail "release asset verification failed: $name"
  cmp -s "$stage/release" "$stage/membership" || fail 'asset proof does not match canonical verified release'
done

san="$uri/.github/workflows/release.yml@refs/tags/$tag"
provenance_query='
  [ .[] | .verificationResult | .signature.certificate as $c |
    select($c.subjectAlternativeName == "'"$san"'" and
      $c.issuer == "https://token.actions.githubusercontent.com" and
      $c.sourceRepositoryURI == "'"$uri"'" and
      $c.sourceRepositoryIdentifier == "1276595321" and
      $c.sourceRepositoryOwnerIdentifier == "2587163" and
      $c.sourceRepositoryDigest == "'"$source"'" and
      $c.sourceRepositoryRef == "refs/tags/'"$tag"'" and
      $c.buildSignerDigest == "'"$source"'" and
      $c.runnerEnvironment == "github-hosted" and $c.buildTrigger == "push") |
    .statement | select(._type == "https://in-toto.io/Statement/v1" and
      .predicateType == "https://slsa.dev/provenance/v1") |
    .subject as $subjects |
    [["'"$mac"'", "'"$mac_sha"'"], ["'"$linux"'", "'"$linux_sha"'"], ["'"$notice"'", "'"$notice_sha"'"]] |
    map(. as $required | [$subjects[] | select(.name == $required[0])] |
      length == 1 and .[0].digest.sha256 == $required[1]) |
    select(. == [true, true, true]) ] | select(length > 0) | "verified"'
for name in "$asset" "$notice"; do
  result=$(gh attestation verify "$stage/download/$name" --bundle "$stage/download/$bundle" \
    --hostname github.com --repo "$repo" --cert-identity "$san" \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    --source-ref "refs/tags/$tag" --source-digest "$source" --signer-digest "$source" \
    --deny-self-hosted-runners --predicate-type https://slsa.dev/provenance/v1 \
    --format json --jq "$provenance_query") || fail "provenance verification failed: $name"
  [ "$result" = verified ] || fail 'no independently complete provenance proof matches all required identities and subjects'
done
header=$(od -An -tx1 -N20 "$stage/download/$asset" | tr -d ' \n')
case "$target:$header" in
  aarch64-apple-darwin:cffaedfe0c000001????????02000000*) ;;
  x86_64-unknown-linux-gnu:7f454c46020101??????????????????0[23]003e00) ;;
  *) fail 'verified payload has the wrong native executable header' ;;
esac
cp "$stage/download/$asset" "$stage/ready/bin/cargo-barbican"
cp "$stage/download/$notice" "$stage/ready/LICENSES.txt"
[ "$(digest "$stage/ready/bin/cargo-barbican")" = "$asset_sha" ] && \
  [ "$(digest "$stage/ready/LICENSES.txt")" = "$notice_sha" ] || fail 'staged copied bytes differ'
chmod 500 "$stage/ready/bin/cargo-barbican"
chmod 400 "$stage/ready/LICENSES.txt"
observed=$(cd "$stage/scratch" && env -i PATH=/usr/bin:/bin HOME="$stage/scratch" TMPDIR="$stage/scratch" \
  "$stage/ready/bin/cargo-barbican" --version) || fail 'verified binary cannot run on this host (including loader/libgcc requirements); nothing activated'
[ "$observed" = "cargo-barbican $version" ] || fail 'verified binary version does not match requested release'

if [ -e "$destination" ] || [ -L "$destination" ]; then
  [ -d "$destination" ] && [ ! -L "$destination" ] || fail 'destination changed; refusing replacement'
  for entry in '' /bin /bin/cargo-barbican /LICENSES.txt; do
    path="$destination$entry"
    [ ! -L "$path" ] || fail 'existing installation contains a symlink'
    case "$entry" in
      ''|/bin) [ -d "$path" ] || fail 'existing installation is incomplete'; mode=700 ;;
      /bin/cargo-barbican) [ -f "$path" ] || fail 'existing executable is not regular'; mode=500 ;;
      *) [ -f "$path" ] || fail 'existing notices are not regular'; mode=400 ;;
    esac
    [ "$(metadata "$path")" = "$uid $mode" ] || fail 'existing installation ownership/permissions conflict'
  done
  [ "$(ls -A "$destination" | wc -l | tr -d ' ')" = 2 ] && \
    [ "$(ls -A "$destination/bin" | wc -l | tr -d ' ')" = 1 ] || fail 'existing installation contains unknown entries'
  cmp -s "$stage/ready/bin/cargo-barbican" "$destination/bin/cargo-barbican" && \
    cmp -s "$stage/ready/LICENSES.txt" "$destination/LICENSES.txt" || fail 'existing installation conflicts; choose a fresh version root'
else
  mv "$stage/ready" "$destination" || fail 'could not publish complete installation'
  published=true
fi
printf 'Installed %s (%s)\nExecutable: %s/bin/cargo-barbican\nNotices: %s/LICENSES.txt\n' "$tag" "$target" "$destination" "$destination"
