# Verified release installation

Install an exact attested release using one standalone installer or the thin
full-SHA setup action. A release is ready for adoption after its signed-public
acceptance gates complete. Source compilation remains an explicit option in
[integration](integration.md); there is no floating release or silent fallback.

## Standalone installer

Fetch the pinned installer with your already trusted gh, review its source,
then run that local copy. These are explicit separate steps, with no fetched
script piped to a shell:

```sh
bootstrap=$(mktemp -d)
gh api --hostname github.com -H 'Accept: application/vnd.github.raw+json' \
  'repos/Rob-Morris/cargo-barbican/contents/scripts/install-barbican.sh?ref=d9bf9b422475ff7e8ca789c9e66c6013d1546cbe' \
  > "$bootstrap/install-barbican.sh"
# Review the downloaded pinned source before continuing.
mkdir -p "$HOME/.local/barbican"
sh "$bootstrap/install-barbican.sh" --version 0.45.1 --install-dir "$HOME/.local/barbican/0.45.1"
```

Select an explicitly reviewed published version; the example pins0.45.1.

Create the parent first; it must be owned by you without group/other write access. This is a
version installation root, containing `bin/cargo-barbican` and `LICENSES.txt`,
not an existing shared bin directory. Invoke the reported exact executable or
add its bin directory to your own PATH. Setup does not modify shell profiles,
Cargo installation ledgers, toolchains or scanner installations.

Supply an already trusted compatible GitHub CLI and read-only GitHub auth.
2.100.0 is the first tested verifier baseline; a version string is not tool
provenance. Required verification commands, flags and verified-result schema
must work; unsupported behaviour refuses. No jq, Python, Rust or compiler is
required to install/start the checker. Cargo-scoped commands still require
trusted Cargo; scanners and compiler selection remain separate.

The core hosts are macOS 15+ ARM64 and GNU Linux x86-64 with glibc 2.35+,
libgcc_s.so.1 and the GNU loader. Other architectures, musl/Alpine, Windows,
GHES and self-hosted Actions runners are not qualified. Online verification
also needs access to GitHub's attestation blobs and Sigstore/TUF trust services.

Setup verifies the canonical signed release, exact signed filenames/digests,
and the source payload provenance's exact workflow/ref/source/certificate
identities. It then checks the native header, rehashes copied bytes, and runs
only the verified staged binary's version probe, with an empty environment
apart from private scratch homes and the system PATH. It publishes the whole
installation only after that probe succeeds. This is ordinary native execution
after verification, not a sandbox or proof that signed code is harmless.

Identical complete installations require fresh online verification and exact
bytes, ownership, permissions and entries. Unknown files, symlinks, partial or
conflicting installations refuse without replacement. Choose a new owned root;
there is no automatic repair/removal. The filesystem contract assumes a single
trusted writer; it does not defeat hostile concurrent same-user mutation.
Cancellation cleans only the owned stage; interruption after publication can
leave a complete install and reports that effect.

## GitHub Actions adapter

The root composite `action.yml` calls this same installer. Consumers pin its
full reviewed commit SHA and supply an exact `version`; no default version is
provided. Configure the caller job with `permissions: contents: read`; the adapter cannot
reduce a more privileged caller token. It uses the built-in job token only
during setup, installs
into a fresh job-local root, returns `executable` and `bin-dir`, and adds that
bin directory to PATH for subsequent steps. Consumers need no PAT, OIDC token,
write permissions, persistent cache or source compilation for checker setup.
Inputs pass through environment variables, never executable shell expressions.

Existing consumer workflows and specialised admission providers are never
rewritten automatically. New ordinary CI uses the reviewed setup commit and
exact0.45.1 release; [CI integration](ci.md) shows the concrete pins. Admission-enabled
providers must install before candidate checkout, retain their own reviewed
identity, and use the exact checker path rather than a candidate PATH entry.

A successful download/provenance check establishes distribution identity and
integrity. It is not a tool/compiler admission receipt or approval of a release.
A validly signed functional defect requires normal incident handling and a
corrected new version; a failed post-publication job does not revoke signatures.

## Consumer-owned admission provider

The provider/controller/approved-input revisions remain exact reviewed choices.
Existing files are never rewritten automatically. Vendor the reviewed installer
from `d9bf9b422475ff7e8ca789c9e66c6013d1546cbe` into the provider (and review that
source); hard-code the chosen exact accepted release in its script. Do not fetch
and execute an unpinned remote shell script. The initial signed-public-release
acceptance gate must complete before adopting this recipe.

The controller passes a fresh private `tools_root`. Add the checker to the
provider's complete `tools_root/bin` contract while retaining notices:

```sh
set -eu
umask 077
tools_root=$1
provider_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
sh "$provider_dir/vendor/install-barbican.sh" \
  --version N.N.N --install-dir "$tools_root/barbican"
mkdir -p "$tools_root/bin"
[ ! -e "$tools_root/bin/cargo-barbican" ] && [ ! -L "$tools_root/bin/cargo-barbican" ]
cp "$tools_root/barbican/bin/cargo-barbican" "$tools_root/bin/cargo-barbican"
cmp -s "$tools_root/barbican/bin/cargo-barbican" "$tools_root/bin/cargo-barbican"
chmod 500 "$tools_root/bin/cargo-barbican"
```

Replace N.N.N with a literal reviewed release before approving the provider.
Its already reviewed provisioning must still supply the qualified Rustup,
its Cargo/rustc/rustdoc launchers, selected scanners and optional nextest. This
fragment alone is deliberately insufficient for the complete controller.
Keep `barbican/LICENSES.txt`; copied checker bytes must match the verified
installation. The filesystem contract assumes the same trusted single writer.

The provider's setup step needs `GH_TOKEN: ${{ github.token }}` with job
`permissions: contents: read`, before any candidate checkout. New controller
templates scope that environment binding to `provision` only. An existing
controller needs a separately reviewed source/pin update; adding the provider
alone cannot supply missing authentication. Do not put the token in GITHUB_ENV
or pass it to candidate-stage commands. Use the exact resulting checker path
for admission before probing/installing the candidate compiler. Copying the
checker does not produce an admission receipt or weaken any existing guard.
