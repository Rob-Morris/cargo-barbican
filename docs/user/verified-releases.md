# Verified release installation

The installer and setup action are the shared bootstrap primitive for attested
binary releases. Until a signed public Barbican release has completed its hosted
acceptance gates, use the current [source installation](integration.md). There
is no floating release or automatic fallback.

## Standalone installer

After reviewing the installer source at an exact commit, run its local copy:

```sh
sh scripts/install-barbican.sh --version N.N.N --install-dir "$HOME/.local/barbican/N.N.N"
```

Replace N.N.N with an explicitly reviewed published release. Create the parent
first; it must be owned by you without group/other write access. This is a
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

This primitive does not rewrite existing consumer workflows or specialised
admission providers. A future versioned adoption change supplies concrete
reviewed pins once the required hosted-token gates pass. Admission-enabled
providers must install before candidate checkout, retain their own reviewed
identity, and use the exact checker path rather than a candidate PATH entry.

A successful download/provenance check establishes distribution identity and
integrity. It is not a tool/compiler admission receipt or approval of a release.
A validly signed functional defect requires normal incident handling and a
corrected new version; a failed post-publication job does not revoke signatures.
