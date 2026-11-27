# Attested binary releases

The release producer is separate from ordinary CI. The approved inert hosted
proof passed in ordinary public, genuine fork/Dependabot PR and private contexts
on Ubuntu22.04/macOS15; see [the recorded witnesses](../dependency-reviews/2026-11-25-release-consumer-token-qualification.md).
New ordinary scaffolds now use the pinned verified-download action. Actual
signed-public Barbican/native/Node24 acceptance and explicit settings/publication
approval remain release gates. See [consumer setup](../user/verified-releases.md),
[exact input review](../dependency-reviews/2026-11-25-attested-release-inputs.md)
and [notice custody](../dependency-reviews/2026-11-25-binary-distribution-notices.md).

## Release flow

1. Review the full diff, canonical gate and security findings. Keep both crate
   versions, lockfile workspace versions, canonical Summary/index, README/docs
   and generated template pins coherent. The setup action pins the already
   reviewed bootstrap commit `fb138d380fd004be6fb1d93da5ceff2b540854cc`, avoiding
   an impossible self-referential commit hash. Never substitute a moving branch.
2. Before changing the emitted default, observe the inert hosted token fixture
   in ordinary public, fork PR, Dependabot PR and private-consumer contexts.
   Record actual actor/head-fork/visibility/run witnesses. Local personal auth,
   source review or mocks do not stand in for these observations.
3. Prepare and obtain explicit approval for the concrete release/settings
   deployment. Enable immutable releases and read back the supported setting.
   Version tags need Active maintainer/admin-only creation authority plus
   **separate no-bypass update/deletion rules**. A creation exception must not
   permit moving/deleting a tag. The earlier ruleset inventory was empty;
   a null API immutability field is not evidence that the setting is enabled.
4. [Rehearse the exact candidate commit](#pre-tag-rehearsal) and confirm it
   passed before creating a tag. Promote/push the same reviewed history through
   the normal dev/main flow without changing the commit SHA. Create
   one lightweight `vN.N.N` tag at the version commit on main, run
   `sh scripts/check_release_tag.sh <commit>`, then deliberately push that tag.
   Annotated tags, prereleases, non-main commits, unprotected refs, incoherent
   version notes or missing rehearsal evidence refuse before building.
5. Observe fresh canonical verification on Linux and qualified macOS26, native
   builds on Ubuntu22.04 and ARM64 macOS15, and direct captured-payload native
   checks/adoption on Ubuntu22/24 and macOS15/26. Minimum-host checker startup
   does not expand native Rustup intake qualification. Other platforms remain
   unsupported; runtime floors are glibc2.35/libgcc and macOS15.
6. The dedicated signer downloads exact captured artifact IDs, checks complete
   source/run/attempt/target/name/size/hash receipts, signs only the two final
   executables and notice file, then retains the generated bundle. Its entire
   allowlist has source read, OIDC and attestation write; no candidate programs,
   Cargo, build scripts or package installation run in that job.
7. The publisher has contents write only. Its reviewed static protocol/API
   helpers inspect bytes, assemble an owned draft and freshly download/check
   every raw file before publishing. It neither signs nor executes candidates.
   The release contains exactly two raw target binaries, LICENSES and the
   generated provenance bundle. The service's immutable-release attestation
   binds all four assets; the bundle does not recursively attest itself.
8. After publication, actual supported installer/action setup and installed-byte
   adoption must pass with ordinary read-only tokens on all core native hosts.
   These are release-completion/adoption gates, not pre-publication evidence.
   Confirm exact public source/asset/provenance identities before calling the
   release complete. Existing consumer workflows/providers migrate deliberately.
   Local binary upgrades are separate explicitly authorised work.

## Pre-tag rehearsal

Push the reviewed candidate commit to the canonical repository under
`release-candidate/`. Use the full SHA you intend to tag, including the
version bundle and the exact setup action pin. For example:

```sh
candidate=$(git rev-parse dev)
git push origin "$candidate:refs/heads/release-candidate/vX.Y.Z"
# Wait for Pre-tag release rehearsal in GitHub Actions, then check the result.
sh scripts/check-release-rehearsal.sh "$candidate"
```

The rehearsal shares the two production builders and the four native payload
checks, including exact linkage, runtime and scanner-backed adoption. It also
combines the two receipts to verify notice agreement. In parallel, it selects
the current immutable stable public release once and checks its real signed
installation on the same runner images. It records the GitHub CLI version and
exercises the candidate installer, the exact pinned action and the action in
the candidate checkout. The three installations must agree on executable bytes.

Use a fresh run close to tagging to catch runner image changes. The check
requires the latest rehearsal for the exact commit to have completed
successfully. If you change the commit, push the new SHA and wait for its run.
If retrying the same run, rerun all jobs. The tag workflow checks the verdict
again before building. Rehearsal jobs have read-only repository permissions
and publish no release. Production builds and signs fresh artifacts for the
protected tag and still checks installation of that newly published release.

## Retry and incident boundaries

Rerun **all jobs**, not failed jobs alone. Artifacts and receipts bind the current
run attempt; stale successful builders cannot stand in for a fresh attempt.
Transport artifacts are attempt-scoped, retained for seven days, and never
replace policy evidence. The v8 downloader can warn about a missing subset of
IDs, so raw-file/directory cardinality checks remain mandatory. Single-artifact
extraction uses its requested root directly; multi-artifact extraction keeps
named directories. Do not rely on executable mode preservation in archives.

Drafts are discovered through the authenticated paginated release listing,
then read by captured numeric ID. The published-release tag endpoint cannot
find drafts. Only the exact protocol-owned source/note body, bot author and
owned asset labels may be reconciled after a complete fresh attempt. Unknown
or manual state refuses; inspect it deliberately. A lost create/publish response
is reconciled by readback. Cancellation may leave a draft or completed public
release and reports that uncertainty. No public `--clobber`, version reuse,
automatic deletion/revocation or silent source fallback is allowed.

A red post-publication job does not revoke a valid signature or stop a consumer
from verifying a signed defective binary. Stop adoption/promotion, follow the
security incident process, and correct under a new version. Never describe
provenance as benignness, reproducible-build or current policy-admission proof.

## Notices and local verification

`release_protocol.py notices` uses locked Cargo metadata and original package
licence/copyright/notice texts, with reviewed exact-version supplements for
missing published files. It conservatively includes the whole locked graph,
including build/platform alternatives. Rust1.95.0's full standard-library notice
inventory is fixed separately; a compiler bump requires review. Unexpected
native linkage or missing/changed text fails, rather than treating licence
policy PASS as distribution compliance. The bundle is retained in every install.

Run the canonical `sh scripts/verify.sh` and `sh scripts/verify-adoption.sh`.
For the captured-byte acceptance, export the absolute regular executable as
`BARBICAN_TEST_RELEASE_BINARY` when invoking the latter. This is a test-harness
seam only; no production verifier bypass or fixture mode exists. Shell/transport
and draft tests are hermetic. Their mock verifier/API cannot prove real signing,
hosted permissions, Node24 runtime, immutable publication or native minimums.

## Reviewed hosted fixture deployment

The concrete fixture is `.github/workflows/qualify-release-consumer.yml`.
It verifies the exact existing immutable cli/cli2.100.0 archive and source with
trusted gh, checks name/digest/provenance, and never extracts or executes it.
It needs only the built-in contents-read token, with no checkout or secrets.

The explicitly approved footprint reuses public
`Rob-Morris/barbican-admission-rehearsal`, adds its isolated `underware-gg` fork
and creates private `Rob-Morris/barbican-release-consumer-proof-private`.
The existing public rehearsal has only a maintainer-dispatched admission
workflow; adding the inert fixture does not dispatch that controller or move
its protected tags. Preserve its existing files, settings and evidence.
Harmless fork/Dependabot fixture PRs establish those actual contexts. Exact
metadata-only inputs live in `.github/fixtures/release-consumer/README.md`;
serde1.0.227 is a deliberately older declaration for the bot and is never built,
installed or executed by a proof job. It is not a product dependency. Merge the
bounded bot configuration without replacing any existing entries. A private
run is separate; a public-only witness cannot establish it. Record exact run
URLs/attempts and limitations before enabling the emitted download default.
No fixture/bypass/repository override is added to the shipped installer.
