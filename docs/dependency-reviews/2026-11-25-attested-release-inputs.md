# Dependency Review: attested binary release inputs

## Summary

25 November 2026, Codex. First-principles review of the exact external verifier
and GitHub Actions inputs for the approved binary release design. No Rust
manifest or reviewed-family changes. This is bounded source qualification;
hosted execution and read-only token witnesses remain release acceptance gates.

## Classification

Elevated-risk: these inputs verify, transport or sign executable distributions.
Consumers supply an independently trusted compatible gh; setup never downloads
a verifier or accepts arbitrary trust roots. The first tested baseline is
2.100.0, not an assertion that all later versions are accepted automatically.

## Targets

- cli/cli 2.100.0, 45437bc7eeeb3359bbfddd1742f79de7652fd3e2.
- actions/attest 4.2.2, 1e69f48acb82d1966a394da916b4c1698aa569d6.
- actions/upload-artifact 7.0.2, cf430e030ddbb5b0abf93d22962f4752f3646cd9.
- actions/download-artifact 8.0.2, 9000827ccba6bdab643e8b6fd33ac0654aef8333.

## Inheritance

First-principles. Source and selected distributed JavaScript were reviewed
before introduction. The attached custody inventory records inspected file
hashes. Archive hashes describe observed GitHub-generated archives rather than
universal stable archive identities. No new product dependency or policy
exception is granted.

## Release Age

The technical qualification on 24 November checked these established releases
and exact tag refs. gh 2.100.0 was released on 3 September 2026.
Independent public release API readback confirmed attest4.2.2 published
2026-08-04T20:36:29Z, upload7.0.2 published2026-10-07T10:08:14Z and download8.0.2
published2026-10-07T10:09:51Z. Each exceeds the seven-day floor on25November.
Action source
cuts and packaged runtime identities, rather than a mutable version alias,
control execution. No crate release-age exemption is introduced.

## Advisory Review

Review covered the exact execution/authentication/transport boundaries and
bundled implementations. It is not a complete vulnerability audit of every
JavaScript/Go transitive dependency. Pinning plus least privilege bounds the
accepted role; upstream security notices and future updates require re-review.
Existing RustSec exceptions and their deadlines are unchanged.

## Source / Upstream Review

# Exact bootstrap input source qualification — 24 November 2026

Read-only source review for Barbican's core attested binary release slice. No downloaded code/actions were executed, no tools installed, no repo/Brain/remote state mutated. Source snapshots only were materialised beneath this reviewer subtree. The initial sandbox network failure was resolved using approved read-only outside-sandbox GitHub API access.

## Inputs and source custody

| Input | Exact source commit | Observed archive SHA-256 |
|---|---|---|
| Existing trusted gh 2.100.0 | cli/cli@45437bc7eeeb3359bbfddd1742f79de7652fd3e2 | fbc7523e742b2b4f116a7a1048b87966c8507dd7c4623a9338e7bbce57e19cc7 |
| actions/attest v4.2.2 | actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 | 809cf546fbd640025e3550aa0de0612bcce8c9388085e9a6bb280a02e5986818 |
| actions/upload-artifact v7.0.2 | actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 | fbfc16e1e41626460fc6935077d5ed6577ed8ed002b153a2c5a0df252026c44e |
| actions/download-artifact v8.0.2 | actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 | 6d2ae083115e05f0770e13af98f4de1184bde8708e7505803fe11faf2530672c |

Archive hashes describe the retrieved GitHub-generated archives, not universal stable archive digests. files-receipt.json records selected source/dist file digests. Actual executed action main bundle hashes:
- attest dist/index.js: 3ca89e06ffcb09ff97e9b1633575865cad0b23310ac82176d72990d7554836b5 (auxiliary chunks also in file receipt).
- upload dist/upload/index.js: c0e58b240360573e6d6c82ea1bb22deff4f85883e00211a52bd27822c3a22617.
- download dist/index.js: 7834b909df0fd656f5ac1c4c4ab4ee3b5e2673e4f4f763549d8abbca16bc5bbe.

The attest v4.2.2 tag was checked through the public git-ref API and resolves to the supplied commit. Its package.json retains version 4.1.0; use release tag plus immutable commit as source identity, not this stale package field.

## Authenticated read paths

gh's root command requires an available credential for ordinary release verification: pkg/cmd/root/root.go:83-93. Provenance's local --bundle flag disables the normal root auth check (pkg/cmd/attestation/verify/verify.go:235-236); that is not an unauthenticated implementation of the accepted online release route.

release verify and verify-asset:
1. GET /repos/{owner}/{repo}/git/ref/tags/{tag}: pkg/cmd/release/shared/fetch.go:138-166.
2. GET /repos/{owner}/{repo}/attestations/{sha1:ref}, predicate_type=release, scoped repo, initiator github, limit100: release/verify/verify.go:138-168; verify-asset/verify_asset.go:150-190.
3. GET /meta for GitHub trust domain: release/shared/attestation.go:32-44; attestation/api/trust_domain.go:3.
4. Download signed bundle URL using unauthenticated external client; initialise normal GitHub TUF trust root.

attestation verify:
1. Hash local file, then GET /repos/{owner}/{repo}/attestations/{sha256:file}, predicate_type SLSA v1 and initiator user: verify/attestation.go:13-38; api/client.go:104-136.
2. Fetch bundle blobs through external client: api/client.go:196-260.
3. Initialise supported public-good and GitHub trust roots as needed. A public-good initialisation failure cannot make a public-good-issued attestation verify using the wrong root: verification/sigstore.go:216-229.

api/http_client.go:99-132 explicitly creates the external client without token/default GitHub auth headers. The authenticated transport avoids adding auth on host-changing redirects:153-188.

Public repository attestation reads are documented as available without the target private-resource permissions; private reads require attestations:read. Public release reads have the corresponding public exception to contents:read. Therefore a read-only consumer-repo GITHUB_TOKEN is a technically sound proposed credential for public upstream resources. A PAT, id-token:write, attestations:write or package write permission is not justified for consumers. Scope workflow token to contents:read, supply GH_TOKEN explicitly only to setup, and use canonical public github.com/repo hosts rather than inheriting an unintended host.

Fork and Dependabot events retain a read-only workflow token; a design requiring only public GETs and that built-in token need not require unavailable user secrets. Private-consumer visibility does not turn the upstream public resources into private resources. However this source analysis is NOT a live proof of GitHub App-token entitlement in those hosted contexts. Keep those three actual context journeys as acceptance gates before changing the generated default. Do not use personal local auth as evidence of their success.

Primary API/behaviour references:
- https://docs.github.com/en/rest/repos/attestations?apiVersion=2026-03-10 (list-attestations endpoint, public-resource exception).
- https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions
- https://docs.github.com/en/code-security/reference/supply-chain-security/troubleshoot-dependabot/dependabot-on-actions

## Protected claims and policy refinements

1. **Use exact SAN, not signer-workflow prefix alone.** verify/policy.go:149-167 compiles --signer-workflow to an anchored-prefix regexp without an end anchor. Prefer --cert-identity exact https://github.com/Rob-Morris/cargo-barbican/.github/workflows/<release>.yml@refs/tags/vX.Y.Z. Retain --repo, --source-ref, --source-digest, --signer-digest, --cert-oidc-issuer and --deny-self-hosted-runners. With exact --cert-identity, do not also pass conflicting SAN selector flags; options policy permits one selector.
2. Source ref/digest/signer digest and issuer flags inspect certificate extensions, not arbitrary predicate text: verify/policy.go:84-105 and verification/extensions.go:43-70. Runner checks use certificate policy. Stable numeric source repository/owner identifiers have no equivalent native CLI flags in this version: explicitly check verificationResult.signature.certificate.sourceRepositoryIdentifier and sourceRepositoryOwnerIdentifier in each relied-on JSON result. Consider requiring the protected buildTrigger push for the accepted tag-only producer protocol.
3. **Subject filename is an independent check.** release verify-asset filters by digest only: verify_asset.go:179-190; shared/attestation.go:76-98. It does not ensure that the same digest occurs under the required asset name. Require the exact expected signed subject name+digest and the canonical release repo/tag/source subject. Successful release verification provides one object; provenance exports an array.
4. **Cardinality is per relied-on result/subject, not global exactly-one provenance attestation.** provenance Verify succeeds if at least one passes and returns all passing results (verification/sigstore.go:281-311; extensions.go:17-40). Re-sign/retry can legitimately yield multiple equivalent proofs. Require at least one result independently satisfying all certificate and subject constraints; never combine fragments across results. Ensure each required subject name/digest is uniquely and coherently represented within the chosen statement. release verify itself rejects more than one release attestation after tag filter (release/verify.go:163-168); verify-asset picks first digest match, so compare its result to the canonical verified release.
5. **Qualify annotated tags rather than assume peeling.** shared/fetch.go:138-166 returns raw git-ref object.sha and ignores object.type; it does not peel annotated tags to commits. Existing repo helper uses ^{commit}. Keep first-slice release tags explicitly lightweight as already documented, or prove an actual immutable annotated-tag fixture before promising support. A filename/version string cannot resolve this identity difference.
6. Trusted-root retrieval remains part of online prerequisites. GitHub root is embedded and updated through TUF; standard metadata cache validity is one day (verification/tuf.go:16-54). Do not add a custom root or offline mode implicitly. Network requirements include signed-bundle/TUF endpoints, not solely api.github.com.

## Exact action runtime and job fit

All three action.yml manifests use node24. Qualify on current Node24-capable hosted Ubuntu x64 and macOS ARM64 runners. No self-hosted/GHES support is established by this review; upload/download v4+ explicitly disclaim GHES in their READMEs. CLI go.mod uses Go1.26.0/toolchain1.26.8; upstream Go1.25/1.26 minimum macOS is12. The original Barbican minos11 metadata cannot establish that the whole installer/verifier bootstrap runs on11. Recommend macOS15 as a native qualification candidate (with26 newer), not an unproved claim of the oldest possible OS. https://go.dev/wiki/MinimumRequirements

Attest: use exact subject-path inputs, not implicit GITHUB_ARTIFACTS_LIST discovery (src/subject.ts:50-65). No SBOM/custom predicate inputs selects ordinary generated SLSA provenance. Explicitly disable push-to-registry and create-storage-record. src/attest.ts:45-110 uses artifact-metadata only in the OCI/storage path; do not copy the README's broad artifact-metadata:write grant into the raw binary signer job. Required signing capabilities are id-token:write and attestations:write, with read-only source/default job permissions and no candidate execution. Pin every action SHA and review the whole privileged job.

Upload: if-no-files-found defaults warn; explicitly choose error. Keep overwrite:false and an exact file set. src/shared/upload-artifact.ts:21-22 exposes artifact ID and transport digest. New v7 supports archive:false for one file, whose basename overrides supplied artifact name; this is an optional raw-transfer simplification to qualify, not assumed tested behaviour.

Download: contrary to generic older-action documentation, this exact v8 defaults digest-mismatch:error and throws on mismatch (action.yml:43-47; src/download-artifact.ts:233-250), mirrored in dist. Set error explicitly and retain final-file SHA/size/name/source/run validation. Missing some requested IDs only warns (src:139-144); empty non-ID list can complete with0 files, so exact expected ID/file cardinality remains required. Prefer same-run artifact context without an unnecessary github-token/cross-run lookup; specifying token activates findBy repository/run lookup. If raw single-file upload is selected, skip-decompress:true is supported and needs integration proof. Never rely on preserved executable modes through zipped transfer; the intended consumer chmod-after-verification sequence is appropriate.

## Assessment and limits

The exact selected inputs fit the bounded core producer/consumer architecture with the refinements above. No new product decision is required by this source review. Do not present it as completed hosted action execution, endpoint-entitlement rehearsal, native compatibility proof, complete third-party vulnerability audit or release readiness. Existing source/action first-principles records should incorporate this bounded review and the actual later integration evidence before introduction.




## Commands Run

Read-only exact-ref GitHub source/archive retrieval and SHA256 inventory;
local trusted gh help, real immutable upstream release and provenance
verification, exact-SAN negative control, renamed-asset digest-only control.
The technical qualification report in Brain records the full observations.
No new action code was executed during source review.

## Outcome

Accept these exact source cuts for the bounded GitHub.com hosted workflow.
Require checked-in full-SHA pins, Node24-capable core runners, exact independent
payload checks and job-scoped privilege separation. Consumer setup requires
read-only auth only. Runtime/token/native acceptance is not established by
this record and must be observed before rollout/default migration.

## Follow-ups

Observe restricted hosted-token contexts and minimum native hosts; retain their
actual limits. GHES, self-hosted runners and additional platform support remain
unsupported. Never treat a mock verifier as cryptographic evidence.
