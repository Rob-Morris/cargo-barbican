//! Prepared domain inputs isolate persistence/assessment composition; verifier and archive
//! authentication have their separate authentic and hostile-input tests.
use super::{
    acceptance, admission,
    repo::RepoContext,
    review::{ReconstructedReview, ReviewRecord},
    store::PrivateStore,
};
use barbican::rust_distribution::*;
use barbican::toolchain_admission::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    review: ReconstructedReview,
    prose: Vec<u8>,
    assessment: HumanAssessment,
    admission: ReviewedToolchainAdmission,
    now: i64,
}
impl Fixture {
    fn new() -> Self {
        Self::prepared(false)
    }
    fn prepared(authenticated: bool) -> Self {
        Self::prepared_at(authenticated, None)
    }
    fn prepared_at(authenticated: bool, clock: Option<i64>) -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "barbican-workflow-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).unwrap();
        let host = "aarch64-apple-darwin";
        let mut raw = format!(
            "manifest-version='2'\ndate='2026-01-01'\n[profiles]\nminimal=['rustc','cargo','rust-std']\ndefault=['rustc','cargo','rust-std']\n[pkg.rust]\nversion='1.99.1 (abc 2026-01-01)'\n[pkg.rust.target.{host}]\navailable=true\ncomponents=["
        );
        for package in ["rustc", "cargo", "rust-std"] {
            raw.push_str(&format!("{{pkg='{package}',target='{host}'}},"));
        }
        raw.push_str("]\n");
        for package in ["rustc", "cargo", "rust-std"] {
            raw.push_str(&format!("[pkg.{package}]\nversion='1.99.1 (abc 2026-01-01)'\n[pkg.{package}.target.{host}]\navailable=true\nxz_url='https://static.rust-lang.org/dist/2026-01-01/{package}-1.99.1-{host}.tar.xz'\nxz_hash='{}'\n","a".repeat(64)));
        }
        let fixture_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/toolchain-intake/workflow");
        if authenticated {
            raw = fs::read_to_string(fixture_path.join("channel-rust-1.99.1.toml")).unwrap();
        }
        let manifest = Manifest::parse(raw.as_bytes(), "1.99.1").unwrap();
        let request = SelectionRequest {
            host: host.into(),
            profile: Profile::Minimal,
            components: vec![],
            targets: vec![],
            encoding: Encoding::Xz,
        };
        let selection = manifest.select(&request).unwrap();
        let inventories: Vec<_> = selection
            .archives
            .iter()
            .map(|identity| {
                if authenticated {
                    return inspect_archive(
                        fs::File::open(
                            fixture_path.join(format!("{}-1.99.1-{host}.tar.xz", identity.package)),
                        )
                        .unwrap(),
                        identity,
                    )
                    .unwrap();
                }
                let texts = BTreeMap::from([
                    ("components".to_owned(), format!("{}\n", identity.component)),
                    ("rust-installer-version".to_owned(), "3\n".to_owned()),
                    (format!("{}/manifest.in", identity.component), String::new()),
                ]);
                let package_metadata = texts
                    .iter()
                    .map(|(path, body)| {
                        (
                            path.clone(),
                            ExpectedEntry {
                                kind: EntryKind::File {
                                    size: body.len() as u64,
                                    sha256: digest_bytes(body.as_bytes()),
                                },
                                mode: 0o644,
                            },
                        )
                    })
                    .collect();
                ArchiveInventory {
                    identity: identity.clone(),
                    expanded_bytes: 4096,
                    physical_headers: 5,
                    effective_entries: 5,
                    payload: BTreeMap::new(),
                    package_metadata,
                    installer_metadata: texts,
                }
            })
            .collect();
        let mut authentication = AuthenticationIdentity {
            manifest_sha256: manifest.sha256(),
            signature_sha256: digest_bytes(b"fixture signature"),
            certificate_sha256: digest_bytes(b"fixture public material"),
            primary_fingerprint: "A".repeat(40),
            signing_fingerprint: "B".repeat(40),
            verification_policy_sha256: digest_bytes(b"fixture policy"),
        };
        if authenticated {
            let material = fixture_material();
            let store = PrivateStore::open(&root.join("fixture-author-trust"), &[]).unwrap();
            let trust = super::trust::Trust::load(&store, &material, 1_793_750_400).unwrap();
            let signature = fs::read(fixture_path.join("channel-rust-1.99.1.toml.asc")).unwrap();
            let signer = trust
                .verify(
                    &material.certificate,
                    &signature,
                    raw.as_bytes(),
                    1_793_750_400,
                )
                .unwrap();
            authentication = AuthenticationIdentity {
                manifest_sha256: manifest.sha256(),
                signature_sha256: digest_bytes(&signature),
                certificate_sha256: digest_bytes(&material.certificate),
                primary_fingerprint: signer.primary,
                signing_fingerprint: signer.component,
                verification_policy_sha256: digest_bytes(
                    super::trust::VERIFICATION_POLICY.as_bytes(),
                ),
            };
        }
        let subject =
            Subject::reconstruct(&manifest, &request, authentication, inventories.clone()).unwrap();
        let now = if authenticated {
            1_793_750_400
        } else {
            barbican::parse_iso_date("2026-01-02")
                .unwrap()
                .midnight()
                .assume_utc()
                .unix_timestamp()
                + 3600
        };
        let now = clock.unwrap_or(now);
        let body = b"bounded source fixture".to_vec();
        let sha = digest_bytes(&body);
        let reference = RecordReference {
            path: "docs/dependency-reviews/toolchains/fixture/sources/source.txt".into(),
            sha256: sha.clone(),
        };
        let observations = required_sources(&subject)
            .into_iter()
            .map(|source| SourceObservation {
                source,
                location: "https://example.test/source".into(),
                provenance: "prepared domain test input".into(),
                revision: "fixture-revision".into(),
                content_sha256: sha.clone(),
                snapshot: reference.clone(),
                status: CollectionStatus::Completed,
                coverage: Coverage::ResidualUnknown,
                coverage_rationale:
                    "Fixture does not establish source authenticity or reachability".into(),
                checked_at: now,
                expires_at: None,
            })
            .collect();
        let evidence = EvidenceRecord {
            component_sources: vec![],
            schema_version: 1,
            subject_id: subject.id().clone(),
            publication: PublicationFacts {
                subject_id: subject.id().clone(),
                authenticated_manifest_day: subject.record().publication_date.clone(),
                corroborated_days: vec![subject.record().publication_date.clone()],
                source: SourceId {
                    kind: SourceKind::Publication,
                    scope: "distribution".into(),
                },
                source_content_sha256: sha,
            },
            observations,
            findings: vec![],
        };
        let policy = EffectivePolicy {
            schema_version: 1,
            minimum_days: 7,
            override_reason: None,
        };
        let record = ReviewRecord {
            schema_version: 1,
            subject: subject.record().clone(),
            evidence,
            policy,
            snapshot_root: "snapshots/fixture".into(),
            created_at: now,
        };
        let review = ReconstructedReview {
            record,
            subject,
            selection,
            inventories,
            manifest_bytes: raw.into_bytes(),
            archives: vec![],
            source_snapshots: BTreeMap::from([(reference.path, body)]),
        };
        let id = review.record.id(&review.subject).unwrap();
        let mut prose = format!(
            "# Completed exact toolchain review\nToolchain-Review: {id}\nSubject: {}\nEvidence: {}\nPolicy: {}\nDecision: ACCEPT\nRationale: Reviewed the exact source scope and explicitly accepted its stated residual uncertainty.\n",
            review.subject.id(),
            review.record.evidence.content_id(&review.subject).unwrap(),
            review.record.policy.id().unwrap()
        );
        for source in review.record.evidence.residual_unknowns() {
            prose.push_str(&format!(
                "Assessed-Unknown: {}\n",
                serde_json::to_string(&source).unwrap()
            ));
        }
        let prose = prose.into_bytes();
        let assessment = acceptance::assess(&review, &id, &prose, now).unwrap();
        let portable = PortableReview {
            schema_version: 1,
            subject: review.subject.record().clone(),
            evidence: review.record.evidence.clone(),
            policy: review.record.policy.clone(),
            assessment: assessment.clone(),
        };
        let portable = serde_json::to_vec_pretty(&portable).unwrap();
        let exception=b"# Completed exact exception\nReviewed the exact subject and repo-a policy; this exception permits only release age.\n";
        let admission = ReviewedToolchainAdmission {
            schema_version: 1,
            subject_id: review.subject.id().clone(),
            policy_id: review.record.policy.id().unwrap(),
            assessment_id: assessment.id().unwrap(),
            scope: "repo-a".into(),
            review_record: assessment.review.path.clone(),
            review_record_sha256: assessment.review.sha256.clone(),
            evidence_record: format!("docs/dependency-reviews/toolchains/{id}/evidence.json"),
            evidence_record_sha256: digest_bytes(&portable),
            review_by: None,
            age_exception: Some(ToolchainAgeException {
                subject_id: review.subject.id().clone(),
                policy_id: review.record.policy.id().unwrap(),
                scope: "repo-a".into(),
                review: RecordReference {
                    path: "docs/dependency-reviews/toolchains/exception.md".into(),
                    sha256: digest_bytes(exception),
                },
                expires_at: now + 86_400,
            }),
        };
        let repo = root.join("repo");
        fs::create_dir(&repo).unwrap();
        write(&repo, "Cargo.toml", b"[workspace]\nmembers=[]\n");
        write(
            &repo,
            "barbican.toml",
            b"[toolchain]\nrequire_admission=true\nadmission_scope='repo-a'\n",
        );
        write(
            &repo,
            "rust-toolchain.toml",
            b"[toolchain]\nchannel='1.99.1'\nprofile='minimal'\n",
        );
        write(
            &repo,
            "reviewed-targets.toml",
            render_admission_fragment(&admission).unwrap().as_bytes(),
        );
        write(&repo, &admission.review_record, &prose);
        write(&repo, &admission.evidence_record, &portable);
        write(
            &repo,
            "docs/dependency-reviews/toolchains/exception.md",
            exception,
        );
        for (path, bytes) in &review.source_snapshots {
            write(&repo, path, bytes);
        }
        if authenticated {
            for (name, source) in [
                ("manifest.toml", "channel-rust-1.99.1.toml"),
                ("manifest.asc", "channel-rust-1.99.1.toml.asc"),
                ("certificate.pgp", "fixture-public-key.asc"),
            ] {
                write(
                    &repo,
                    &format!("docs/dependency-reviews/toolchains/{id}/{name}"),
                    &fs::read(fixture_path.join(source)).unwrap(),
                );
            }
        }
        Self {
            root,
            review,
            prose,
            assessment,
            admission,
            now,
        }
    }
    fn data(&self, name: &str) -> PrivateStore {
        PrivateStore::open(&self.root.join(name), &[&self.root.join("repo")]).unwrap()
    }
    fn repo(&self) -> RepoContext {
        RepoContext::capture(&self.root.join("repo")).unwrap()
    }
    fn id(&self) -> barbican::Sha256Digest {
        self.review.record.id(&self.review.subject).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn write(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn copy_approved_fixture(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_approved_fixture(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn approved_inputs_bind_all_toolchain_authority_before_creating_local_state() {
    use clap::Parser;
    for mutation in [
        "pin",
        "governance",
        "age",
        "admission",
        "evidence",
        "prose",
        "manifest",
        "signature",
        "certificate",
        "source",
        "exception",
        "missing",
        "symlink",
        "intermediate-link",
        "shadow-pin",
        "self",
    ] {
        let fixture = Fixture::prepared(true);
        let approved = fixture.root.join("approved");
        copy_approved_fixture(&fixture.repo().root, &approved);
        let candidate = fixture.repo().root;
        let id = fixture.id();
        let bundle = format!("docs/dependency-reviews/toolchains/{id}");
        let path = match mutation {
            "pin" => "rust-toolchain.toml".into(),
            "governance" | "age" => "barbican.toml".into(),
            "admission" => "reviewed-targets.toml".into(),
            "evidence" | "missing" | "symlink" => fixture.admission.evidence_record.clone(),
            "prose" => fixture.admission.review_record.clone(),
            "manifest" => format!("{bundle}/manifest.toml"),
            "signature" => format!("{bundle}/manifest.asc"),
            "certificate" => format!("{bundle}/certificate.pgp"),
            "source" => fixture.review.record.evidence.observations[0]
                .snapshot
                .path
                .clone(),
            "exception" => "docs/dependency-reviews/toolchains/exception.md".into(),
            "self" | "intermediate-link" | "shadow-pin" => String::new(),
            _ => unreachable!(),
        };
        if mutation == "shadow-pin" {
            fs::write(candidate.join("rust-toolchain"), b"1.99.1\n").unwrap();
        } else if mutation == "intermediate-link" {
            let relative = "docs/dependency-reviews/toolchains";
            fs::rename(candidate.join(relative), fixture.root.join("retained-tree")).unwrap();
            std::os::unix::fs::symlink(approved.join(relative), candidate.join(relative)).unwrap();
        } else if mutation == "missing" {
            fs::remove_file(candidate.join(&path)).unwrap();
        } else if mutation == "symlink" {
            fs::remove_file(candidate.join(&path)).unwrap();
            std::os::unix::fs::symlink(approved.join(&path), candidate.join(&path)).unwrap();
        } else if mutation != "self" {
            let mut bytes = fs::read(candidate.join(&path)).unwrap();
            if mutation == "governance" {
                bytes =
                    b"[toolchain]\nrequire_admission=false\nadmission_scope='repo-a'\n".to_vec();
            } else if mutation == "age" {
                bytes.extend_from_slice(b"\n[release_age]\nminimum_days=8\n");
            } else if mutation == "admission" {
                bytes = String::from_utf8(bytes)
                    .unwrap()
                    .replace("repo-a", "repo-b")
                    .into_bytes();
            } else {
                bytes.extend_from_slice(b"\nchanged candidate bytes\n");
            }
            fs::write(candidate.join(&path), bytes).unwrap();
        }
        let approved_arg = if mutation == "self" {
            &candidate
        } else {
            &approved
        };
        let record = approved_arg.join(&fixture.admission.review_record);
        let data = fixture.root.join("must-remain-absent");
        let cache = fixture.root.join("cache-must-remain-absent");
        let cli = crate::cli::Cli::try_parse_from([
            "cargo-barbican",
            "--repo",
            candidate.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--cache-dir",
            cache.to_str().unwrap(),
            "toolchain",
            "accept",
            id.as_str(),
            "--approved-repo",
            approved_arg.to_str().unwrap(),
            "--record",
            record.to_str().unwrap(),
        ])
        .unwrap();
        let result = super::frontend::run(
            &cli,
            &fixture.root,
            barbican::OffsetDateTime::from_unix_timestamp(fixture.now).unwrap(),
            &mut Vec::new(),
            false,
        );
        assert!(result.is_err(), "{mutation}");
        assert!(!data.exists(), "{mutation}: {result:?}");
        assert!(!cache.exists(), "{mutation}");
    }
}

#[test]
fn approved_inputs_allow_unrelated_dependency_edits_but_recheck_both_checkouts() {
    let fixture = Fixture::prepared(true);
    let approved = fixture.root.join("approved");
    copy_approved_fixture(&fixture.repo().root, &approved);
    let candidate = fixture.repo().root;
    let mut policy = fs::read_to_string(candidate.join("reviewed-targets.toml")).unwrap();
    policy.push_str("\n[[rust.families]]\nname='other'\nreview_record='docs/other.md'\n[rust.families.resolved]\nserde='1.0.228'\n");
    fs::write(candidate.join("reviewed-targets.toml"), policy).unwrap();
    let capture = || {
        super::approved::ApprovedInputs::capture(
            &fixture.repo(),
            &approved,
            &fixture.id(),
            &approved.join(&fixture.admission.review_record),
        )
    };
    let guard = capture().unwrap();
    guard.recheck().unwrap();
    let original = fs::read(approved.join(&fixture.admission.review_record)).unwrap();
    fs::write(
        approved.join(&fixture.admission.review_record),
        b"changed approval",
    )
    .unwrap();
    assert!(guard.recheck().is_err());
    fs::write(approved.join(&fixture.admission.review_record), &original).unwrap();
    let guard = capture().unwrap();
    fs::write(
        candidate.join(&fixture.admission.review_record),
        b"changed candidate",
    )
    .unwrap();
    assert!(guard.recheck().is_err());
}

#[test]
fn fresh_user_reuses_portable_assessment_and_exact_age_exception_without_rewriting_repo() {
    let fixture = Fixture::new();
    let data = fixture.data("new-user");
    let repo = fixture.repo();
    let before_policy = fs::read(repo.root.join("reviewed-targets.toml")).unwrap();
    let before_evidence = fs::read(repo.root.join(&fixture.admission.evidence_record)).unwrap();
    let id = fixture.id();
    let assessment = acceptance::portable_assessment(&repo, &fixture.review, &id, &fixture.prose)
        .unwrap()
        .unwrap();
    assert_eq!(assessment, fixture.assessment);
    let (accepted, operation) = acceptance::publish_personal(
        &data,
        &id,
        &fixture.review,
        assessment,
        fixture.prose.clone(),
        FreshnessRequest::Cached {
            reason: "explicit disconnected CI test".into(),
        },
        &CurrentKnowledge::default(),
        Some(&repo),
        fixture.now + 60,
    )
    .unwrap();
    assert_eq!(accepted.assessment.assessed_at, fixture.now);
    assert_eq!(accepted.acceptance.accepted_at, fixture.now + 60);
    assert!(operation.age_exception_id.is_some());
    admission::publish_repository(
        &data,
        &fixture.review,
        &accepted,
        &repo,
        FreshnessRequest::Cached {
            reason: "explicit disconnected CI test".into(),
        },
        fixture.now + 60,
    )
    .unwrap();
    assert_eq!(
        fs::read(repo.root.join("reviewed-targets.toml")).unwrap(),
        before_policy
    );
    assert_eq!(
        fs::read(repo.root.join(&fixture.admission.evidence_record)).unwrap(),
        before_evidence
    );
    assert!(data.root().join(format!("acceptances/{id}.json")).exists());
}

#[test]
fn scoped_age_exception_rejects_wrong_scope_expiry_and_missing_prose() {
    for case in ["scope", "expiry", "missing"] {
        let fixture = Fixture::new();
        let data = fixture.data("new-user");
        let now = match case {
            "scope" => {
                write(
                    &fixture.root.join("repo"),
                    "barbican.toml",
                    b"[toolchain]\nrequire_admission=true\nadmission_scope='repo-b'\n",
                );
                fixture.now
            }
            "expiry" => fixture.now + 86_400,
            _ => {
                fs::remove_file(
                    fixture
                        .root
                        .join("repo/docs/dependency-reviews/toolchains/exception.md"),
                )
                .unwrap();
                fixture.now
            }
        };
        let repo = fixture.repo();
        assert!(
            acceptance::publish_personal(
                &data,
                &fixture.id(),
                &fixture.review,
                fixture.assessment.clone(),
                fixture.prose.clone(),
                FreshnessRequest::Cached {
                    reason: "explicit test".into()
                },
                &CurrentKnowledge::default(),
                Some(&repo),
                now
            )
            .is_err(),
            "{case}"
        );
        assert!(
            !data
                .root()
                .join(format!("acceptances/{}.json", fixture.id()))
                .exists()
        );
    }
}

#[test]
fn same_second_source_conflict_is_retained_before_refusal_and_cannot_replay_old_evidence() {
    let mut fixture = Fixture::new();
    let data = fixture.data("knowledge");
    admission::retain_knowledge(&data, &fixture.review, fixture.now).unwrap();
    let original = fixture.review.record.evidence.clone();
    fixture.review.record.evidence.observations[0].coverage_rationale =
        "different successfully fetched scope at the same clock second".into();
    assert!(admission::retain_knowledge(&data, &fixture.review, fixture.now).is_err());
    fixture.review.record.evidence = original;
    let knowledge = admission::knowledge(&data, &fixture.review.subject).unwrap();
    assert!(
        knowledge
            .adverse_subjects
            .contains(fixture.review.subject.id())
    );
    assert!(
        acceptance::publish_personal(
            &data,
            &fixture.id(),
            &fixture.review,
            fixture.assessment.clone(),
            fixture.prose.clone(),
            FreshnessRequest::Cached {
                reason: "must not replay old cached source".into()
            },
            &knowledge,
            Some(&fixture.repo()),
            fixture.now
        )
        .is_err()
    );
    for source in &mut fixture.review.record.evidence.observations {
        source.checked_at += 1;
    }
    admission::retain_knowledge(&data, &fixture.review, fixture.now + 1).unwrap();
    assert!(
        !admission::knowledge(&data, &fixture.review.subject)
            .unwrap()
            .adverse_subjects
            .contains(fixture.review.subject.id())
    );
    fixture.review.record.evidence.observations[0].checked_at += 10;
    assert!(admission::retain_knowledge(&data, &fixture.review, fixture.now + 1).is_err());
}

#[test]
fn independent_explicit_workspace_root_is_not_an_implicit_parent_member() {
    let fixture = Fixture::new();
    let nested = fixture.root.join("repo/nested");
    fs::create_dir(&nested).unwrap();
    write(&nested, "Cargo.toml", b"[workspace]\nmembers=[]\n");
    assert!(RepoContext::capture(&nested).is_ok());
    write(
        &nested,
        "Cargo.toml",
        b"[package]\nname='member'\nversion='0.1.0'\n",
    );
    assert!(RepoContext::capture(&nested).is_err());
}

fn fixture_material() -> super::trust::Material {
    super::trust::Material {
        certificate: include_bytes!(
            "../../tests/fixtures/toolchain-intake/workflow/fixture-public-key.asc"
        )
        .to_vec(),
        fingerprint: "D876DF286C33E94B5CFEA6538E16ED03DD101204".into(),
        purpose: "official-exact-stable-rust-distribution-manifest".into(),
        source: "authored test-only synthetic distribution; never official supplier evidence"
            .into(),
    }
}

#[test]
fn empty_state_cli_import_authenticates_archives_and_preserves_portable_author_assessment() {
    use clap::Parser;
    for tamper in [
        None,
        Some("signature"),
        Some("archive"),
        Some("source"),
        Some("stale"),
    ] {
        let fixture = Fixture::prepared(true);
        let data = fixture.data("empty-ci-data");
        let cache = fixture.data("disposable-ci-cache");
        assert!(!data.root().join("reviews").exists());
        assert!(!data.root().join("acceptances").exists());
        // Explicit local trust setup approves only the authored public test certificate.
        // No review, personal acceptance or installed record is copied from the author.
        let material = fixture_material();
        super::trust::Trust::load(&data, &material, fixture.now).unwrap();
        for archive in &fixture.review.selection.archives {
            let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "tests/fixtures/toolchain-intake/workflow/{}-1.99.1-aarch64-apple-darwin.tar.xz",
                archive.package
            ));
            cache
                .publish(
                    Path::new(&format!("archives/{}", archive.sha256)),
                    &fs::read(source).unwrap(),
                )
                .unwrap();
        }
        let repo = fixture.repo();
        let approved = fixture.root.join("approved");
        copy_approved_fixture(&repo.root, &approved);
        let before = fs::read(repo.root.join("reviewed-targets.toml")).unwrap();
        let evidence_before = fs::read(repo.root.join(&fixture.admission.evidence_record)).unwrap();
        let id = fixture.id();
        let prose = approved.join(&fixture.admission.review_record);
        let cli = crate::cli::Cli::try_parse_from([
            "cargo-barbican",
            "--repo",
            repo.root.to_str().unwrap(),
            "--data-dir",
            data.root().to_str().unwrap(),
            "--cache-dir",
            cache.root().to_str().unwrap(),
            "toolchain",
            "accept",
            id.as_str(),
            "--approved-repo",
            approved.to_str().unwrap(),
            "--record",
            prose.to_str().unwrap(),
            "--cached-admission",
            "--cache-reason",
            "explicit isolated test CI import",
            "--format",
            "json",
        ])
        .unwrap();
        if let Some(tamper) = tamper.filter(|value| *value != "stale") {
            let path = match tamper {
                "signature" => repo.root.join(format!(
                    "docs/dependency-reviews/toolchains/{id}/manifest.asc"
                )),
                "archive" => cache.root().join(format!(
                    "archives/{}",
                    fixture.review.selection.archives[0].sha256
                )),
                _ => repo
                    .root
                    .join(&fixture.review.record.evidence.observations[0].snapshot.path),
            };
            fs::write(path, b"tampered independently supplied input").unwrap();
        }
        let mut output = Vec::new();
        let now = fixture.now + if tamper == Some("stale") { 86_401 } else { 60 };
        let result = super::frontend::run(
            &cli,
            &fixture.root,
            barbican::OffsetDateTime::from_unix_timestamp(now).unwrap(),
            &mut output,
            false,
        );
        if let Some(tamper) = tamper {
            assert!(result.is_err(), "{tamper}");
            assert!(!data.root().join(format!("acceptances/{id}.json")).exists());
            assert_eq!(
                fs::read(repo.root.join("reviewed-targets.toml")).unwrap(),
                before
            );
            continue;
        }
        assert_eq!(result.unwrap(), std::process::ExitCode::SUCCESS);
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["accepted_at"], now);
        assert_eq!(
            result["eligibility"]["eligibility"]["mode"],
            "explicit-cached"
        );
        let accepted: acceptance::AcceptanceRecord = parse_record(
            data.read(
                Path::new(&format!("acceptances/{id}.json")),
                MAX_RECORD_BYTES as u64,
            )
            .unwrap()
            .bytes(),
        )
        .unwrap();
        assert_eq!(accepted.assessment.assessed_at, fixture.now);
        assert_eq!(accepted.acceptance.accepted_at, now);
        assert_eq!(
            fs::read(repo.root.join("reviewed-targets.toml")).unwrap(),
            before
        );
        assert_eq!(
            fs::read(repo.root.join(&fixture.admission.evidence_record)).unwrap(),
            evidence_before
        );
        assert!(data.root().join(format!("reviews/{id}.json")).exists());
        // The retained archive is independently owned; candidate bytes are never run.
        use std::os::unix::fs::MetadataExt;
        let archive = &fixture.review.selection.archives[0];
        let relative = format!("archives/{}", archive.sha256);
        assert_ne!(
            fs::metadata(data.root().join(&relative)).unwrap().ino(),
            fs::metadata(cache.root().join(relative)).unwrap().ino()
        );
    }
}

#[test]
fn standalone_age_override_is_explicit_on_every_operation_not_a_saved_waiver() {
    use clap::Parser;
    for days in [7, 14, 0] {
        let mut fixture = Fixture::prepared(true);
        let old_id = fixture.id();
        let old_policy = fixture.review.record.policy.id().unwrap();
        fixture.review.record.policy = super::review::invocation_policy(None, Some(days)).unwrap();
        let id = fixture.id();
        fixture.prose = String::from_utf8(fixture.prose.clone())
            .unwrap()
            .replace(old_id.as_str(), id.as_str())
            .replace(
                old_policy.as_str(),
                fixture.review.record.policy.id().unwrap().as_str(),
            )
            .into_bytes();
        let data = fixture.data("standalone-data");
        let cache = fixture.data("standalone-cache");
        super::trust::Trust::load(&data, &fixture_material(), fixture.now).unwrap();
        let source_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/toolchain-intake/workflow");
        for (name, source) in [
            ("manifest.toml", "channel-rust-1.99.1.toml"),
            ("manifest.asc", "channel-rust-1.99.1.toml.asc"),
            ("certificate.pgp", "fixture-public-key.asc"),
        ] {
            data.publish(
                &Path::new(&fixture.review.record.snapshot_root).join(name),
                &fs::read(source_root.join(source)).unwrap(),
            )
            .unwrap();
        }
        for archive in &fixture.review.selection.archives {
            data.publish(
                Path::new(&format!("archives/{}", archive.sha256)),
                &fs::read(source_root.join(format!(
                    "{}-1.99.1-aarch64-apple-darwin.tar.xz",
                    archive.package
                )))
                .unwrap(),
            )
            .unwrap();
        }
        for (path, bytes) in &fixture.review.source_snapshots {
            data.publish(
                &Path::new(&fixture.review.record.snapshot_root).join(path),
                bytes,
            )
            .unwrap();
        }
        data.publish(
            Path::new(&format!("reviews/{id}.json")),
            &serde_json::to_vec(&fixture.review.record).unwrap(),
        )
        .unwrap();
        let prose_path = fixture.root.join("completed.md");
        fs::write(&prose_path, &fixture.prose).unwrap();
        let base = vec![
            "cargo-barbican".to_owned(),
            "--data-dir".into(),
            data.root().to_str().unwrap().into(),
            "--cache-dir".into(),
            cache.root().to_str().unwrap().into(),
            "toolchain".into(),
            "accept".into(),
            id.to_string(),
            "--standalone".into(),
            "--record".into(),
            prose_path.to_str().unwrap().into(),
            "--cached-admission".into(),
            "--cache-reason".into(),
            "explicit policy test".into(),
        ];
        let now = fixture.now + 60;
        let cli = crate::cli::Cli::try_parse_from(&base).unwrap();
        let error = super::frontend::run(
            &cli,
            &fixture.root,
            barbican::OffsetDateTime::from_unix_timestamp(now).unwrap(),
            &mut Vec::new(),
            false,
        )
        .unwrap_err();
        assert!(error.contains("current operation policy"), "{error}");
        assert!(!data.root().join(format!("acceptances/{id}.json")).exists());
        let mut repeated = base;
        repeated.extend(["--min-age-days".into(), days.to_string()]);
        let cli = crate::cli::Cli::try_parse_from(&repeated).unwrap();
        super::frontend::run(
            &cli,
            &fixture.root,
            barbican::OffsetDateTime::from_unix_timestamp(now).unwrap(),
            &mut Vec::new(),
            false,
        )
        .unwrap();
        let freshness = FreshnessRequest::Cached {
            reason: "explicit policy test installation eligibility".into(),
        };
        assert!(
            admission::AcceptedContext::load(
                &data,
                id.clone(),
                None,
                super::review::invocation_policy(None, None).unwrap(),
                freshness.clone(),
                now
            )
            .is_err()
        );
        let context = admission::AcceptedContext::load(
            &data,
            id,
            None,
            super::review::invocation_policy(None, Some(days)).unwrap(),
            freshness,
            now,
        )
        .unwrap();
        context
            .recheck_before_effects(EligibilityPurpose::Installation, None, now)
            .unwrap();
        assert!(super::review::invocation_policy(Some(&fixture.repo()), Some(days)).is_err());
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn observed_signal_during_context_install_preserves_binding_and_intent_history() {
    use clap::Parser;
    use std::sync::atomic::AtomicBool;
    const CHILD: &str = "BARBICAN_CONTEXT_SIGNAL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "toolchain_intake::workflow_tests::observed_signal_during_context_install_preserves_binding_and_intent_history", "--nocapture"])
            .env(CHILD, "1")
            .env_remove("RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS")
            .env_remove("RUSTUP_DIST_SERVER")
            .env_remove("RUSTUP_UPDATE_ROOT")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let cancellation = super::installation::NativeCancellation::install().unwrap();
    let evaluator = PathBuf::from(
        std::env::var_os("BARBICAN_TEST_RUSTUP").expect("explicit reviewed evaluator"),
    );
    for signal in ["-INT", "-TERM"] {
        for existing in [false, true] {
            cancellation.flag().store(false, Ordering::SeqCst);
            let now = barbican::OffsetDateTime::now_utc().unix_timestamp();
            let fixture = Fixture::prepared_at(true, Some(now));
            let data = fixture.data("signal-data");
            let cache = fixture.data("signal-cache");
            super::trust::Trust::load(&data, &fixture_material(), now).unwrap();
            for archive in &fixture.review.selection.archives {
                let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/toolchain-intake/workflow/{}-1.99.1-aarch64-apple-darwin.tar.xz", archive.package));
                cache
                    .publish(
                        Path::new(&format!("archives/{}", archive.sha256)),
                        &fs::read(source).unwrap(),
                    )
                    .unwrap();
            }
            let repo = fixture.repo();
            let id = fixture.id();
            let prose = repo.root.join(&fixture.admission.review_record);
            let cli = crate::cli::Cli::try_parse_from([
                "cargo-barbican",
                "--repo",
                repo.root.to_str().unwrap(),
                "--data-dir",
                data.root().to_str().unwrap(),
                "--cache-dir",
                cache.root().to_str().unwrap(),
                "toolchain",
                "accept",
                id.as_str(),
                "--record",
                prose.to_str().unwrap(),
                "--cached-admission",
                "--cache-reason",
                "authored context cancellation control",
            ])
            .unwrap();
            super::frontend::run(
                &cli,
                &fixture.root,
                barbican::OffsetDateTime::from_unix_timestamp(now).unwrap(),
                &mut Vec::new(),
                false,
            )
            .unwrap();
            let context = admission::AcceptedContext::load(
                &data,
                id,
                Some(fixture.repo()),
                fixture.review.record.policy.clone(),
                FreshnessRequest::Cached {
                    reason: "authored context cancellation control".into(),
                },
                now,
            )
            .unwrap();
            let home = fixture.root.join("rustup");
            let pin_before = fs::read(repo.root.join("rust-toolchain.toml")).unwrap();
            let binding = data.root().join(format!(
                "continuing/{}/{}.json",
                admission::consumer_id(&repo).unwrap(),
                fixture.review.subject.id()
            ));
            if existing {
                context
                    .install(
                        &home,
                        &evaluator,
                        super::installation::InstallMode::Install {
                            allow_initial_default: true,
                        },
                        &AtomicBool::new(false),
                        now,
                    )
                    .unwrap();
                assert!(binding.is_file());
            }
            let before = fs::read(&binding).ok();
            super::installation::VERIFICATION_CHECKPOINT.with(|checkpoint| {
                *checkpoint.borrow_mut() = Some(Box::new(move || {
                    assert!(
                        std::process::Command::new("/bin/kill")
                            .args([signal, &std::process::id().to_string()])
                            .status()
                            .unwrap()
                            .success()
                    );
                }));
            });
            let result = context.install(
                &home,
                &evaluator,
                super::installation::InstallMode::Install {
                    allow_initial_default: true,
                },
                cancellation.flag(),
                now,
            );
            let error = result
                .err()
                .expect("observed cancellation must suppress installed-verified outcome");
            assert!(
                cancellation.flag().load(Ordering::SeqCst),
                "verification checkpoint not reached: {error}"
            );
            assert!(
                error.contains("cancelled during installed verification"),
                "{error}"
            );
            assert_eq!(fs::read(&binding).ok(), before);
            assert!(
                home.join("toolchains/1.99.1-aarch64-apple-darwin/bin/rustc")
                    .is_file()
            );
            assert_eq!(
                fs::read(repo.root.join("rust-toolchain.toml")).unwrap(),
                pin_before
            );
            assert!(data.root().join("operations").is_dir());
        }
    }
}
