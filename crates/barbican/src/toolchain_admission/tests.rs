use super::*;
use crate::rust_distribution::*;
use std::collections::{BTreeMap, BTreeSet};

fn fixture_inputs(
    metadata: &[u8],
) -> (
    Manifest,
    SelectionRequest,
    AuthenticationIdentity,
    Vec<ArchiveInventory>,
) {
    fixture_inputs_for(metadata, Profile::Minimal, false)
}

fn fixture_inputs_for(
    metadata: &[u8],
    profile: Profile,
    docs: bool,
) -> (
    Manifest,
    SelectionRequest,
    AuthenticationIdentity,
    Vec<ArchiveInventory>,
) {
    let host = "aarch64-apple-darwin";
    let mut packages = vec!["rustc", "cargo", "rust-std"];
    if docs {
        packages.push("rust-docs");
    }
    let mut raw = format!(
        "manifest-version = '2'\ndate = '2026-01-01'\n[profiles]\nminimal = ['rustc','cargo','rust-std']\ndefault = ['rustc','cargo','rust-std']\n[pkg.rust]\nversion = '1.99.1 (abc 2026-01-01)'\n[pkg.rust.target.{host}]\navailable = true\ncomponents = ["
    );
    for package in &packages {
        raw.push_str(&format!("{{pkg='{package}',target='{host}'}},"));
    }
    raw.push_str("]\n");
    for package in &packages {
        raw.push_str(&format!("[pkg.{package}]\nversion='1.99.1 (abc 2026-01-01)'\n[pkg.{package}.target.{host}]\navailable=true\nxz_url='https://static.rust-lang.org/dist/2026-01-01/{package}-1.99.1-{host}.tar.xz'\nxz_hash='{}'\n", "a".repeat(64)));
    }
    let manifest = Manifest::parse(raw.as_bytes(), "1.99.1").unwrap();
    let request = SelectionRequest {
        host: host.into(),
        profile,
        components: if docs {
            vec!["rust-docs".into()]
        } else {
            vec![]
        },
        targets: vec![],
        encoding: Encoding::Xz,
    };
    let inventories = manifest
        .select(&request)
        .unwrap()
        .archives
        .into_iter()
        .map(|identity| {
            let texts = BTreeMap::from([
                ("components".to_owned(), format!("{}\n", identity.component)),
                ("rust-installer-version".to_owned(), "3\n".to_owned()),
                (
                    format!("{}/manifest.in", identity.component),
                    std::str::from_utf8(metadata).unwrap().to_owned(),
                ),
            ]);
            ArchiveInventory {
                payload: BTreeMap::from([(
                    format!("bin/{}", identity.package),
                    ExpectedEntry {
                        kind: EntryKind::File {
                            size: 3,
                            sha256: digest_bytes(b"bin"),
                        },
                        mode: 0o755,
                    },
                )]),
                package_metadata: texts
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
                    .collect(),
                installer_metadata: texts,
                identity,
                expanded_bytes: 4096,
                physical_headers: 5,
                effective_entries: 5,
            }
        })
        .collect();
    let authentication = AuthenticationIdentity {
        manifest_sha256: manifest.sha256(),
        signature_sha256: digest_bytes(b"signature"),
        certificate_sha256: digest_bytes(b"certificate"),
        primary_fingerprint: "A".repeat(40),
        signing_fingerprint: "B".repeat(40),
        verification_policy_sha256: digest_bytes(b"current verifier policy"),
    };
    (manifest, request, authentication, inventories)
}
fn fixture_subject(metadata: &[u8]) -> Subject {
    let (manifest, request, authentication, inventories) = fixture_inputs(metadata);
    Subject::reconstruct(&manifest, &request, authentication, inventories).unwrap()
}

struct Fixture {
    subject: Subject,
    evidence: EvidenceRecord,
    policy: EffectivePolicy,
    assessment: HumanAssessment,
    acceptance: PersonalAcceptance,
    admission: ReviewedToolchainAdmission,
    portable: Vec<u8>,
    installed: InstalledCorrespondence,
    binding: ContinuingUseBinding,
    knowledge: CurrentKnowledge,
    snapshots: BTreeMap<String, Vec<u8>>,
    now: i64,
    review: Vec<u8>,
    consumer: crate::Sha256Digest,
}
impl Fixture {
    fn new() -> Self {
        let subject = fixture_subject(b"file:bin/tool\n");
        let now = crate::parse_iso_date("2026-01-10")
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp();
        let observations: Vec<_> = required_sources(&subject)
            .into_iter()
            .map(|source| SourceObservation {
                source,
                location: "https://example.test/official-snapshot".into(),
                provenance: "official authenticated metadata and exact source revision".into(),
                revision: "revision-1".into(),
                content_sha256: digest_bytes(b"source snapshot"),
                snapshot: RecordReference {
                    path: "docs/dependency-reviews/toolchains/sources/source.txt".into(),
                    sha256: digest_bytes(b"source snapshot"),
                },
                status: CollectionStatus::Completed,
                coverage: Coverage::ResidualUnknown,
                coverage_rationale:
                    "Reachability and completeness are not proven; reviewer assesses this limit"
                        .into(),
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
                authenticated_manifest_day: "2026-01-01".into(),
                corroborated_days: vec!["2026-01-01".into()],
                source: SourceId {
                    kind: SourceKind::Publication,
                    scope: "distribution".into(),
                },
                source_content_sha256: digest_bytes(b"source snapshot"),
            },
            observations,
            findings: vec![],
        };
        let policy = EffectivePolicy {
            schema_version: 1,
            minimum_days: 7,
            override_reason: None,
        };
        let review = b"# Completed review\nI assessed the exact inputs, source coverage gaps and supplier risk.\n".to_vec();
        let assessment = HumanAssessment {
            schema_version: 1,
            subject_id: subject.id().clone(),
            evidence_id: evidence.content_id(&subject).unwrap(),
            policy_id: policy.id().unwrap(),
            review: RecordReference {
                path: "docs/dependency-reviews/toolchain.md".into(),
                sha256: digest_bytes(&review),
            },
            assessed_at: now,
            assessed_unknowns: evidence.residual_unknowns(),
            assessed_findings: BTreeSet::new(),
        };
        let acceptance = PersonalAcceptance {
            schema_version: 1,
            subject_id: subject.id().clone(),
            assessment_id: assessment.id().unwrap(),
            accepted_at: now,
        };
        let portable = serde_json::to_vec(&PortableReview {
            schema_version: 1,
            subject: subject.record().clone(),
            evidence: evidence.clone(),
            policy: policy.clone(),
            assessment: assessment.clone(),
        })
        .unwrap();
        let admission = ReviewedToolchainAdmission {
            schema_version: 1,
            subject_id: subject.id().clone(),
            policy_id: policy.id().unwrap(),
            assessment_id: assessment.id().unwrap(),
            scope: "repo-a".into(),
            review_record: assessment.review.path.clone(),
            review_record_sha256: assessment.review.sha256.clone(),
            evidence_record: "docs/dependency-reviews/toolchain.json".into(),
            evidence_record_sha256: digest_bytes(&portable),
            review_by: None,
            age_exception: None,
        };
        let installed = InstalledCorrespondence {
            subject_id: subject.id().clone(),
            mapping_sha256: subject.record().mapping_sha256.clone(),
            installation_id: digest_bytes(b"local installation root identity"),
        };
        let consumer = digest_bytes(b"local repo root identity");
        let binding = ContinuingUseBinding {
            schema_version: 1,
            subject_id: subject.id().clone(),
            admission_id: admission.id().unwrap(),
            consumer_context_id: consumer.clone(),
            installation_id: installed.installation_id.clone(),
        };
        Self {
            subject,
            evidence,
            policy,
            assessment,
            acceptance,
            admission,
            portable,
            installed,
            binding,
            knowledge: CurrentKnowledge::default(),
            snapshots: BTreeMap::from([(
                "docs/dependency-reviews/toolchains/sources/source.txt".into(),
                b"source snapshot".to_vec(),
            )]),
            now,
            review,
            consumer,
        }
    }
    fn input(
        &self,
        purpose: EligibilityPurpose,
        freshness: FreshnessRequest,
    ) -> EligibilityInput<'_> {
        EligibilityInput {
            purpose,
            subject: &self.subject,
            evidence: &self.evidence,
            source_snapshots: &self.snapshots,
            policy: &self.policy,
            assessment: &self.assessment,
            review_bytes: &self.review,
            personal: Some(PersonalApproval {
                acceptance: &self.acceptance,
                assessment: &self.assessment,
                review_bytes: &self.review,
            }),
            repository: Some(RepositoryContext {
                scope: "repo-a",
                consumer_context_id: &self.consumer,
                admission: &self.admission,
                evidence_bytes: &self.portable,
                exception_review_bytes: Some(&self.review),
                continuing: Some(&self.binding),
            }),
            installed: Some(&self.installed),
            knowledge: &self.knowledge,
            freshness,
            now: self.now,
        }
    }
    fn rebind(&mut self) {
        self.assessment.evidence_id = self.evidence.content_id(&self.subject).unwrap();
        self.assessment.policy_id = self.policy.id().unwrap();
        self.assessment.assessed_unknowns = self.evidence.residual_unknowns();
        self.assessment.assessed_findings = self
            .evidence
            .findings
            .iter()
            .map(|f| f.id.clone())
            .collect();
        self.acceptance.assessment_id = self.assessment.id().unwrap();
        self.portable = serde_json::to_vec(&PortableReview {
            schema_version: 1,
            subject: self.subject.record().clone(),
            evidence: self.evidence.clone(),
            policy: self.policy.clone(),
            assessment: self.assessment.clone(),
        })
        .unwrap();
        self.admission.policy_id = self.policy.id().unwrap();
        self.admission.assessment_id = self.assessment.id().unwrap();
        self.admission.evidence_record_sha256 = digest_bytes(&self.portable);
        self.binding.admission_id = self.admission.id().unwrap();
    }
}

#[test]
fn cached_48_hours_allows_only_same_admitted_local_use_and_activation() {
    let mut f = Fixture::new();
    f.now += 48 * 3600;
    for purpose in [
        EligibilityPurpose::ContinuingUse,
        EligibilityPurpose::Activation,
    ] {
        assert_eq!(
            evaluate_eligibility(f.input(purpose, FreshnessRequest::Local))
                .unwrap()
                .mode,
            EligibilityMode::ContinuingLocal
        );
    }
    for purpose in [
        EligibilityPurpose::Installation,
        EligibilityPurpose::FirstAdoption,
        EligibilityPurpose::RepositoryAdmission,
        EligibilityPurpose::PersonalAcceptance,
    ] {
        assert!(
            evaluate_eligibility(f.input(
                purpose,
                FreshnessRequest::Cached {
                    reason: "disconnected".into()
                }
            ))
            .is_err()
        );
    }
    f.consumer = digest_bytes(b"different repo root");
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::Activation, FreshnessRequest::Local))
            .is_err()
    );
}

#[test]
fn cache_boundary_oldest_source_earlier_expiry_and_online_operation() {
    let mut f = Fixture::new();
    f.now += 86400;
    let cached = || FreshnessRequest::Cached {
        reason: "explicit disconnected operation".into(),
    };
    assert!(evaluate_eligibility(f.input(EligibilityPurpose::Installation, cached())).is_ok());
    f.now += 1;
    assert!(evaluate_eligibility(f.input(EligibilityPurpose::Installation, cached())).is_err());
    f.now -= 1;
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
    for source in &mut f.evidence.observations {
        source.checked_at = f.now;
    }
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_ok()
    );
    f.evidence.observations[0].expires_at = Some(f.now + 1);
    f.rebind();
    f.now += 1;
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
}

#[test]
fn refresh_does_not_reapprove_and_new_source_content_cannot_reuse_assessment() {
    let mut f = Fixture::new();
    let acceptance = f.acceptance.id().unwrap();
    let evidence = f.evidence.content_id(&f.subject).unwrap();
    f.now += 3600;
    for observation in &mut f.evidence.observations {
        observation.checked_at = f.now;
    }
    assert_eq!(f.evidence.content_id(&f.subject).unwrap(), evidence);
    assert_eq!(f.acceptance.id().unwrap(), acceptance);
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_ok()
    );
    f.evidence.observations[0].revision = "new-content-revision".into();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
}

#[test]
fn required_source_identity_and_completion_cannot_be_replaced_by_unknown_coverage() {
    let mut f = Fixture::new();
    assert!(f.evidence.content_id(&f.subject).is_ok());
    let original = f.evidence.observations[0].clone();
    for status in [
        CollectionStatus::Missing,
        CollectionStatus::Failed,
        CollectionStatus::Inapplicable,
    ] {
        f.evidence.observations[0].status = status;
        assert!(f.evidence.content_id(&f.subject).is_err());
    }
    f.evidence.observations[0] = original.clone();
    f.evidence.observations[0].source.scope = "unrelated-host".into();
    assert!(f.evidence.content_id(&f.subject).is_err());
    f.evidence.observations[0] = original;
    f.evidence
        .observations
        .push(f.evidence.observations[0].clone());
    assert!(f.evidence.content_id(&f.subject).is_err());
}

#[test]
fn advisory_clearance_cannot_precede_component_identity_and_required_sources_are_applicable() {
    let mut f = Fixture::new();
    let advisory = f
        .evidence
        .observations
        .iter()
        .position(|o| o.source.kind == SourceKind::Advisories)
        .unwrap();
    f.evidence.observations[advisory].coverage = Coverage::Covered;
    assert!(f.evidence.content_id(&f.subject).is_err());
    f.evidence.observations[advisory].coverage = Coverage::ResidualUnknown;
    let publication = f
        .evidence
        .observations
        .iter_mut()
        .find(|o| o.source.kind == SourceKind::Publication)
        .unwrap();
    publication.coverage = Coverage::NotApplicable;
    assert!(f.evidence.content_id(&f.subject).is_err());
}

#[test]
fn dates_are_exact_subject_conservative_and_future_or_inconsistent_refuse() {
    let f = Fixture::new();
    let mut publication = f.evidence.publication.clone();
    let jan2 = crate::parse_iso_date("2026-01-02")
        .unwrap()
        .midnight()
        .assume_utc()
        .unix_timestamp();
    assert_eq!(publication.maturity_start(&f.subject, f.now).unwrap(), jan2);
    publication.corroborated_days.push("2026-01-03".into());
    assert_eq!(
        publication.maturity_start(&f.subject, f.now).unwrap(),
        jan2 + 2 * 86400
    );
    publication.corroborated_days = vec!["2025-12-31".into()];
    assert!(publication.maturity_start(&f.subject, f.now).is_err());
    publication.corroborated_days = vec!["2026-01-11".into()];
    assert!(publication.maturity_start(&f.subject, f.now).is_err());
    publication.corroborated_days.clear();
    assert!(publication.maturity_start(&f.subject, f.now).is_err());
    publication = f.evidence.publication.clone();
    publication.subject_id = digest_bytes(b"same label, changed bytes");
    assert!(publication.maturity_start(&f.subject, f.now).is_err());
}

#[test]
fn stricter_repo_policy_requires_its_own_assessment_and_exact_finite_age_exception() {
    let mut f = Fixture::new();
    f.policy.minimum_days = 30;
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
    f.rebind();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
    f.admission.age_exception = Some(ToolchainAgeException {
        subject_id: f.subject.id().clone(),
        policy_id: f.policy.id().unwrap(),
        scope: "repo-a".into(),
        review: f.assessment.review.clone(),
        expires_at: f.now + 60,
    });
    f.binding.admission_id = f.admission.id().unwrap();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .unwrap()
        .age_exception_id
        .is_some()
    );
    f.admission.age_exception.as_mut().unwrap().scope = "repo-b".into();
    assert!(f.admission.validate().is_err());
    f.admission.age_exception.as_mut().unwrap().scope = "repo-a".into();
    f.now += 60;
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
}

#[test]
fn optional_deadline_prose_and_current_installed_bytes_always_apply() {
    let mut f = Fixture::new();
    f.admission.review_by = Some("2026-01-10".into());
    f.binding.admission_id = f.admission.id().unwrap();
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_ok()
    );
    f.now += 86400;
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    f.admission.review_by = None;
    f.binding.admission_id = f.admission.id().unwrap();
    f.installed.mapping_sha256 = digest_bytes(b"tampered installed tree");
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    f.installed.mapping_sha256 = f.subject.record().mapping_sha256.clone();
    f.review.push(b'!');
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
}

#[test]
fn adverse_knowledge_and_observation_rollback_block_even_continuing_use() {
    let mut f = Fixture::new();
    f.knowledge.adverse_signers.insert("A".repeat(40));
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    f.knowledge.adverse_signers.clear();
    f.knowledge
        .source_checks
        .insert(f.evidence.observations[0].source.clone(), f.now + 1);
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    f.knowledge.source_checks.clear();
    f.evidence.observations[0].checked_at = f.now + 1;
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
}

#[test]
fn same_second_source_content_or_provenance_cannot_roll_back() {
    let mut f = Fixture::new();
    let mut newer = f.evidence.observations[0].clone();
    newer.revision = "different revision observed in same second".into();
    f.knowledge
        .source_checks
        .insert(newer.source.clone(), newer.checked_at);
    f.knowledge
        .source_contents
        .insert(newer.source.clone(), newer.content_id().unwrap());
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    f.knowledge.source_contents.insert(
        newer.source.clone(),
        f.evidence.observations[0].content_id().unwrap(),
    );
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_ok()
    );
    f.knowledge.source_contents.clear();
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
}

#[test]
fn findings_and_unknowns_need_explicit_assessment_and_known_adverse_cannot_be_waived() {
    let mut f = Fixture::new();
    f.assessment.assessed_unknowns.clear();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::PersonalAcceptance,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
    f.evidence.findings.push(Finding {
        id: "upstream-issue-1".into(),
        source: f.evidence.observations[0].source.clone(),
        change: FindingChange::PreExisting,
        exposure: Exposure::Unknown,
        rationale: "reachability not established".into(),
    });
    f.rebind();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_ok()
    );
    f.evidence.findings[0].exposure = Exposure::Known;
    f.rebind();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
    f.evidence.findings[0].change = FindingChange::Resolved;
    f.rebind();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_ok()
    );
}

#[test]
fn subject_and_metadata_mapping_tamper_cannot_use_stored_commitment() {
    let a = fixture_subject(b"metadata-a");
    let b = fixture_subject(b"metadata-b");
    assert_ne!(a.id(), b.id());
    assert_ne!(a.record().mapping_sha256, b.record().mapping_sha256);
    assert!(a.record().validate_against(&b).is_err());
    let mut record = a.record().clone();
    record.archives[0].url = "https://attacker.test/archive.tar.xz".into();
    assert!(record.validate_against(&a).is_err());
}

#[test]
fn strict_records_portable_paths_and_pending_prose_fail_closed() {
    let f = Fixture::new();
    let mut json = serde_json::to_value(&f.admission).unwrap();
    json["cache_default"] = serde_json::json!(true);
    assert!(
        parse_record::<ReviewedToolchainAdmission>(&serde_json::to_vec(&json).unwrap()).is_err()
    );
    for path in [
        "/private/review.md",
        "../review.md",
        "docs/../review.md",
        "C:\\review.md",
        "docs//review.md",
        "docs/./review.md",
    ] {
        assert!(
            RecordReference {
                path: path.into(),
                sha256: digest_bytes(b"x")
            }
            .validate()
            .is_err()
        );
    }
    let pending = b"# Review\nBARBICAN-REVIEW-PENDING\n";
    assert!(
        RecordReference {
            path: "docs/review.md".into(),
            sha256: digest_bytes(pending)
        }
        .verify_completed(pending)
        .is_err()
    );
    let mut json = serde_json::to_value(&f.acceptance).unwrap();
    json["subject_id"] = serde_json::json!("not-a-digest");
    assert!(parse_record::<PersonalAcceptance>(&serde_json::to_vec(&json).unwrap()).is_err());
}

#[test]
fn toolchain_schema_does_not_supply_crate_families_and_config_is_explicit() {
    let f = Fixture::new();
    let text = format!(
        "[[rust.toolchains]]\n{}",
        toml::to_string(&f.admission).unwrap()
    );
    let parsed = crate::parse_reviewed_targets_toml(&text).unwrap();
    assert_eq!(parsed.rust_toolchains().len(), 1);
    assert!(parsed.rust_families().is_empty());
    assert!(crate::parse_reviewed_targets_toml(&(text.clone() + &text)).is_err());
    assert!(crate::parse_reviewed_targets_toml(&(text + "unknown_mode=true\n")).is_err());
    assert!(
        !crate::BarbicanConfig::from_toml_str("")
            .unwrap()
            .toolchain
            .require_admission
    );
    assert!(
        crate::BarbicanConfig::from_toml_str("[toolchain]\nrequire_admission=true")
            .unwrap()
            .toolchain
            .require_admission
    );
    assert!(crate::BarbicanConfig::from_toml_str("[toolchain]\ncached=true").is_err());
    assert_eq!(
        crate::BarbicanConfig::from_toml_str("[toolchain]\nadmission_scope='repository-a'")
            .unwrap()
            .toolchain
            .admission_scope
            .as_deref(),
        Some("repository-a")
    );
    for value in ["''", "'   '", "\"line\\ncontrol\""] {
        assert!(
            crate::BarbicanConfig::from_toml_str(&format!("[toolchain]\nadmission_scope={value}"))
                .is_err()
        );
    }
}

#[test]
fn subject_constructor_requires_full_authenticated_inventory_and_metadata_bytes() {
    let (manifest, request, auth, inventories) = fixture_inputs(b"file:bin/tool\n");
    let good =
        Subject::reconstruct(&manifest, &request, auth.clone(), inventories.clone()).unwrap();
    let mut reordered = inventories.clone();
    reordered.reverse();
    assert_eq!(
        good.id(),
        Subject::reconstruct(&manifest, &request, auth.clone(), reordered)
            .unwrap()
            .id()
    );
    let mut incomplete = inventories.clone();
    incomplete.pop();
    assert!(Subject::reconstruct(&manifest, &request, auth.clone(), incomplete).is_err());
    let mut duplicate = inventories.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(Subject::reconstruct(&manifest, &request, auth.clone(), duplicate).is_err());
    let mut tampered = inventories.clone();
    tampered[0].identity.sha256 = digest_bytes(b"other archive");
    assert!(Subject::reconstruct(&manifest, &request, auth.clone(), tampered).is_err());
    let mut tampered = inventories.clone();
    tampered[0]
        .installer_metadata
        .insert("components".into(), "other-component\n".into());
    assert!(Subject::reconstruct(&manifest, &request, auth.clone(), tampered).is_err());
    let mut wrong = auth;
    wrong.manifest_sha256 = digest_bytes(b"other original manifest");
    assert!(Subject::reconstruct(&manifest, &request, wrong, inventories).is_err());
}

#[test]
fn bounded_stream_digest_and_record_parser_observe_actual_byte_limits() {
    let bytes = vec![0x31; 65537];
    assert_eq!(
        digest_reader(bytes.as_slice(), bytes.len() as u64).unwrap(),
        (digest_bytes(&bytes), bytes.len() as u64)
    );
    assert!(digest_reader(bytes.as_slice(), 65536).is_err());
    assert!(digest_reader(&b"x"[..], 0).is_err());
    assert_eq!(digest_reader(&b""[..], 0).unwrap(), (digest_bytes(b""), 0));
    assert!(parse_record::<PersonalAcceptance>(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
}

#[test]
fn required_snapshot_tamper_or_absence_blocks_cached_and_continuing_operations() {
    let mut f = Fixture::new();
    let path = f.evidence.observations[0].snapshot.path.clone();
    f.snapshots.get_mut(&path).unwrap().push(b'!');
    assert!(
        evaluate_eligibility(f.input(EligibilityPurpose::ContinuingUse, FreshnessRequest::Local))
            .is_err()
    );
    f.snapshots.clear();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Cached {
                reason: "disconnected".into()
            }
        ))
        .is_err()
    );
}

#[test]
fn original_personal_approval_survives_a_separate_current_repo_assessment() {
    let mut f = Fixture::new();
    let original_assessment = f.assessment.clone();
    let original_acceptance = f.acceptance.clone();
    let original_id = original_acceptance.id().unwrap();
    f.now += 30 * 86400;
    for source in &mut f.evidence.observations {
        source.checked_at = f.now;
    }
    f.policy.minimum_days = 30;
    f.assessment.assessed_at = f.now;
    f.rebind();
    let mut input = f.input(
        EligibilityPurpose::RepositoryAdmission,
        FreshnessRequest::Online {
            operation_started_at: f.now,
        },
    );
    input.personal = Some(PersonalApproval {
        acceptance: &original_acceptance,
        assessment: &original_assessment,
        review_bytes: &f.review,
    });
    assert!(evaluate_eligibility(input).is_ok());
    assert_eq!(original_acceptance.id().unwrap(), original_id);
    assert!(original_acceptance.accepted_at < f.now);
    let mut input = f.input(
        EligibilityPurpose::RepositoryAdmission,
        FreshnessRequest::Online {
            operation_started_at: f.now,
        },
    );
    input.personal = Some(PersonalApproval {
        acceptance: &original_acceptance,
        assessment: &original_assessment,
        review_bytes: &f.review,
    });
    input.repository.as_mut().unwrap().scope = "unrelated-repo";
    assert!(evaluate_eligibility(input).is_err());
}

#[test]
fn portable_repo_review_does_not_impersonate_a_new_users_local_acceptance() {
    let mut f = Fixture::new();
    let portable_id = f.admission.id().unwrap();
    let old_acceptance = f.acceptance.id().unwrap();
    f.now += 3600;
    for source in &mut f.evidence.observations {
        source.checked_at = f.now;
    }
    f.acceptance.accepted_at = f.now;
    assert_ne!(old_acceptance, f.acceptance.id().unwrap());
    assert_eq!(portable_id, f.admission.id().unwrap());
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::RepositoryAdmission,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_ok()
    );
    let mut input = f.input(
        EligibilityPurpose::RepositoryAdmission,
        FreshnessRequest::Online {
            operation_started_at: f.now,
        },
    );
    input.personal = None;
    assert!(evaluate_eligibility(input).is_err());
}

#[test]
fn advertised_source_and_preferred_encoding_are_exposed_without_inferred_identity() {
    let (manifest, request, _, _) = fixture_inputs(b"file:bin/tool\n");
    let original = std::str::from_utf8(manifest.original_bytes()).unwrap();
    let changed = original
        .replace(
            "[pkg.cargo]\n",
            "[pkg.cargo]\ngit_commit_hash='rust-tree-not-proven-cargo-submodule'\n",
        )
        .replace(
            "xz_hash=",
            "zst_url='https://static.rust-lang.org/unsupported.tar.zst'\nxz_hash=",
        );
    let parsed = Manifest::parse(changed.as_bytes(), "1.99.1").unwrap();
    assert_eq!(
        parsed
            .package_source_metadata("cargo")
            .unwrap()
            .git_commit_hash,
        Some("rust-tree-not-proven-cargo-submodule")
    );
    assert!(
        parsed
            .archive_encodings("cargo", &request.host)
            .unwrap()
            .zstd_advertised
    );
    assert!(parsed.package_source_metadata("unknown").is_none());
}

#[test]
fn publication_age_boundary_never_invents_midnight_precision() {
    let mut f = Fixture::new();
    f.now = crate::parse_iso_date("2026-01-09")
        .unwrap()
        .midnight()
        .assume_utc()
        .unix_timestamp()
        - 1;
    f.assessment.assessed_at = f.now;
    f.acceptance.accepted_at = f.now;
    for observation in &mut f.evidence.observations {
        observation.checked_at = f.now;
    }
    f.rebind();
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Online {
                operation_started_at: f.now
            }
        ))
        .is_err()
    );
    f.now += 1;
    assert!(
        evaluate_eligibility(f.input(
            EligibilityPurpose::Installation,
            FreshnessRequest::Cached {
                reason: "explicit".into()
            }
        ))
        .is_ok()
    );
}

#[test]
fn standalone_installation_inspection_is_read_only_and_never_an_execution_grant() {
    let mut f = Fixture::new();
    f.now += 172_800;
    let mut input = f.input(
        EligibilityPurpose::InstallationInspection,
        FreshnessRequest::Local,
    );
    input.repository = None;
    assert_eq!(
        evaluate_eligibility(input).unwrap().mode,
        EligibilityMode::StaticInspection
    );
    let mut input = f.input(
        EligibilityPurpose::InstallationInspection,
        FreshnessRequest::Local,
    );
    input.repository = None;
    input.installed = None;
    assert!(
        evaluate_eligibility(input)
            .unwrap_err()
            .to_string()
            .contains("installed correspondence")
    );
    let mut changed = f.installed.clone();
    changed.mapping_sha256 = digest_bytes(b"modified installed mapping");
    let mut input = f.input(
        EligibilityPurpose::InstallationInspection,
        FreshnessRequest::Local,
    );
    input.repository = None;
    input.installed = Some(&changed);
    assert!(evaluate_eligibility(input).is_err());
    for purpose in [
        EligibilityPurpose::Installation,
        EligibilityPurpose::FirstAdoption,
        EligibilityPurpose::Activation,
        EligibilityPurpose::ContinuingUse,
    ] {
        let mut input = f.input(purpose, FreshnessRequest::Local);
        input.repository = None;
        assert!(
            evaluate_eligibility(input).is_err(),
            "inspection must not permit {purpose:?}"
        );
    }
    f.knowledge.adverse_subjects.insert(f.subject.id().clone());
    let mut input = f.input(
        EligibilityPurpose::InstallationInspection,
        FreshnessRequest::Local,
    );
    input.repository = None;
    assert!(evaluate_eligibility(input).is_err());
}

#[test]
fn component_matrix_changes_assessment_identity_and_missing_rows_cannot_be_accepted() {
    let mut f = Fixture::new();
    let legacy = f.evidence.content_id(&f.subject).unwrap();
    assert!(
        !String::from_utf8(serde_json::to_vec(&f.evidence).unwrap())
            .unwrap()
            .contains("component_sources")
    );
    let restored: EvidenceRecord = parse_record(&serde_json::to_vec(&f.evidence).unwrap()).unwrap();
    assert_eq!(restored.content_id(&f.subject).unwrap(), legacy);
    f.evidence.schema_version = 2;
    assert!(
        f.evidence
            .content_id(&f.subject)
            .unwrap_err()
            .to_string()
            .contains("incomplete")
    );
    for archive in &f.subject.record().archives {
        let snapshot = super::component_evidence::tests::snapshot(archive);
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        let sha = digest_bytes(&bytes);
        let path = format!("docs/sources/{sha}.json");
        f.evidence.component_sources.push(snapshot.component);
        let observation = f
            .evidence
            .observations
            .iter_mut()
            .find(|o| {
                o.source.kind == SourceKind::SourceIdentity
                    && o.source.scope == format!("{}/{}", archive.package, archive.target)
            })
            .unwrap();
        observation.content_sha256 = sha.clone();
        observation.snapshot = RecordReference {
            path: path.clone(),
            sha256: sha,
        };
        f.snapshots.insert(path, bytes);
    }
    let cached = || FreshnessRequest::Cached {
        reason: "explicit fixture cache use".into(),
    };
    assert_ne!(f.evidence.content_id(&f.subject).unwrap(), legacy);
    assert!(evaluate_eligibility(f.input(EligibilityPurpose::Installation, cached())).is_err());
    f.rebind();
    evaluate_eligibility(f.input(EligibilityPurpose::Installation, cached())).unwrap();
    let good = f.evidence.clone();
    f.evidence.component_sources[0].archive.sha256 = digest_bytes(b"wrong archive");
    assert!(evaluate_eligibility(f.input(EligibilityPurpose::Installation, cached())).is_err());
    f.evidence = good.clone();
    f.evidence.component_sources[0] = f.evidence.component_sources[1].clone();
    assert!(f.evidence.content_id(&f.subject).is_err());
    f.evidence = good;
    f.evidence.component_sources[0].residual_coverage.clear();
    assert!(f.evidence.content_id(&f.subject).is_err());
}

#[test]
fn legacy_default_and_explicit_docs_cached_acceptance_require_new_component_review() {
    for (profile, docs) in [(Profile::Default, false), (Profile::Minimal, true)] {
        let mut f = Fixture::new();
        let (manifest, request, auth, inventories) =
            fixture_inputs_for(b"file:bin/tool\n", profile, docs);
        f.subject = Subject::reconstruct(&manifest, &request, auth, inventories).unwrap();
        f.evidence.subject_id = f.subject.id().clone();
        f.evidence.publication.subject_id = f.subject.id().clone();
        for purpose in [
            EligibilityPurpose::Installation,
            EligibilityPurpose::FirstAdoption,
            EligibilityPurpose::Activation,
        ] {
            let error = evaluate_eligibility(f.input(
                purpose,
                FreshnessRequest::Cached {
                    reason: "fresh old generic default/docs acceptance".into(),
                },
            ))
            .unwrap_err();
            assert!(
                error.to_string().contains("legacy generic evidence"),
                "{error}"
            );
        }
    }
}
