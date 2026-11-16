use super::*;
use std::collections::{BTreeMap, BTreeSet};
fn hash(label: &str) -> crate::Sha256Digest {
    sha256(label.as_bytes())
}
fn executable() -> ExecutableIdentity {
    ExecutableIdentity {
        sha256: hash("compiler"),
        version: "1.95.0".into(),
        commit: "a".repeat(40),
        host: "aarch64-apple-darwin".into(),
    }
}
fn subject() -> Subject {
    let root = RootSourceIdentity::CratesIo {
        name: "harmless".into(),
        version: "1.0.0".into(),
        archive_sha256: hash("archive"),
    };
    Subject {
        schema_version: 1,
        root: root.clone(),
        original_lock: OriginalLock::Absent,
        effective_lock: EffectiveLock::Derived {
            sha256: hash("lock"),
            reason: "upstream archive contains no lock".into(),
        },
        graph: InstallGraph {
            root: "root".into(),
            nodes: BTreeMap::from([(
                "root".into(),
                GraphNode {
                    package: root.package(),
                    context: CompilationContext::Target,
                    features: BTreeSet::new(),
                    build_script: false,
                    proc_macro: false,
                    native_links: false,
                },
            )]),
            edges: BTreeSet::new(),
        },
        selection: BuildSelection {
            bins: BTreeMap::from([("harmless".into(), BTreeSet::new())]),
            requested_features: BTreeSet::new(),
            default_features: true,
            all_features: false,
            profile: BuildProfile::Release,
            host: "aarch64-apple-darwin".into(),
            target: "aarch64-apple-darwin".into(),
            resolver: 3,
        },
        evaluator: BuildEvaluator {
            cargo: executable(),
            rustc: executable(),
            qualification_sha256: hash("qualification"),
        },
        config_sha256: hash("config"),
        native_mode: NativeMode::VerifiedPath,
        inputs: BTreeSet::from([InputFile {
            kind: InputKind::RegularFile,
            path: "Cargo.toml".into(),
            mode: 0o644,
            bytes: 32,
            sha256: hash("manifest"),
        }]),
    }
}
fn policy() -> OriginPolicy {
    OriginPolicy {
        schema_version: 1,
        scope: PolicyScope::Standalone,
        policy_sha256: hash("policy"),
        required_checks: BTreeSet::from(["advisory".into()]),
        evaluator_sha256: BTreeSet::from([hash("scanner")]),
        tool_exceptions: BTreeSet::new(),
        ioc_exceptions: BTreeSet::new(),
    }
}
fn evidence(
    subject: &Subject,
    policy: &OriginPolicy,
    checked: i64,
) -> (EvidenceRecord, SourceKnowledge) {
    let facts = BTreeSet::from([
        SourceFact {
            key: KnowledgeKey::Package {
                package: subject.root.package(),
            },
            facts_sha256: hash("package facts"),
            status: SecurityStatus::Clear,
            expires_at_utc: None,
        },
        SourceFact {
            key: KnowledgeKey::Evaluator {
                sha256: hash("scanner"),
            },
            facts_sha256: hash("evaluator facts"),
            status: SecurityStatus::Clear,
            expires_at_utc: None,
        },
    ]);
    let content = EvidenceContent {
        schema_version: 1,
        subject_id: subject.id().unwrap(),
        policy_id: policy.id().unwrap(),
        evaluator_sha256: policy.evaluator_sha256.clone(),
        covered_checks: policy.required_checks.clone(),
        facts: facts.clone(),
        findings: BTreeSet::new(),
        complete: true,
    };
    let observation = Observation {
        schema_version: 1,
        content_id: content.id().unwrap(),
        sources: facts
            .iter()
            .map(|f| SourceObservation {
                key: f.key.clone(),
                semantic_sha256: f.semantic_sha256().unwrap(),
                source_version: 1,
                checked_at_utc: checked,
            })
            .collect(),
        completed_at_utc: checked,
        fresh_until_utc: checked + MAX_CACHE_SECONDS,
    };
    let mut knowledge = SourceKnowledge::default();
    for fact in facts {
        knowledge
            .remember(
                KnowledgeEntry {
                    fact,
                    source_version: 1,
                    checked_at_utc: checked,
                },
                checked,
            )
            .unwrap();
    }
    (
        EvidenceRecord {
            content,
            observation,
        },
        knowledge,
    )
}
fn review(subject: &Subject, policy: &OriginPolicy, evidence: &EvidenceRecord) -> Review {
    Review {
        schema_version: 1,
        subject_id: subject.id().unwrap(),
        policy_id: policy.id().unwrap(),
        evidence_content_id: evidence.content_id().unwrap(),
        assessment_requirements: BTreeSet::from(["execution risk".into()]),
    }
}
fn assessment(review: &Review) -> Assessment {
    Assessment {
        schema_version: 1,
        review_id: review.id().unwrap(),
        reviewer: "local reviewer".into(),
        completed_at_utc: 101,
        prose: "Reviewed exact source and all selected build surfaces.".into(),
        responses: BTreeMap::from([(
            "execution risk".into(),
            "Accepted ordinary build execution for this reviewed source.".into(),
        )]),
    }
}
fn acceptance(review: &Review, assessment: &Assessment) -> LocalAcceptance {
    LocalAcceptance {
        schema_version: 1,
        review_id: review.id().unwrap(),
        assessment_id: assessment.id().unwrap(),
        subject_id: review.subject_id.clone(),
        evidence_content_id: review.evidence_content_id.clone(),
        policy_id: review.policy_id.clone(),
        local_user: "uid:501".into(),
        accepted_at_utc: 102,
        deployment: DeploymentScope::Roots {
            roots: BTreeSet::from(["/tmp/tool-root".into()]),
        },
        risk_acknowledgement: "Accept reviewed build execution at the selected local root.".into(),
    }
}
fn output() -> OutputObservation {
    OutputObservation {
        name: "harmless".into(),
        path: "/tmp/tool-root/bin/harmless".into(),
        mode: 0o755,
        sha256: hash("output"),
        native_owner: "harmless 1.0.0 (path+file:///tmp/stage)".into(),
    }
}
fn binding(subject: &Subject, acceptance: &LocalAcceptance) -> InstalledBinding {
    InstalledBinding {
        schema_version: 1,
        root_package: subject.root.package(),
        subject_id: subject.id().unwrap(),
        review_id: acceptance.review_id.clone(),
        acceptance_id: acceptance.id().unwrap(),
        local_user: acceptance.local_user.clone(),
        root: "/tmp/tool-root".into(),
        outputs: BTreeSet::from([output()]),
        native_owner: output().native_owner,
        native_tracking_sha256: hash("native ledger"),
        installed_at_utc: 103,
    }
}
fn cached(operation: OperationKind) -> OperationIntent {
    OperationIntent {
        operation,
        freshness: FreshnessIntent::Cached {
            reason: "explicit offline operation".into(),
        },
    }
}

#[test]
fn round_trip_domain_and_cross_kind_refusal() {
    let s = subject();
    let encoded = encode_record(&s).unwrap();
    assert_eq!(parse_record::<Subject>(&encoded).unwrap(), s);
    assert!(parse_record::<Review>(&encoded).is_err());
    let id = s.id().unwrap();
    assert_eq!(id.to_string().parse::<RecordId>().unwrap(), id);
    assert!(
        id.to_string()
            .replace("cargo-tool", "rust-toolchain")
            .parse::<RecordId>()
            .is_err()
    );
}
#[test]
fn parser_rejects_unknown_duplicate_and_noncanonical_sets() {
    let mut raw: serde_json::Value =
        serde_json::from_slice(&encode_record(&subject()).unwrap()).unwrap();
    raw["record"]["unknown"] = true.into();
    assert!(parse_record::<Subject>(&serde_json::to_vec(&raw).unwrap()).is_err());
    let text = String::from_utf8(encode_record(&subject()).unwrap()).unwrap();
    let duplicate = text.replacen(
        "\"kind\":\"subject\"",
        "\"kind\":\"subject\",\"kind\":\"subject\"",
        1,
    );
    assert!(parse_record::<Subject>(duplicate.as_bytes()).is_err());
    let mut raw: serde_json::Value = serde_json::from_str(&text).unwrap();
    raw["record"]["selection"]["requested_features"] = serde_json::json!(["z", "a"]);
    assert!(parse_record::<Subject>(&serde_json::to_vec(&raw).unwrap()).is_err());
    raw["record"]["selection"]["requested_features"] = serde_json::json!(["a", "a"]);
    assert!(parse_record::<Subject>(&serde_json::to_vec(&raw).unwrap()).is_err());
}
#[test]
fn bounded_record_rejects_oversize_before_parse() {
    assert!(parse_record::<Subject>(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    assert!(parse_record::<Subject>(br#"{\"schema_version\":1.0}"#).is_err());
}
#[test]
fn subject_identity_binds_all_critical_build_choices() {
    let s = subject();
    let original = s.id().unwrap();
    let mut cases = Vec::new();
    let mut t = s.clone();
    t.selection.default_features = false;
    cases.push(t);
    let mut t = s.clone();
    t.config_sha256 = hash("other");
    cases.push(t);
    let mut t = s.clone();
    t.evaluator.cargo.sha256 = hash("other");
    cases.push(t);
    let mut t = s.clone();
    t.effective_lock = EffectiveLock::Derived {
        sha256: hash("other"),
        reason: "absent".into(),
    };
    cases.push(t);
    let mut t = s.clone();
    t.selection.bins.insert("extra".into(), BTreeSet::new());
    cases.push(t);
    for t in cases {
        assert_ne!(t.id().unwrap(), original);
    }
}
#[test]
fn lock_provenance_cannot_be_relabelled() {
    let mut s = subject();
    s.effective_lock = EffectiveLock::Upstream {
        sha256: hash("lock"),
    };
    assert!(s.validate().is_err());
    s.original_lock = OriginalLock::Usable {
        sha256: hash("lock"),
    };
    assert!(s.validate().is_ok());
    s.effective_lock = EffectiveLock::Derived {
        sha256: hash("new"),
        reason: "new graph".into(),
    };
    assert!(s.validate().is_err());
}
#[test]
fn graph_rejects_unreachable_cycles_and_duplicate_context() {
    let mut s = subject();
    let mut other = s.graph.nodes["root"].clone();
    other.package.name = "other".into();
    s.graph.nodes.insert("other".into(), other.clone());
    assert!(s.validate().is_err());
    s.graph.edges.insert(GraphEdge {
        from: "root".into(),
        to: "other".into(),
        kind: DependencyKind::Normal,
        declared_targets: BTreeSet::from([String::new()]),
    });
    assert!(s.validate().is_ok());
    s.graph.edges.insert(GraphEdge {
        from: "other".into(),
        to: "root".into(),
        kind: DependencyKind::Normal,
        declared_targets: BTreeSet::from([String::new()]),
    });
    assert!(s.validate().is_err());
    s.graph.edges.retain(|e| e.from == "root");
    s.graph.nodes.insert("duplicate".into(), other);
    assert!(s.validate().is_err());
}
#[test]
fn host_build_and_proc_macro_contexts_are_not_flattened() {
    let mut s = subject();
    let mut host = s.graph.nodes["root"].clone();
    host.package.name = "helper".into();
    host.context = CompilationContext::HostBuild;
    host.features.insert("host-only".into());
    s.graph.nodes.insert("host".into(), host.clone());
    s.graph.edges.insert(GraphEdge {
        from: "root".into(),
        to: "host".into(),
        kind: DependencyKind::Build,
        declared_targets: BTreeSet::from(["cfg(unix)".into()]),
    });
    assert!(s.validate().is_ok());
    s.graph.nodes.get_mut("host").unwrap().context = CompilationContext::Target;
    assert!(s.validate().is_err());
    s.graph.nodes.get_mut("host").unwrap().context = CompilationContext::HostProcMacro;
    s.graph.nodes.get_mut("host").unwrap().proc_macro = true;
    assert!(s.validate().is_ok());
}
#[test]
fn selected_bins_require_available_features_and_native_target() {
    let mut s = subject();
    s.selection
        .bins
        .get_mut("harmless")
        .unwrap()
        .insert("extra".into());
    assert!(s.validate().is_err());
    s.graph
        .nodes
        .get_mut("root")
        .unwrap()
        .features
        .insert("extra".into());
    assert!(s.validate().is_ok());
    s.selection.target = "other-host".into();
    assert!(s.validate().is_err());
}
#[test]
fn original_git_identity_never_requires_fabricated_archive() {
    let mut s = subject();
    s.root = RootSourceIdentity::Git {
        url: "https://example.org/tools.git".into(),
        rev: "b".repeat(40),
        package: "harmless".into(),
        version: "1.0.0".into(),
        workspace_manifest: "Cargo.toml".into(),
        package_manifest: "tools/harmless/Cargo.toml".into(),
        materialisation_sha256: hash("immutable blobs"),
    };
    s.graph.nodes.get_mut("root").unwrap().package = s.root.package();
    assert!(s.validate().is_ok());
    if let RootSourceIdentity::Git { rev, .. } = &mut s.root {
        *rev = "branch".into();
    }
    assert!(s.validate().is_err());
}
#[test]
fn aggregate_file_budget_and_path_limits_are_checked() {
    let mut s = subject();
    s.inputs = BTreeSet::new();
    for i in 0..8 {
        s.inputs.insert(InputFile {
            kind: InputKind::RegularFile,
            path: format!("file{i}"),
            mode: 0o644,
            bytes: MAX_FILE_BYTES,
            sha256: hash("x"),
        });
    }
    assert!(s.validate().is_ok());
    s.inputs.insert(InputFile {
        kind: InputKind::RegularFile,
        path: "overflow".into(),
        mode: 0o644,
        bytes: 1,
        sha256: hash("x"),
    });
    assert!(s.validate().is_err());
    assert!(super::record::relative_path(&"a/".repeat(128)).is_err());
    assert!(super::record::relative_path("../escape").is_err());
    assert!(super::record::relative_path(&"a".repeat(4096)).is_ok());
    assert!(super::record::relative_path(&"a".repeat(4097)).is_err());
}
#[test]
fn completed_scaffold_preserves_review_id_but_mutation_changes_assessment() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let id = r.id().unwrap();
    let mut a = assessment(&r);
    a.prose = "BARBICAN-REVIEW-PENDING".into();
    assert!(a.id().is_err());
    a.prose = "Completed source review.".into();
    a.applicable(&r, 101).unwrap();
    assert_eq!(r.id().unwrap(), id);
    let grant = acceptance(&r, &a);
    grant.applicable(&r, &a, "uid:501", 102).unwrap();
    a.prose.push_str(" Changed decision.");
    assert!(grant.applicable(&r, &a, "uid:501", 102).is_err());
}
#[test]
fn local_grant_never_transfers_users_or_roots() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    assert!(grant.applicable(&r, &a, "uid:502", 102).is_err());
    assert!(grant.permits_root("/tmp/unrelated").is_err());
    assert!(parse_record::<RepoAdmission>(&encode_record(&grant).unwrap()).is_err());
}
#[test]
fn unchanged_refresh_preserves_review_assessment_and_acceptance() {
    let s = subject();
    let p = policy();
    let (e, k) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let (fresh, fresh_k) = evidence(&s, &p, 200);
    assert_eq!(e.content_id().unwrap(), fresh.content_id().unwrap());
    assert_ne!(e.observation.id().unwrap(), fresh.observation.id().unwrap());
    let fresh_r = review(&s, &p, &fresh);
    assert_eq!(r.id().unwrap(), fresh_r.id().unwrap());
    grant.applicable(&fresh_r, &a, "uid:501", 200).unwrap();
    assert_eq!(a.completed_at_utc, 101);
    assert_eq!(grant.accepted_at_utc, 102);
    check_eligibility(
        &s,
        &p,
        &fresh,
        &fresh_k,
        &OperationIntent {
            operation: OperationKind::Install,
            freshness: FreshnessIntent::Online {
                started_at_utc: 200,
            },
        },
        200,
    )
    .unwrap();
    assert!(
        check_eligibility(
            &s,
            &p,
            &e,
            &k,
            &OperationIntent {
                operation: OperationKind::Install,
                freshness: FreshnessIntent::Online {
                    started_at_utc: 200
                }
            },
            200
        )
        .is_err()
    );
}
#[test]
fn freshness_boundary_future_clock_and_empty_reason_refuse() {
    let s = subject();
    let p = policy();
    let (e, k) = evidence(&s, &p, 100);
    check_eligibility(
        &s,
        &p,
        &e,
        &k,
        &cached(OperationKind::Install),
        100 + MAX_CACHE_SECONDS,
    )
    .unwrap();
    assert!(
        check_eligibility(
            &s,
            &p,
            &e,
            &k,
            &cached(OperationKind::Install),
            100 + MAX_CACHE_SECONDS + 1
        )
        .is_err()
    );
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 99).is_err());
    let mut intent = cached(OperationKind::Install);
    intent.freshness = FreshnessIntent::Cached { reason: " ".into() };
    assert!(check_eligibility(&s, &p, &e, &k, &intent, 100).is_err());
}
#[test]
fn continuing_use_has_no_age_only_expiry_but_source_expiry_still_blocks() {
    let s = subject();
    let p = policy();
    let (e, k) = evidence(&s, &p, 100);
    check_eligibility(
        &s,
        &p,
        &e,
        &k,
        &cached(OperationKind::ContinuingUse),
        100 + MAX_CACHE_SECONDS + 1,
    )
    .unwrap();
    let mut expired = e.clone();
    let mut facts = expired.content.facts.iter().cloned().collect::<Vec<_>>();
    facts[0].expires_at_utc = Some(110);
    expired.content.facts = facts.into_iter().collect();
    let mut knowledge = SourceKnowledge::default();
    for f in &expired.content.facts {
        knowledge
            .remember(
                KnowledgeEntry {
                    fact: f.clone(),
                    source_version: 1,
                    checked_at_utc: 100,
                },
                100,
            )
            .unwrap();
    }
    expired.observation.content_id = expired.content.id().unwrap();
    expired.observation.sources = expired
        .content
        .facts
        .iter()
        .map(|f| SourceObservation {
            key: f.key.clone(),
            semantic_sha256: f.semantic_sha256().unwrap(),
            source_version: 1,
            checked_at_utc: 100,
        })
        .collect();
    assert!(
        check_eligibility(
            &s,
            &p,
            &expired,
            &knowledge,
            &cached(OperationKind::ContinuingUse),
            110
        )
        .is_err()
    );
}
#[test]
fn adverse_shared_dependency_survives_later_collection_failure() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    let x = k
        .entries
        .iter()
        .find(|e| matches!(e.fact.key, KnowledgeKey::Package { .. }))
        .unwrap()
        .clone();
    let mut adverse = x.clone();
    adverse.fact.status = SecurityStatus::Adverse;
    adverse.fact.facts_sha256 = hash("new yank");
    adverse.source_version = 2;
    adverse.checked_at_utc = 200;
    k.remember(adverse, 200).unwrap();
    let evaluator = k
        .entries
        .iter()
        .find(|e| matches!(e.fact.key, KnowledgeKey::Evaluator { .. }))
        .unwrap();
    assert_eq!(evaluator.checked_at_utc, 100);
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 201).is_err());
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::ContinuingUse), 201).is_err());
    assert!(k.remember(x, 201).is_err());
}
#[test]
fn same_time_and_version_conflicts_cannot_refresh() {
    let s = subject();
    let p = policy();
    let (_, clean) = evidence(&s, &p, 100);
    let mut k = clean.clone();
    let mut conflict = k.entries[0].clone();
    conflict.fact.facts_sha256 = hash("contradiction");
    assert!(k.remember(conflict.clone(), 100).is_err());
    assert_eq!(k.conflicts.len(), 1);
    let mut other = clean.clone();
    conflict.source_version = 2;
    assert!(other.remember(conflict, 100).is_err());
    assert_eq!(other.conflicts.len(), 1);
    let mut refresh = k.entries[0].clone();
    refresh.checked_at_utc = 200;
    assert!(k.remember(refresh.clone(), 200).is_err());
    let mut current = clean;
    current.remember(refresh, 200).unwrap();
    assert!(current.remember(current.entries[0].clone(), 199).is_err());
}

#[test]
fn partial_missing_evaluator_and_prose_cannot_waive_security() {
    let s = subject();
    let p = policy();
    let (mut e, k) = evidence(&s, &p, 100);
    e.content.complete = false;
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Accept), 100).is_err());
    e.content.complete = true;
    e.content.findings.insert(Finding {
        identity: "checksum".into(),
        package: s.root.package(),
        kind: FindingKind::Checksum,
        blocking: false,
        detail_sha256: hash("mismatch"),
    });
    assert!(e.content.validate().is_err());
    let (mut e, _) = evidence(&s, &p, 100);
    e.content
        .facts
        .retain(|f| !matches!(f.key, KnowledgeKey::Evaluator { .. }));
    assert!(e.content.applicable(&s, &p).is_err());
}
#[test]
fn output_correspondence_checks_all_outputs_modes_and_owner() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let b = binding(&s, &grant);
    b.applicable(&s, &grant).unwrap();
    b.corresponds(&b.outputs, &b.native_owner, &b.native_tracking_sha256)
        .unwrap();
    let mut changed = output();
    changed.mode = 0o700;
    assert!(
        b.corresponds(
            &BTreeSet::from([changed]),
            &b.native_owner,
            &b.native_tracking_sha256
        )
        .is_err()
    );
    assert!(
        b.corresponds(&BTreeSet::new(), &b.native_owner, &b.native_tracking_sha256)
            .is_err()
    );
    assert!(
        b.corresponds(&b.outputs, "another owner", &b.native_tracking_sha256)
            .is_err()
    );
}
#[test]
fn native_bootstrap_family_allows_old_versions_without_claiming_hashes() {
    let old = parse_native_original_owner(
        "harmless 0.9.0 (registry+https://github.com/rust-lang/crates.io-index)",
    )
    .unwrap();
    assert_eq!(old.family, subject().root.package().family());
    assert_eq!(old.version, "0.9.0");
    assert!(old.git_commit.is_none());
    assert!(parse_native_original_owner("harmless 0.9.0 (path+file:///tmp/stage)").is_err());
    let old = parse_native_original_owner(&format!(
        "harmless 0.9.0 (git+https://example.org/tools.git?branch=main#{})",
        "a".repeat(40)
    ))
    .unwrap();
    assert_eq!(old.git_commit, Some("a".repeat(40)));
}
#[test]
fn bootstrap_requires_explicit_flag_and_cannot_bypass_known_binding() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let b = binding(&s, &grant);
    let intent = InstallIntent {
        schema_version: 1,
        subject_id: s.id().unwrap(),
        acceptance_id: grant.id().unwrap(),
        root: b.root.clone(),
        prior: PriorInstallation::TrackedBootstrap {
            old_package: parse_native_original_owner(
                "harmless 0.9.0 (registry+https://github.com/rust-lang/crates.io-index)",
            )
            .unwrap(),
            new_package: s.root.package(),
            old_outputs: b
                .outputs
                .iter()
                .cloned()
                .map(|mut output| {
                    output.native_owner =
                        "harmless 0.9.0 (registry+https://github.com/rust-lang/crates.io-index)"
                            .into();
                    output
                })
                .collect(),
        },
        affected_bins: BTreeSet::from(["harmless".into()]),
    };
    assert!(
        validate_install_intent(&intent, &s, &grant, None, &intent.prior.outputs(), false).is_err()
    );
    validate_install_intent(&intent, &s, &grant, None, &intent.prior.outputs(), true).unwrap();
    assert!(validate_install_intent(&intent, &s, &grant, Some(&b), &b.outputs, true).is_err());
}
#[test]
fn partial_or_cancelled_installation_never_publishes() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let intent = InstallIntent {
        schema_version: 1,
        subject_id: s.id().unwrap(),
        acceptance_id: grant.id().unwrap(),
        root: "/tmp/tool-root".into(),
        prior: PriorInstallation::Absent,
        affected_bins: BTreeSet::from(["harmless".into()]),
    };
    let mut completion = InstallCompletion {
        native_success: true,
        cancelled: false,
        inputs_rechecked: true,
        context_rechecked: true,
        outputs: BTreeSet::from([output()]),
        affected_outputs: BTreeMap::from([("harmless".into(), Some(output()))]),
        native_owner: output().native_owner,
        native_tracking_sha256: hash("native ledger"),
        completed_at_utc: 103,
    };
    assert!(complete_install(&intent, &s, &grant, &completion).is_ok());
    completion.cancelled = true;
    assert!(complete_install(&intent, &s, &grant, &completion).is_err());
    completion.cancelled = false;
    completion.native_success = false;
    assert!(complete_install(&intent, &s, &grant, &completion).is_err());
    completion.native_success = true;
    completion.outputs.clear();
    assert!(complete_install(&intent, &s, &grant, &completion).is_err());
}
#[test]
fn off_path_correspondence_is_not_consumer_admission() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let b = binding(&s, &grant);
    b.corresponds(&b.outputs, &b.native_owner, &b.native_tracking_sha256)
        .unwrap();
    let selected = ConsumerSelection::Direct {
        executable: "/other/bin/harmless".into(),
    };
    assert!(check_consumer_selection(&b, "harmless", &selected, &output()).is_err());
    let selected = ConsumerSelection::ProcessPath {
        path_entries: vec!["".into(), "/tmp/tool-root/bin".into()],
        selected_executable: output().path,
    };
    assert!(check_consumer_selection(&b, "harmless", &selected, &output()).is_err());
}
#[test]
fn unavailable_baseline_is_not_an_empty_clean_delta() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    assert_eq!(
        tool_delta(&s, &e.content, None).unwrap(),
        ToolDelta::BaselineUnavailable
    );
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let b = binding(&s, &grant);
    assert!(tool_delta(&s, &e.content, Some((&s, &e.content, &b, &BTreeSet::new()))).is_err());
}
#[test]
fn native_ledger_and_consumer_configuration_refuse_ambiguity() {
    assert_eq!(
        parse_native_v1("[v1]\n'foo 1.0.0 (path+file:///tmp/a)'=['foo']")
            .unwrap()
            .len(),
        1
    );
    assert!(parse_native_v1("[v1]\na=['foo']\nb=['foo']").is_err());
    assert!(consumer_config_safe("[alias]\nfoo='run'", "foo").is_err());
    assert!(consumer_config_safe("include='elsewhere'", "foo").is_err());
    assert!(consumer_config_safe("[env]\nPATH='/tmp'", "foo").is_err());
    assert!(consumer_config_safe("[alias]\nother='run'", "foo").is_ok());
}

#[test]
fn exact_exception_is_finite_completed_source_and_policy_bound() {
    let s = subject();
    let mut p = policy();
    let finding = Finding {
        identity: "RUSTSEC-2026-0001".into(),
        package: s.root.package(),
        kind: FindingKind::Advisory,
        blocking: false,
        detail_sha256: hash("advisory body"),
    };
    let prose = "Reviewed this exact source-bound advisory and accepted the stated temporary risk.";
    let exception = ToolException {
        subject_id: s.id().unwrap(),
        package: s.root.package(),
        policy_sha256: p.policy_sha256.clone(),
        exception: ExceptionKind::Advisory {
            identity: finding.identity.clone(),
            detail_sha256: finding.detail_sha256.clone(),
        },
        expires_at_utc: 120,
        reviewed_at_utc: 90,
        reviewer: "reviewer".into(),
        review_record: prose.into(),
        review_record_sha256: sha256(prose.as_bytes()),
    };
    exception.validate().unwrap();
    assert!(
        exception
            .applies_to(&finding, &s.id().unwrap(), &p.policy_sha256, 119)
            .unwrap()
    );
    assert!(
        !exception
            .applies_to(&finding, &s.id().unwrap(), &p.policy_sha256, 120)
            .unwrap()
    );
    let mut changed = finding.clone();
    changed.kind = FindingKind::Yank;
    assert!(
        !exception
            .applies_to(&changed, &s.id().unwrap(), &p.policy_sha256, 100)
            .unwrap()
    );
    changed = finding.clone();
    changed.detail_sha256 = hash("amended advisory");
    assert!(
        !exception
            .applies_to(&changed, &s.id().unwrap(), &p.policy_sha256, 100)
            .unwrap()
    );
    let (e, _) = evidence(&s, &p, 100);
    let mut content = e.content;
    content.findings.insert(finding.clone());
    assert!(content.applicable(&s, &p).is_err());
    p.tool_exceptions.insert(exception);
    let (mut e, k) = evidence(&s, &p, 100);
    e.content.findings.insert(finding);
    e.observation.content_id = e.content.id().unwrap();
    check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Accept), 119).unwrap();
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Accept), 120).is_err());
    let mut bad = p.tool_exceptions.first().unwrap().clone();
    bad.review_record = "BARBICAN-REVIEW-PENDING".into();
    bad.review_record_sha256 = sha256(bad.review_record.as_bytes());
    assert!(bad.validate().is_err());
}
#[test]
fn contradictory_registry_bytes_cannot_create_a_fresh_knowledge_key() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    let mut adverse = k
        .entries
        .iter()
        .find(|entry| matches!(entry.fact.key, KnowledgeKey::Package { .. }))
        .unwrap()
        .clone();
    if let KnowledgeKey::Package { package } = &mut adverse.fact.key {
        package.source = PackageSource::CratesIo {
            archive_sha256: hash("contradictory archive"),
        };
    }
    adverse.fact.status = SecurityStatus::Adverse;
    adverse.source_version = 2;
    adverse.checked_at_utc = 200;
    k.remember(adverse, 200).unwrap();
    assert_eq!(k.entries.len(), 2);
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 200).is_err());
}
#[test]
fn assigned_advisory_updates_share_key_but_provisional_bodies_do_not() {
    let assigned = KnowledgeKey::Advisory {
        package: subject().root.package(),
        source: "https://github.com/RustSec/advisory-db".into(),
        identity: AdvisoryIdentity::Assigned {
            rustsec_id: "RUSTSEC-2026-0001".into(),
        },
    };
    let mut k = SourceKnowledge::default();
    let mut entry = KnowledgeEntry {
        fact: SourceFact {
            key: assigned,
            facts_sha256: hash("old body"),
            status: SecurityStatus::Clear,
            expires_at_utc: None,
        },
        source_version: 1,
        checked_at_utc: 100,
    };
    k.remember(entry.clone(), 100).unwrap();
    entry.fact.facts_sha256 = hash("new body");
    entry.fact.status = SecurityStatus::Adverse;
    entry.source_version = 2;
    entry.checked_at_utc = 200;
    k.remember(entry, 200).unwrap();
    assert_eq!(k.entries.len(), 1);
    for body in ["pending one", "pending two"] {
        k.remember(
            KnowledgeEntry {
                fact: SourceFact {
                    key: KnowledgeKey::Advisory {
                        package: subject().root.package(),
                        source: "https://github.com/RustSec/advisory-db".into(),
                        identity: AdvisoryIdentity::Provisional {
                            body_sha256: hash(body),
                        },
                    },
                    facts_sha256: hash(body),
                    status: SecurityStatus::Adverse,
                    expires_at_utc: None,
                },
                source_version: 2,
                checked_at_utc: 200,
            },
            200,
        )
        .unwrap();
    }
    assert_eq!(k.entries.len(), 3);
}
#[test]
fn known_updates_require_family_correspondence_and_all_old_outputs() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let mut old = binding(&s, &grant);
    let mut obsolete = output();
    obsolete.name = "obsolete".into();
    obsolete.path = "/tmp/tool-root/bin/obsolete".into();
    old.outputs.insert(obsolete);
    let mut intent = InstallIntent {
        schema_version: 1,
        subject_id: s.id().unwrap(),
        acceptance_id: grant.id().unwrap(),
        root: old.root.clone(),
        prior: PriorInstallation::Known {
            installation_id: old.id().unwrap(),
            subject_id: old.subject_id.clone(),
            outputs: old.outputs.clone(),
        },
        affected_bins: BTreeSet::from(["harmless".into()]),
    };
    assert!(validate_install_intent(&intent, &s, &grant, Some(&old), &old.outputs, false).is_err());
    intent.affected_bins.insert("obsolete".into());
    validate_install_intent(&intent, &s, &grant, Some(&old), &old.outputs, false).unwrap();
    old.root_package.name = "unrelated".into();
    if let PriorInstallation::Known {
        installation_id, ..
    } = &mut intent.prior
    {
        *installation_id = old.id().unwrap();
    }
    assert!(validate_install_intent(&intent, &s, &grant, Some(&old), &old.outputs, true).is_err());
}
#[test]
fn publication_requires_observations_for_removed_old_bins() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let mut old = binding(&s, &grant);
    let mut obsolete = output();
    obsolete.name = "obsolete".into();
    obsolete.path = "/tmp/tool-root/bin/obsolete".into();
    old.outputs.insert(obsolete);
    let intent = InstallIntent {
        schema_version: 1,
        subject_id: s.id().unwrap(),
        acceptance_id: grant.id().unwrap(),
        root: "/tmp/tool-root".into(),
        prior: PriorInstallation::Known {
            installation_id: old.id().unwrap(),
            subject_id: old.subject_id.clone(),
            outputs: old.outputs.clone(),
        },
        affected_bins: BTreeSet::from(["harmless".into(), "obsolete".into()]),
    };
    let mut completion = InstallCompletion {
        native_success: true,
        cancelled: false,
        inputs_rechecked: true,
        context_rechecked: true,
        outputs: BTreeSet::from([output()]),
        affected_outputs: BTreeMap::from([("harmless".into(), Some(output()))]),
        native_owner: output().native_owner,
        native_tracking_sha256: hash("native ledger"),
        completed_at_utc: 103,
    };
    assert!(complete_install(&intent, &s, &grant, &completion).is_err());
    completion.affected_outputs.insert("obsolete".into(), None);
    assert!(complete_install(&intent, &s, &grant, &completion).is_ok());
}

#[test]
fn inventory_binds_directory_types_modes_and_empty_directories() {
    let mut s = subject();
    let directory = InputFile {
        path: "empty".into(),
        kind: InputKind::Directory,
        mode: 0o755,
        bytes: 0,
        sha256: sha256(b""),
    };
    s.inputs.insert(directory.clone());
    s.validate().unwrap();
    let id = s.id().unwrap();
    s.inputs.remove(&directory);
    let mut changed = directory;
    changed.mode = 0o700;
    s.inputs.insert(changed);
    assert_ne!(s.id().unwrap(), id);
    let file = InputFile {
        path: "missing/file".into(),
        kind: InputKind::RegularFile,
        mode: 0o644,
        bytes: 1,
        sha256: hash("x"),
    };
    s.inputs.insert(file.clone());
    assert!(s.validate().is_err());
    s.inputs.insert(InputFile {
        path: "missing".into(),
        kind: InputKind::Directory,
        mode: 0o755,
        bytes: 0,
        sha256: sha256(b""),
    });
    assert!(s.validate().is_ok());
    s.inputs.insert(InputFile {
        path: file.path,
        kind: InputKind::Directory,
        mode: 0o755,
        bytes: 0,
        sha256: sha256(b""),
    });
    assert!(s.validate().is_err());
}
#[test]
fn semantically_changed_coverage_evaluator_expiry_and_policy_invalidate_review() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let mut changed = e.content.clone();
    changed.covered_checks.insert("new coverage".into());
    assert!(r.applicable(&s, &p, &changed).is_err());
    changed = e.content.clone();
    changed
        .evaluator_sha256
        .insert(hash("replacement evaluator"));
    assert!(r.applicable(&s, &p, &changed).is_err());
    changed = e.content.clone();
    let mut facts = changed.facts.iter().cloned().collect::<Vec<_>>();
    facts[0].expires_at_utc = Some(200);
    changed.facts = facts.into_iter().collect();
    assert!(r.applicable(&s, &p, &changed).is_err());
    let mut changed_policy = p.clone();
    changed_policy.policy_sha256 = hash("new policy");
    assert!(r.applicable(&s, &changed_policy, &e.content).is_err());
}
#[test]
fn negative_evidence_is_persistable_but_never_eligible() {
    let s = subject();
    let p = policy();
    let (mut e, k) = evidence(&s, &p, 100);
    e.content.findings.insert(Finding {
        identity: "known yank".into(),
        package: s.root.package(),
        kind: FindingKind::Yank,
        blocking: true,
        detail_sha256: hash("yank"),
    });
    e.observation.content_id = e.content.id().unwrap();
    parse_record::<EvidenceContent>(&encode_record(&e.content).unwrap()).unwrap();
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Accept), 100).is_err());
}
#[test]
fn stale_observation_cannot_be_forged_ahead_of_source_knowledge() {
    let s = subject();
    let p = policy();
    let (mut e, k) = evidence(&s, &p, 100);
    e.observation.completed_at_utc = 200;
    e.observation.fresh_until_utc = 200 + MAX_CACHE_SECONDS;
    e.observation.sources = e
        .observation
        .sources
        .into_iter()
        .map(|mut source| {
            source.checked_at_utc = 200;
            source
        })
        .collect();
    assert!(
        check_eligibility(
            &s,
            &p,
            &e,
            &k,
            &OperationIntent {
                operation: OperationKind::Install,
                freshness: FreshnessIntent::Online {
                    started_at_utc: 200
                }
            },
            200
        )
        .is_err()
    );
}

#[test]
fn new_advisory_key_learned_from_another_tool_blocks_old_snapshot() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    let adverse = SourceFact {
        key: KnowledgeKey::Advisory {
            package: s.root.package(),
            source: "https://github.com/RustSec/advisory-db".into(),
            identity: AdvisoryIdentity::Assigned {
                rustsec_id: "RUSTSEC-2026-0007".into(),
            },
        },
        facts_sha256: hash("new advisory"),
        status: SecurityStatus::Adverse,
        expires_at_utc: None,
    };
    assert!(!e.content.facts.iter().any(|fact| fact.key == adverse.key));
    k.remember(
        KnowledgeEntry {
            fact: adverse,
            source_version: 2,
            checked_at_utc: 200,
        },
        200,
    )
    .unwrap();
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 200).is_err());
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::ContinuingUse), 200).is_err());
}
#[test]
fn api_clear_refresh_cannot_erase_independent_inspection_adverse() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    k.remember(
        KnowledgeEntry {
            fact: SourceFact {
                key: KnowledgeKey::Inspection {
                    inspector_sha256: hash("trusted inspector"),
                    package: s.root.package(),
                },
                facts_sha256: hash("confirmed IOC"),
                status: SecurityStatus::Adverse,
                expires_at_utc: None,
            },
            source_version: 1,
            checked_at_utc: 200,
        },
        200,
    )
    .unwrap();
    let mut api = k
        .entry_for(&KnowledgeKey::Package {
            package: s.root.package(),
        })
        .unwrap()
        .clone();
    api.checked_at_utc = 300;
    k.remember(api, 300).unwrap();
    assert_eq!(k.entries.len(), 3);
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 300).is_err());
}
#[test]
fn unrelated_adverse_package_never_blocks_this_tool() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    let mut unrelated = s.root.package();
    unrelated.name = "unrelated".into();
    k.remember(
        KnowledgeEntry {
            fact: SourceFact {
                key: KnowledgeKey::Inspection {
                    package: unrelated,
                    inspector_sha256: hash("trusted inspector"),
                },
                facts_sha256: hash("unrelated IOC"),
                status: SecurityStatus::Adverse,
                expires_at_utc: None,
            },
            source_version: 1,
            checked_at_utc: 200,
        },
        200,
    )
    .unwrap();
    check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 200).unwrap();
}
#[test]
fn current_advisory_adverse_requires_exact_body_bound_exception() {
    let s = subject();
    let mut p = policy();
    let body = hash("reviewed advisory body");
    let prose = "Reviewed exact advisory body and temporary mitigation.";
    p.tool_exceptions.insert(ToolException {
        subject_id: s.id().unwrap(),
        package: s.root.package(),
        policy_sha256: p.policy_sha256.clone(),
        exception: ExceptionKind::Advisory {
            identity: "RUSTSEC-2026-0007".into(),
            detail_sha256: body.clone(),
        },
        expires_at_utc: 120,
        reviewed_at_utc: 90,
        reviewer: "reviewer".into(),
        review_record: prose.into(),
        review_record_sha256: sha256(prose.as_bytes()),
    });
    let (mut e, mut k) = evidence(&s, &p, 100);
    let fact = SourceFact {
        key: KnowledgeKey::Advisory {
            package: s.root.package(),
            source: "https://github.com/RustSec/advisory-db".into(),
            identity: AdvisoryIdentity::Assigned {
                rustsec_id: "RUSTSEC-2026-0007".into(),
            },
        },
        facts_sha256: body.clone(),
        status: SecurityStatus::Adverse,
        expires_at_utc: None,
    };
    e.content.facts.insert(fact.clone());
    e.content.findings.insert(Finding {
        identity: "RUSTSEC-2026-0007".into(),
        package: s.root.package(),
        kind: FindingKind::Advisory,
        blocking: false,
        detail_sha256: body,
    });
    e.observation.content_id = e.content.id().unwrap();
    e.observation.sources.insert(SourceObservation {
        key: fact.key.clone(),
        semantic_sha256: fact.semantic_sha256().unwrap(),
        source_version: 1,
        checked_at_utc: 100,
    });
    k.remember(
        KnowledgeEntry {
            fact,
            source_version: 1,
            checked_at_utc: 100,
        },
        100,
    )
    .unwrap();
    check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 119).unwrap();
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 120).is_err());
}
#[test]
fn native_tracking_scope_drift_is_not_hidden_by_same_owner_label() {
    let s = subject();
    let p = policy();
    let (e, _) = evidence(&s, &p, 100);
    let r = review(&s, &p, &e);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let b = binding(&s, &grant);
    assert!(
        b.corresponds(
            &b.outputs,
            &b.native_owner,
            &hash("changed features or rustc")
        )
        .is_err()
    );
    b.corresponds(&b.outputs, &b.native_owner, &b.native_tracking_sha256)
        .unwrap();
}

#[test]
fn persisted_record_byte_limit_is_inclusive() {
    let mut bytes = encode_record(&subject()).unwrap();
    bytes.resize(MAX_RECORD_BYTES, b' ');
    parse_record::<Subject>(&bytes).unwrap();
    bytes.push(b' ');
    assert!(parse_record::<Subject>(&bytes).is_err());
}
#[test]
fn same_packages_with_different_feature_context_has_explicit_graph_delta() {
    let old = subject();
    let p = policy();
    let (old_evidence, _) = evidence(&old, &p, 100);
    let r = review(&old, &p, &old_evidence);
    let a = assessment(&r);
    let grant = acceptance(&r, &a);
    let b = binding(&old, &grant);
    let mut next = old.clone();
    next.graph
        .nodes
        .get_mut("root")
        .unwrap()
        .features
        .insert("resolved-extra".into());
    let (next_evidence, _) = evidence(&next, &p, 200);
    let delta = tool_delta(
        &next,
        &next_evidence.content,
        Some((&old, &old_evidence.content, &b, &b.outputs)),
    )
    .unwrap();
    assert!(
        matches!(delta,ToolDelta::Compared{changed_graph:true,added,removed,..} if added.is_empty() && removed.is_empty())
    );
}

#[test]
fn contradictory_new_adverse_is_retained_even_when_observation_is_rejected() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    let key = KnowledgeKey::Package {
        package: s.root.package(),
    };
    let mut contradiction = k.entry_for(&key).unwrap().clone();
    contradiction.fact.status = SecurityStatus::Adverse;
    contradiction.fact.facts_sha256 = hash("same-version new yank");
    contradiction.checked_at_utc = 200;
    assert!(k.remember(contradiction, 200).is_err());
    assert_eq!(k.conflicts.len(), 1);
    assert_eq!(k.entry_for(&key).unwrap().checked_at_utc, 100);
    let persisted = encode_record(&k).unwrap();
    let restored = parse_record::<SourceKnowledge>(&persisted).unwrap();
    assert_eq!(restored, k);
    assert!(
        check_eligibility(&s, &p, &e, &restored, &cached(OperationKind::Install), 200).is_err()
    );
    assert!(
        check_eligibility(
            &s,
            &p,
            &e,
            &restored,
            &cached(OperationKind::ContinuingUse),
            200
        )
        .is_err()
    );
}
#[test]
fn new_inspector_cannot_erase_adverse_from_earlier_trusted_inspector() {
    let s = subject();
    let p = policy();
    let (e, mut k) = evidence(&s, &p, 100);
    for (inspector, status, time) in [
        ("old inspector", SecurityStatus::Adverse, 200),
        ("new inspector", SecurityStatus::Clear, 300),
    ] {
        k.remember(
            KnowledgeEntry {
                fact: SourceFact {
                    key: KnowledgeKey::Inspection {
                        package: s.root.package(),
                        inspector_sha256: hash(inspector),
                    },
                    facts_sha256: hash(inspector),
                    status,
                    expires_at_utc: None,
                },
                source_version: 1,
                checked_at_utc: time,
            },
            time,
        )
        .unwrap();
    }
    assert_eq!(k.entries.len(), 4);
    assert!(check_eligibility(&s, &p, &e, &k, &cached(OperationKind::Install), 300).is_err());
}

#[test]
fn two_distinct_tool_subjects_share_transitive_adverse_knowledge() {
    let mut a = subject();
    let mut shared = a.root.package();
    shared.name = "shared-dependency".into();
    let node = GraphNode {
        package: shared.clone(),
        context: CompilationContext::Target,
        features: BTreeSet::new(),
        build_script: false,
        proc_macro: false,
        native_links: false,
    };
    a.graph.nodes.insert("shared".into(), node);
    a.graph.edges.insert(GraphEdge {
        from: "root".into(),
        to: "shared".into(),
        kind: DependencyKind::Normal,
        declared_targets: BTreeSet::from([String::new()]),
    });
    let mut b = a.clone();
    if let RootSourceIdentity::CratesIo { name, .. } = &mut b.root {
        *name = "other-tool".into();
    }
    b.graph.nodes.get_mut("root").unwrap().package = b.root.package();
    b.validate().unwrap();
    assert_ne!(a.id().unwrap(), b.id().unwrap());
    assert!(b.graph.packages().contains(&shared));
    let p = policy();
    let (mut e, mut knowledge) = evidence(&a, &p, 100);
    let clear = SourceFact {
        key: KnowledgeKey::Package {
            package: shared.clone(),
        },
        facts_sha256: hash("shared release facts"),
        status: SecurityStatus::Clear,
        expires_at_utc: None,
    };
    e.content.facts.insert(clear.clone());
    e.observation.sources.insert(SourceObservation {
        key: clear.key.clone(),
        semantic_sha256: clear.semantic_sha256().unwrap(),
        source_version: 1,
        checked_at_utc: 100,
    });
    knowledge
        .remember(
            KnowledgeEntry {
                fact: clear,
                source_version: 1,
                checked_at_utc: 100,
            },
            100,
        )
        .unwrap();
    e.observation.content_id = e.content.id().unwrap();
    check_eligibility(&a, &p, &e, &knowledge, &cached(OperationKind::Install), 100).unwrap();
    knowledge
        .remember(
            KnowledgeEntry {
                fact: SourceFact {
                    key: KnowledgeKey::Inspection {
                        package: shared,
                        inspector_sha256: hash("trusted inspector"),
                    },
                    facts_sha256: hash(
                        "IOC learned during B collection before later source failure",
                    ),
                    status: SecurityStatus::Adverse,
                    expires_at_utc: None,
                },
                source_version: 1,
                checked_at_utc: 200,
            },
            200,
        )
        .unwrap();
    assert!(
        check_eligibility(&a, &p, &e, &knowledge, &cached(OperationKind::Install), 200).is_err()
    );
    assert_eq!(e.observation.completed_at_utc, 100);
}

#[test]
fn graph_declared_targets_are_canonical_bounded_and_identity_bound() {
    let mut s = subject();
    let mut child = s.graph.nodes["root"].clone();
    child.package.name = "declared-child".into();
    s.graph.nodes.insert("child".into(), child);
    let mut edge = GraphEdge {
        from: "root".into(),
        to: "child".into(),
        kind: DependencyKind::Normal,
        declared_targets: BTreeSet::from([String::new(), "cfg(unix)".into()]),
    };
    s.graph.edges.insert(edge.clone());
    let original = s.id().unwrap();
    let mut reordered = edge.clone();
    reordered.declared_targets = ["cfg(unix)".into(), String::new()].into_iter().collect();
    assert_eq!(
        canonical_bytes(&edge).unwrap(),
        canonical_bytes(&reordered).unwrap()
    );
    edge.declared_targets
        .insert("cfg(target_os = \"none\")".into());
    s.graph.edges = BTreeSet::from([edge.clone()]);
    assert_ne!(s.id().unwrap(), original);
    let mut duplicate = edge.clone();
    duplicate.declared_targets = BTreeSet::from([String::new()]);
    s.graph.edges.insert(duplicate);
    assert!(
        s.graph
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate selected")
    );
    for targets in [
        BTreeSet::new(),
        BTreeSet::from(["cfg(unix)\n".into()]),
        BTreeSet::from(["x".repeat(MAX_LINE_BYTES + 1)]),
        (0..=MAX_GRAPH_NODES)
            .map(|i| format!("target-{i}"))
            .collect(),
        (0..=MAX_RECORD_BYTES / MAX_LINE_BYTES)
            .map(|i| format!("{i:08}{}", "x".repeat(MAX_LINE_BYTES - 8)))
            .collect(),
    ] {
        edge.declared_targets = targets;
        s.graph.edges = BTreeSet::from([edge.clone()]);
        assert!(s.graph.validate().is_err());
    }
}

#[test]
fn exact_ioc_allowance_preserves_raw_knowledge_and_does_not_cover_new_or_legacy_causes() {
    let subject = subject();
    let package = subject.root.package();
    let mut scanner = crate::ioc::ScanAccumulator::new(crate::ioc::Source::from(&package)).unwrap();
    scanner
        .scan_file(
            "build.rs",
            b"Command::new(",
            &crate::ioc::Scope {
                build_script_paths: BTreeSet::from(["build.rs".into()]),
                ..Default::default()
            },
            &mut crate::ioc::ScanBudget::default(),
        )
        .unwrap();
    let inspected = scanner.finish(None);
    let mut reviewed =
        crate::ioc::parse_review(&crate::ioc::scaffold_review(&inspected).unwrap()).unwrap();
    reviewed.reviewer = "Maintainer".into();
    reviewed.reviewed_at_utc = Some(90);
    reviewed.conclusion = crate::ioc::Conclusion::ExpectedBehaviour;
    reviewed.rationale="Reviewed the original helper and every occurrence; it invokes the specified compiler for this declared build.".into();
    let allowance =
        crate::ioc::Allowance::from_text(&crate::ioc::render_review(&reviewed).unwrap()).unwrap();
    let mut policy = policy();
    policy.ioc_exceptions.insert(ToolIocException {
        subject_id: subject.id().unwrap(),
        policy_sha256: policy.policy_sha256.clone(),
        allowance: allowance.clone(),
    });
    let (mut evidence, mut knowledge) = evidence(&subject, &policy, 100);
    let finding_id = inspected.findings[0].id().unwrap();
    let fact = SourceFact {
        key: KnowledgeKey::Ioc {
            package: package.clone(),
            finding_id: finding_id.clone(),
        },
        facts_sha256: finding_id.clone(),
        status: SecurityStatus::Adverse,
        expires_at_utc: None,
    };
    knowledge
        .remember(
            KnowledgeEntry {
                fact: fact.clone(),
                source_version: 1,
                checked_at_utc: 100,
            },
            100,
        )
        .unwrap();
    evidence.content.facts.insert(fact.clone());
    evidence.content.findings.insert(Finding {
        identity: finding_id.to_string(),
        package: package.clone(),
        kind: FindingKind::Ioc,
        blocking: false,
        detail_sha256: finding_id,
    });
    evidence.observation.sources.insert(SourceObservation {
        key: fact.key.clone(),
        semantic_sha256: fact.semantic_sha256().unwrap(),
        source_version: 1,
        checked_at_utc: 100,
    });
    evidence.observation.content_id = evidence.content.id().unwrap();
    check_eligibility(
        &subject,
        &policy,
        &evidence,
        &knowledge,
        &cached(OperationKind::Install),
        100,
    )
    .unwrap();
    assert_eq!(
        knowledge.entry_for(&fact.key).unwrap().fact.status,
        SecurityStatus::Adverse
    );
    assert!(
        knowledge
            .ioc_decision(
                std::slice::from_ref(&inspected.source),
                std::slice::from_ref(&allowance),
                100
            )
            .unwrap()
            .is_success()
    );
    let fresh_at = MAX_CACHE_SECONDS + 200;
    let mut refreshed = evidence.clone();
    let mut current_knowledge = knowledge.clone();
    refreshed.observation.completed_at_utc = fresh_at;
    refreshed.observation.fresh_until_utc = fresh_at + MAX_CACHE_SECONDS;
    refreshed.observation.sources = refreshed
        .observation
        .sources
        .iter()
        .cloned()
        .map(|mut observed| {
            if !matches!(observed.key, KnowledgeKey::Ioc { .. }) {
                observed.checked_at_utc = fresh_at;
            }
            observed
        })
        .collect();
    for source_fact in refreshed
        .content
        .facts
        .iter()
        .filter(|f| !matches!(f.key, KnowledgeKey::Ioc { .. }))
    {
        current_knowledge
            .remember(
                KnowledgeEntry {
                    fact: source_fact.clone(),
                    source_version: 1,
                    checked_at_utc: fresh_at,
                },
                fresh_at,
            )
            .unwrap();
    }
    let online = OperationIntent {
        operation: OperationKind::Install,
        freshness: FreshnessIntent::Online {
            started_at_utc: fresh_at,
        },
    };
    check_eligibility(
        &subject,
        &policy,
        &refreshed,
        &current_knowledge,
        &online,
        fresh_at,
    )
    .unwrap();
    assert_eq!(
        current_knowledge
            .entry_for(&fact.key)
            .unwrap()
            .checked_at_utc,
        100
    );
    let mut stale_mutable = refreshed.clone();
    stale_mutable.observation.sources = stale_mutable
        .observation
        .sources
        .iter()
        .cloned()
        .map(|mut observed| {
            if matches!(observed.key, KnowledgeKey::Package { .. }) {
                observed.checked_at_utc = 100;
            }
            observed
        })
        .collect();
    assert!(
        check_eligibility(
            &subject,
            &policy,
            &stale_mutable,
            &current_knowledge,
            &online,
            fresh_at
        )
        .is_err()
    );
    assert!(
        check_eligibility(
            &subject,
            &policy,
            &stale_mutable,
            &current_knowledge,
            &cached(OperationKind::Install),
            fresh_at
        )
        .is_err()
    );
    let newly_observed = hash("another exact finding learned by standalone IOC check");
    knowledge
        .remember(
            KnowledgeEntry {
                fact: SourceFact {
                    key: KnowledgeKey::Ioc {
                        package: package.clone(),
                        finding_id: newly_observed.clone(),
                    },
                    facts_sha256: newly_observed,
                    status: SecurityStatus::Adverse,
                    expires_at_utc: None,
                },
                source_version: 1,
                checked_at_utc: 101,
            },
            101,
        )
        .unwrap();
    assert!(
        check_eligibility(
            &subject,
            &policy,
            &evidence,
            &knowledge,
            &cached(OperationKind::Install),
            101
        )
        .is_err()
    );
    assert!(
        !knowledge
            .ioc_decision(&[inspected.source], &[allowance], 101)
            .unwrap()
            .is_success()
    );
    let retained = SourceFact {
        key: KnowledgeKey::Inspection {
            package,
            inspector_sha256: hash("old inspector"),
        },
        facts_sha256: hash("coarse legacy IOC or checksum or coverage cause"),
        status: SecurityStatus::Adverse,
        expires_at_utc: None,
    };
    knowledge
        .remember(
            KnowledgeEntry {
                fact: retained,
                source_version: 1,
                checked_at_utc: 102,
            },
            102,
        )
        .unwrap();
    assert!(
        check_eligibility(
            &subject,
            &policy,
            &evidence,
            &knowledge,
            &cached(OperationKind::ContinuingUse),
            102
        )
        .is_err()
    );
}

#[test]
fn many_ioc_findings_use_one_scoped_current_index_and_preserve_all_cause_checks() {
    let subject = subject();
    let package = subject.root.package();
    let source = crate::ioc::Source::from(&package);
    let mut scan = crate::ioc::ScanAccumulator::new(source.clone()).unwrap();
    let scope = crate::ioc::Scope {
        proc_macro: true,
        ..Default::default()
    };
    let mut budget = crate::ioc::ScanBudget::default();
    const COUNT: usize = 1000;
    for n in 0..COUNT {
        scan.scan_file(
            &format!("src/case-{n}.rs"),
            b"Command::new(",
            &scope,
            &mut budget,
        )
        .unwrap();
    }
    let inspected = scan.finish(None);
    assert_eq!(inspected.findings.len(), COUNT);
    let mut record =
        crate::ioc::parse_review(&crate::ioc::scaffold_review(&inspected).unwrap()).unwrap();
    record.reviewer = "Maintainer".into();
    record.reviewed_at_utc = Some(90);
    record.conclusion = crate::ioc::Conclusion::ExpectedBehaviour;
    record.rationale="Reviewed this generated source family and each displayed compiler invocation in the original immutable input.".into();
    let allowance =
        crate::ioc::Allowance::from_text(&crate::ioc::render_review(&record).unwrap()).unwrap();
    let mut policy = policy();
    let grant = ToolIocException {
        subject_id: subject.id().unwrap(),
        policy_sha256: policy.policy_sha256.clone(),
        allowance,
    };
    policy.ioc_exceptions.insert(grant.clone());
    let findings: Vec<_> = inspected
        .findings
        .iter()
        .map(|finding| {
            let id = finding.id().unwrap();
            Finding {
                identity: id.to_string(),
                package: package.clone(),
                kind: FindingKind::Ioc,
                blocking: false,
                detail_sha256: id,
            }
        })
        .collect();
    let mut checks = 0;
    let index = ToolIocIndex::prepare(&policy, &subject.id().unwrap(), 100, &mut || {
        checks += 1;
        Ok(())
    })
    .unwrap();
    assert!(
        (COUNT..=4 * COUNT + 16).contains(&checks),
        "preparation must remain bounded by source findings and records"
    );
    let prepared_checks = checks;
    assert!(findings.iter().all(|finding| index.allows(finding)));
    assert_eq!(checks, prepared_checks);
    let mut cancelled_checks = 0;
    assert!(
        ToolIocIndex::prepare(&policy, &subject.id().unwrap(), 100, &mut || {
            cancelled_checks += 1;
            if cancelled_checks == 17 {
                Err("cancelled index preparation".into())
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap()
        .to_string()
        .contains("cancelled")
    );
    assert_eq!(cancelled_checks, 17);

    let (mut evidence, mut knowledge) = evidence(&subject, &policy, 100);
    for finding in &findings {
        let fact = SourceFact {
            key: KnowledgeKey::Ioc {
                package: package.clone(),
                finding_id: finding.detail_sha256.clone(),
            },
            facts_sha256: finding.detail_sha256.clone(),
            status: SecurityStatus::Adverse,
            expires_at_utc: None,
        };
        evidence.observation.sources.insert(SourceObservation {
            key: fact.key.clone(),
            semantic_sha256: fact.semantic_sha256().unwrap(),
            source_version: 1,
            checked_at_utc: 100,
        });
        evidence.content.facts.insert(fact.clone());
        knowledge
            .remember(
                KnowledgeEntry {
                    fact,
                    source_version: 1,
                    checked_at_utc: 100,
                },
                100,
            )
            .unwrap();
    }
    evidence.content.findings = findings.iter().cloned().collect();
    evidence.observation.content_id = evidence.content.id().unwrap();
    let online = OperationIntent {
        operation: OperationKind::Install,
        freshness: FreshnessIntent::Online {
            started_at_utc: 100,
        },
    };
    for intent in [
        online,
        cached(OperationKind::Install),
        cached(OperationKind::ContinuingUse),
    ] {
        check_eligibility(&subject, &policy, &evidence, &knowledge, &intent, 100).unwrap();
    }
    assert!(
        knowledge
            .entries
            .iter()
            .filter(|entry| matches!(entry.fact.key, KnowledgeKey::Ioc { .. }))
            .all(|entry| entry.fact.status == SecurityStatus::Adverse)
    );
    let mut split = policy.clone();
    split.ioc_exceptions.clear();
    for half in record.findings.chunks(COUNT / 2) {
        let mut part = record.clone();
        part.findings = half.to_vec();
        split.ioc_exceptions.insert(ToolIocException {
            allowance: crate::ioc::Allowance::from_text(&crate::ioc::render_review(&part).unwrap())
                .unwrap(),
            ..grant.clone()
        });
    }
    let split_index =
        ToolIocIndex::prepare(&split, &subject.id().unwrap(), 100, &mut || Ok(())).unwrap();
    assert!(findings.iter().all(|finding| split_index.allows(finding)));
    let mut unrelated = policy.clone();
    unrelated.ioc_exceptions.clear();
    let mut wrong = grant.clone();
    wrong.subject_id.sha256 = hash("different subject");
    unrelated.ioc_exceptions.insert(wrong);
    let mut wrong = grant.clone();
    wrong.policy_sha256 = hash("different base policy");
    unrelated.ioc_exceptions.insert(wrong);
    assert!(
        !ToolIocIndex::prepare(&unrelated, &subject.id().unwrap(), 100, &mut || Ok(()))
            .unwrap()
            .allows(&findings[0])
    );
    let mut expired = policy.clone();
    expired.ioc_exceptions.clear();
    let mut expired_grant = grant;
    expired_grant.allowance.record.review_by_utc = Some(100);
    expired.ioc_exceptions.insert(expired_grant);
    assert!(
        !ToolIocIndex::prepare(&expired, &subject.id().unwrap(), 100, &mut || Ok(()))
            .unwrap()
            .allows(&findings[0])
    );
    let mut unknown = findings[0].clone();
    unknown.detail_sha256 = hash("uncovered new finding");
    unknown.identity = unknown.detail_sha256.to_string();
    assert!(!index.allows(&unknown));
}

#[test]
fn exception_authoring_selects_exact_registry_findings_and_completes_only_drafts() {
    let subject = subject();
    let policy = policy();
    let (mut evidence, _) = evidence(&subject, &policy, 100);
    let age = Finding {
        identity: "release-age".into(),
        package: subject.root.package(),
        kind: FindingKind::ReleaseAge,
        blocking: true,
        detail_sha256: hash("age"),
    };
    let advisory = Finding {
        identity: "RUSTSEC-2026-0001".into(),
        kind: FindingKind::Advisory,
        detail_sha256: hash("advisory"),
        ..age.clone()
    };
    evidence
        .content
        .findings
        .extend([age.clone(), advisory.clone()]);
    let source = crate::ioc::Source::from(&age.package).id().unwrap();
    assert_eq!(
        select_exception_finding(
            &subject,
            &evidence.content,
            None,
            Some("harmless@1.0.0"),
            Some(source.as_str())
        )
        .unwrap(),
        &age
    );
    assert_eq!(
        select_exception_finding(
            &subject,
            &evidence.content,
            Some("RUSTSEC-2026-0001"),
            None,
            None
        )
        .unwrap(),
        &advisory
    );
    for id in ["RUSTSEC-0000-0000", "pending", "body-only"] {
        assert!(
            select_exception_finding(&subject, &evidence.content, Some(id), None, None).is_err()
        );
    }
    assert!(
        select_exception_finding(&subject, &evidence.content, None, Some("wrong"), None).is_err()
    );
    assert!(
        select_exception_finding(&subject, &evidence.content, None, None, Some("wrong")).is_err()
    );
    let mut draft = ToolException::pending(
        subject.id().unwrap(),
        policy.policy_sha256.clone(),
        &advisory,
        300,
    )
    .unwrap();
    draft.review_record_sha256 = sha256(draft.review_record.as_bytes());
    assert!(
        draft.validate().is_err(),
        "pending prose must fail even with a manually recomputed digest"
    );
    draft.review_record = "Reviewed exact advisory risk pending upstream remediation; mitigations constrain exposure.".into();
    for reviewer in ["", "PENDING", "TODO", "TBD", "scaffold reviewer"] {
        let mut incomplete = draft.clone();
        incomplete.reviewer = reviewer.into();
        assert!(incomplete.complete_draft(100).is_err());
    }
    draft.reviewer = "Fixture reviewer".into();
    draft.complete_draft(100).unwrap();
    let completed = draft.clone();
    draft.complete_draft(200).unwrap();
    assert_eq!(draft, completed, "retry preserves review time and digest");
    assert!(draft.validate_authoring(99).is_err());
    assert!(draft.validate_authoring(300).is_err());
    assert!(
        draft
            .applies_to(
                &advisory,
                &subject.id().unwrap(),
                &policy.policy_sha256,
                200
            )
            .unwrap()
    );
    for kind in [
        FindingKind::Yank,
        FindingKind::Checksum,
        FindingKind::RequiredCoverage,
        FindingKind::ReleaseAge,
    ] {
        assert!(
            !draft
                .applies_to(
                    &Finding {
                        kind,
                        ..advisory.clone()
                    },
                    &subject.id().unwrap(),
                    &policy.policy_sha256,
                    200
                )
                .unwrap()
        );
    }
    assert!(
        !draft
            .applies_to(
                &Finding {
                    detail_sha256: hash("changed body"),
                    ..advisory.clone()
                },
                &subject.id().unwrap(),
                &policy.policy_sha256,
                200
            )
            .unwrap()
    );
    let mut changed = draft.clone();
    changed.review_record.push_str(" Changed.");
    assert!(
        changed.complete_draft(200).is_err(),
        "finalised retry does not normalise changed content"
    );
    evidence.content.findings.insert(Finding {
        identity: "another age".into(),
        ..age.clone()
    });
    assert!(select_exception_finding(&subject, &evidence.content, None, None, None).is_err());
}
