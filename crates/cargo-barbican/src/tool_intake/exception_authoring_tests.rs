use super::super::{
    collection::ReviewRequest,
    context::{NativeContext, RepoContext},
    frontend::{self, StoredReview},
    process::Budget,
    source::Stage,
    store::Stores,
};
use super::*;
use crate::cli::{AuditOutputFormat, IocSelectionArgs};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};
fn hash(label: &str) -> barbican::Sha256Digest {
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

struct Fixture {
    ctx: Context,
    stored: StoredReview,
    _stage: Stage,
}
impl Fixture {
    fn new(repository: bool) -> Self {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        let stores = Stores::open(
            &stage.root,
            None,
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap();
        let home = stage.root.join("home");
        fs::create_dir(&home).unwrap();
        if repository {
            fs::create_dir(stage.root.join("reviews")).unwrap();
            fs::write(stage.root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
            fs::write(
                stage.root.join("barbican.toml"),
                "# preserve reviewer commentary\n",
            )
            .unwrap();
        } else {
            stores
                .data
                .publish(
                    Path::new("cargo-tools/v1/policy.toml"),
                    b"# preserve reviewer commentary\n",
                )
                .unwrap();
        }
        let repo = RepoContext::capture(
            &stage.root,
            repository.then_some(stage.root.as_path()),
            !repository,
            &budget,
        )
        .unwrap();
        let ctx = Context {
            current: stage.root.clone(),
            repo,
            stores,
            evaluator: None,
            original_cargo_home: home.clone(),
            native_root: home.clone(),
            native: NativeContext {
                cargo_home: home.clone(),
                install_root: home,
                configurations: vec![],
            },
            now: OffsetDateTime::now_utc().unix_timestamp(),
            budget,
            progress: Default::default(),
            authored_refresh: None,
            ioc_budget: Default::default(),
            source_client: crate::crates_io_http::UreqCratesIoClient::new(
                crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
            ),
        };
        let subject = subject();
        let (scope, base) = super::super::policy::origin_binding(&ctx).unwrap();
        let mut policy = policy();
        policy.scope = scope;
        policy.policy_sha256 = base;
        let (mut evidence, _) = evidence(&subject, &policy, ctx.now);
        evidence.content.findings.insert(Finding {
            identity: "release-age".into(),
            package: subject.root.package(),
            kind: FindingKind::ReleaseAge,
            blocking: true,
            detail_sha256: hash("age"),
        });
        evidence.observation.content_id = evidence.content.id().unwrap();
        let review = Review {
            schema_version: 1,
            subject_id: subject.id().unwrap(),
            policy_id: policy.id().unwrap(),
            evidence_content_id: evidence.content.id().unwrap(),
            assessment_requirements: BTreeSet::from(["risk".into()]),
        };
        let stored = StoredReview {
            subject,
            policy,
            review,
            evidence,
            request: ReviewRequest {
                spec: Some("harmless@1.0.0".into()),
                git: None,
                rev: None,
                package: None,
                bins: vec![],
                features: vec![],
                no_default_features: false,
                all_features: false,
                profile: "release".into(),
                target: None,
                from: None,
                cargo: "/never-execute-cargo".into(),
                rustc: "/never-execute-rustc".into(),
            },
        };
        frontend::save_review(&ctx, &stored).unwrap();
        Self {
            ctx,
            stored,
            _stage: stage,
        }
    }
    fn args(&self) -> ToolIocExceptionArgs {
        ToolIocExceptionArgs {
            review_id: self.stored.review.id().unwrap().to_string(),
            ioc: false,
            age: true,
            advisory: None,
            review_record: Some("reviews/age.json".into()),
            record: None,
            review_by: Some("2099-01-01".into()),
            selection: IocSelectionArgs {
                package: None,
                source_id: None,
                paths: vec![],
                rules: vec![],
            },
            standalone: self.ctx.repo.is_none(),
            format: AuditOutputFormat::Json,
        }
    }
    fn path(&self) -> std::path::PathBuf {
        self.ctx
            .repo
            .as_ref()
            .map(|r| r.root.clone())
            .unwrap_or(self.ctx.stores.data.root().to_owned())
            .join("reviews/age.json")
    }
    fn refresh(&mut self) {
        if let Some(repo) = &self.ctx.repo {
            self.ctx.repo =
                RepoContext::capture(&self.ctx.current, Some(&repo.root), false, &self.ctx.budget)
                    .unwrap();
        }
    }
}

#[test]
fn exception_authoring_public_owner_scaffold_publish_recollect_and_live_authority() {
    for repository in [false, true] {
        let mut f = Fixture::new(repository);
        let mut args = f.args();
        let now = OffsetDateTime::now_utc();
        assert!(
            f.stored
                .evidence
                .content
                .applicable(&f.stored.subject, &f.stored.policy)
                .is_err()
        );
        let scaffold = run(&f.ctx, &args, now).unwrap();
        assert_eq!(scaffold["status"], "pending-scaffold");
        let command = scaffold["publication_command"].as_str().unwrap();
        assert!(command.contains(&format!(
            "--data-dir '{}'",
            f.ctx.stores.data.root().display()
        )));
        assert!(command.contains(&format!(
            "--cache-dir '{}'",
            f.ctx.stores.cache.root().display()
        )));
        assert_eq!(command.contains("--standalone"), !repository);
        assert!(
            run(&f.ctx, &args, now).is_err(),
            "exclusive scaffold creation"
        );
        args.record = args.review_record.take();
        assert!(run(&f.ctx, &args, now).is_err());
        let mut record: ToolException =
            serde_json::from_slice(&fs::read(f.path()).unwrap()).unwrap();
        record.reviewer = "Test reviewer".into();
        record.review_record = "Reviewed exact source, early release risk and bounded mitigations pending upstream maturity.".into();
        fs::write(f.path(), serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        assert_eq!(run(&f.ctx, &args, now).unwrap()["status"], "current");
        f.refresh();
        let final_bytes = fs::read(f.path()).unwrap();
        assert_eq!(run(&f.ctx, &args, now).unwrap()["status"], "current");
        assert_eq!(fs::read(f.path()).unwrap(), final_bytes);
        let config = super::super::policy::configuration(&f.ctx).unwrap();
        assert_eq!(config.tools.exception_records, ["reviews/age.json"]);
        let config_path = if repository {
            f.ctx.current.join("barbican.toml")
        } else {
            f.ctx.stores.data.root().join("cargo-tools/v1/policy.toml")
        };
        assert!(
            fs::read_to_string(config_path)
                .unwrap()
                .contains("# preserve reviewer commentary")
        );
        let (grants, _) = super::super::policy::load_exceptions(
            &f.ctx,
            &config,
            &f.stored.policy.policy_sha256,
            &f.ctx.budget,
        )
        .unwrap();
        let mut policy = f.stored.policy.clone();
        policy.tool_exceptions = grants;
        let mut recollected = f.stored.evidence.content.clone();
        recollected.policy_id = policy.id().unwrap();
        recollected.findings = recollected
            .findings
            .into_iter()
            .map(|mut finding| {
                finding.blocking = !policy.tool_exceptions.iter().any(|e| {
                    e.applies_to(
                        &finding,
                        &recollected.subject_id,
                        &policy.policy_sha256,
                        now.unix_timestamp(),
                    )
                    .unwrap()
                });
                finding
            })
            .collect();
        recollected.applicable(&f.stored.subject, &policy).unwrap();
        let age = recollected.findings.first().unwrap().clone();
        recollected.findings.insert(Finding {
            identity: "yank".into(),
            kind: FindingKind::Yank,
            blocking: true,
            ..age
        });
        assert!(recollected.applicable(&f.stored.subject, &policy).is_err());
        let mut changed: ToolException = serde_json::from_slice(&final_bytes).unwrap();
        changed.review_record.push_str(" Edited.");
        fs::write(f.path(), serde_json::to_vec(&changed).unwrap()).unwrap();
        let changed_bytes = fs::read(f.path()).unwrap();
        assert!(run(&f.ctx, &args, now).is_err());
        assert_eq!(
            fs::read(f.path()).unwrap(),
            changed_bytes,
            "active authority never rewritten"
        );
        assert!(
            super::super::policy::load_exceptions(
                &f.ctx,
                &config,
                &f.stored.policy.policy_sha256,
                &f.ctx.budget
            )
            .is_err()
        );
    }
}

#[test]
fn exception_authoring_refuses_missing_deadline_unsafe_paths_wrong_binding_and_duplicates() {
    let f = Fixture::new(false);
    let now = OffsetDateTime::now_utc();
    let mut args = f.args();
    args.review_by = None;
    assert!(run(&f.ctx, &args, now).unwrap_err().contains("--review-by"));
    args = f.args();
    args.review_record = Some("../escape.json".into());
    assert!(run(&f.ctx, &args, now).is_err());
    args = f.args();
    args.selection.paths.push("src/lib.rs".into());
    assert!(run(&f.ctx, &args, now).unwrap_err().contains("IOC-only"));
    args = f.args();
    run(&f.ctx, &args, now).unwrap();
    args.record = args.review_record.take();
    let mut record: ToolException = serde_json::from_slice(&fs::read(f.path()).unwrap()).unwrap();
    record.reviewer = "Test reviewer".into();
    record.review_record =
        "Exact finding reviewed with bounded exposure and explicit risk acceptance.".into();
    let original = record.clone();
    record.policy_sha256 = hash("wrong-policy");
    fs::write(f.path(), serde_json::to_vec(&record).unwrap()).unwrap();
    let bytes = fs::read(f.path()).unwrap();
    assert!(run(&f.ctx, &args, now).is_err());
    assert_eq!(fs::read(f.path()).unwrap(), bytes);
    fs::write(f.path(), serde_json::to_vec(&original).unwrap()).unwrap();
    run(&f.ctx, &args, now).unwrap();
    let duplicate = f.path().with_file_name("duplicate.json");
    fs::copy(f.path(), &duplicate).unwrap();
    args.record = Some("reviews/duplicate.json".into());
    assert!(run(&f.ctx, &args, now).unwrap_err().contains("duplicate"));
    let bytes = fs::read(&duplicate).unwrap();
    f.ctx
        .cancelled()
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(run(&f.ctx, &args, now).is_err());
    assert_eq!(fs::read(duplicate).unwrap(), bytes);
}

#[test]
fn exception_authoring_cli_kind_contract() {
    use crate::cli::Cli;
    use clap::Parser;
    for kind in [
        vec!["--ioc"],
        vec!["--age"],
        vec!["--advisory", "RUSTSEC-2026-0001"],
    ] {
        let mut args = vec![
            "cargo-barbican",
            "tool",
            "exception",
            "review-id",
            "--record",
            "review.json",
        ];
        args.extend(kind);
        assert!(Cli::try_parse_from(args).is_ok());
    }
    for kinds in [
        vec![],
        vec!["--ioc", "--age"],
        vec!["--age", "--advisory", "RUSTSEC-2026-0001"],
    ] {
        let mut args = vec![
            "cargo-barbican",
            "tool",
            "exception",
            "review-id",
            "--record",
            "review.json",
        ];
        args.extend(kinds);
        assert!(Cli::try_parse_from(args).is_err());
    }
}

type BeforeWriteHook = Option<(&'static str, Box<dyn FnOnce()>)>;
thread_local! {
    static BEFORE_WRITE: std::cell::RefCell<BeforeWriteHook> = const { std::cell::RefCell::new(None) };
}
pub(super) fn before_write(stage: &str) {
    let hook = BEFORE_WRITE.with(|cell| {
        let mut hook = cell.borrow_mut();
        if hook.as_ref().is_some_and(|(wanted, _)| *wanted == stage) {
            hook.take()
        } else {
            None
        }
    });
    if let Some((_, hook)) = hook {
        hook();
    }
}

#[test]
fn exception_authoring_final_guards_preserve_drift_and_report_retained_unreferenced_record() {
    for repository in [false, true] {
        for stage in ["record", "config"] {
            for drift in ["config-bytes", "config-references", "draft-bytes", "cancel"] {
                let f = Fixture::new(repository);
                let now = OffsetDateTime::now_utc();
                let mut args = f.args();
                run(&f.ctx, &args, now).unwrap();
                args.record = args.review_record.take();
                let mut record: ToolException =
                    serde_json::from_slice(&fs::read(f.path()).unwrap()).unwrap();
                record.reviewer = "Guard fixture reviewer".into();
                record.review_record =
                    "Reviewed exact finding and bounded risk for this guard fixture.".into();
                fs::write(f.path(), serde_json::to_vec(&record).unwrap()).unwrap();
                let original = fs::read(f.path()).unwrap();
                let record_path = f.path();
                let config_path = if repository {
                    f.ctx.current.join("barbican.toml")
                } else {
                    f.ctx.stores.data.root().join("cargo-tools/v1/policy.toml")
                };
                let mutated_config = config_path.clone();
                let cancel = f.ctx.budget.cancelled.clone();
                BEFORE_WRITE.with(|cell| {
                    *cell.borrow_mut() = Some((
                        stage,
                        Box::new(move || match drift {
                            "config-bytes" => {
                                fs::write(mutated_config, "# concurrently edited comment\n")
                                    .unwrap()
                            }
                            "config-references" => fs::write(
                                mutated_config,
                                "[tools]\nexception_records=[\"other.json\"]\n",
                            )
                            .unwrap(),
                            "draft-bytes" => {
                                fs::write(record_path, "external record change").unwrap()
                            }
                            "cancel" => cancel.store(true, std::sync::atomic::Ordering::SeqCst),
                            _ => unreachable!(),
                        }),
                    ))
                });
                let error = run(&f.ctx, &args, now).unwrap_err();
                assert!(
                    !fs::read_to_string(config_path)
                        .unwrap()
                        .contains("reviews/age.json"),
                    "no authority after {stage}/{drift}"
                );
                if stage == "config" {
                    assert!(error.contains("unreferenced record retained"), "{error}");
                }
                if drift == "draft-bytes" {
                    assert_eq!(
                        fs::read_to_string(f.path()).unwrap(),
                        "external record change"
                    );
                } else if stage == "record" {
                    assert_eq!(fs::read(f.path()).unwrap(), original);
                } else {
                    let completed: ToolException =
                        serde_json::from_slice(&fs::read(f.path()).unwrap()).unwrap();
                    completed
                        .validate_authoring(OffsetDateTime::now_utc().unix_timestamp())
                        .unwrap();
                }
            }
        }
    }
}
