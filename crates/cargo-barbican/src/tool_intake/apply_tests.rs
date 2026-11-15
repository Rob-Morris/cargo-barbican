use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{acceptance, native, output_files};
use barbican::cargo_tool::*;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "barbican-tool-apply-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
    fn output(&self, name: &str, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(self.0.join("bin")).unwrap();
        let path = self.0.join("bin").join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
    fn ledger(&self, owners: &[(&str, &[&str])]) {
        let mut toml = String::from("[v1]\n");
        let mut installs = serde_json::Map::new();
        for (owner, bins) in owners {
            toml.push_str(&format!(
                "{} = {}\n",
                serde_json::to_string(owner).unwrap(),
                serde_json::to_string(bins).unwrap()
            ));
            installs.insert((*owner).into(), serde_json::json!({"bins":bins,"features":[],"all_features":false,"no_default_features":false,"profile":"release","target":"aarch64-apple-darwin","rustc":"reviewed fixture transport","version_req":null}));
        }
        fs::write(self.0.join(".crates.toml"), toml).unwrap();
        fs::write(
            self.0.join(".crates2.json"),
            serde_json::to_vec(&serde_json::json!({"installs":installs})).unwrap(),
        )
        .unwrap();
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn output_hashing_detects_bytes_modes_links_and_cancellation_without_execution() {
    let scratch = Scratch::new();
    let output = scratch.output("owned", b"inert observed bytes; never executable code");
    let cancel = AtomicBool::new(false);
    let baseline = output_files::observe(&output, scratch.uid(), true, &cancel).unwrap();
    fs::write(&output, b"different inert bytes").unwrap();
    assert_ne!(
        output_files::observe(&output, scratch.uid(), true, &cancel).unwrap(),
        baseline
    );
    fs::set_permissions(&output, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(output_files::observe(&output, scratch.uid(), true, &cancel).is_err());
    fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).unwrap();
    fs::hard_link(&output, scratch.0.join("alias")).unwrap();
    assert!(output_files::observe(&output, scratch.uid(), true, &cancel).is_err());
    fs::remove_file(scratch.0.join("alias")).unwrap();
    cancel.store(true, Ordering::SeqCst);
    assert!(
        output_files::observe(&output, scratch.uid(), true, &cancel)
            .unwrap_err()
            .contains("cancelled")
    );
    cancel.store(false, Ordering::SeqCst);
    let target = scratch.0.join("target");
    fs::rename(&output, &target).unwrap();
    symlink(&target, &output).unwrap();
    assert!(output_files::observe(&output, scratch.uid(), true, &cancel).is_err());
}

#[test]
fn cargo_artifact_hardlinks_preserve_digest_checks_and_installed_output_isolation() {
    let scratch = Scratch::new();
    let artifact = scratch.output("owned", b"inert build artifact; never executed");
    let alias = scratch.0.join("cargo-artifact-alias");
    fs::hard_link(&artifact, &alias).unwrap();
    let selected = BTreeSet::from(["owned".into()]);
    let protocol = serde_json::to_vec(&serde_json::json!({
        "reason": "compiler-artifact",
        "target": { "kind": ["bin"], "name": "owned" },
        "executable": artifact,
    }))
    .unwrap();
    let cancel = AtomicBool::new(false);
    let observe_artifacts = || {
        super::installation::artifact_outputs(
            &protocol,
            &scratch.0,
            &selected,
            scratch.uid(),
            &cancel,
        )
    };
    let baseline = observe_artifacts().unwrap();
    let installed = scratch.0.join("independent-installed-copy");
    fs::copy(&artifact, &installed).unwrap();
    assert_eq!(
        baseline["owned"],
        output_files::observe(&installed, scratch.uid(), true, &cancel).unwrap()
    );
    assert!(output_files::observe(&artifact, scratch.uid(), true, &cancel).is_err());
    assert!(output_files::observe_trusted_executable(&artifact, scratch.uid(), &cancel).is_err());
    assert!(output_files::read_record(&artifact, scratch.uid(), 1024, &cancel).is_err());

    fs::write(&alias, b"changed through the other artifact link").unwrap();
    assert_ne!(observe_artifacts().unwrap(), baseline);
    assert_eq!(
        output_files::observe(&installed, scratch.uid(), true, &cancel).unwrap(),
        baseline["owned"]
    );
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(observe_artifacts().is_err());
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(&artifact).unwrap();
    symlink(&alias, &artifact).unwrap();
    assert!(observe_artifacts().is_err());
}

#[test]
fn native_tracking_reconciles_both_ledgers_and_preserves_unrelated_owners() {
    let scratch = Scratch::new();
    let owner = "owned 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)";
    let unrelated = "other 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)";
    scratch.output("owned", b"old inert bytes");
    scratch.output("other", b"unrelated inert bytes");
    scratch.ledger(&[(owner, &["owned"]), (unrelated, &["other"])]);
    let cancel = AtomicBool::new(false);
    let baseline = native::snapshot(&scratch.0, scratch.uid(), &cancel).unwrap();
    let affected = BTreeSet::from(["owned".into()]);
    assert!(native::preflight_names(&scratch.0, &baseline, &affected, Some(owner)).is_ok());
    assert!(native::preflight_names(&scratch.0, &baseline, &affected, Some(unrelated)).is_err());
    scratch.output("unmanaged", b"unmanaged inert bytes");
    assert!(
        native::preflight_names(
            &scratch.0,
            &baseline,
            &BTreeSet::from(["unmanaged".into()]),
            Some(owner)
        )
        .is_err()
    );
    scratch.output("owned", b"new inert bytes");
    let updated = native::snapshot(&scratch.0, scratch.uid(), &cancel).unwrap();
    native::preserved(&baseline, &updated, &affected, Some(owner)).unwrap();
    scratch.output("other", b"changed unrelated inert bytes");
    let drift = native::snapshot(&scratch.0, scratch.uid(), &cancel).unwrap();
    assert!(native::preserved(&baseline, &drift, &affected, Some(owner)).is_err());
    fs::write(scratch.0.join(".crates.toml"), "[v1]\n").unwrap();
    assert!(native::snapshot(&scratch.0, scratch.uid(), &cancel).is_err());
}

#[test]
fn partial_diagnosis_keeps_changed_missing_and_wrong_type_state_unbound() {
    let scratch = Scratch::new();
    let owner = "owned 1.0.0 (path+file:///disposable/source)";
    scratch.output("a", b"old a");
    let b = scratch.output("b", b"old b");
    scratch.ledger(&[(owner, &["a", "b"])]);
    let baseline = native::snapshot(&scratch.0, scratch.uid(), &AtomicBool::new(false)).unwrap();
    scratch.output("a", b"new a");
    fs::remove_file(&b).unwrap();
    fs::create_dir(&b).unwrap();
    let diagnosis = native::diagnose(
        &scratch.0,
        &BTreeSet::from(["a".into(), "b".into(), "missing".into()]),
        &baseline,
        scratch.uid(),
    );
    assert_eq!(diagnosis["outputs"]["a"]["state"], "changed-or-new-unbound");
    assert_eq!(
        diagnosis["outputs"]["b"]["state"],
        "missing-wrong-type-or-conflicting"
    );
    assert_eq!(diagnosis["tracking"]["state"], "incomplete-or-conflicting");
    assert!(b.is_dir());
}

#[test]
fn native_destination_precedence_uses_original_context() {
    let scratch = Scratch::new();
    let explicit = scratch.0.join("explicit");
    let environment = scratch.0.join("environment");
    let configured = scratch.0.join("configured");
    let home = scratch.0.join("home");
    assert_eq!(
        native::resolve_root(
            Some(&explicit),
            Some(&environment),
            Some(&configured),
            &home,
            &scratch.0
        )
        .unwrap(),
        explicit
    );
    assert_eq!(
        native::resolve_root(
            None,
            Some(&environment),
            Some(&configured),
            &home,
            &scratch.0
        )
        .unwrap(),
        environment
    );
    assert_eq!(
        native::resolve_root(None, None, Some(&configured), &home, &scratch.0).unwrap(),
        configured
    );
    assert_eq!(
        native::resolve_root(None, None, None, &home, &scratch.0).unwrap(),
        home
    );
    assert_eq!(
        native::resolve_root(Some(Path::new("relative")), None, None, &home, &scratch.0).unwrap(),
        scratch.0.join("relative")
    );
}

#[test]
fn cooperating_root_lock_refuses_overlap_and_preserves_changed_lock() {
    let scratch = Scratch::new();
    let lock = native::RootLock::acquire(&scratch.0, scratch.uid()).unwrap();
    assert!(native::RootLock::acquire(&scratch.0, scratch.uid()).is_err());
    lock.recheck().unwrap();
    drop(lock);
    let lock = native::RootLock::acquire(&scratch.0, scratch.uid()).unwrap();
    let path = scratch.0.join(".barbican-cargo-tool-operation.lock");
    fs::write(&path, b"external changed lock: preserve").unwrap();
    assert!(lock.recheck().is_err());
    drop(lock);
    assert_eq!(fs::read(&path).unwrap(), b"external changed lock: preserve");
}

#[test]
fn native_owner_digest_is_independent_of_unrelated_installs() {
    let scratch = Scratch::new();
    let owner = "owned 1.0.0 (path+file:///disposable/source)";
    let other = "other 1.0.0 (path+file:///another/source)";
    scratch.output("owned", b"owned inert bytes");
    scratch.ledger(&[(owner, &["owned"])]);
    let cancelled = AtomicBool::new(false);
    let selected = BTreeSet::from(["owned".into()]);
    let before =
        native::snapshot_scope(&scratch.0, scratch.uid(), &cancelled, Some(&selected)).unwrap();
    let digest = sha256(&canonical_bytes(&before.packages[owner]).unwrap());
    scratch.output("other", b"unrelated inert bytes");
    scratch.ledger(&[(owner, &["owned"]), (other, &["other"])]);
    let after =
        native::snapshot_scope(&scratch.0, scratch.uid(), &cancelled, Some(&selected)).unwrap();
    assert_eq!(before.outputs, after.outputs);
    assert_eq!(
        digest,
        sha256(&canonical_bytes(&after.packages[owner]).unwrap())
    );
}

#[test]
fn completing_prose_preserves_review_id_but_changes_assessment_identity() {
    let id = |kind| RecordId {
        kind,
        schema_version: SCHEMA_VERSION,
        sha256: sha256(b"fixture"),
    };
    let review = Review {
        schema_version: SCHEMA_VERSION,
        subject_id: id(RecordKind::Subject),
        policy_id: id(RecordKind::OriginPolicy),
        evidence_content_id: id(RecordKind::EvidenceContent),
        assessment_requirements: BTreeSet::from(["source".into(), "execution".into()]),
    };
    let review_id = review.id().unwrap();
    let prose = format!(
        "Cargo-Tool-Review: {review_id}\nReviewer: fixture reviewer\nDecision: ACCEPT\nResponse: source=Reviewed the exact harmless source fixture.\nResponse: execution=Accepted the fixture's ordinary native build effects.\nRisk-Acknowledgement: Accepted the stated static check and ordinary build limitations.\n"
    );
    let assessment = acceptance::assess(&review, prose.as_bytes(), 100).unwrap();
    assert!(
        acceptance::assess(
            &review,
            prose
                .replace("Decision: ACCEPT", "Decision: PENDING")
                .as_bytes(),
            100
        )
        .is_err()
    );
    assert!(
        acceptance::assess(
            &review,
            prose
                .replace("Response: source=", "Response: unknown=")
                .as_bytes(),
            100
        )
        .is_err()
    );
    let changed = acceptance::assess(
        &review,
        prose
            .replace("fixture reviewer", "another reviewer")
            .as_bytes(),
        100,
    )
    .unwrap();
    assert_eq!(review.id().unwrap(), review_id);
    assert_ne!(assessment.id().unwrap(), changed.id().unwrap());
}

#[test]
fn real_native_reviewed_two_bin_publication_matches_artifacts_and_survives_stage_deletion() {
    use super::process;
    use std::ffi::OsString;
    use std::sync::Arc;
    // Authored and reviewed inert fixture: no dependencies, build scripts or tool execution.
    const MANIFEST: &str = "[package]\nname = \"barbican-owned-apply-fixture\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[[bin]]\nname = \"barbican-owned-a\"\npath = \"a.rs\"\n[[bin]]\nname = \"barbican-owned-b\"\npath = \"b.rs\"\n";
    const PROGRAM: &str = "fn main() {}\n";
    const LOCK: &str =
        "version = 4\n[[package]]\nname = \"barbican-owned-apply-fixture\"\nversion = \"1.0.0\"\n";
    let scratch = Scratch::new();
    let source = scratch.0.join("reviewed-source");
    let home = scratch.0.join("home");
    let cargo_home = scratch.0.join("cargo-home");
    let target = scratch.0.join("fresh-target");
    let root = scratch.0.join("ordinary-install-root");
    for directory in [&source, &home, &cargo_home, &target, &root] {
        fs::create_dir(directory).unwrap();
    }
    fs::write(source.join("Cargo.toml"), MANIFEST).unwrap();
    fs::write(source.join("Cargo.lock"), LOCK).unwrap();
    fs::write(source.join("a.rs"), PROGRAM).unwrap();
    fs::write(source.join("b.rs"), PROGRAM).unwrap();
    let host =
        process::native_host().expect("native fixture requires a qualified host; no tests skipped");
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or(process::absolute_home().unwrap().join(".rustup"));
    let compiler = rustup_home
        .join("toolchains")
        .join(format!("1.95.0-{host}"))
        .join("bin");
    let budget = process::Budget::native(Arc::new(AtomicBool::new(false)));
    let cargo = process::Executable::capture(&compiler.join("cargo"), &budget)
        .expect("already trusted exact Cargo must be installed before tests");
    let rustc = process::Executable::capture(&compiler.join("rustc"), &budget)
        .expect("already trusted exact rustc must be installed before tests");
    let mut environment = process::base_environment(&home, &cargo_home, &rustc.path);
    environment.insert("CARGO_TARGET_DIR".into(), target.as_os_str().to_owned());
    let cargo_version = process::run(&cargo, &["-V"], &scratch.0, &environment, &budget).unwrap();
    assert!(cargo_version.status.success());
    assert!(
        String::from_utf8(cargo_version.stdout)
            .unwrap()
            .starts_with("cargo 1.95.0 ")
    );
    let args: Vec<OsString> = vec![
        "install".into(),
        "--path".into(),
        source.as_os_str().into(),
        "--root".into(),
        root.as_os_str().into(),
        "--frozen".into(),
        "--offline".into(),
        "--target".into(),
        host.into(),
        "--bin".into(),
        "barbican-owned-a".into(),
        "--bin".into(),
        "barbican-owned-b".into(),
        "--message-format=json".into(),
    ];
    let output = process::run(&cargo, &args, &scratch.0, &environment, &budget).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let selected = BTreeSet::from(["barbican-owned-a".into(), "barbican-owned-b".into()]);
    let artifacts = super::installation::artifact_outputs(
        &output.stdout,
        &target,
        &selected,
        scratch.uid(),
        &budget.cancelled,
    )
    .unwrap();
    let observed = native::snapshot(&root, scratch.uid(), &budget.cancelled).unwrap();
    for name in &selected {
        assert_eq!(artifacts[name], observed.outputs[name]);
    }
    assert_eq!(observed.owners.len(), 2);
    assert_eq!(observed.packages.len(), 1);
    fs::remove_dir_all(source).unwrap();
    assert_eq!(
        native::snapshot(&root, scratch.uid(), &budget.cancelled).unwrap(),
        observed
    );
    let drifted = root.join("bin/barbican-owned-a");
    fs::write(&drifted, b"inert replacement, never executed").unwrap();
    assert_ne!(
        native::snapshot(&root, scratch.uid(), &budget.cancelled)
            .unwrap()
            .outputs["barbican-owned-a"],
        observed.outputs["barbican-owned-a"]
    );
}

#[test]
fn failed_diagnostic_publication_preserves_native_failure_retained_effects_and_completed_id() {
    let scratch = Scratch::new();
    let owner = "owned 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)";
    let output = scratch.output("owned", b"inert original bytes; never executed");
    scratch.ledger(&[(owner, &["owned"])]);
    let before = native::snapshot(&scratch.0, scratch.uid(), &AtomicBool::new(false)).unwrap();
    fs::write(output, b"inert partially published replacement bytes").unwrap();
    let diagnosis = native::diagnose(
        &scratch.0,
        &BTreeSet::from(["owned".into()]),
        &before,
        scratch.uid(),
    );
    let store = crate::private_store::PrivateStore::open(&scratch.0.join("data"), &[]).unwrap();
    // An actual wrong-type state path prevents diagnostic publication.
    super::apply_records::publish(
        &store,
        Path::new("cargo-tools/v1/install-diagnostics"),
        &serde_json::json!("blocked by a regular file"),
        || Ok(()),
    )
    .unwrap();
    let intent = RecordId {
        kind: RecordKind::InstallIntent,
        schema_version: SCHEMA_VERSION,
        sha256: sha256(b"fixture intent"),
    };
    let completed = RecordId {
        kind: RecordKind::InstalledBinding,
        schema_version: SCHEMA_VERSION,
        sha256: sha256(b"fixture completed binding"),
    };
    for completion in [None, Some(&completed)] {
        let report = super::installation::failure_report(
            &store,
            &intent,
            completion,
            "native Cargo failed after publishing one output",
            &diagnosis,
        );
        assert!(report.contains("native Cargo failed after publishing one output"));
        assert!(report.contains("changed-or-new-unbound"));
        assert!(report.contains("Reconcile every affected output"));
        assert!(report.contains(&intent.to_string()));
        assert!(report.contains("diagnostic persistence failed"));
        if let Some(id) = completion {
            assert!(report.contains("installation-completed-before-late-failure"));
            assert!(report.contains(&id.to_string()));
        } else {
            assert!(report.contains("installation-incomplete"));
            assert!(report.contains("completed installation none"));
        }
    }
    assert!(
        store
            .root()
            .join("cargo-tools/v1/install-diagnostics")
            .is_file()
    );
}

// This journey authenticates no remote origin: its source is deliberately authored
// here, then passed through the production graph, scanner and application owners.
// It is enabled explicitly by the required native journey, never by ordinary tests.
mod lifecycle {
    use super::super::{
        admission, check, collection,
        context::NativeContext,
        frontend::{self, Context, StoredReview},
        installation, policy, process,
        source::Stage,
        store::Stores,
    };
    use super::*;
    use crate::cli::{
        AuditOutputFormat, ToolAcceptArgs, ToolAdmissionArgs, ToolFreshnessArgs, ToolInstallArgs,
    };

    const PACKAGE: &str = "barbican-owned-lifecycle";
    const ORIGIN: &str = "https://example.invalid/barbican-owned-lifecycle";

    fn cached() -> ToolFreshnessArgs {
        ToolFreshnessArgs {
            cached_admission: true,
            cache_reason: Some("Use this invocation's completed current scanner evidence for the explicitly authored native fixture journey.".into()),
            standalone: true,
            format: AuditOutputFormat::Json,
        }
    }

    struct Journey {
        ctx: Context,
        _stage: Stage,
    }
    impl Journey {
        fn new() -> Self {
            let stage = Stage::new().unwrap();
            let budget = process::Budget::new(false).unwrap();
            let evaluator =
                process::Evaluator::capture(None, None, &stage.root, &budget, true).unwrap();
            let stores = Stores::open(
                &stage.root,
                None,
                Some(&stage.root.join("data")),
                Some(&stage.root.join("cache")),
            )
            .unwrap();
            stores
                .data
                .publish(
                    Path::new("cargo-tools/v1/policy.toml"),
                    b"[delegates.advisories]\nlockfile_scanner = \"both\"\n",
                )
                .unwrap();
            stores
                .data
                .publish(
                    Path::new("cargo-tools/v1/deny.toml"),
                    format!(
                        "[licenses]\nallow = [\"MIT\"]\n[sources]\nallow-git = [\"{ORIGIN}\"]\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            let home = stage.root.join("native-home");
            fs::create_dir(&home).unwrap();
            Self {
                ctx: Context {
                    ioc_budget: Default::default(),
                    source_client: crate::crates_io_http::UreqCratesIoClient::new(
                        crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
                    ),
                    current: stage.root.clone(),
                    repo: None,
                    stores,
                    evaluator: Some(evaluator),
                    original_cargo_home: home.clone(),
                    native_root: home.clone(),
                    native: NativeContext {
                        cargo_home: home.clone(),
                        install_root: home,
                        configurations: Vec::new(),
                    },
                    now: acceptance::now().unwrap(),
                    budget,
                },
                _stage: stage,
            }
        }

        fn assert_cached_receipt(&self, result: &serde_json::Value, review: &StoredReview) {
            let path = PathBuf::from(result["cached_use_record"].as_str().unwrap());
            assert!(path.starts_with(self.ctx.stores.data.root()));
            let receipt: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(receipt["cache_reason"], cached().cache_reason.unwrap());
            assert_eq!(
                receipt["review_id"],
                serde_json::to_value(review.review.id().unwrap()).unwrap()
            );
            assert_eq!(
                receipt["observation_id"],
                serde_json::to_value(review.evidence.observation.id().unwrap()).unwrap()
            );
            assert_eq!(receipt["status"], "requested");
        }

        fn receipt(&self, label: &str, result: &serde_json::Value) {
            let Some(directory) = std::env::var_os("BARBICAN_TOOL_APPLY_RECEIPTS") else {
                return;
            };
            let directory = PathBuf::from(directory).join(label);
            assert!(directory.is_absolute());
            fn copy(source: &Path, destination: &Path) {
                fs::create_dir_all(destination).unwrap();
                for entry in fs::read_dir(source).unwrap() {
                    let entry = entry.unwrap();
                    let metadata = fs::symlink_metadata(entry.path()).unwrap();
                    assert!(!metadata.file_type().is_symlink());
                    if metadata.is_dir() {
                        copy(&entry.path(), &destination.join(entry.file_name()));
                    } else {
                        fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
                    }
                }
            }
            copy(
                self.ctx.stores.data.root(),
                &directory.join("private-fixture-evidence"),
            );
            fs::write(
                directory.join("result.json"),
                serde_json::to_vec_pretty(result).unwrap(),
            )
            .unwrap();
        }

        fn review_and_accept(
            &mut self,
            label: &str,
            main: &str,
            build: Option<&str>,
        ) -> StoredReview {
            self.ctx.now = acceptance::now().unwrap();
            let source = self.ctx.current.join(format!("authored-{label}"));
            fs::create_dir(&source).unwrap();
            fs::write(source.join("Cargo.toml"), format!("[package]\nname = \"{PACKAGE}\"\nversion = \"1.0.0\"\nedition = \"2024\"\nlicense = \"MIT\"\n[[bin]]\nname = \"barbican-lifecycle-a\"\npath = \"a.rs\"\n[[bin]]\nname = \"barbican-lifecycle-b\"\npath = \"b.rs\"\n")).unwrap();
            fs::write(
                source.join("Cargo.lock"),
                format!("version = 4\n[[package]]\nname = \"{PACKAGE}\"\nversion = \"1.0.0\"\n"),
            )
            .unwrap();
            fs::write(source.join("a.rs"), main).unwrap();
            fs::write(source.join("b.rs"), "fn main() {}\n").unwrap();
            if let Some(build) = build {
                fs::write(source.join("build.rs"), build).unwrap();
            }
            let request = collection::ReviewRequest {
                spec: None,
                git: Some(ORIGIN.into()),
                rev: Some(
                    sha256(format!("{label}\0{main}\0{build:?}").as_bytes()).as_str()[..40].into(),
                ),
                package: Some(PACKAGE.into()),
                bins: vec!["barbican-lifecycle-a".into(), "barbican-lifecycle-b".into()],
                features: Vec::new(),
                no_default_features: false,
                all_features: false,
                profile: "release".into(),
                target: None,
                from: None,
                cargo: self.ctx.evaluator().unwrap().cargo.path.clone(),
                rustc: self.ctx.evaluator().unwrap().rustc.path.clone(),
            };
            let prepared = collection::authored_fixture(&self.ctx, &request, &source).unwrap();
            let evidence = policy::collect(&self.ctx, &prepared).unwrap();
            assert!(evidence.content.complete);
            assert!(
                !evidence
                    .content
                    .findings
                    .iter()
                    .any(|finding| finding.blocking),
                "{:?}",
                evidence.content.findings
            );
            let review = Review {
                schema_version: SCHEMA_VERSION,
                subject_id: prepared.subject.id().unwrap(),
                policy_id: evidence.policy.id().unwrap(),
                evidence_content_id: evidence.content.id().unwrap(),
                assessment_requirements: [
                    "source-review",
                    "execution-surfaces",
                    "runtime-use",
                    "coverage-limitations",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            };
            prepared.save_sources(&self.ctx).unwrap();
            frontend::retain_details(&self.ctx, &review, &evidence.details).unwrap();
            let stored = StoredReview {
                subject: prepared.subject.clone(),
                policy: evidence.policy,
                review,
                evidence: EvidenceRecord {
                    content: evidence.content,
                    observation: evidence.observation,
                },
                request,
            };
            let review_id = frontend::save_review(&self.ctx, &stored).unwrap();
            let record = self.ctx.current.join(format!("assessment-{label}.md"));
            let mut assessment = format!(
                "Cargo-Tool-Review: {review_id}\nReviewer: authored native lifecycle fixture reviewer\nDecision: ACCEPT\n"
            );
            for requirement in &stored.review.assessment_requirements {
                assessment.push_str(&format!("Response: {requirement}=I reviewed the complete authored manifests, lockfile, both Rust entry points and optional build script shown below. This fixture has no dependencies. Its only accepted effects are native publication under this private test root and the explicitly shown owned scratch signal, destination-bin obstruction or index obstruction. The binaries are not executed; the synthetic Git identity provides no source authentication.\n"));
            }
            assessment.push_str("Risk-Acknowledgement: I accept these exact authored fixture build and publication effects in disposable owned directories; scanner coverage does not establish benign runtime behaviour or authenticate the synthetic Git origin.\n\nReviewed a.rs:\n");
            assessment.push_str(main);
            assessment.push_str("\nReviewed b.rs: fn main() {}\nReviewed optional build.rs:\n");
            assessment.push_str(build.unwrap_or("No build script."));
            fs::write(&record, &assessment).unwrap();
            let accepted = acceptance::accept(
                &self.ctx,
                &stored,
                &ToolAcceptArgs {
                    review_id: review_id.to_string(),
                    record,
                    approve_repo: false,
                    repo_record: None,
                    options: cached(),
                },
            )
            .unwrap();
            assert_eq!(accepted["status"], "locally-accepted");
            self.assert_cached_receipt(&accepted, &stored);
            self.receipt(label, &serde_json::json!({"qualification":"explicitly authored fixture; synthetic Git identity; no remote source authentication; no installed programs invoked", "subject":stored.subject,"review":stored.review,"evidence":stored.evidence,"assessment":assessment,"acceptance":accepted}));
            // Drop disposable initial preparation before install: the owner must use
            // the persisted accepted inputs and cannot depend on this source stage.
            drop(prepared);
            fs::remove_dir_all(source).unwrap();
            stored
        }

        fn install_args(&self, review: &StoredReview, root: &Path) -> ToolInstallArgs {
            ToolInstallArgs {
                review_id: review.review.id().unwrap().to_string(),
                root: Some(root.into()),
                replace_existing: false,
                options: cached(),
            }
        }
        fn bindings(&self) -> BTreeSet<RecordId> {
            let directory = self
                .ctx
                .stores
                .data
                .root()
                .join("cargo-tools/v1/records/installed-binding");
            match fs::read_dir(directory) {
                Ok(entries) => entries
                    .map(|entry| {
                        let bytes = fs::read(entry.unwrap().path()).unwrap();
                        barbican::cargo_tool::parse_record::<InstalledBinding>(&bytes)
                            .unwrap()
                            .id()
                            .unwrap()
                    })
                    .collect(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
                Err(error) => panic!("read bindings: {error}"),
            }
        }
    }

    #[test]
    fn native_application_owners_accept_install_check_admit_and_retain_failure_effects() {
        if std::env::var("BARBICAN_TOOL_APPLY_NATIVE").as_deref() != Ok("1") {
            return;
        }
        let mut journey = Journey::new();
        let guard_root = journey.ctx.current.join("evaluator-collision-control");
        fs::create_dir_all(guard_root.join("bin")).unwrap();
        let original_cargo = journey.ctx.evaluator.as_ref().unwrap().cargo.clone();
        let copied_cargo = guard_root.join("bin/owned-trusted-cargo");
        fs::copy(&original_cargo.path, &copied_cargo).unwrap();
        fs::set_permissions(&copied_cargo, fs::Permissions::from_mode(0o700)).unwrap();
        journey.ctx.evaluator.as_mut().unwrap().cargo =
            process::Executable::capture(&copied_cargo, &journey.ctx.budget).unwrap();
        let affected = BTreeSet::from(["owned-trusted-cargo".into()]);
        assert!(
            installation::guard_independent_evaluator(&journey.ctx, &guard_root, &affected)
                .unwrap_err()
                .contains("active trusted evaluator")
        );
        journey.ctx.evaluator.as_mut().unwrap().cargo = original_cargo;
        installation::guard_independent_evaluator(&journey.ctx, &guard_root, &affected).unwrap();
        eprintln!(
            "authored native application journey: synthetic Git identity; real graph, scanners and application owners; accepted build scripts only; no installed programs invoked"
        );
        let review = journey.review_and_accept("success", "fn main() {}\n", None);
        let (authority, existing_local, existing_assessment) =
            acceptance::load(&journey.ctx, &review).unwrap();
        let repeated = acceptance::accept(
            &journey.ctx,
            &review,
            &ToolAcceptArgs {
                review_id: review.review.id().unwrap().to_string(),
                record: authority.completed_record,
                approve_repo: false,
                repo_record: None,
                options: cached(),
            },
        )
        .unwrap();
        assert_eq!(
            repeated["assessment_id"],
            existing_assessment.id().unwrap().to_string()
        );
        assert_eq!(
            repeated["acceptance_id"],
            existing_local.id().unwrap().to_string(),
            "unchanged evidence and prose must not renew human acceptance time"
        );
        journey.assert_cached_receipt(&repeated, &review);
        let root = journey.ctx.current.join("installation-success");
        let mut args = journey.install_args(&review, &root);
        let installed = installation::install(&journey.ctx, &review, &args).unwrap();
        let mut id: RecordId = installed["installation_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(installed["status"], "installed-complete");
        journey.assert_cached_receipt(&installed, &review);
        assert_eq!(
            check::installation_check(&journey.ctx, &id).unwrap()["status"],
            "local-correspondence"
        );
        let mut admission = ToolAdmissionArgs {
            installation_id: id.to_string(),
            bin: "barbican-lifecycle-a".into(),
            executable: Some(root.join("bin/barbican-lifecycle-a")),
            lookup_path: false,
            cargo_subcommand: None,
            options: cached(),
        };
        assert_eq!(
            admission::admission_check(&journey.ctx, &id, &admission).unwrap()["continuing_unchanged_context"],
            false
        );
        assert_eq!(
            admission::admission_check(&journey.ctx, &id, &admission).unwrap()["continuing_unchanged_context"],
            true
        );
        let unchanged = installation::install(&journey.ctx, &review, &args).unwrap();
        assert_eq!(unchanged["installation_id"], id.to_string());
        assert_eq!(unchanged["unchanged"], true);
        journey.assert_cached_receipt(&unchanged, &review);
        assert_ne!(
            unchanged["cached_use_record"],
            installed["cached_use_record"]
        );
        let (authority, old_acceptance, _) = acceptance::load(&journey.ctx, &review).unwrap();
        let mut amended = fs::read_to_string(&authority.completed_record).unwrap();
        amended.push_str("\nCompleted reassessment: I reviewed the same exact authored source again and retain the explicitly bounded fixture build and publication decision.\n");
        fs::write(&authority.completed_record, amended).unwrap();
        let reapproved = acceptance::accept(
            &journey.ctx,
            &review,
            &ToolAcceptArgs {
                review_id: review.review.id().unwrap().to_string(),
                record: authority.completed_record,
                approve_repo: false,
                repo_record: None,
                options: cached(),
            },
        )
        .unwrap();
        assert_ne!(
            reapproved["acceptance_id"],
            old_acceptance.id().unwrap().to_string()
        );
        assert!(admission::admission_check(&journey.ctx, &id, &admission).is_err());
        let reapplied = installation::install(&journey.ctx, &review, &args).unwrap();
        let new_id: RecordId = reapplied["installation_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(new_id, id);
        id = new_id;
        admission.installation_id = id.to_string();
        assert_eq!(
            admission::admission_check(&journey.ctx, &id, &admission).unwrap()["status"],
            "consumer-admission"
        );
        // The pre-feature input is an explicitly authored native-state fixture,
        // not evidence of old binary provenance. Native Cargo owns the real update.
        let bootstrap = Scratch::new();
        let old_owner = format!(
            "{PACKAGE} 0.9.0 (git+{ORIGIN}?tag=older#{})",
            &sha256(b"synthetic older original commit").as_str()[..40]
        );
        let unrelated_owner =
            "unrelated-fixture 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)";
        bootstrap.output(
            "barbican-lifecycle-a",
            b"inert pre-feature old selected output",
        );
        bootstrap.output("excluded-old", b"inert pre-feature excluded output");
        bootstrap.output("unrelated-fixture", b"inert unrelated preserved output");
        bootstrap.ledger(&[
            (&old_owner, &["barbican-lifecycle-a", "excluded-old"]),
            (unrelated_owner, &["unrelated-fixture"]),
        ]);
        let baseline =
            native::snapshot(&bootstrap.0, bootstrap.uid(), journey.ctx.cancelled()).unwrap();
        let mut bootstrap_args = journey.install_args(&review, &bootstrap.0);
        assert!(
            installation::install(&journey.ctx, &review, &bootstrap_args)
                .unwrap_err()
                .contains("--replace-existing")
        );
        bootstrap_args.replace_existing = true;
        let replaced = installation::install(&journey.ctx, &review, &bootstrap_args).unwrap();
        let replaced_id: RecordId = replaced["installation_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let after =
            native::snapshot(&bootstrap.0, bootstrap.uid(), journey.ctx.cancelled()).unwrap();
        assert_eq!(
            after.outputs["unrelated-fixture"],
            baseline.outputs["unrelated-fixture"]
        );
        assert_eq!(
            after.owners["unrelated-fixture"],
            baseline.owners["unrelated-fixture"]
        );
        if let Some(retained) = after.outputs.get("excluded-old") {
            assert_eq!(retained, &baseline.outputs["excluded-old"]);
            assert_eq!(
                after.owners["excluded-old"],
                baseline.owners["excluded-old"]
            );
            assert_eq!(
                replaced["retained_excluded_outputs"],
                serde_json::json!(["excluded-old"])
            );
            assert!(!replaced["excluded_output_observations"]["excluded-old"].is_null());
        } else {
            assert_eq!(
                replaced["removed_excluded_outputs"],
                serde_json::json!(["excluded-old"])
            );
            assert!(replaced["excluded_output_observations"]["excluded-old"].is_null());
        }
        assert_eq!(
            check::installation_check(&journey.ctx, &replaced_id).unwrap()["status"],
            "local-correspondence"
        );

        fs::write(
            root.join("bin/barbican-lifecycle-b"),
            b"inert drift of the other output",
        )
        .unwrap();
        assert!(check::installation_check(&journey.ctx, &id).is_err());
        assert!(admission::admission_check(&journey.ctx, &id, &admission).is_err());
        assert!(installation::install(&journey.ctx, &review, &args).is_err());
        args.replace_existing = true;
        assert!(
            installation::install(&journey.ctx, &review, &args).is_err(),
            "replacement flag cannot bypass an existing binding's drift"
        );

        let failed_root = journey.ctx.current.join("installation-failure");
        let baseline = installation::install(
            &journey.ctx,
            &review,
            &journey.install_args(&review, &failed_root),
        )
        .unwrap();
        let baseline_id: RecordId = baseline["installation_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let original_a = output_files::observe(
            &failed_root.join("bin/barbican-lifecycle-a"),
            journey.ctx.uid().unwrap(),
            true,
            journey.ctx.cancelled(),
        )
        .unwrap();
        let conflict = failed_root.join("bin/barbican-lifecycle-b");
        let build = format!(
            "fn main() {{ let path = std::path::Path::new({:?}); std::fs::remove_file(path).unwrap(); std::fs::create_dir(path).unwrap(); std::fs::write(path.join(\"keep\"), b\"accepted owned conflict; preserve on failure\").unwrap(); }}\n",
            conflict.to_str().unwrap()
        );
        let failed = journey.review_and_accept(
            "native-partial-failure",
            "fn main() { std::hint::black_box(42); }\n",
            Some(&build),
        );
        assert!(
            conflict.is_file(),
            "collection and acceptance must not execute the authored build script"
        );
        let before = journey.bindings();
        let args = journey.install_args(&failed, &failed_root);
        let error = installation::install(&journey.ctx, &failed, &args).unwrap_err();
        assert!(error.contains("native Cargo install failed"), "{error}");
        assert!(
            error.contains("installation-incomplete") && error.contains("retained effects"),
            "{error}"
        );
        assert_eq!(journey.bindings(), before);
        assert!(
            error.contains("changed-or-new-unbound")
                && error.contains("missing-wrong-type-or-conflicting"),
            "{error}"
        );
        assert_ne!(
            output_files::observe(
                &failed_root.join("bin/barbican-lifecycle-a"),
                journey.ctx.uid().unwrap(),
                true,
                journey.ctx.cancelled()
            )
            .unwrap()
            .sha256,
            original_a.sha256
        );
        assert_eq!(
            fs::read(conflict.join("keep")).unwrap(),
            b"accepted owned conflict; preserve on failure"
        );
        assert!(check::installation_check(&journey.ctx, &baseline_id).is_err());
        journey.receipt("native-partial-failure-result", &serde_json::json!({"primary_error":error,"previous_binding":baseline_id.to_string(),"new_complete_binding":false}));

        let signal = journey.ctx.current.join("accepted-build-started");
        let build = format!(
            "fn main() {{ std::fs::write({:?}, b\"accepted fixture build started\").unwrap(); std::thread::sleep(std::time::Duration::from_secs(30)); }}\n",
            signal.to_str().unwrap()
        );
        let cancelled = journey.review_and_accept("cancel", "fn main() {}\n", Some(&build));
        assert!(
            !signal.exists(),
            "no build-script effect before accepted installation"
        );
        let args = journey.install_args(
            &cancelled,
            &journey.ctx.current.join("installation-cancelled"),
        );
        let cancellation = journey.ctx.budget.cancelled.clone();
        let watcher = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
            while !signal.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            assert!(
                signal.exists(),
                "accepted build never reached its explicit cancellation signal"
            );
            cancellation.store(true, Ordering::SeqCst);
        });
        let error = installation::install(&journey.ctx, &cancelled, &args).unwrap_err();
        watcher.join().unwrap();
        journey.ctx.budget.cancelled.store(false, Ordering::SeqCst);
        assert!(
            error.contains("cancelled")
                && error.contains("installation-incomplete")
                && error.contains("retained effects"),
            "{error}"
        );
        assert_eq!(journey.bindings(), before);

        let late_root = journey.ctx.current.join("installation-late-failure");
        let index =
            journey
                .ctx
                .stores
                .data
                .root()
                .join(super::super::apply_records::deployment_path(
                    late_root.to_str().unwrap(),
                    PACKAGE,
                ));
        let build = format!(
            "fn main() {{ std::fs::create_dir_all({:?}).unwrap(); }}\n",
            index.to_str().unwrap()
        );
        let late = journey.review_and_accept("late-failure", "fn main() {}\n", Some(&build));
        assert!(
            !index.exists(),
            "no build-script index obstruction before accepted installation"
        );
        let error = installation::install(
            &journey.ctx,
            &late,
            &journey.install_args(&late, &late_root),
        )
        .unwrap_err();
        assert!(
            error.contains("installation-completed-before-late-failure")
                && error.contains("retained effects"),
            "{error}"
        );
        let added: Vec<_> = journey.bindings().difference(&before).cloned().collect();
        assert_eq!(added.len(), 1);
        assert!(error.contains(&added[0].to_string()));
        assert_eq!(
            check::installation_check(&journey.ctx, &added[0]).unwrap()["status"],
            "local-correspondence"
        );
        journey.receipt("completed", &serde_json::json!({"qualification":"authored native application owner journey, synthetic Git identity, accepted fixture build scripts executed, no installed programs invoked", "installation":id.to_string(), "late_completed_installation":added[0].to_string(), "native_failure_and_cancellation":"no complete binding", "late_failure":error}));
        eprintln!(
            "native application owner journey PASS: completed {}, failed/cancelled without binding, late completed {} retained; no installed programs invoked",
            id, added[0]
        );
    }
}

#[test]
fn cached_use_is_durable_per_invocation_and_never_becomes_default_authority() {
    let scratch = Scratch::new();
    let store = crate::private_store::PrivateStore::open(&scratch.0.join("data"), &[]).unwrap();
    let id = |kind| RecordId {
        kind,
        schema_version: SCHEMA_VERSION,
        sha256: sha256(b"exact cached invocation fixture"),
    };
    let review = Review {
        schema_version: SCHEMA_VERSION,
        subject_id: id(RecordKind::Subject),
        policy_id: id(RecordKind::OriginPolicy),
        evidence_content_id: id(RecordKind::EvidenceContent),
        assessment_requirements: BTreeSet::from(["source-review".into()]),
    };
    let observation = id(RecordKind::Observation);
    let cached = OperationIntent { operation: OperationKind::Install, freshness: FreshnessIntent::Cached { reason: "Explicitly use this exact completed observation for the isolated fixture invocation.".into() } };
    let path = super::apply_records::cached_use(&store, &review, &observation, &cached, || Ok(()))
        .unwrap()
        .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        saved["cache_reason"],
        "Explicitly use this exact completed observation for the isolated fixture invocation."
    );
    assert_eq!(saved["status"], "requested");
    assert_eq!(saved["freshness_mode"], "cached");
    assert_eq!(
        saved["review_id"],
        serde_json::to_value(review.id().unwrap()).unwrap()
    );
    assert_eq!(
        saved["observation_id"],
        serde_json::to_value(&observation).unwrap()
    );
    assert!(saved["requested_at_utc"].as_u64().unwrap() > 0);
    let another =
        super::apply_records::cached_use(&store, &review, &observation, &cached, || Ok(()))
            .unwrap()
            .unwrap();
    assert_ne!(
        path, another,
        "each invocation has an immutable separate intent receipt"
    );
    let online = OperationIntent {
        operation: OperationKind::Install,
        freshness: FreshnessIntent::Online {
            started_at_utc: acceptance::now().unwrap(),
        },
    };
    assert!(
        super::apply_records::cached_use(&store, &review, &observation, &online, || panic!(
            "online invocation must not write cached intent"
        ))
        .unwrap()
        .is_none()
    );
    let records = path.parent().unwrap();
    assert_eq!(fs::read_dir(records).unwrap().count(), 2);
    assert!(
        super::apply_records::cached_use(&store, &review, &observation, &cached, || Err(
            "fixture final publication guard refused".into()
        ))
        .unwrap_err()
        .contains("publication guard refused")
    );
    assert_eq!(fs::read_dir(records).unwrap().count(), 2);
    assert_eq!(
        fs::read(&path).unwrap(),
        serde_json::to_vec(&saved).unwrap()
    );
}
