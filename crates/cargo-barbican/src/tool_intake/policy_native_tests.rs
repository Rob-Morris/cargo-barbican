use super::super::{collection, context::NativeContext, source, store::Stores};
use super::*;
use crate::command_runner::CommandOutput;
use std::fs;
use std::path::PathBuf;

const ORIGIN: &str = "https://example.invalid/barbican-owned-policy-matrix";
const ADVISORY: &str = "RUSTSEC-2020-0071";
const QUALIFICATION: &str = "Authored inert source only. Git origins and registry release/API/archive identity are explicitly synthetic scanner transport fixtures, not publisher authentication. Actual trusted Cargo metadata/tree and cargo-deny/cargo-audit run; fixture code is never built, installed or executed.";

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn context(stage: &source::Stage) -> Context {
    let budget = process::Budget::new(false).unwrap();
    let evaluator = process::Evaluator::capture(None, None, &stage.root, &budget, true).unwrap();
    let stores = Stores::open(
        &stage.root,
        None,
        Some(&stage.root.join("data")),
        Some(&stage.root.join("cache")),
    )
    .unwrap();
    let native = stage.root.join("native");
    fs::create_dir(&native).unwrap();
    Context {
        ioc_budget: Default::default(),
        source_client: crate::crates_io_http::UreqCratesIoClient::new(
            crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
        ),
        current: stage.root.clone(),
        repo: None,
        stores,
        evaluator: Some(evaluator),
        original_cargo_home: native.clone(),
        native_root: native.clone(),
        native: NativeContext {
            cargo_home: native.clone(),
            install_root: native,
            configurations: Vec::new(),
        },
        now: barbican::OffsetDateTime::now_utc().unix_timestamp(),
        budget,
    }
}

fn policy_file(ctx: &Context, relative: &str, content: &[u8]) {
    let path = Path::new(relative);
    match ctx
        .stores
        .data
        .read_optional(path, MAX_RECORD_BYTES as u64)
        .unwrap()
    {
        Some(previous) => ctx.stores.data.replace(&previous, content).unwrap(),
        None => ctx.stores.data.publish(path, content).unwrap(),
    }
}

fn configure(ctx: &Context, exceptions: &[String], native_ignore: bool) {
    policy_file(
        ctx,
        "cargo-tools/v1/policy.toml",
        format!(
            "[delegates.advisories]\nlockfile_scanner=\"both\"\n[tools]\nexception_records={}\n",
            serde_json::to_string(exceptions).unwrap()
        )
        .as_bytes(),
    );
    policy_file(ctx, "cargo-tools/v1/deny.toml", format!(
        "[licenses]\nallow=[\"MIT\"]\n[sources]\nunknown-git=\"deny\"\nallow-git=[{origin}]\n[graph]\nexclude=[\"owned-normal\",\"owned-builder\"]\n[advisories]\nignore={ignores}\n",
        origin=json!(ORIGIN), ignores=if native_ignore {json!([ADVISORY])}else{json!([])}).as_bytes());
}

fn fixture(
    ctx: &Context,
    root_advisory: bool,
    normal_license: &str,
    build_license: &str,
) -> PreparedSource {
    let authored = source::Stage::new().unwrap();
    let (root_name, root_version) = if root_advisory {
        ("time", "0.1.44")
    } else {
        ("owned-policy-root", "1.0.0")
    };
    write(
        &authored.root,
        "Cargo.toml",
        &format!(
            "[workspace]\nmembers=[\"normal\",\"builder\",\"dev-only\",\"inactive\",\"unselected\"]\nresolver=\"3\"\n[package]\nname={name}\nversion={version}\nedition=\"2024\"\nlicense=\"MIT\"\nbuild=\"build.rs\"\n[[bin]]\nname=\"owned-policy-tool\"\npath=\"main.rs\"\n[dependencies]\nowned-normal={{path=\"normal\"}}\n[build-dependencies]\nowned-builder={{path=\"builder\"}}\n[dev-dependencies]\nowned-dev-only={{path=\"dev-only\"}}\n[target.'cfg(target_os = \"none\")'.dependencies]\nowned-inactive={{path=\"inactive\"}}\nowned-normal={{path=\"normal\"}}\n[target.'cfg(unix)'.dependencies]\nowned-normal={{path=\"normal\"}}\n[target.'cfg(target_os = \"none\")'.build-dependencies]\nowned-builder={{path=\"builder\"}}\n[target.'cfg(unix)'.build-dependencies]\nowned-builder={{path=\"builder\"}}\n",
            name = json!(root_name),
            version = json!(root_version)
        ),
    );
    write(&authored.root, "main.rs", "fn main() {}\n");
    write(&authored.root, "build.rs", "fn main() {}\n");
    for (directory, license) in [
        ("normal", normal_license),
        ("builder", build_license),
        ("dev-only", "GPL-3.0-only"),
        ("inactive", "GPL-3.0-only"),
        ("unselected", "GPL-3.0-only"),
    ] {
        write(
            &authored.root,
            &format!("{directory}/Cargo.toml"),
            &format!(
                "[package]\nname=\"owned-{directory}\"\nversion=\"1.0.0\"\nedition=\"2024\"\nlicense={}\n",
                json!(license)
            ),
        );
        write(
            &authored.root,
            &format!("{directory}/src/lib.rs"),
            "pub fn inert() {}\n",
        );
    }
    write(
        &authored.root,
        "deny.toml",
        &format!(
            "[licenses]\nallow=[\"MIT\",\"GPL-3.0-only\"]\n[advisories]\nignore=[{}]\n",
            json!(ADVISORY)
        ),
    );
    let revision = source::inventory_digest(
        &source::inventory(&authored.root, "authored", &ctx.budget).unwrap(),
    )
    .unwrap();
    let evaluator = ctx.evaluator().unwrap();
    let request = collection::ReviewRequest {
        spec: None,
        git: Some(ORIGIN.into()),
        rev: Some(revision.as_str()[..40].into()),
        package: Some(root_name.into()),
        bins: vec!["owned-policy-tool".into()],
        features: Vec::new(),
        no_default_features: false,
        all_features: false,
        profile: "release".into(),
        target: None,
        from: None,
        cargo: evaluator.cargo.path.clone(),
        rustc: evaluator.rustc.path.clone(),
    };
    let prepared = collection::authored_fixture(ctx, &request, &authored.root).unwrap();
    assert_eq!(
        prepared
            .subject
            .graph
            .packages()
            .iter()
            .map(|package| package.name.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([root_name, "owned-normal", "owned-builder"])
    );
    assert_eq!(prepared.metadata["packages"].as_array().unwrap().len(), 6);
    assert!(
        prepared
            .subject
            .graph
            .edges
            .iter()
            .any(|edge| edge.kind == DependencyKind::Build)
    );
    assert!(
        prepared
            .subject
            .graph
            .edges
            .iter()
            .any(|edge| edge.kind == DependencyKind::Normal)
    );
    let declared_targets = BTreeSet::from([
        String::new(),
        "cfg(unix)".into(),
        "cfg(target_os = \"none\")".into(),
    ]);
    for edge in &prepared.subject.graph.edges {
        assert_eq!(edge.declared_targets, declared_targets);
    }
    let projected = project(&prepared).unwrap();
    let mut single_declaration_graph = prepared.subject.graph.clone();
    single_declaration_graph.edges = single_declaration_graph
        .edges
        .into_iter()
        .map(|mut edge| {
            edge.declared_targets = BTreeSet::from([String::new()]);
            edge
        })
        .collect();
    let original_graph = prepared.subject.graph.clone();
    let mut prepared = prepared;
    prepared.subject.graph = single_declaration_graph;
    let single_declaration = project(&prepared).unwrap();
    assert_eq!(projected.lock, single_declaration.lock);
    assert_eq!(
        projected.metadata["packages"],
        single_declaration.metadata["packages"]
    );
    prepared.subject.graph = original_graph;
    prepared
}

fn replace_identity(
    prepared: &mut PreparedSource,
    previous: &PackageIdentity,
    next: &PackageIdentity,
    inspection: barbican::ioc::Inspection,
) {
    // These are synthetic native-scanner transport identities. Changing one
    // also requires a real scan under its new source/scope identity; keeping
    // the old map would correctly fail production required-coverage checks.
    assert_eq!(inspection.source, barbican::ioc::Source::from(next));
    inspection.validate().unwrap();
    assert!(matches!(
        inspection.coverage,
        barbican::ioc::Coverage::Complete
    ));
    let previous_inspection = prepared.ioc_inspections.remove(previous).unwrap();
    assert_eq!(
        previous_inspection.source,
        barbican::ioc::Source::from(previous)
    );
    assert!(
        prepared
            .ioc_inspections
            .insert(next.clone(), inspection)
            .is_none()
    );
    for identity in prepared.origins.values_mut() {
        if identity == previous {
            *identity = next.clone();
        }
    }
    for node in prepared.subject.graph.nodes.values_mut() {
        if node.package == *previous {
            node.package = next.clone();
        }
    }
}

fn archive(root: &Path, package: &PackageIdentity, budget: &process::Budget) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for input in source::inventory(root, "archive", budget)
        .unwrap()
        .iter()
        .filter(|input| input.kind == InputKind::RegularFile)
    {
        let relative = input.path.strip_prefix("archive/").unwrap();
        if relative == "Cargo.lock" {
            continue;
        }
        let bytes = fs::read(root.join(relative)).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{}-{}/{relative}", package.name, package.version),
                bytes.as_slice(),
            )
            .unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let mut crc = 0xffff_ffff_u32;
    for byte in &tar {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320_u32.wrapping_mul(crc & 1));
        }
    }
    let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    gzip.extend(miniz_oxide::deflate::compress_to_vec(&tar, 6));
    gzip.extend((!crc).to_le_bytes());
    gzip.extend((tar.len() as u32).to_le_bytes());
    gzip
}

fn synthetic_registry_root(ctx: &Context, prepared: &mut PreparedSource) {
    let previous = prepared.subject.root.package();
    let archive = archive(&prepared.root, &previous, &ctx.budget);
    let checksum = sha256(&archive);
    let package = PackageIdentity {
        name: previous.name.clone(),
        version: previous.version.clone(),
        source: PackageSource::CratesIo {
            archive_sha256: checksum.clone(),
        },
    };
    let release = barbican::CrateRelease {
        checksum_sha256_hex: checksum,
        published_at_raw: "2020-09-13T12:26:40Z".into(),
        published_at: barbican::OffsetDateTime::from_unix_timestamp(1_600_000_000).unwrap(),
        yanked: false,
    };
    let report = barbican::inspect_published_crate_at(
        format!("{}@{}", package.name, package.version)
            .parse()
            .unwrap(),
        release,
        &archive,
        barbican::OffsetDateTime::from_unix_timestamp(ctx.now).unwrap(),
        7,
        None,
    );
    assert!(report.checksum_matches());
    assert!(report.ioc_hits().is_empty());
    assert!(
        report.inspection_failures().is_empty(),
        "{:?}",
        report.inspection_failures()
    );
    assert!(report.release_age().is_success());
    let source_fact=SourceFact {key:KnowledgeKey::Package {package:package.clone()},facts_sha256:digest(&json!({"fixture":QUALIFICATION,"archive_sha256":sha256(&archive),"yanked":false,"published_at":"2020-09-13T12:26:40Z"})).unwrap(),status:SecurityStatus::Clear,expires_at_utc:None};
    let inspection=SourceFact {key:KnowledgeKey::Inspection {package:package.clone(),inspector_sha256:ctx.evaluator().unwrap().inspector.sha256.clone()},facts_sha256:digest(&json!({"fixture":QUALIFICATION,"archive_sha256":sha256(&archive),"checksum_matches":report.checksum_matches(),"failures":report.inspection_failures(),"build_scripts":report.build_script_paths()})).unwrap(),status:SecurityStatus::Clear,expires_at_utc:None};
    remember(ctx, &source_fact, 1).unwrap();
    remember(ctx, &inspection, 1).unwrap();
    replace_identity(
        prepared,
        &previous,
        &package,
        report.ioc_inspection().unwrap().clone(),
    );
    prepared.subject.root = RootSourceIdentity::CratesIo {
        name: package.name.clone(),
        version: package.version.clone(),
        archive_sha256: sha256(&archive),
    };
    prepared.inspected.insert(package.clone(), report);
    prepared.source_facts.insert(package, source_fact);
    prepared.subject.validate().unwrap();
}

fn copy_receipts(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        assert!(!metadata.file_type().is_symlink());
        if metadata.is_dir() {
            copy_receipts(&entry.path(), &destination.join(entry.file_name()));
        } else {
            fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        }
    }
}
fn record(ctx: &Context, prepared: &PreparedSource, label: &str, result: &Result<PolicyEvidence>) {
    if let Some(root) = std::env::var_os("BARBICAN_TOOL_POLICY_RECEIPTS") {
        let destination = PathBuf::from(root).join(label);
        assert!(destination.is_absolute());
        fs::create_dir_all(&destination).unwrap();
        let body = match result {
            Ok(evidence) => {
                json!({"qualification":QUALIFICATION,"subject":prepared.subject,"policy":evidence.policy,"content":evidence.content,"observation":evidence.observation,"details":evidence.details})
            }
            Err(error) => {
                json!({"qualification":QUALIFICATION,"error":error,"subject":prepared.subject})
            }
        };
        fs::write(
            destination.join("result.json"),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
        let raw = ctx.stores.data.root().join(format!(
            "cargo-tools/v1/policy-dossier/{}",
            prepared.subject.id().unwrap().sha256
        ));
        if raw.exists() {
            copy_receipts(&raw, &destination.join("native-output"));
        }
    }
}
fn collected(ctx: &Context, prepared: &PreparedSource, label: &str) -> PolicyEvidence {
    eprintln!("policy native matrix: {label}");
    let result = collect(ctx, prepared);
    record(ctx, prepared, label, &result);
    result.unwrap_or_else(|error| panic!("{label}: {error}"))
}
fn refused(ctx: &Context, prepared: &PreparedSource, label: &str, message: &str) {
    let result = collect(ctx, prepared);
    record(ctx, prepared, label, &result);
    match result {
        Err(error) => assert!(error.contains(message), "{label}: {error}"),
        Ok(_) => panic!("{label}: invalid scanner input was accepted"),
    }
}
fn diagnostic_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(name) = fields
                .get("Krate")
                .and_then(|krate| krate.get("name"))
                .and_then(Value::as_str)
            {
                names.insert(name.into());
            }
            for value in fields.values() {
                diagnostic_names(value, names);
            }
        }
        Value::Array(values) => {
            for value in values {
                diagnostic_names(value, names);
            }
        }
        _ => {}
    }
}
fn native_errors(evidence: &PolicyEvidence) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for diagnostic in evidence.details["native_deny_diagnostics"]
        .as_array()
        .unwrap()
    {
        if diagnostic["severity"] == "error" {
            diagnostic_names(&diagnostic["graphs"], &mut names);
        }
    }
    names
}
fn assert_blocked(evidence: &PolicyEvidence, identity: &str, package: &str) {
    assert!(evidence.content.complete);
    assert!(
        evidence
            .content
            .findings
            .iter()
            .any(|finding| finding.identity == identity && finding.blocking)
    );
    assert!(
        native_errors(evidence).contains(package),
        "missing exact native failing member {package}: {}",
        evidence.details
    );
}
fn native_output(ctx: &Context, prepared: &PreparedSource, scanner: &str) -> CommandOutput {
    let directory = ctx.stores.data.root().join(format!(
        "cargo-tools/v1/policy-dossier/{}",
        prepared.subject.id().unwrap().sha256
    ));
    for entry in fs::read_dir(directory).unwrap() {
        let raw: Value = serde_json::from_slice(&fs::read(entry.unwrap().path()).unwrap()).unwrap();
        if raw["scanner"] == scanner {
            return CommandOutput {
                stdout: raw["stdout"].as_str().unwrap().into(),
                stderr: raw["stderr"].as_str().unwrap().into(),
                exit_code: raw["status"].as_i64().map(|value| value as i32),
            };
        }
    }
    panic!("missing actual {scanner} receipt")
}

#[test]
fn native_policy_matrix_preserves_sources_closure_advisories_and_refuses_bad_coverage() {
    if std::env::var("BARBICAN_TOOL_POLICY_NATIVE").as_deref() != Ok("1") {
        return;
    }
    eprintln!("{QUALIFICATION}");
    let stage = source::Stage::new().unwrap();
    let mut ctx = context(&stage);
    configure(&ctx, &[], false);
    let mut baseline = fixture(&ctx, false, "MIT", "MIT");
    let clean = collected(&ctx, &baseline, "closure-excludes-dev-inactive-unselected");
    clean
        .content
        .applicable(&baseline.subject, &clean.policy)
        .unwrap();
    assert_eq!(
        clean
            .content
            .facts
            .iter()
            .filter(|fact| matches!(fact.key, KnowledgeKey::Package { .. }))
            .count(),
        3
    );
    assert!(native_errors(&clean).is_empty());
    let normal = fixture(&ctx, false, "GPL-3.0-only", "MIT");
    let normal_evidence = collected(
        &ctx,
        &normal,
        "normal-license-origin-graph-exclusion-neutralised",
    );
    assert_blocked(&normal_evidence, "cargo-deny-licenses", "owned-normal");
    let builder = fixture(&ctx, false, "MIT", "GPL-3.0-only");
    let builder_evidence = collected(
        &ctx,
        &builder,
        "build-license-candidate-policy-not-authority",
    );
    assert_blocked(&builder_evidence, "cargo-deny-licenses", "owned-builder");
    for name in ["owned-normal", "owned-builder"] {
        let old = baseline
            .subject
            .graph
            .packages()
            .into_iter()
            .find(|package| package.name == name)
            .unwrap();
        let mut changed = old.clone();
        let PackageSource::Git { url, .. } = &mut changed.source else {
            panic!("expected Git transport")
        };
        *url = format!("https://example.invalid/forbidden-{name}");
        let inspection = crate::ioc_intake::inspect_tree(
            &ctx.stores,
            &ctx.budget,
            &baseline.root,
            barbican::ioc::Source::from(&changed),
            &mut ctx.ioc_budget.borrow_mut(),
        )
        .unwrap();
        replace_identity(&mut baseline, &old, &changed, inspection);
    }
    let source_evidence = collected(&ctx, &baseline, "normal-and-build-original-source-denied");
    for name in ["owned-normal", "owned-builder"] {
        assert_blocked(&source_evidence, "cargo-deny-sources", name);
    }
    let original_metadata = baseline.metadata.clone();
    baseline.metadata["packages"]
        .as_array_mut()
        .unwrap()
        .retain(|package| package["name"] != "owned-builder");
    refused(
        &ctx,
        &baseline,
        "missing-required-build-member",
        "absent from scanner source metadata",
    );
    baseline.metadata = original_metadata.clone();
    baseline.metadata["packages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|package| package["name"] == "owned-builder")
        .unwrap()["name"] = json!("contradictory-native-identity");
    refused(
        &ctx,
        &baseline,
        "contradictory-native-origin",
        "contradicts authenticated origin",
    );
    baseline.metadata = original_metadata;
    let builder_id = baseline
        .origins
        .iter()
        .find(|(_, package)| package.name == "owned-builder")
        .unwrap()
        .0
        .clone();
    baseline.origins.remove(&builder_id);
    refused(
        &ctx,
        &baseline,
        "unbound-required-build-member",
        "absent from scanner source metadata",
    );

    configure(&ctx, &[], true);
    let mut vulnerable = fixture(&ctx, true, "MIT", "MIT");
    synthetic_registry_root(&ctx, &mut vulnerable);
    let advisory = collected(
        &ctx,
        &vulnerable,
        "registry-labelled-binary-root-advisory-native-ignore-neutralised",
    );
    let affected = advisory
        .content
        .findings
        .iter()
        .find(|finding| finding.identity == ADVISORY && finding.blocking)
        .expect("native root advisory missing");
    assert_eq!(affected.package, vulnerable.subject.root.package());
    assert!(matches!(
        affected.package.source,
        PackageSource::CratesIo { .. }
    ));
    assert!(
        advisory
            .content
            .findings
            .iter()
            .any(|finding| finding.identity == "native-ignores:deny.toml")
    );
    assert!(advisory.content.facts.iter().any(|fact|matches!(&fact.key,KnowledgeKey::Advisory {package,identity:AdvisoryIdentity::Assigned {rustsec_id},..} if package==&affected.package&&rustsec_id==ADVISORY)&&fact.status==SecurityStatus::Adverse));
    let deny = native_output(&ctx, &vulnerable, "cargo-deny");
    let audit_output = native_output(&ctx, &vulnerable, "cargo-audit");
    assert!(
        audit::parse_deny_evidence(&deny)
            .unwrap()
            .findings()
            .iter()
            .any(|finding| finding.advisory_id().to_string() == ADVISORY
                && finding.package().crate_name() == "time")
    );
    assert!(
        audit::parse_audit_evidence(&audit_output)
            .unwrap()
            .findings()
            .iter()
            .any(|finding| finding.advisory_id().to_string() == ADVISORY
                && finding.package().crate_name() == "time")
    );
    actual_native_coverage_controls(&ctx, &vulnerable, &deny, &audit_output);

    // Exercise the authoring owner against actual scanner evidence before the
    // independent wrong-subject and all-advisory reconciliation controls below.
    let review = Review {
        schema_version: 1,
        subject_id: vulnerable.subject.id().unwrap(),
        policy_id: advisory.policy.id().unwrap(),
        evidence_content_id: advisory.content.id().unwrap(),
        assessment_requirements: BTreeSet::from(["risk".into()]),
    };
    let stored = super::super::frontend::StoredReview {
        subject: vulnerable.subject.clone(),
        policy: advisory.policy.clone(),
        review,
        evidence: EvidenceRecord {
            content: advisory.content.clone(),
            observation: advisory.observation.clone(),
        },
        request: collection::ReviewRequest {
            spec: Some("time@0.1.44".into()),
            git: None,
            rev: None,
            package: None,
            bins: vec!["owned-policy-tool".into()],
            features: vec![],
            no_default_features: false,
            all_features: false,
            profile: "release".into(),
            target: None,
            from: None,
            cargo: ctx.evaluator().unwrap().cargo.path.clone(),
            rustc: ctx.evaluator().unwrap().rustc.path.clone(),
        },
    };
    let review_id = super::super::frontend::save_review(&ctx, &stored).unwrap();
    let mut args = crate::cli::ToolIocExceptionArgs {
        review_id: review_id.to_string(),
        ioc: false,
        age: false,
        advisory: Some(ADVISORY.into()),
        review_record: Some("authored-native-advisory.json".into()),
        record: None,
        review_by: Some("2099-01-01".into()),
        selection: crate::cli::IocSelectionArgs {
            package: Some("time@0.1.44".into()),
            source_id: None,
            paths: vec![],
            rules: vec![],
        },
        standalone: true,
        format: crate::cli::AuditOutputFormat::Json,
    };
    super::super::exception_authoring::run(&ctx, &args, barbican::OffsetDateTime::now_utc())
        .unwrap();
    let path = Path::new("authored-native-advisory.json");
    let pending = ctx.stores.data.read(path, MAX_RECORD_BYTES as u64).unwrap();
    let mut authored: ToolException = serde_json::from_slice(pending.bytes()).unwrap();
    assert!(authored.validate().is_err());
    authored.reviewer = "owned native qualification reviewer".into();
    authored.review_record = "Reviewed only this inert authored registry transport fixture and this assigned advisory. No published time code is approved; only the disposable exact synthetic subject receives this bounded exception.".into();
    policy_file(
        &ctx,
        path.to_str().unwrap(),
        &serde_json::to_vec(&authored).unwrap(),
    );
    args.record = args.review_record.take();
    super::super::exception_authoring::run(&ctx, &args, barbican::OffsetDateTime::now_utc())
        .unwrap();
    ctx.now = barbican::OffsetDateTime::now_utc().unix_timestamp();
    let published_subject = vulnerable.subject.id().unwrap();
    // A new invocation requires fresh archive inspection as well as fresh scanners.
    // Re-inspect the same inert synthetic archive; do not renew timestamps alone.
    synthetic_registry_root(&ctx, &mut vulnerable);
    assert_eq!(vulnerable.subject.id().unwrap(), published_subject);
    let recollected = collected(
        &ctx,
        &vulnerable,
        "authoring-scaffold-completed-published-native-recollection",
    );
    assert_eq!(recollected.policy.tool_exceptions.len(), 1);
    assert!(
        recollected
            .content
            .findings
            .iter()
            .any(|finding| finding.identity == ADVISORY && !finding.blocking)
    );
    for finding in advisory
        .content
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::Advisory && f.identity != ADVISORY)
    {
        assert!(
            recollected
                .content
                .findings
                .iter()
                .any(|current| current.identity == finding.identity && current.blocking)
        );
    }
    actual_native_coverage_controls(&ctx, &vulnerable, &deny, &audit_output);
    configure(&ctx, &[], true);

    let prose = "Reviewed only this authored inert synthetic registry transport fixture; this is not a grant to published time crate code or any other subject.";
    let mut exceptions = Vec::new();
    for (index, finding) in advisory
        .content
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::Advisory)
        .enumerate()
    {
        let exception = ToolException {
            subject_id: RecordId {
                kind: RecordKind::Subject,
                schema_version: 1,
                sha256: sha256(b"deliberately different fixture subject"),
            },
            package: finding.package.clone(),
            policy_sha256: advisory.policy.policy_sha256.clone(),
            exception: ExceptionKind::Advisory {
                identity: finding.identity.clone(),
                detail_sha256: finding.detail_sha256.clone(),
            },
            expires_at_utc: ctx.now + 3600,
            reviewed_at_utc: ctx.now - 1,
            reviewer: "owned native fixture qualification".into(),
            review_record: prose.into(),
            review_record_sha256: sha256(prose.as_bytes()),
        };
        let path = format!("fixture-exception-{index}.json");
        policy_file(&ctx, &path, &serde_json::to_vec(&exception).unwrap());
        exceptions.push((path, exception));
    }
    configure(
        &ctx,
        &exceptions
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>(),
        true,
    );
    let wrong = collected(
        &ctx,
        &vulnerable,
        "tool-exception-wrong-subject-remains-blocked",
    );
    assert!(
        wrong
            .content
            .findings
            .iter()
            .any(|finding| finding.identity == ADVISORY && finding.blocking)
    );
    for (path, exception) in &mut exceptions {
        exception.subject_id = vulnerable.subject.id().unwrap();
        policy_file(&ctx, path, &serde_json::to_vec(exception).unwrap());
    }
    let allowed = collected(
        &ctx,
        &vulnerable,
        "tool-exact-completed-exception-reconciled",
    );
    assert!(
        allowed
            .content
            .findings
            .iter()
            .any(|finding| finding.identity == ADVISORY && !finding.blocking)
    );
    allowed
        .content
        .applicable(&vulnerable.subject, &allowed.policy)
        .unwrap();
    assert_ne!(allowed.policy.id().unwrap(), advisory.policy.id().unwrap());
    assert_eq!(allowed.policy.policy_sha256, advisory.policy.policy_sha256);
    eprintln!(
        "native policy matrix passed: exact closure/exclusions; normal/build licence and original-source controls; both native root advisories; ignore neutralisation; scoped exception; actual-output missing/unbound/contradictory coverage refusals"
    );
}

fn actual_native_coverage_controls(
    ctx: &Context,
    prepared: &PreparedSource,
    deny: &CommandOutput,
    audit_output: &CommandOutput,
) {
    let mut contradictory = deny.clone();
    contradictory.exit_code = Some(127);
    assert!(audit::parse_deny_evidence(&contradictory).is_err());
    let mut records: Vec<Value> = deny
        .stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let actual_advisory = records
        .iter()
        .find(|record| {
            record
                .pointer("/fields/advisory/id")
                .and_then(Value::as_str)
                == Some(ADVISORY)
        })
        .unwrap();
    let mut unbound = actual_advisory.clone();
    unbound["fields"]["graphs"][0]["Krate"]["name"] = json!("unbound-native-finding");
    assert!(
        validate_native_package_references(&unbound, &prepared.subject.graph.packages()).is_err()
    );
    let summary = records
        .iter_mut()
        .find(|record| record["type"] == "summary")
        .unwrap();
    summary["fields"]
        .as_object_mut()
        .unwrap()
        .remove("advisories");
    let missing = CommandOutput {
        stdout: deny.stdout.clone(),
        stderr: records
            .iter()
            .map(|record| serde_json::to_string(record).unwrap())
            .collect::<Vec<_>>()
            .join("\n"),
        exit_code: Some(0),
    };
    let mut deny_report = audit::parse_deny_evidence(&missing).unwrap();
    let mut audit_report = audit::parse_audit_evidence(audit_output).unwrap();
    let config = configuration(ctx).unwrap();
    let text = origin_text(ctx, "deny.toml").unwrap();
    let explicit = audit::prepare_explicit_audit_policy(&config, text.as_deref()).unwrap();
    let projection = project(prepared).unwrap();
    let lock = barbican::parse_lockfile(&projection.lock).unwrap();
    let outcome = audit::evaluate_explicit_audit(
        &explicit,
        Some(&lock),
        &mut deny_report,
        Some(&mut audit_report),
        &[],
        barbican::OffsetDateTime::from_unix_timestamp(ctx.now).unwrap(),
    );
    assert!(
        outcome
            .completeness_failures()
            .iter()
            .any(|failure| matches!(
                failure,
                barbican::AdvisoryAuditCompletenessFailure::MissingCargoDenySummaryCheck {
                    check: barbican::CargoDenyCheck::Advisories
                }
            ))
    );
    assert!(!outcome.is_success());
    if let Some(root) = std::env::var_os("BARBICAN_TOOL_POLICY_RECEIPTS") {
        let path = PathBuf::from(root).join("actual-native-output-coverage-controls.json");
        fs::write(path,serde_json::to_vec_pretty(&json!({"qualification":QUALIFICATION,"source":"captured actual native root-advisory output","contradictory_exit":"refused","unbound_native_package":"refused","missing_advisories_summary":"refused","failure":format!("{:?}",outcome.completeness_failures())})).unwrap()).unwrap();
    }
}
