use super::{
    collection::PreparedSource,
    frontend::Context,
    process::{self, Result, err},
};
use crate::commands::audit;
use barbican::cargo_tool::*;
use barbican::{BarbicanConfig, Sha256Digest};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[cfg(test)]
#[path = "policy_native_tests.rs"]
mod native_tests;

pub(crate) struct PolicyEvidence {
    pub policy: OriginPolicy,
    pub content: EvidenceContent,
    pub observation: Observation,
    pub details: Value,
}

pub(crate) fn configuration(ctx: &Context) -> Result<BarbicanConfig> {
    configuration_with_budget(ctx, &ctx.budget)
}
fn configuration_with_budget(ctx: &Context, budget: &process::Budget) -> Result<BarbicanConfig> {
    ctx.check_with_budget(budget)?;
    if let Some(repo) = &ctx.repo {
        return Ok(repo.config.clone());
    }
    match ctx.stores.data.read_optional(
        Path::new("cargo-tools/v1/policy.toml"),
        MAX_RECORD_BYTES as u64,
    )? {
        Some(bytes) => {
            BarbicanConfig::from_toml_str(std::str::from_utf8(bytes.bytes()).map_err(err)?)
                .map_err(err)
        }
        None => Ok(BarbicanConfig::default()),
    }
}

fn origin_text(ctx: &Context, relative: &str) -> Result<Option<String>> {
    origin_text_with_budget(ctx, relative, &ctx.budget)
}
fn origin_text_with_budget(
    ctx: &Context,
    relative: &str,
    budget: &process::Budget,
) -> Result<Option<String>> {
    let bytes = if let Some(repo) = &ctx.repo {
        super::context::read_optional(&repo.root, Path::new(relative), budget)?
    } else {
        ctx.stores
            .data
            .read_optional(
                &Path::new("cargo-tools/v1").join(relative),
                MAX_RECORD_BYTES as u64,
            )?
            .map(|bytes| bytes.bytes().to_vec())
    };
    bytes
        .map(|bytes| String::from_utf8(bytes).map_err(err))
        .transpose()
}

pub(crate) fn capture(ctx: &Context) -> Result<OriginPolicy> {
    capture_with_budget(ctx, &ctx.budget)
}
pub(crate) fn capture_after_build(ctx: &Context) -> Result<OriginPolicy> {
    let budget = process::Budget::native(ctx.budget.cancelled.clone());
    capture_with_budget(ctx, &budget)
}
fn capture_with_budget(ctx: &Context, budget: &process::Budget) -> Result<OriginPolicy> {
    let config = configuration_with_budget(ctx, budget)?;
    for relative in [
        "deny.exceptions.toml",
        ".deny.exceptions.toml",
        ".cargo/deny.exceptions.toml",
    ] {
        if origin_text_with_budget(ctx, relative, budget)?.is_some() {
            return Err("tool origin licence exceptions must be declared explicitly in deny.toml; auxiliary deny.exceptions.toml authority is unsupported".into());
        }
    }
    let (scope, policy_sha256) = origin_binding_with_budget(ctx, &config, budget)?;
    let deny = origin_text_with_budget(ctx, "deny.toml", budget)?;
    let explicit = audit::prepare_explicit_audit_policy(&config, deny.as_deref())?;
    let mut required_checks: BTreeSet<String> = [
        "source-authenticity",
        "release-age",
        "archive-inspection",
        "execution-surfaces",
        "advisories",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    required_checks.extend(
        explicit
            .checks
            .iter()
            .map(|check| format!("cargo-deny:{}", check.as_str())),
    );
    if explicit.uses_cargo_audit() {
        required_checks.insert("cargo-audit".into());
    }
    let evaluator = ctx.evaluator()?;
    evaluator.recheck(budget)?;
    let evaluator_sha256 = [
        &evaluator.cargo,
        &evaluator.rustc,
        &evaluator.deny,
        &evaluator.inspector,
    ]
    .into_iter()
    .chain(evaluator.audit.iter())
    .map(|exe| exe.sha256.clone())
    .collect();
    let (tool_exceptions, ioc_exceptions) = load_exceptions(ctx, &config, &policy_sha256, budget)?;
    let policy = OriginPolicy {
        schema_version: 1,
        scope,
        policy_sha256,
        required_checks,
        evaluator_sha256,
        tool_exceptions,
        ioc_exceptions,
    };
    policy.validate().map_err(err)?;
    Ok(policy)
}

pub(crate) fn load_exceptions(
    ctx: &Context,
    config: &BarbicanConfig,
    policy_sha256: &Sha256Digest,
    budget: &process::Budget,
) -> Result<(BTreeSet<ToolException>, BTreeSet<ToolIocException>)> {
    let mut tool_exceptions = BTreeSet::new();
    let mut ioc_exceptions = BTreeSet::new();
    for path in &config.tools.exception_records {
        let bytes = if let Some(repo) = &ctx.repo {
            super::context::read_optional(&repo.root, Path::new(path), budget)?
                .ok_or("tool exception record missing")?
        } else {
            ctx.stores
                .data
                .read(Path::new(path), MAX_RECORD_BYTES as u64)?
                .bytes()
                .to_vec()
        };
        let kind: Value = serde_json::from_slice(&bytes).map_err(err)?;
        if kind.get("record_kind").is_some() {
            let reference: super::ioc_exception::ToolIocRecordReference =
                serde_json::from_slice(&bytes).map_err(err)?;
            let exception = reference.load(ctx, budget)?;
            if exception.policy_sha256 != *policy_sha256 || !ioc_exceptions.insert(exception) {
                return Err("duplicate or wrong-policy tool IOC exception".into());
            }
            continue;
        }
        let exception: ToolException = serde_json::from_slice(&bytes).map_err(err)?;
        exception.validate().map_err(err)?;
        if exception.policy_sha256 != *policy_sha256 {
            return Err("tool exception binds another base origin policy".into());
        }
        if !tool_exceptions.insert(exception) {
            return Err("duplicate tool exception".into());
        }
    }
    Ok((tool_exceptions, ioc_exceptions))
}

pub(crate) fn origin_binding(ctx: &Context) -> Result<(PolicyScope, Sha256Digest)> {
    let config = configuration(ctx)?;
    origin_binding_with_budget(ctx, &config, &ctx.budget)
}
fn origin_binding_with_budget(
    ctx: &Context,
    config: &BarbicanConfig,
    budget: &process::Budget,
) -> Result<(PolicyScope, Sha256Digest)> {
    let scope = match &ctx.repo {
        Some(_) => PolicyScope::Repository {
            governance_id: config
                .tools
                .admission_scope
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| {
                    format!(
                        "local-repository:{}",
                        sha256(
                            ctx.repo
                                .as_ref()
                                .expect("matched repository")
                                .root
                                .as_os_str()
                                .as_encoded_bytes()
                        )
                    )
                }),
        },
        None => PolicyScope::Standalone,
    };
    let deny = origin_text_with_budget(ctx, "deny.toml", budget)?;
    let native_audit = origin_text_with_budget(ctx, ".cargo/audit.toml", budget)?;
    let mut base_configuration = config.clone();
    base_configuration.tools.exception_records.clear();
    let policy_sha256 = digest(
        &json!({"schema_version":1,"configuration":base_configuration,"scope":scope,"deny_toml":deny,"audit_toml":native_audit,"tool_graph_scope":"exact-install-closure-v1"}),
    )?;
    Ok((scope, policy_sha256))
}

fn digest(value: &impl serde::Serialize) -> Result<Sha256Digest> {
    Ok(sha256(&serde_json::to_vec(value).map_err(err)?))
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("scanner input lacks {name}"))
}
fn source_label(package: &PackageIdentity) -> String {
    match &package.source {
        PackageSource::CratesIo { .. } => barbican::CRATES_IO_SOURCE.into(),
        PackageSource::Git { url, rev, .. } => format!("git+{url}?rev={rev}#{rev}"),
    }
}
fn scanner_id(package: &PackageIdentity) -> String {
    match &package.source {
        PackageSource::CratesIo { .. } => format!(
            "{}#{}@{}",
            barbican::CRATES_IO_SOURCE,
            package.name,
            package.version
        ),
        PackageSource::Git { url, rev, .. } => {
            format!("git+{url}?rev={rev}#{}@{}", package.name, package.version)
        }
    }
}

#[derive(Debug)]
struct Projection {
    metadata: Value,
    lock: String,
    packages: BTreeSet<PackageIdentity>,
}
fn project(prepared: &PreparedSource) -> Result<Projection> {
    prepared.subject.validate().map_err(err)?;
    project_graph(
        &prepared.metadata,
        &prepared.origins,
        &prepared.subject.graph,
    )
}
fn project_graph(
    metadata: &Value,
    origins: &BTreeMap<String, PackageIdentity>,
    graph: &InstallGraph,
) -> Result<Projection> {
    graph.validate().map_err(err)?;
    let packages = graph.packages();
    let root = &graph
        .nodes
        .get(&graph.root)
        .ok_or("scanner root missing")?
        .package;
    let mut selected = BTreeMap::new();
    let mut old_ids = BTreeMap::new();
    let mut new_ids = BTreeSet::new();
    for raw in metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("metadata packages missing")?
    {
        let old = field(raw, "id")?;
        let Some(original) = origins.get(old) else {
            continue;
        };
        if !packages.contains(original) {
            continue;
        }
        if field(raw, "name")? != original.name || field(raw, "version")? != original.version {
            return Err("metadata identity contradicts authenticated origin".into());
        }
        let mut package = raw.clone();
        let id = scanner_id(original);
        if !new_ids.insert(id.clone()) || old_ids.insert(old.to_owned(), original.clone()).is_some()
        {
            return Err("ambiguous scanner package identity".into());
        }
        package["id"] = json!(id);
        package["source"] = json!(source_label(original));
        selected.insert(original.clone(), package);
    }
    if selected.keys().cloned().collect::<BTreeSet<_>>() != packages {
        return Err("exact graph package absent from scanner source metadata".into());
    }
    let mut nodes = Vec::new();
    let mut lock = String::from("version = 4\n");
    for package in &packages {
        let contexts: Vec<_> = graph
            .nodes
            .iter()
            .filter(|(_, node)| &node.package == package)
            .collect();
        let features: BTreeSet<_> = contexts
            .iter()
            .flat_map(|(_, node)| node.features.iter().cloned())
            .collect();
        let mut dependencies: BTreeMap<PackageIdentity, BTreeSet<(String, String)>> =
            BTreeMap::new();
        for (key, _) in &contexts {
            for edge in graph.edges.iter().filter(|edge| edge.from == **key) {
                let target = &graph
                    .nodes
                    .get(&edge.to)
                    .ok_or("unbound scanner graph edge")?
                    .package;
                let kind = match edge.kind {
                    DependencyKind::Normal => "normal",
                    DependencyKind::Build => "build",
                };
                dependencies.entry(target.clone()).or_default().extend(
                    edge.declared_targets
                        .iter()
                        .map(|target| (kind.into(), target.clone())),
                );
            }
        }
        let mut deps = Vec::new();
        for (target, kinds) in &dependencies {
            let original_raw = selected.get(package).ok_or("scanner package missing")?;
            let declared = original_raw
                .get("dependencies")
                .and_then(Value::as_array)
                .ok_or("metadata dependency declarations missing")?;
            let aliases: BTreeSet<_> = declared
                .iter()
                .filter(|dependency| {
                    dependency.get("name").and_then(Value::as_str) == Some(&target.name)
                })
                .map(|dependency| {
                    dependency
                        .get("rename")
                        .and_then(Value::as_str)
                        .unwrap_or(&target.name)
                        .replace('-', "_")
                })
                .collect();
            if aliases.len() != 1 {
                return Err("scanner dependency alias is missing or ambiguous".into());
            }
            deps.push(json!({"name":aliases.iter().next().ok_or("dependency alias missing")?,"pkg":scanner_id(target),"dep_kinds":kinds.iter().map(|(kind,condition)| json!({"kind":if kind=="normal" {Value::Null}else{json!(kind)},"target":if condition.is_empty(){Value::Null}else{json!(condition)}})).collect::<Vec<_>>()}));
        }
        nodes.push(json!({"id":scanner_id(package),"dependencies":dependencies.keys().map(scanner_id).collect::<Vec<_>>(),"deps":deps,"features":features}));
        lock.push_str(&format!(
            "\n[[package]]\nname = {}\nversion = {}\nsource = {}\n",
            json!(package.name),
            json!(package.version),
            json!(source_label(package))
        ));
        if let PackageSource::CratesIo { archive_sha256 } = &package.source {
            lock.push_str(&format!("checksum = {}\n", json!(archive_sha256.as_str())));
        }
        lock.push_str("dependencies = [\n");
        for target in dependencies.keys() {
            lock.push_str(&format!(
                " {},\n",
                json!(format!(
                    "{} {} ({})",
                    target.name,
                    target.version,
                    source_label(target)
                ))
            ));
        }
        lock.push_str("]\n");
    }
    barbican::parse_lockfile(&lock).map_err(err)?;
    let mut projected = metadata.clone();
    projected["packages"] = json!(selected.into_values().collect::<Vec<_>>());
    projected["workspace_members"] = json!([scanner_id(root)]);
    projected["workspace_default_members"] = json!([scanner_id(root)]);
    projected["resolve"] = json!({"root":scanner_id(root),"nodes":nodes});
    Ok(Projection {
        metadata: projected,
        lock,
        packages,
    })
}

pub(crate) fn collect(ctx: &Context, prepared: &PreparedSource) -> Result<PolicyEvidence> {
    prepared.recheck(ctx)?;
    check_native_exception_paths(&prepared.manifest)?;
    let policy = capture(ctx)?;
    let config = configuration(ctx)?;
    let deny_text = origin_text(ctx, "deny.toml")?;
    let audit_text = origin_text(ctx, ".cargo/audit.toml")?;
    let explicit = audit::prepare_explicit_audit_policy(&config, deny_text.as_deref())?;
    let projected = project(prepared)?;
    let subject_id = prepared.subject.id().map_err(err)?;
    let mut facts = BTreeSet::new();
    let mut findings = BTreeSet::new();
    let mut detail_rows = Vec::new();
    let inspector = &ctx.evaluator()?.inspector;
    let ioc_knowledge = ctx.knowledge()?;
    let ioc_index = ToolIocIndex::prepare(
        &policy,
        &subject_id,
        barbican::OffsetDateTime::now_utc().unix_timestamp(),
        &mut || ctx.budget.check(),
    )
    .map_err(err)?;
    for package in &projected.packages {
        let inspected = prepared
            .ioc_inspections
            .get(package)
            .ok_or("IOC coverage missing for graph package")?;
        if !matches!(inspected.coverage, barbican::ioc::Coverage::Complete) {
            return Err("required IOC coverage is incomplete".into());
        }
        for raw in &inspected.findings {
            let id = raw.id()?;
            let mut finding = Finding {
                identity: id.to_string(),
                package: package.clone(),
                kind: FindingKind::Ioc,
                blocking: true,
                detail_sha256: id.clone(),
            };
            finding.blocking = !ioc_index.allows(&finding);
            let fact = SourceFact {
                key: KnowledgeKey::Ioc {
                    package: package.clone(),
                    finding_id: id.clone(),
                },
                facts_sha256: id,
                status: SecurityStatus::Adverse,
                expires_at_utc: None,
            };
            if ioc_knowledge
                .entry_for(&fact.key)
                .is_none_or(|entry| entry.fact != fact)
            {
                return Err("IOC fact was not durably retained by source collection".into());
            }
            facts.insert(fact);
            detail_rows.push(json!({"finding":finding,"detail":raw}));
            findings.insert(finding);
        }
        match &package.source {
            PackageSource::CratesIo { .. } => {
                facts.insert(
                    prepared
                        .source_facts
                        .get(package)
                        .ok_or("registry API facts missing for graph package")?
                        .clone(),
                );
                let report = prepared
                    .inspected
                    .get(package)
                    .ok_or("archive inspection missing for graph package")?;
                let knowledge = ctx.knowledge()?;
                let inspection = knowledge
                    .entry_for(&KnowledgeKey::Inspection {
                        package: package.clone(),
                        inspector_sha256: inspector.sha256.clone(),
                    })
                    .ok_or("durable archive inspection missing")?;
                if inspection.checked_at_utc < ctx.now {
                    return Err("archive inspection was not refreshed for this operation".into());
                }
                facts.insert(inspection.fact.clone());
                let age = report.release_age();
                let age_detail = json!({"published_at":age.published_at_raw(),"minimum_days":config.release_age.minimum_days,"outcome":format!("{:?}",age.outcome())});
                if !report.checksum_matches() {
                    add_finding(
                        &mut findings,
                        &mut detail_rows,
                        package,
                        "archive-checksum",
                        FindingKind::Checksum,
                        true,
                        json!({"local":report.local_checksum_sha256_hex(),"published":report.published_checksum_sha256_hex()}),
                    )?;
                }
                if !report.inspection_failures().is_empty() {
                    add_finding(
                        &mut findings,
                        &mut detail_rows,
                        package,
                        "archive-coverage",
                        FindingKind::RequiredCoverage,
                        true,
                        json!({"failures":report.inspection_failures()}),
                    )?;
                }
                match age.outcome() {
                    barbican::ReleaseAgeOutcome::Yanked => add_finding(
                        &mut findings,
                        &mut detail_rows,
                        package,
                        "release-yanked",
                        FindingKind::Yank,
                        true,
                        age_detail.clone(),
                    )?,
                    barbican::ReleaseAgeOutcome::TooFresh => add_finding(
                        &mut findings,
                        &mut detail_rows,
                        package,
                        "release-age",
                        FindingKind::ReleaseAge,
                        true,
                        age_detail.clone(),
                    )?,
                    barbican::ReleaseAgeOutcome::ExceptionArtefactMismatch { .. } => {
                        return Err("archive release-age checksum exception mismatch".into());
                    }
                    _ => {}
                }
                detail_rows
                    .push(json!({"package":package,"check":"release-age","facts":age_detail}));
                detail_rows.push(json!({"package":package,"check":"archive-inspection","checksum_matches":report.checksum_matches(),"vcs":report.vcs_info().map(|vcs|json!({"git_sha1":vcs.git_sha1(),"path_in_vcs":vcs.path_in_vcs()})),"build_scripts":report.build_script_paths(),"proc_macro":report.proc_macro(),"links":report.package_links(),"native_sources":report.native_source_paths()}));
            }
            PackageSource::Git { .. } => {
                let fact = SourceFact {
                    key: KnowledgeKey::Package {
                        package: package.clone(),
                    },
                    facts_sha256: digest(
                        &json!({"source":package.source,"verification":"immutable-git-blob-inventory-v1"}),
                    )?,
                    status: SecurityStatus::Clear,
                    expires_at_utc: None,
                };
                remember(ctx, &fact, 1)?;
                facts.insert(fact);
                add_finding(
                    &mut findings,
                    &mut detail_rows,
                    package,
                    "git-manual-source-review",
                    FindingKind::SourceReview,
                    false,
                    json!({"source":package.source,"required_review":"Review the represented exact Git source and native execution surfaces. Registry publication age and crates.io archive authentication do not apply; RustSec coverage for this Git identity is unestablished."}),
                )?;
            }
        }
        let nodes: Vec<_> = prepared
            .subject
            .graph
            .nodes
            .values()
            .filter(|node| &node.package == package)
            .collect();
        if nodes
            .iter()
            .any(|node| node.build_script || node.proc_macro || node.native_links)
        {
            add_finding(
                &mut findings,
                &mut detail_rows,
                package,
                "execution-surfaces",
                FindingKind::ExecutionSurface,
                false,
                json!({"contexts":nodes}),
            )?;
        }
    }
    let stage = super::source::Stage::new()?;
    let scanner_home = prepared.cargo_home.clone();
    std::fs::create_dir_all(&scanner_home).map_err(err)?;
    std::fs::create_dir_all(stage.root.join("home")).map_err(err)?;
    let metadata_path = stage.root.join("metadata.json");
    let lock_path = stage.root.join("Cargo.lock");
    let config_path = stage.root.join("deny.toml");
    std::fs::write(
        &metadata_path,
        serde_json::to_vec(&projected.metadata).map_err(err)?,
    )
    .map_err(err)?;
    std::fs::write(&lock_path, &projected.lock).map_err(err)?;
    std::fs::write(
        &config_path,
        explicit.tool_runtime_config(deny_text.as_deref())?,
    )
    .map_err(err)?;
    let evaluator = ctx.evaluator()?;
    let mut env = process::base_environment(
        &stage.root.join("home"),
        &scanner_home,
        &evaluator.rustc.path,
    );
    env.insert("CARGO".into(), evaluator.cargo.path.as_os_str().to_owned());
    env.insert(
        "PATH".into(),
        std::env::join_paths([
            evaluator
                .cargo
                .path
                .parent()
                .ok_or("trusted Cargo directory missing")?,
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .map_err(err)?,
    );
    let pending: Vec<_> = projected
        .packages
        .iter()
        .map(super::store::package_advisory_observation_key)
        .collect::<Result<_>>()?;
    for key in &pending {
        ctx.stores.begin_source(key)?;
    }
    let deny_database = if explicit
        .checks
        .contains(&barbican::CargoDenyCheck::Advisories)
    {
        let args = vec![
            "--manifest-path".to_owned(),
            prepared.manifest.to_string_lossy().into_owned(),
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "--config".into(),
            config_path.to_string_lossy().into_owned(),
            "db".into(),
        ];
        let fetched = command_output(process::run(
            &evaluator.deny,
            &args,
            &stage.root,
            &env,
            &ctx.budget,
        )?)?;
        persist_native_output(ctx, &subject_id, "cargo-deny-fetch", &fetched)?;
        if fetched.exit_code != Some(0) {
            return Err(format!(
                "fresh RustSec advisory database fetch failed: {}",
                fetched.stderr
            ));
        }
        Some(database_version(
            ctx,
            &scanner_home.join("advisory-dbs"),
            &env,
        )?)
    } else {
        None
    };
    let source_version = deny_database
        .as_ref()
        .map_or(1, |database| database.source_version);
    let mut args = vec![
        "--frozen".to_owned(),
        "--manifest-path".to_owned(),
        prepared.manifest.to_string_lossy().into_owned(),
        "--target".into(),
        evaluator.host.clone(),
        "--no-default-features".into(),
        "-f".into(),
        "json".into(),
        "check".into(),
        "--metadata-path".into(),
        metadata_path.to_string_lossy().into_owned(),
        "--config".into(),
        config_path.to_string_lossy().into_owned(),
    ];
    args.extend(
        explicit
            .checks
            .iter()
            .map(|check| check.as_str().to_owned()),
    );
    check_native_exception_paths(&prepared.manifest)?;
    let deny_output = process::run(&evaluator.deny, &args, &stage.root, &env, &ctx.budget)?;
    let deny_output = command_output(deny_output)?;
    persist_native_output(ctx, &subject_id, "cargo-deny", &deny_output)?;
    let mut deny_raw = Vec::new();
    for line in deny_output
        .stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let record: Value = serde_json::from_str(line).map_err(err)?;
        validate_native_package_references(&record, &projected.packages)?;
        retain_deny_advisories(
            ctx,
            &projected.packages,
            std::slice::from_ref(&record),
            source_version,
            &mut facts,
            &mut findings,
            &mut detail_rows,
        )?;
        deny_raw.push(record);
    }
    let deny_raw = normalise_diagnostics(deny_raw, prepared, &stage.root)?;
    if let Some(error) = deny_raw.iter().find(|record| {
        record.get("type").and_then(Value::as_str) == Some("log")
            && record.pointer("/fields/level").and_then(Value::as_str) == Some("ERROR")
    }) {
        return Err(format!(
            "required cargo-deny operational coverage failed: {}",
            error
                .pointer("/fields/message")
                .and_then(Value::as_str)
                .unwrap_or("unknown scanner error")
        ));
    }
    let mut deny_report = audit::parse_deny_evidence(&deny_output)?;
    let mut audit_report = None;
    let mut audit_raw = None;
    let mut audit_database = None;
    if explicit.uses_cargo_audit() {
        let executable = evaluator
            .audit
            .as_ref()
            .ok_or("required cargo-audit evaluator missing")?;
        let args = vec![
            "audit".to_owned(),
            "--json".into(),
            "--file".into(),
            lock_path.to_string_lossy().into_owned(),
            "--db".into(),
            stage.root.join("audit-db").to_string_lossy().into_owned(),
        ];
        let output = command_output(process::run(
            executable,
            &args,
            &stage.root,
            &env,
            &ctx.budget,
        )?)?;
        persist_native_output(ctx, &subject_id, "cargo-audit", &output)?;
        let raw: Value = serde_json::from_str(&output.stdout).map_err(err)?;
        let database = database_version(ctx, &stage.root.join("audit-db"), &env)?;
        retain_audit_advisories(
            ctx,
            &projected.packages,
            &raw,
            database.source_version,
            &mut facts,
            &mut findings,
            &mut detail_rows,
        )?;
        if raw
            .pointer("/lockfile/dependency-count")
            .and_then(Value::as_u64)
            != Some(projected.packages.len() as u64)
        {
            return Err("cargo-audit exact package coverage count mismatch".into());
        }
        if output.stderr.lines().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            line.starts_with("warning:")
                || line.starts_with("error:")
                || line.contains("[warn]")
                || line.contains("[error]")
        }) {
            return Err(format!(
                "cargo-audit reported unavailable operational coverage: {}",
                output.stderr
            ));
        }
        audit_report = Some(audit::parse_audit_evidence(&output)?);
        audit_raw = Some(raw);
        audit_database = Some(database);
    }
    if let Some(database) = &deny_database
        && database_version(ctx, &scanner_home.join("advisory-dbs"), &env)? != *database
    {
        return Err("advisory database changed during frozen evaluation".into());
    }
    let lock = barbican::parse_lockfile(&projected.lock).map_err(err)?;
    let mut bound_exceptions = Vec::new();
    for exception in &policy.tool_exceptions {
        let ExceptionKind::Advisory { identity, .. } = &exception.exception else {
            continue;
        };
        let Some(finding) = findings.iter().find(|finding| {
            exception
                .applies_to(finding, &subject_id, &policy.policy_sha256, ctx.now)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let PackageSource::CratesIo { archive_sha256 } = &finding.package.source else {
            return Err("Git cannot receive a registry exception".into());
        };
        bound_exceptions.push(
            barbican::ReviewedAdvisoryException::from_explicit_binding(
                format!("{}@{}", finding.package.name, finding.package.version)
                    .parse()
                    .map_err(err)?,
                archive_sha256.clone(),
                barbican::RustSecAdvisoryId::parse(identity).map_err(err)?,
                barbican::OffsetDateTime::from_unix_timestamp(exception.expires_at_utc)
                    .map_err(err)?
                    .date(),
                "cargo-tool-exact-subject".into(),
                format!(
                    "cargo-tool-assessment/{}.md",
                    exception.review_record_sha256
                ),
            )
            .map_err(err)?,
        );
    }
    let exception_refs: Vec<_> = bound_exceptions.iter().collect();
    let outcome = audit::evaluate_explicit_audit(
        &explicit,
        Some(&lock),
        &mut deny_report,
        audit_report.as_mut(),
        &exception_refs,
        barbican::OffsetDateTime::from_unix_timestamp(ctx.now).map_err(err)?,
    );
    for finding in deny_report
        .findings()
        .iter()
        .chain(audit_report.iter().flat_map(|report| report.findings()))
    {
        let package = bind_finding(
            &projected.packages,
            finding.package().crate_name(),
            finding.package().version(),
            finding.source(),
        )?;
        if finding.source_status() != barbican::AdvisorySourceStatus::Resolved {
            return Err("native advisory source mapping is incomplete".into());
        }
        if !findings
            .iter()
            .any(|stored| stored.package == *package && stored.kind == FindingKind::Advisory)
        {
            return Err("native advisory has no preserved structured body".into());
        }
    }
    let root_package = prepared.subject.root.package();
    if !outcome.completeness_failures().is_empty()
        || !outcome.cargo_audit_settings_ignore().is_empty()
        || outcome.cargo_audit_idless_warnings() > 0
        || (!outcome.cargo_deny_no_advisory_errors().is_empty()
            && outcome.cargo_deny_non_advisory_errors().is_empty())
    {
        return Err(format!(
            "required native scanner coverage unavailable: completeness={:?}; deny={:?}; audit ignores={:?}; idless warnings={}",
            outcome.completeness_failures(),
            outcome.cargo_deny_no_advisory_errors(),
            outcome.cargo_audit_settings_ignore(),
            outcome.cargo_audit_idless_warnings()
        ));
    }
    for counts in outcome.cargo_deny_non_advisory_errors() {
        add_finding(
            &mut findings,
            &mut detail_rows,
            &root_package,
            &format!("cargo-deny-{}", counts.check()),
            FindingKind::RequiredCoverage,
            true,
            json!({"check":counts.check(),"errors":counts.errors(),"diagnostics":semantic_diagnostics(&deny_raw,counts.check())}),
        )?;
    }
    for record in &deny_raw {
        let Some(code) = record.pointer("/fields/code").and_then(Value::as_str) else {
            continue;
        };
        if code == "index-failure" {
            let rows = record
                .pointer("/fields/graphs")
                .and_then(Value::as_array)
                .ok_or("index failure lacks bound packages")?;
            if rows.is_empty() {
                return Err("index failure has empty package scope".into());
            }
            for row in rows {
                let krate = row.get("Krate").ok_or("index failure missing package")?;
                let package = bind_finding(
                    &projected.packages,
                    field(krate, "name")?,
                    field(krate, "version")?,
                    krate.get("source").and_then(Value::as_str),
                )?;
                if !matches!(package.source, PackageSource::CratesIo { .. })
                    || !prepared.source_facts.contains_key(package)
                {
                    return Err("native index coverage unavailable without independent current crates.io API evidence".into());
                }
            }
            detail_rows.push(json!({"check":"yank-coverage","native_diagnostic":semantic_diagnostic(record),"independent_authority":"fresh exact crates.io version API checksum/publication/yank facts"}));
        }
    }
    let mut native_ignores = Vec::new();
    for (origin, text) in [
        ("deny.toml", deny_text.as_deref()),
        (".cargo/audit.toml", audit_text.as_deref()),
    ] {
        if let Some(entry) = crate::commands::native_ignore_entry(origin, text).map_err(err)? {
            native_ignores.push(entry);
        }
    }
    for row in audit::reconcile_native_ignores(&native_ignores, &outcome) {
        let blocked = audit::unmanaged_native_ignores_fail(
            std::slice::from_ref(&row),
            config.delegates.unmanaged_delegated_policy,
        );
        add_finding(
            &mut findings,
            &mut detail_rows,
            &root_package,
            &format!("native-ignores:{}", row.source()),
            if blocked {
                FindingKind::RequiredCoverage
            } else {
                FindingKind::ResidualRisk
            },
            blocked,
            json!({"origin":row.source(),"ignored_ids":row.advisory_ids(),"unmanaged_ids":row.unmanaged_advisory_ids(),"effect":"native ignores removed for maximum disclosure"}),
        )?;
    }
    let mut final_findings = BTreeSet::new();
    for mut finding in findings {
        if (finding.kind == FindingKind::ReleaseAge
            || (finding.kind == FindingKind::Advisory
                && outcome.accepted_exceptions().iter().any(|exception| {
                    exception.advisory_id().to_string() == finding.identity
                        && exception.spec().crate_name() == finding.package.name
                        && exception.spec().version() == finding.package.version
                })))
            && policy.tool_exceptions.iter().any(|exception| {
                exception
                    .applies_to(&finding, &subject_id, &policy.policy_sha256, ctx.now)
                    .unwrap_or(false)
            })
        {
            finding.blocking = false;
        }
        final_findings.insert(finding);
    }
    for package in &projected.packages {
        for (scanner, database) in [(&evaluator.deny, deny_database.as_ref())]
            .into_iter()
            .chain(
                evaluator
                    .audit
                    .iter()
                    .map(|scanner| (scanner, audit_database.as_ref())),
            )
        {
            let fact = SourceFact {
                key: KnowledgeKey::Inspection {
                    package: package.clone(),
                    inspector_sha256: scanner.sha256.clone(),
                },
                facts_sha256: digest(
                    &json!({"schema_version":1,"coverage":"exact-source-preserving-install-closure","scanner":scanner.sha256,"git_rustsec_coverage":if matches!(package.source,PackageSource::Git{..}){"unestablished-manual-review-required"}else{"crates.io"}}),
                )?,
                status: SecurityStatus::Clear,
                expires_at_utc: None,
            };
            remember(
                ctx,
                &fact,
                database.map_or(1, |database| database.source_version),
            )?;
            facts.insert(fact);
        }
    }
    for sha in &policy.evaluator_sha256 {
        let fact = SourceFact {
            key: KnowledgeKey::Evaluator {
                sha256: sha.clone(),
            },
            facts_sha256: digest(
                &json!({"sha256":sha,"status":"protected-current-evaluator-rechecked"}),
            )?,
            status: SecurityStatus::Clear,
            expires_at_utc: None,
        };
        remember(ctx, &fact, 1)?;
        facts.insert(fact);
    }
    prepared.recheck(ctx)?;
    check_native_exception_paths(&prepared.manifest)?;
    if capture(ctx)? != policy {
        return Err("origin tool policy changed during collection".into());
    }
    let content = EvidenceContent {
        schema_version: 1,
        subject_id: subject_id.clone(),
        policy_id: policy.id().map_err(err)?,
        evaluator_sha256: policy.evaluator_sha256.clone(),
        covered_checks: policy.required_checks.clone(),
        facts,
        findings: final_findings,
        complete: true,
    };
    content.validate().map_err(err)?;
    let knowledge = ctx.knowledge()?;
    let mut sources = BTreeSet::new();
    for fact in &content.facts {
        let entry = knowledge
            .entry_for(&fact.key)
            .ok_or("source observation not durable")?;
        if entry.fact != *fact
            || (!matches!(fact.key, KnowledgeKey::Ioc { .. }) && entry.checked_at_utc < ctx.now)
        {
            return Err("source fact differs from the current durable observation".into());
        }
        sources.insert(SourceObservation {
            key: fact.key.clone(),
            semantic_sha256: fact.semantic_sha256().map_err(err)?,
            source_version: entry.source_version,
            checked_at_utc: entry.checked_at_utc,
        });
    }
    let completed_at_utc = barbican::OffsetDateTime::now_utc().unix_timestamp();
    if completed_at_utc < ctx.now {
        return Err("clock rollback during evidence collection".into());
    }
    let fresh_until_utc = content
        .facts
        .iter()
        .filter_map(|fact| fact.expires_at_utc)
        .fold(
            ctx.now
                .checked_add(MAX_CACHE_SECONDS)
                .ok_or("freshness overflow")?,
            i64::min,
        );
    let observation = Observation {
        schema_version: 1,
        content_id: content.id().map_err(err)?,
        sources,
        completed_at_utc,
        fresh_until_utc,
    };
    observation.validate().map_err(err)?;
    for key in &pending {
        ctx.stores.finish_source(key)?;
    }
    let details = json!({"schema_version":1,"subject_id":subject_id,"policy":policy,"ioc_inspections":prepared.ioc_inspections.values().collect::<Vec<_>>(),"findings":detail_rows,"native_deny_diagnostics":deny_raw.iter().map(semantic_diagnostic).collect::<Vec<_>>(),"advisory_source_observations":{"operation_started_at_utc":ctx.now,"cargo_deny":deny_database,"cargo_audit":audit_database},"native_audit":audit_raw.map(|raw|json!({"settings":raw.get("settings"),"vulnerabilities":raw.get("vulnerabilities"),"warnings":raw.get("warnings")})),"limitations":["Static source and native scanner evidence do not prove benign runtime behaviour.","Git RustSec coverage is unestablished; exact Git source and native surfaces require human review."]});
    Ok(PolicyEvidence {
        policy,
        content,
        observation,
        details,
    })
}

fn remember(ctx: &Context, fact: &SourceFact, source_version: u64) -> Result<()> {
    let observed_at = barbican::OffsetDateTime::now_utc().unix_timestamp();
    if observed_at < ctx.now {
        return Err("clock rollback during source observation".into());
    }
    ctx.stores.remember(
        KnowledgeEntry {
            fact: fact.clone(),
            source_version,
            checked_at_utc: observed_at,
        },
        observed_at,
    )
}
fn add_finding(
    findings: &mut BTreeSet<Finding>,
    details: &mut Vec<Value>,
    package: &PackageIdentity,
    identity: &str,
    kind: FindingKind,
    blocking: bool,
    body: Value,
) -> Result<()> {
    let finding = Finding {
        identity: identity.into(),
        package: package.clone(),
        kind,
        blocking,
        detail_sha256: digest(&body)?,
    };
    if let Some(previous) = findings
        .iter()
        .find(|old| old.identity == finding.identity && old.package == finding.package)
    {
        if previous != &finding {
            return Err("native scanners supplied contradictory semantic finding bodies".into());
        }
    } else {
        details.push(json!({"finding":finding,"detail":body}));
        findings.insert(finding);
    }
    Ok(())
}
fn bind_finding<'a>(
    packages: &'a BTreeSet<PackageIdentity>,
    name: &str,
    version: &str,
    source: Option<&str>,
) -> Result<&'a PackageIdentity> {
    let matches: Vec<_> = packages
        .iter()
        .filter(|package| {
            package.name == name
                && package.version == version
                && source.is_none_or(|source| source == source_label(package))
        })
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "native finding identity is unknown or ambiguous: {name}@{version}"
        ));
    }
    Ok(matches[0])
}
fn command_output(output: process::ProcessOutput) -> Result<crate::command_runner::CommandOutput> {
    Ok(crate::command_runner::CommandOutput {
        exit_code: output.status.code(),
        stdout: String::from_utf8(output.stdout).map_err(err)?,
        stderr: String::from_utf8(output.stderr).map_err(err)?,
    })
}
fn persist_native_output(
    ctx: &Context,
    subject: &RecordId,
    scanner: &str,
    output: &crate::command_runner::CommandOutput,
) -> Result<()> {
    let bytes=serde_json::to_vec(&json!({"scanner":scanner,"subject":subject,"observed_at_utc":ctx.now,"status":output.exit_code,"stdout":output.stdout,"stderr":output.stderr})).map_err(err)?;
    let path = std::path::PathBuf::from(format!(
        "cargo-tools/v1/policy-dossier/{}/{}-{}.json",
        subject.sha256,
        scanner,
        sha256(&bytes)
    ));
    if ctx
        .stores
        .data
        .read_optional(&path, process::FILE_LIMIT)?
        .is_none()
    {
        ctx.stores
            .data
            .publish_checked(&path, &bytes, || ctx.check())?;
    }
    Ok(())
}
fn retain_advisory(
    ctx: &Context,
    package: &PackageIdentity,
    body: &Value,
    source_version: u64,
    facts: &mut BTreeSet<SourceFact>,
    findings: &mut BTreeSet<Finding>,
    details: &mut Vec<Value>,
) -> Result<()> {
    let body_sha256 = digest(body)?;
    let (identity, label) = advisory_identity(body, &body_sha256)?;
    let version = if matches!(identity, AdvisoryIdentity::Provisional { .. }) {
        1
    } else {
        source_version
    };
    let fact = SourceFact {
        key: KnowledgeKey::Advisory {
            package: package.clone(),
            source: "https://github.com/RustSec/advisory-db".into(),
            identity,
        },
        facts_sha256: body_sha256,
        status: SecurityStatus::Adverse,
        expires_at_utc: None,
    };
    if !facts.contains(&fact) {
        remember(ctx, &fact, version)?;
    }
    facts.insert(fact);
    add_finding(
        findings,
        details,
        package,
        &label,
        FindingKind::Advisory,
        true,
        body.clone(),
    )
}
fn retain_deny_advisories(
    ctx: &Context,
    packages: &BTreeSet<PackageIdentity>,
    records: &[Value],
    source_version: u64,
    facts: &mut BTreeSet<SourceFact>,
    findings: &mut BTreeSet<Finding>,
    details: &mut Vec<Value>,
) -> Result<()> {
    for record in records {
        let Some(body) = record.pointer("/fields/advisory") else {
            continue;
        };
        let graphs = record
            .pointer("/fields/graphs")
            .and_then(Value::as_array)
            .ok_or("advisory package graphs missing")?;
        if graphs.is_empty() {
            return Err("advisory has empty package coverage".into());
        }
        for graph in graphs {
            let package = graph.get("Krate").ok_or("advisory package missing")?;
            let package = bind_finding(
                packages,
                field(package, "name")?,
                field(package, "version")?,
                package.get("source").and_then(Value::as_str),
            )?;
            retain_advisory(ctx, package, body, source_version, facts, findings, details)?;
            let (_, identity) = advisory_identity(body, &digest(body)?)?;
            add_finding(
                findings,
                details,
                package,
                &format!("advisory-remediation:cargo-deny:{identity}"),
                FindingKind::ResidualRisk,
                false,
                json!({"advisory":identity,"scanner":"cargo-deny","notes":record.pointer("/fields/notes")}),
            )?;
        }
    }
    Ok(())
}
fn retain_audit_advisories(
    ctx: &Context,
    packages: &BTreeSet<PackageIdentity>,
    raw: &Value,
    source_version: u64,
    facts: &mut BTreeSet<SourceFact>,
    findings: &mut BTreeSet<Finding>,
    details: &mut Vec<Value>,
) -> Result<()> {
    let vulnerabilities = raw
        .pointer("/vulnerabilities/list")
        .and_then(Value::as_array)
        .ok_or("cargo-audit vulnerability list missing")?;
    let warnings = raw
        .get("warnings")
        .and_then(Value::as_object)
        .ok_or("cargo-audit warnings missing")?;
    let mut entries: Vec<&Value> = vulnerabilities.iter().collect();
    for rows in warnings.values() {
        entries.extend(
            rows.as_array()
                .ok_or("cargo-audit warning list malformed")?,
        );
    }
    for entry in entries {
        let Some(body) = entry.get("advisory") else {
            continue;
        };
        let package = entry
            .get("package")
            .ok_or("cargo-audit advisory package missing")?;
        let package = bind_finding(
            packages,
            field(package, "name")?,
            field(package, "version")?,
            package.get("source").and_then(Value::as_str),
        )?;
        retain_advisory(ctx, package, body, source_version, facts, findings, details)?;
        let (_, identity) = advisory_identity(body, &digest(body)?)?;
        add_finding(
            findings,
            details,
            package,
            &format!("advisory-remediation:cargo-audit:{identity}"),
            FindingKind::ResidualRisk,
            false,
            json!({"advisory":identity,"scanner":"cargo-audit","versions":entry.get("versions")}),
        )?;
    }
    Ok(())
}
fn semantic_diagnostic(record: &Value) -> Value {
    let fields = record.get("fields").unwrap_or(record);
    json!({"severity":fields.get("severity"),"code":fields.get("code"),"message":fields.get("message"),"advisory":fields.get("advisory"),"graphs":fields.get("graphs"),"notes":fields.get("notes")})
}
fn semantic_diagnostics(records: &[Value], _check: &str) -> Vec<Value> {
    records
        .iter()
        .filter(|record| {
            record.pointer("/fields/severity").and_then(Value::as_str) == Some("error")
                && record.pointer("/fields/advisory").is_none()
        })
        .map(semantic_diagnostic)
        .collect()
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct DatabaseObservation {
    source_version: u64,
    revision: String,
}

fn database_version(
    ctx: &Context,
    root: &Path,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<DatabaseObservation> {
    let mut pending = vec![(root.to_owned(), 0usize)];
    let mut databases = Vec::new();
    while let Some((directory, depth)) = pending.pop() {
        ctx.budget.check()?;
        if depth > 6 {
            return Err("scanner database directory depth exceeds bound".into());
        }
        match std::fs::symlink_metadata(directory.join(".git")) {
            Ok(metadata) if metadata.is_dir() => {
                databases.push(directory);
                continue;
            }
            Ok(_) => return Err("scanner advisory Git metadata is not a directory".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        for entry in std::fs::read_dir(&directory).map_err(err)? {
            let entry = entry.map_err(err)?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(err)?;
            if metadata.file_type().is_symlink() {
                return Err("scanner database contains unsupported symlink".into());
            }
            if metadata.is_dir() {
                pending.push((entry.path(), depth + 1));
            }
        }
        if pending.len() > 4096 {
            return Err("scanner database directory budget exceeded".into());
        }
    }
    if databases.len() != 1 {
        return Err("fresh scanner advisory database identity missing or ambiguous".into());
    }
    let git = process::Executable::capture(Path::new("/usr/bin/git"), &ctx.budget)?;
    let args = vec![
        "-C".to_owned(),
        databases[0].to_string_lossy().into_owned(),
        "show".into(),
        "-s".into(),
        "--format=%ct%n%H".into(),
        "HEAD".into(),
    ];
    let output = process::run_git_bounded(&git, &args, root, environment, &ctx.budget)?;
    if !output.status.success() {
        return Err("cannot establish authenticated advisory source revision time".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(err)?;
    let mut lines = text.lines();
    let version = lines
        .next()
        .ok_or("advisory source revision time missing")?
        .parse::<u64>()
        .map_err(err)?;
    let revision = lines
        .next()
        .ok_or("advisory source revision missing")?
        .to_owned();
    if lines.next().is_some()
        || revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid advisory source revision".into());
    }
    if version == 0 || version > ctx.now as u64 {
        return Err("advisory source revision time invalid or future".into());
    }
    Ok(DatabaseObservation {
        source_version: version,
        revision,
    })
}

fn normalise_diagnostics(
    mut records: Vec<Value>,
    prepared: &PreparedSource,
    stage: &Path,
) -> Result<Vec<Value>> {
    let mut replacements = Vec::new();
    for package in prepared
        .metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("metadata packages missing")?
    {
        let Some(identity) = prepared.origins.get(field(package, "id")?) else {
            continue;
        };
        let directory = Path::new(field(package, "manifest_path")?)
            .parent()
            .ok_or("package manifest directory missing")?;
        replacements.push((
            directory.to_string_lossy().into_owned(),
            format!("source:{}", scanner_id(identity)),
        ));
    }
    replacements.push((
        prepared.workspace_root.to_string_lossy().into_owned(),
        "source:workspace".into(),
    ));
    replacements.push((
        prepared.root.to_string_lossy().into_owned(),
        "source:root".into(),
    ));
    replacements.push((
        stage.to_string_lossy().into_owned(),
        "scanner:inputs".into(),
    ));
    replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0.len()));
    fn visit(value: &mut Value, replacements: &[(String, String)]) {
        match value {
            Value::String(text) => {
                for (from, to) in replacements {
                    *text = text.replace(from, to);
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, replacements);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    visit(value, replacements);
                }
            }
            _ => {}
        }
    }
    for record in &mut records {
        visit(record, &replacements);
    }
    Ok(records)
}

fn validate_native_package_references(
    value: &Value,
    packages: &BTreeSet<PackageIdentity>,
) -> Result<()> {
    match value {
        Value::Object(fields) => {
            if let Some(krate) = fields.get("Krate") {
                bind_finding(
                    packages,
                    field(krate, "name")?,
                    field(krate, "version")?,
                    krate.get("source").and_then(Value::as_str),
                )?;
            }
            for child in fields.values() {
                validate_native_package_references(child, packages)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_native_package_references(child, packages)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn advisory_identity(
    body: &Value,
    body_sha256: &Sha256Digest,
) -> Result<(AdvisoryIdentity, String)> {
    let raw_id = field(body, "id")?;
    let result = match barbican::RustSecAdvisoryId::parse(raw_id) {
        Ok(id) if raw_id != "RUSTSEC-0000-0000" => (
            AdvisoryIdentity::Assigned {
                rustsec_id: id.to_string(),
            },
            id.to_string(),
        ),
        _ => (
            AdvisoryIdentity::Provisional {
                body_sha256: body_sha256.clone(),
            },
            format!("provisional:{body_sha256}"),
        ),
    };
    Ok(result)
}

fn check_native_exception_paths(manifest: &Path) -> Result<()> {
    let parent = manifest.parent().ok_or("scanner manifest parent missing")?;
    for ancestor in parent.ancestors() {
        for relative in [
            "deny.exceptions.toml",
            ".deny.exceptions.toml",
            ".cargo/deny.exceptions.toml",
        ] {
            match std::fs::symlink_metadata(ancestor.join(relative)) {
                Ok(_)=>return Err("candidate or ancestor cargo-deny local exceptions could override origin licence policy; tool scanner refuses this unsupported auxiliary authority".into()),
                Err(error) if error.kind()==std::io::ErrorKind::NotFound=>{},
                Err(error)=>return Err(error.to_string()),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package(name: &str) -> PackageIdentity {
        PackageIdentity {
            name: name.into(),
            version: "1.0.0".into(),
            source: PackageSource::CratesIo {
                archive_sha256: sha256(name.as_bytes()),
            },
        }
    }
    fn fixture() -> (Value, BTreeMap<String, PackageIdentity>, InstallGraph) {
        let app = package("app");
        let builder = package("builder");
        let graph = InstallGraph {
            root: "app-target".into(),
            nodes: BTreeMap::from([
                (
                    "app-target".into(),
                    GraphNode {
                        package: app.clone(),
                        context: CompilationContext::Target,
                        features: BTreeSet::from(["selected".into()]),
                        build_script: true,
                        proc_macro: false,
                        native_links: false,
                    },
                ),
                (
                    "builder-host".into(),
                    GraphNode {
                        package: builder.clone(),
                        context: CompilationContext::HostBuild,
                        features: BTreeSet::new(),
                        build_script: false,
                        proc_macro: false,
                        native_links: false,
                    },
                ),
            ]),
            edges: BTreeSet::from([GraphEdge {
                from: "app-target".into(),
                to: "builder-host".into(),
                kind: DependencyKind::Build,
                declared_targets: BTreeSet::from([String::new()]),
            }]),
        };
        let metadata = json!({"packages":[
            {"id":"path-app","name":"app","version":"1.0.0","source":null,"manifest_path":"/fixture/app/Cargo.toml","dependencies":[{"name":"builder","rename":"build_helper","kind":"build"},{"name":"devonly","kind":"dev"}],"targets":[{"kind":["bin"],"name":"app"}]},
            {"id":"path-builder","name":"builder","version":"1.0.0","source":null,"manifest_path":"/fixture/builder/Cargo.toml","dependencies":[]},
            {"id":"path-devonly","name":"devonly","version":"1.0.0","source":null,"dependencies":[]}],
            "workspace_members":["path-app","path-devonly"],"workspace_default_members":["path-devonly"],"resolve":{"root":null,"nodes":[{"id":"path-app","features":["selected","dev-leak"]}]}});
        (
            metadata,
            BTreeMap::from([("path-app".into(), app), ("path-builder".into(), builder)]),
            graph,
        )
    }
    fn native_fixture(ctx: &Context, license: &str) -> PreparedSource {
        authored_fixture(ctx, license, true)
    }
    fn authored_fixture(ctx: &Context, license: &str, native_metadata: bool) -> PreparedSource {
        use super::super::source;
        let stage = source::Stage::new().unwrap();
        let root = stage.root.join("authored-source");
        std::fs::create_dir(&root).unwrap();
        let manifest = format!(
            "[package]\nname = \"barbican-owned-apply-fixture\"\nversion = \"1.0.0\"\nedition = \"2024\"\nlicense = \"{license}\"\n[[bin]]\nname = \"barbican-owned-a\"\npath = \"a.rs\"\n[[bin]]\nname = \"barbican-owned-b\"\npath = \"b.rs\"\n"
        );
        source::write_source(&root, "Cargo.toml", 0o644, manifest.as_bytes(), &ctx.budget).unwrap();
        for name in ["a.rs", "b.rs"] {
            source::write_source(&root, name, 0o644, b"fn main() {}\n", &ctx.budget).unwrap();
        }
        let lock=b"version = 4\n[[package]]\nname = \"barbican-owned-apply-fixture\"\nversion = \"1.0.0\"\n".to_vec();
        source::write_source(&root, "Cargo.lock", 0o644, &lock, &ctx.budget).unwrap();
        let cargo_home = stage.root.join("fixture-cargo-home");
        std::fs::create_dir(&cargo_home).unwrap();
        let environment = process::base_environment(
            &stage.root,
            &cargo_home,
            &ctx.evaluator().unwrap().rustc.path,
        );
        let metadata: Value = if native_metadata {
            let output = process::run(
                &ctx.evaluator().unwrap().cargo,
                &[
                    "metadata",
                    "--format-version=1",
                    "--frozen",
                    "--offline",
                    "--no-deps",
                    "--manifest-path",
                    root.join("Cargo.toml").to_str().unwrap(),
                ],
                &stage.root,
                &environment,
                &ctx.budget,
            )
            .unwrap();
            assert!(
                output.status.success(),
                "metadata: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice(&output.stdout).unwrap()
        } else {
            json!({"packages":[{"id":"synthetic-filesystem-only-fixture"}]})
        };
        let original_id = metadata["packages"][0]["id"].as_str().unwrap().to_owned();
        let inputs = source::inventory(&root, "fixture", &ctx.budget).unwrap();
        let materialisation_sha256 = source::inventory_digest(&inputs).unwrap();
        let root_identity = RootSourceIdentity::Git {
            url: "https://example.invalid/barbican-owned-policy-fixture".into(),
            rev: materialisation_sha256.as_str()[..40].into(),
            package: "barbican-owned-apply-fixture".into(),
            version: "1.0.0".into(),
            workspace_manifest: "Cargo.toml".into(),
            package_manifest: "Cargo.toml".into(),
            materialisation_sha256,
        };
        let package = root_identity.package();
        let evaluator = ctx.evaluator().unwrap();
        let subject = Subject {
            schema_version: 1,
            root: root_identity,
            original_lock: OriginalLock::Usable {
                sha256: sha256(&lock),
            },
            effective_lock: EffectiveLock::Upstream {
                sha256: sha256(&lock),
            },
            graph: InstallGraph {
                root: "fixture-target".into(),
                nodes: BTreeMap::from([(
                    "fixture-target".into(),
                    GraphNode {
                        package: package.clone(),
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
                bins: BTreeMap::from([
                    ("barbican-owned-a".into(), BTreeSet::new()),
                    ("barbican-owned-b".into(), BTreeSet::new()),
                ]),
                requested_features: BTreeSet::new(),
                default_features: true,
                all_features: false,
                profile: BuildProfile::Release,
                host: evaluator.host.clone(),
                target: evaluator.host.clone(),
                resolver: 3,
            },
            evaluator: super::super::graph::build_evaluator(evaluator).unwrap(),
            config_sha256: sha256(b"explicit-synthetic-native-policy-fixture"),
            native_mode: NativeMode::VerifiedPath,
            inputs,
        };
        super::super::collection::policy_fixture(
            ctx,
            stage,
            root,
            subject,
            metadata,
            BTreeMap::from([(original_id, package)]),
            lock,
        )
        .unwrap()
    }

    fn native_collect_with_receipt(
        ctx: &Context,
        prepared: &PreparedSource,
        label: &str,
    ) -> Result<PolicyEvidence> {
        let result = collect(ctx, prepared);
        if let Some(destination) = std::env::var_os("BARBICAN_TOOL_POLICY_RECEIPTS") {
            let destination = std::path::PathBuf::from(destination).join(label);
            assert!(destination.is_absolute());
            fn copy_tree(source: &Path, destination: &Path) {
                std::fs::create_dir_all(destination).unwrap();
                for entry in std::fs::read_dir(source).unwrap() {
                    let entry = entry.unwrap();
                    let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                    assert!(!metadata.file_type().is_symlink());
                    if metadata.is_dir() {
                        copy_tree(&entry.path(), &destination.join(entry.file_name()));
                    } else {
                        std::fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
                    }
                }
            }
            copy_tree(
                ctx.stores.data.root(),
                &destination.join("private-fixture-evidence"),
            );
            let summary = match &result {
                Ok(evidence) => {
                    json!({"qualification":"authored inert fixture; synthetic Git transport identity; no source authentication/build/install claim","subject":prepared.subject,"policy":evidence.policy,"content":evidence.content,"observation":evidence.observation,"details":evidence.details})
                }
                Err(error) => {
                    json!({"error":error,"qualification":"authored inert fixture; synthetic Git transport identity"})
                }
            };
            std::fs::write(
                destination.join("result.json"),
                serde_json::to_vec_pretty(&summary).unwrap(),
            )
            .unwrap();
        }
        result
    }

    #[test]
    fn native_policy_scanners_preserve_review_identity_and_reject_root_license() {
        if std::env::var("BARBICAN_TOOL_POLICY_NATIVE").as_deref() != Ok("1") {
            return;
        }
        use super::super::{context::NativeContext, source::Stage, store::Stores};
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
        stores.data.publish(Path::new("cargo-tools/v1/deny.toml"),b"[licenses]\nallow = [\"MIT\"]\n[sources]\nallow-git = [\"https://example.invalid/barbican-owned-policy-fixture\"]\n").unwrap();
        let private_cargo = stage.root.join("native-cargo-home");
        std::fs::create_dir(&private_cargo).unwrap();
        let mut ctx = Context {
            ioc_budget: Default::default(),
            source_client: crate::crates_io_http::UreqCratesIoClient::new(
                crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
            ),
            current: stage.root.clone(),
            repo: None,
            stores,
            evaluator: Some(evaluator),
            original_cargo_home: private_cargo.clone(),
            native_root: private_cargo.clone(),
            native: NativeContext {
                cargo_home: private_cargo.clone(),
                install_root: private_cargo,
                configurations: Vec::new(),
            },
            now: barbican::OffsetDateTime::now_utc().unix_timestamp(),
            budget,
        };
        let prepared = native_fixture(&ctx, "MIT");
        eprintln!(
            "native policy fixture: authored inert two-bin source; synthetic Git transport identity; no authentication, build or installation claim"
        );
        let first = native_collect_with_receipt(&ctx, &prepared, "first").unwrap();
        assert!(first.content.complete);
        assert!(
            !first
                .content
                .findings
                .iter()
                .any(|finding| finding.blocking)
        );
        first
            .content
            .applicable(&prepared.subject, &first.policy)
            .unwrap();
        ctx.now = barbican::OffsetDateTime::now_utc().unix_timestamp();
        let second = native_collect_with_receipt(&ctx, &prepared, "refresh").unwrap();
        assert_eq!(
            first.content.id().unwrap(),
            second.content.id().unwrap(),
            "unchanged current fetch altered review content identity"
        );
        assert!(second.observation.completed_at_utc >= first.observation.completed_at_utc);
        ctx.now = barbican::OffsetDateTime::now_utc().unix_timestamp();
        let forbidden = native_fixture(&ctx, "GPL-3.0-only");
        let blocked =
            native_collect_with_receipt(&ctx, &forbidden, "root-license-negative").unwrap();
        assert!(
            blocked
                .content
                .findings
                .iter()
                .any(|finding| finding.identity == "cargo-deny-licenses" && finding.blocking)
        );
        assert!(
            blocked
                .content
                .applicable(&forbidden.subject, &blocked.policy)
                .is_err()
        );
        eprintln!(
            "native policy scanner qualification passed: current deny+audit; stable refresh content {}; forbidden binary-root licence rejected",
            first.content.id().unwrap()
        );
    }

    #[test]
    fn projection_preserves_binary_root_origin_and_only_exact_build_closure() {
        let (metadata, origins, graph) = fixture();
        let projected = project_graph(&metadata, &origins, &graph).unwrap();
        assert_eq!(projected.metadata["packages"].as_array().unwrap().len(), 2);
        assert_eq!(
            projected.metadata["workspace_members"],
            json!([scanner_id(&package("app"))])
        );
        assert_eq!(
            projected.metadata["packages"][0]["targets"][0]["kind"],
            json!(["bin"])
        );
        let nodes = projected.metadata["resolve"]["nodes"].as_array().unwrap();
        let app = nodes
            .iter()
            .find(|node| node["id"] == scanner_id(&package("app")))
            .unwrap();
        assert_eq!(app["features"], json!(["selected"]));
        assert_eq!(app["deps"][0]["name"], "build_helper");
        assert_eq!(app["deps"][0]["dep_kinds"][0]["kind"], "build");
        let lock = barbican::parse_lockfile(&projected.lock).unwrap();
        assert_eq!(lock.packages().len(), 2);
        assert!(
            lock.packages()
                .iter()
                .all(
                    |package| package.source.as_deref() == Some(barbican::CRATES_IO_SOURCE)
                        && package.checksum.is_some()
                )
        );
        assert!(!projected.lock.contains("devonly"));
    }
    #[test]
    fn projection_retains_declared_target_alternatives_inside_only_selected_edges() {
        let (metadata, origins, mut graph) = fixture();
        let original = project_graph(&metadata, &origins, &graph).unwrap();
        let mut edge = graph.edges.pop_first().unwrap();
        edge.declared_targets = BTreeSet::from([
            String::new(),
            "cfg(unix)".into(),
            "cfg(target_os = \"none\")".into(),
        ]);
        graph.edges.insert(edge);
        let projected = project_graph(&metadata, &origins, &graph).unwrap();
        assert_eq!(projected.lock, original.lock);
        assert_eq!(
            projected.metadata["packages"],
            original.metadata["packages"]
        );
        let nodes = projected.metadata["resolve"]["nodes"].as_array().unwrap();
        let app = nodes
            .iter()
            .find(|node| node["id"] == scanner_id(&package("app")))
            .unwrap();
        assert_eq!(app["dependencies"].as_array().unwrap().len(), 1);
        assert_eq!(app["deps"].as_array().unwrap().len(), 1);
        assert_eq!(
            app["deps"][0]["dep_kinds"],
            json!([
                {"kind":"build","target":null},
                {"kind":"build","target":"cfg(target_os = \"none\")"},
                {"kind":"build","target":"cfg(unix)"},
            ])
        );
        assert_eq!(nodes.len(), 2);
    }
    #[test]
    fn projection_refuses_missing_or_ambiguous_authenticated_members() {
        let (metadata, mut origins, graph) = fixture();
        origins.remove("path-builder");
        assert!(
            project_graph(&metadata, &origins, &graph)
                .unwrap_err()
                .contains("absent")
        );
        let (mut metadata, origins, graph) = fixture();
        let duplicate = metadata["packages"][0].clone();
        metadata["packages"].as_array_mut().unwrap().push(duplicate);
        assert!(
            project_graph(&metadata, &origins, &graph)
                .unwrap_err()
                .contains("ambiguous")
        );
    }
    #[test]
    fn source_erasure_cannot_change_git_policy_or_allow_ambiguous_findings() {
        let registry = package("same");
        let git = PackageIdentity {
            name: registry.name.clone(),
            version: registry.version.clone(),
            source: PackageSource::Git {
                url: "https://github.com/example/owned".into(),
                rev: "a".repeat(40),
                subdirectory: ".".into(),
                materialisation_sha256: sha256(b"git"),
            },
        };
        let packages = BTreeSet::from([registry.clone(), git.clone()]);
        assert!(bind_finding(&packages, "same", "1.0.0", None).is_err());
        assert_eq!(
            bind_finding(&packages, "same", "1.0.0", Some(&source_label(&git))).unwrap(),
            &git
        );
        assert!(scanner_id(&git).ends_with("#same@1.0.0"));
        assert!(source_label(&git).ends_with(&format!("#{}", "a".repeat(40))));
        assert!(bind_finding(&packages, "unknown", "1.0.0", None).is_err());
    }
    #[test]
    fn distinct_placeholder_bodies_cannot_collapse_into_an_assigned_exception() {
        let first = json!({"id":"RUSTSEC-0000-0000","description":"first issue"});
        let second = json!({"id":"RUSTSEC-0000-0000","description":"second issue"});
        let left = advisory_identity(&first, &digest(&first).unwrap()).unwrap();
        let right = advisory_identity(&second, &digest(&second).unwrap()).unwrap();
        assert!(matches!(left.0, AdvisoryIdentity::Provisional { .. }));
        assert_ne!(left, right);
    }
    #[test]
    fn post_build_capture_detects_policy_and_exception_drift_after_collection_deadline() {
        use super::super::{context::NativeContext, source::Stage, store::Stores};
        let stage = Stage::new().unwrap();
        let budget = process::Budget::new(false).unwrap();
        let executable = process::Executable::capture(Path::new("/bin/sh"), &budget).unwrap();
        let evaluator = process::Evaluator {
            inspector: executable.clone(),
            cargo: executable.clone(),
            rustc: executable.clone(),
            deny: executable,
            audit: None,
            host: process::native_host().unwrap(),
            cargo_version: format!("release: 1.95.0\ncommit-hash: {}", "a".repeat(40)),
            rustc_version: format!("release: 1.95.0\ncommit-hash: {}", "b".repeat(40)),
        };
        let stores = Stores::open(
            &stage.root,
            None,
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap();
        let mut ctx = Context {
            ioc_budget: Default::default(),
            source_client: crate::crates_io_http::UreqCratesIoClient::new(
                crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
            ),
            current: stage.root.clone(),
            repo: None,
            stores,
            evaluator: Some(evaluator),
            original_cargo_home: stage.root.join("native"),
            native_root: stage.root.join("native"),
            native: NativeContext {
                cargo_home: stage.root.join("native"),
                install_root: stage.root.join("native"),
                configurations: Vec::new(),
            },
            now: barbican::OffsetDateTime::now_utc().unix_timestamp(),
            budget,
        };
        let original = capture(&ctx).unwrap();
        let config_path = Path::new("cargo-tools/v1/policy.toml");
        ctx.stores
            .data
            .publish(
                config_path,
                b"[tools]\nexception_records = [\"tool-exception.json\"]\n",
            )
            .unwrap();
        assert!(
            capture(&ctx).is_err(),
            "declared absent grant must never be silently omitted"
        );
        let prose = "Reviewed this exact immutable fixture and accepted only its short release-age exception.";
        let mut exception = ToolException {
            subject_id: RecordId {
                kind: RecordKind::Subject,
                schema_version: 1,
                sha256: sha256(b"owned synthetic subject"),
            },
            package: package("fixture"),
            policy_sha256: original.policy_sha256.clone(),
            exception: ExceptionKind::ReleaseAge,
            expires_at_utc: ctx.now + 3600,
            reviewed_at_utc: ctx.now - 1,
            reviewer: "fixture reviewer".into(),
            review_record: prose.into(),
            review_record_sha256: sha256(prose.as_bytes()),
        };
        let exception_path = Path::new("tool-exception.json");
        ctx.stores
            .data
            .publish(exception_path, &serde_json::to_vec(&exception).unwrap())
            .unwrap();
        let granted = capture(&ctx).unwrap();
        assert_eq!(
            original.policy_sha256, granted.policy_sha256,
            "grant transport cannot cause an exception bootstrap cycle"
        );
        assert_ne!(
            original.id().unwrap(),
            granted.id().unwrap(),
            "actual grant set remains part of full authority"
        );
        let prepared = authored_fixture(&ctx, "MIT", false);
        ctx.budget.expire_for_test();
        prepared.recheck_after_build(&ctx).unwrap();
        std::fs::write(
            prepared.root.join("a.rs"),
            b"fn main() { let _changed = 1; }\n",
        )
        .unwrap();
        assert!(
            prepared
                .recheck_after_build(&ctx)
                .unwrap_err()
                .contains("source inventory changed")
        );
        assert!(capture(&ctx).is_err());
        assert_eq!(capture_after_build(&ctx).unwrap(), granted);
        exception.review_record =
            "Reviewed the same exact fixture with an amended, completed rationale.".into();
        exception.review_record_sha256 = sha256(exception.review_record.as_bytes());
        let previous = ctx
            .stores
            .data
            .read(exception_path, MAX_RECORD_BYTES as u64)
            .unwrap();
        ctx.stores
            .data
            .replace(&previous, &serde_json::to_vec(&exception).unwrap())
            .unwrap();
        let amended = capture_after_build(&ctx).unwrap();
        assert_ne!(
            amended, granted,
            "post-build reread must detect changed exception prose and binding"
        );
        let previous = ctx
            .stores
            .data
            .read(config_path, MAX_RECORD_BYTES as u64)
            .unwrap();
        ctx.stores
            .data
            .replace(&previous, b"[release_age]\nminimum_days=99\n")
            .unwrap();
        let changed = capture_after_build(&ctx).unwrap();
        assert_ne!(
            changed.policy_sha256, original.policy_sha256,
            "base rule changes remain bound"
        );
    }

    #[test]
    fn candidate_local_license_exception_authority_is_rejected_before_scanning() {
        let stage = super::super::source::Stage::new().unwrap();
        let root = stage.root.join("candidate");
        std::fs::create_dir(&root).unwrap();
        let manifest = root.join("Cargo.toml");
        check_native_exception_paths(&manifest).unwrap();
        std::fs::write(
            root.join("deny.exceptions.toml"),
            "[licenses]\nexceptions=[]\n",
        )
        .unwrap();
        assert!(
            check_native_exception_paths(&manifest)
                .unwrap_err()
                .contains("override origin licence policy")
        );
        std::fs::remove_file(root.join("deny.exceptions.toml")).unwrap();
        std::fs::write(
            stage.root.join(".deny.exceptions.toml"),
            "[licenses]\nexceptions=[]\n",
        )
        .unwrap();
        assert!(check_native_exception_paths(&manifest).is_err());
    }
    #[test]
    fn material_body_changes_findings_but_unrelated_corpus_metadata_is_excluded() {
        let package = package("app");
        let mut findings = BTreeSet::new();
        let mut details = Vec::new();
        add_finding(
            &mut findings,
            &mut details,
            &package,
            "RUSTSEC-2026-0001",
            FindingKind::Advisory,
            true,
            json!({"title":"unsafe","description":"original"}),
        )
        .unwrap();
        assert!(
            add_finding(
                &mut findings,
                &mut details,
                &package,
                "RUSTSEC-2026-0001",
                FindingKind::Advisory,
                true,
                json!({"title":"unsafe","description":"changed"})
            )
            .is_err()
        );
        let first = json!({"type":"diagnostic","timestamp":"yesterday","fields":{"severity":"error","code":"banned","message":"forbidden","graphs":[]}});
        let mut second = first.clone();
        second["timestamp"] = json!("today");
        assert_eq!(
            digest(&semantic_diagnostic(&first)).unwrap(),
            digest(&semantic_diagnostic(&second)).unwrap()
        );
    }
}
