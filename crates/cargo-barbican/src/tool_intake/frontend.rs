use super::progress::{Handle, Phase, Scope, Target};
use super::{
    context::{NativeContext, RepoContext},
    process::{Budget, Evaluator, Result},
    store::Stores,
};
use crate::cli::{Cli, Command};
use barbican::cargo_tool::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

pub(crate) struct Context {
    pub progress: Handle,
    #[cfg(test)]
    pub authored_refresh: Option<PathBuf>,
    pub current: PathBuf,
    pub repo: Option<RepoContext>,
    pub stores: Stores,
    pub evaluator: Option<Evaluator>,
    pub original_cargo_home: PathBuf,
    pub native_root: PathBuf,
    pub native: NativeContext,
    pub now: i64,
    pub budget: Budget,
    pub ioc_budget: std::cell::RefCell<barbican::ioc::ScanBudget>,
    pub source_client: crate::crates_io_http::UreqCratesIoClient,
}
impl Context {
    pub fn uid(&self) -> Result<u32> {
        crate::private_store::effective_owner()
    }
    pub fn local_user(&self) -> Result<String> {
        Ok(format!("uid:{}", self.uid()?))
    }
    pub fn cancelled(&self) -> &AtomicBool {
        &self.budget.cancelled
    }
    pub fn check(&self) -> Result<()> {
        self.check_with_budget(&self.budget)
    }
    pub fn check_with_budget(&self, budget: &Budget) -> Result<()> {
        budget.check()?;
        self.stores.data.recheck()?;
        self.stores.cache.recheck()?;
        self.native.recheck(budget)?;
        if let Some(repo) = &self.repo {
            repo.recheck(budget)?;
        }
        Ok(())
    }
    pub fn check_after_build(&self) -> Result<()> {
        let budget = Budget::native(self.budget.cancelled.clone());
        self.check_with_budget(&budget)?;
        if let Some(evaluator) = &self.evaluator {
            evaluator.recheck(&budget)?;
        }
        Ok(())
    }
    pub fn evaluator(&self) -> Result<&Evaluator> {
        self.evaluator
            .as_ref()
            .ok_or_else(|| "trusted tool evaluator unavailable".into())
    }
    pub fn knowledge(&self) -> Result<SourceKnowledge> {
        self.stores.knowledge()
    }
    pub fn check_consumer_context(&self) -> Result<()> {
        self.check()?;
        RepoContext::capture_consumer(
            &self.current,
            self.repo.as_ref().map(|repo| repo.root.as_path()),
            self.repo.is_none(),
            &self.budget,
        )?;
        Ok(())
    }
}
pub(crate) struct StoredReview {
    pub subject: Subject,
    pub policy: OriginPolicy,
    pub review: Review,
    pub evidence: EvidenceRecord,
    pub request: super::collection::ReviewRequest,
}
pub(crate) fn is_static(cli: &Cli) -> bool {
    matches!(cli.command, Command::Tool { .. })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewIndex {
    schema_version: u32,
    subject: RecordId,
    policy: RecordId,
    review: RecordId,
    content: RecordId,
    observation: RecordId,
    request: super::collection::ReviewRequest,
}
fn review_path(id: &RecordId) -> Result<PathBuf> {
    id.require_kind(RecordKind::Review)
        .map_err(super::process::err)?;
    Ok(PathBuf::from(format!(
        "cargo-tools/v1/reviews/{}.json",
        id.sha256
    )))
}
pub(crate) fn load_review(ctx: &Context, id: &RecordId) -> Result<StoredReview> {
    let bytes = ctx
        .stores
        .data
        .read(&review_path(id)?, MAX_RECORD_BYTES as u64)?;
    let index: ReviewIndex = serde_json::from_slice(bytes.bytes()).map_err(super::process::err)?;
    if index.schema_version != 1 || index.review != *id {
        return Err("invalid review index schema or binding".into());
    }
    let result = StoredReview {
        subject: ctx.stores.read(&index.subject)?,
        policy: ctx.stores.read(&index.policy)?,
        review: ctx.stores.read(&index.review)?,
        evidence: EvidenceRecord {
            content: ctx.stores.read(&index.content)?,
            observation: ctx.stores.read(&index.observation)?,
        },
        request: index.request,
    };
    result
        .review
        .applicable(&result.subject, &result.policy, &result.evidence.content)
        .map_err(super::process::err)?;
    result.evidence.validate().map_err(super::process::err)?;
    Ok(result)
}
pub(crate) fn save_review(ctx: &Context, review: &StoredReview) -> Result<RecordId> {
    ctx.check()?;
    review.evidence.validate().map_err(super::process::err)?;
    let id = ctx.stores.write(&review.review)?;
    let index = ReviewIndex {
        schema_version: 1,
        subject: ctx.stores.write(&review.subject)?,
        policy: ctx.stores.write(&review.policy)?,
        review: id.clone(),
        content: ctx.stores.write(&review.evidence.content)?,
        observation: ctx.stores.write(&review.evidence.observation)?,
        request: review.request.clone(),
    };
    let bytes = serde_json::to_vec(&index).map_err(super::process::err)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("review index exceeds record budget".into());
    }
    let path = review_path(&id)?;
    match ctx
        .stores
        .data
        .read_optional(&path, MAX_RECORD_BYTES as u64)?
    {
        Some(previous) => ctx
            .stores
            .data
            .replace_checked(&previous, &bytes, || ctx.check())?,
        None => ctx
            .stores
            .data
            .publish_checked(&path, &bytes, || ctx.check())?,
    }
    Ok(id)
}

pub(crate) fn retain_details(
    ctx: &Context,
    review: &Review,
    details: &serde_json::Value,
) -> Result<PathBuf> {
    let bytes = canonical_bytes(details).map_err(super::process::err)?;
    let directory = PathBuf::from(format!(
        "cargo-tools/v1/dossiers/{}",
        review.id().map_err(super::process::err)?.sha256
    ));
    let path = directory.join(format!("{}.json", sha256(&bytes)));
    if let Some(previous) = ctx
        .stores
        .data
        .read_optional(&path, MAX_RECORD_BYTES as u64)?
    {
        if previous.bytes() != bytes {
            return Err("dossier content digest conflict".into());
        }
    } else {
        ctx.stores
            .data
            .publish_checked(&path, &bytes, || ctx.check())?;
    }
    if let Some(inspections) = details.get("ioc_inspections") {
        let report = barbican::ioc::Report {
            schema_version: 1,
            scope: "selected-tool-install-sources".into(),
            sources: serde_json::from_value(inspections.clone()).map_err(super::process::err)?,
            excluded: vec![],
            errors: vec![],
        };
        let report_bytes = report.encode()?;
        let path = super::ioc_exception::report_path(&review.id().map_err(super::process::err)?);
        if let Some(existing) = ctx
            .stores
            .data
            .read_optional(&path, MAX_RECORD_BYTES as u64)?
        {
            if existing.bytes() != report_bytes {
                return Err("review IOC source report changed".into());
            }
        } else {
            ctx.stores
                .data
                .publish_checked(&path, &report_bytes, || ctx.check())?;
        }
    }
    Ok(ctx.stores.data.root().join(directory))
}

pub(crate) fn run(
    cli: &Cli,
    current: &Path,
    now: barbican::OffsetDateTime,
    stdout: &mut dyn std::io::Write,
    register_signals: bool,
    progress: Target,
) -> Result<std::process::ExitCode> {
    use crate::cli::{AuditOutputFormat, ToolCommand};
    let Command::Tool { command } = &cli.command else {
        return Err("expected tool command".into());
    };
    let (operation, format) = match command {
        ToolCommand::Review(args) => ("review", args.format),
        ToolCommand::Exception(args) => ("exception", args.format),
        ToolCommand::Accept(args) => ("accept", args.options.format),
        ToolCommand::Install(args) => ("install", args.options.format),
        ToolCommand::InstallationCheck { format, .. } => ("installation-check", *format),
        ToolCommand::AdmissionCheck(args) => ("admission-check", args.options.format),
    };
    let validate = || -> Result<()> {
        let parse = |value: &str, kind: RecordKind| -> Result<()> {
            value
                .parse::<RecordId>()
                .map_err(super::process::err)?
                .require_kind(kind)
                .map_err(super::process::err)
        };
        match command {
            ToolCommand::Review(args) => {
                if let Some(spec) = &args.spec {
                    spec.parse::<barbican::ExactCrateSpec>()
                        .map_err(super::process::err)?;
                }
                if let Some(url) = &args.git {
                    barbican::GitSourceIdentity::new(
                        url,
                        args.rev.as_deref().ok_or("full Git revision missing")?,
                    )
                    .map_err(super::process::err)?;
                }
                if let Some(previous) = &args.from {
                    parse(previous, RecordKind::InstalledBinding)?;
                }
                if args.target.as_ref().is_some_and(|target| {
                    super::process::native_host().is_ok_and(|host| host != *target)
                }) {
                    return Err("--target must be the qualified native host".into());
                }
            }
            ToolCommand::Exception(args) => parse(&args.review_id, RecordKind::Review)?,
            ToolCommand::Accept(args) => parse(&args.review_id, RecordKind::Review)?,
            ToolCommand::Install(args) => parse(&args.review_id, RecordKind::Review)?,
            ToolCommand::InstallationCheck {
                installation_id, ..
            } => parse(installation_id, RecordKind::InstalledBinding)?,
            ToolCommand::AdmissionCheck(args) => {
                parse(&args.installation_id, RecordKind::InstalledBinding)?
            }
        }
        Ok(())
    };
    let (failure, code) = match validate() {
        Err(error) => (Some(error), 2),
        Ok(()) => match run_operation(cli, current, now, stdout, register_signals, progress) {
            Ok(code) => return Ok(code),
            Err(error) => (Some(error), 1),
        },
    };
    let detail = failure.ok_or("missing tool failure diagnostic")?;
    match format{
        AuditOutputFormat::Json=>writeln!(stdout,"{}",serde_json::json!({"schema_version":1,"operation":operation,"status":if code==2{"invalid-input"}else{"blocked-or-unavailable"},"diagnostic":detail})),
        AuditOutputFormat::Text=>writeln!(stdout,"Tool {operation}: {}",crate::commands::escape_diagnostic_for_terminal(&detail)),
    }.map_err(super::process::err)?;
    Ok(std::process::ExitCode::from(code))
}

fn run_operation(
    cli: &Cli,
    current: &Path,
    now: barbican::OffsetDateTime,
    stdout: &mut dyn std::io::Write,
    register_signals: bool,
    progress: Target,
) -> Result<std::process::ExitCode> {
    use super::collection::{self, ReviewRequest};
    use crate::cli::{AuditOutputFormat, ToolCommand};
    let Command::Tool { command } = &cli.command else {
        return Err("expected tool command".into());
    };
    let (standalone, format) = match command {
        ToolCommand::Review(args) => (args.standalone, args.format),
        ToolCommand::Exception(args) => (args.standalone, args.format),
        ToolCommand::Accept(args) => (args.options.standalone, args.options.format),
        ToolCommand::Install(args) => (args.options.standalone, args.options.format),
        ToolCommand::AdmissionCheck(args) => (args.options.standalone, args.options.format),
        ToolCommand::InstallationCheck { format, .. } => (true, *format),
    };
    let budget = Budget::new(register_signals)?;
    let scope = match command {
        ToolCommand::Review(_) => progress.start(Phase::Review),
        ToolCommand::Install(_) => progress.start(Phase::Install),
        _ => Scope::default(),
    };
    let static_check = matches!(command, ToolCommand::InstallationCheck { .. });
    let repo = if static_check {
        None
    } else if matches!(command, ToolCommand::AdmissionCheck(_)) {
        RepoContext::capture_consumer(current, cli.repo.as_deref(), standalone, &budget)?
    } else {
        RepoContext::capture(current, cli.repo.as_deref(), standalone, &budget)?
    };
    let native = if static_check || matches!(command, ToolCommand::Exception(_)) {
        NativeContext::for_static()?
    } else {
        NativeContext::capture(current, &budget)?
    };
    let stores = Stores::open(
        current,
        repo.as_ref().map(|repo| repo.root.as_path()),
        cli.data_dir.as_deref(),
        cli.cache_dir.as_deref(),
    )?;
    let mut ctx = Context {
        progress: scope.handle.clone(),
        #[cfg(test)]
        authored_refresh: None,
        current: current.to_owned(),
        repo,
        stores,
        evaluator: None,
        original_cargo_home: native.cargo_home.clone(),
        native_root: native.install_root.clone(),
        native,
        now: now.unix_timestamp(),
        budget,
        ioc_budget: Default::default(),
        source_client: crate::crates_io_http::UreqCratesIoClient::new(
            crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
        ),
    };
    let evaluator_stage = super::source::Stage::new()?;
    let requested_paths = match command {
        ToolCommand::Review(args) => Some((args.cargo.clone(), args.rustc.clone())),
        _ => None,
    };
    let requested_paths = match command {
        ToolCommand::Accept(args) => {
            let review = load_review(&ctx, &args.review_id.parse().map_err(super::process::err)?)?;
            Some((Some(review.request.cargo), Some(review.request.rustc)))
        }
        ToolCommand::Install(args) => {
            let review = load_review(&ctx, &args.review_id.parse().map_err(super::process::err)?)?;
            Some((Some(review.request.cargo), Some(review.request.rustc)))
        }
        ToolCommand::AdmissionCheck(_) => Some((None, None)),
        _ => requested_paths,
    };
    if let Some((cargo, rustc)) = requested_paths {
        let config = super::policy::configuration(&ctx)?;
        let uses_audit = matches!(
            config.delegates.advisories.lockfile_scanner,
            barbican::LockfileAdvisoryScanner::CargoAudit | barbican::LockfileAdvisoryScanner::Both
        );
        ctx.progress.phase(Phase::Evaluators);
        ctx.evaluator = Some(Evaluator::capture(
            cargo.as_deref(),
            rustc.as_deref(),
            &evaluator_stage.root,
            &ctx.budget,
            uses_audit,
        )?);
    }
    let result = match command {
        ToolCommand::Exception(args) => {
            if args.ioc {
                super::ioc_exception::run(&ctx, args, now)?
            } else {
                super::exception_authoring::run(&ctx, args, now)?
            }
        }
        ToolCommand::Review(args) => {
            let evaluator = ctx.evaluator()?;
            let request = ReviewRequest {
                spec: args.spec.clone(),
                git: args.git.clone(),
                rev: args.rev.clone(),
                package: args.package.clone(),
                bins: args.bins.clone(),
                features: args.features.clone(),
                no_default_features: args.no_default_features,
                all_features: args.all_features,
                profile: args.profile.clone(),
                target: args.target.clone(),
                from: args.from.clone(),
                cargo: evaluator.cargo.path.clone(),
                rustc: evaluator.rustc.path.clone(),
            };
            let prepared = collection::prepare(&ctx, &request)?;
            let policy = super::policy::collect(&ctx, &prepared)?;
            if !policy.content.complete {
                return Err(
                    "required tool evidence is incomplete; no complete review published".into(),
                );
            }
            let review = Review {
                schema_version: 1,
                subject_id: prepared.subject.id().map_err(super::process::err)?,
                policy_id: policy.policy.id().map_err(super::process::err)?,
                evidence_content_id: policy.content.id().map_err(super::process::err)?,
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
            ctx.progress.phase(Phase::ReviewRecords);
            let dossier_directory = retain_details(&ctx, &review, &policy.details)?;
            let source_directory = prepared.save_sources(&ctx)?;
            let stored = StoredReview {
                subject: prepared.subject,
                policy: policy.policy,
                review,
                evidence: EvidenceRecord {
                    content: policy.content,
                    observation: policy.observation,
                },
                request,
            };
            let baseline = if let Some(prior_id) = &stored.request.from {
                let prior = (|| -> Result<_> {
                    let binding: InstalledBinding = ctx
                        .stores
                        .read(&prior_id.parse().map_err(super::process::err)?)?;
                    let observed = super::check::correspondence(&ctx, &binding)?;
                    let previous = load_review(&ctx, &binding.review_id)?;
                    super::acceptance::load(&ctx, &previous)?;
                    tool_delta(
                        &stored.subject,
                        &stored.evidence.content,
                        Some((
                            &previous.subject,
                            &previous.evidence.content,
                            &binding,
                            &observed,
                        )),
                    )
                    .map_err(super::process::err)
                })();
                match prior {
                    Ok(delta) => serde_json::to_value(delta).map_err(super::process::err)?,
                    Err(reason) => {
                        serde_json::json!({"status":"baseline-unavailable","reason":reason})
                    }
                }
            } else {
                serde_json::to_value(ToolDelta::BaselineUnavailable).map_err(super::process::err)?
            };
            let id = save_review(&ctx, &stored)?;
            let scaffold_path = PathBuf::from(format!("cargo-tools/v1/reviews/{}.md", id.sha256));
            if ctx
                .stores
                .data
                .read_optional(&scaffold_path, MAX_RECORD_BYTES as u64)?
                .is_none()
            {
                let mut scaffold = format!(
                    "# Cargo tool assessment\n\nCargo-Tool-Review: {id}\nReviewer: PENDING\nDecision: PENDING\n"
                );
                for requirement in &stored.review.assessment_requirements {
                    scaffold.push_str(&format!("Response: {requirement}=PENDING\n"));
                }
                scaffold.push_str("Risk-Acknowledgement: PENDING\n");
                ctx.stores
                    .data
                    .publish_checked(&scaffold_path, scaffold.as_bytes(), || ctx.check())?;
            }
            let blocked = stored
                .evidence
                .content
                .findings
                .iter()
                .any(|finding| finding.blocking);
            let next_action = if blocked {
                "Resolve the blocking source and policy findings, then perform a fresh tool review."
                    .into()
            } else {
                format!(
                    "Complete the PENDING assessment; using the same governance and storage options run cargo-barbican tool accept {} --record {}{}",
                    shell_quote(&id.to_string()),
                    shell_quote(
                        &ctx.stores
                            .data
                            .root()
                            .join(&scaffold_path)
                            .to_string_lossy()
                    ),
                    if standalone { " --standalone" } else { "" }
                )
            };
            serde_json::json!({"schema_version":1,"operation":"review","status":if blocked{"evidence-complete-blocked"}else{"evidence-complete-pending-human"},"review_id":id.to_string(),"subject_id":stored.review.subject_id.to_string(),"policy_id":stored.review.policy_id.to_string(),"policy_sha256":stored.policy.policy_sha256,"subject":stored.subject,"findings":stored.evidence.content.findings,"baseline":baseline,"source_directory":source_directory,"dossier_directory":dossier_directory,"assessment_record":ctx.stores.data.root().join(&scaffold_path),"next_action":next_action})
        }
        ToolCommand::Accept(args) => {
            let review = load_review(&ctx, &args.review_id.parse().map_err(super::process::err)?)?;
            super::acceptance::accept(&ctx, &review, args)?
        }
        ToolCommand::Install(args) => {
            let review = load_review(&ctx, &args.review_id.parse().map_err(super::process::err)?)?;
            super::installation::install(&ctx, &review, args)?
        }
        ToolCommand::InstallationCheck {
            installation_id, ..
        } => super::check::installation_check(
            &ctx,
            &installation_id.parse().map_err(super::process::err)?,
        )?,
        ToolCommand::AdmissionCheck(args) => super::admission::admission_check(
            &ctx,
            &args.installation_id.parse().map_err(super::process::err)?,
            args,
        )?,
    };
    drop(scope);
    match format {
        AuditOutputFormat::Json => writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&result).map_err(super::process::err)?
        ),
        AuditOutputFormat::Text => render_text(stdout, &result),
    }
    .map_err(super::process::err)?;
    let blocking = result
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|findings| {
            findings
                .iter()
                .any(|finding| finding.get("blocking") == Some(&serde_json::Value::Bool(true)))
        });
    Ok(if blocking {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    })
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn render_text(stdout: &mut dyn std::io::Write, result: &serde_json::Value) -> std::io::Result<()> {
    let escape = crate::commands::escape_diagnostic_for_terminal;
    if result.get("operation").and_then(serde_json::Value::as_str) == Some("review") {
        writeln!(
            stdout,
            "Tool review: {}",
            escape(
                result
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unavailable")
            )
        )?;
        for (field, label) in [
            ("review_id", "Review"),
            ("subject_id", "Subject"),
            ("policy_sha256", "Base policy SHA256"),
            ("source_directory", "Source dossier"),
            ("dossier_directory", "Policy dossier"),
            ("assessment_record", "Pending assessment"),
        ] {
            if let Some(value) = result.get(field).and_then(serde_json::Value::as_str) {
                writeln!(stdout, "{label}: {}", escape(value))?;
            }
        }
        if let Some(subject) = result.get("subject") {
            let nodes = subject
                .pointer("/graph/nodes")
                .and_then(serde_json::Value::as_object)
                .map_or(0, |nodes| nodes.len());
            let bins = subject
                .pointer("/selection/bins")
                .and_then(serde_json::Value::as_object)
                .map(|bins| bins.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            writeln!(
                stdout,
                "Native graph: {nodes} package contexts; binaries: {}",
                escape(&bins)
            )?;
        }
        if let Some(baseline) = result.get("baseline") {
            if baseline.get("status").and_then(serde_json::Value::as_str) == Some("compared") {
                let count = |field| {
                    baseline
                        .get(field)
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, Vec::len)
                };
                writeln!(
                    stdout,
                    "Verified installation delta: {} packages added, {} removed; {} new findings",
                    count("added"),
                    count("removed"),
                    count("new_findings")
                )?;
                for (field, label) in [
                    ("changed_selection", "Binary or feature selection"),
                    ("changed_graph", "Install graph"),
                    ("changed_inputs", "Source inputs"),
                ] {
                    if baseline.get(field).and_then(serde_json::Value::as_bool) == Some(true) {
                        writeln!(stdout, "Changed: {label}")?;
                    }
                }
            } else {
                writeln!(stdout, "Baseline unavailable; this is a full fresh review")?;
                if let Some(reason) = baseline.get("reason").and_then(serde_json::Value::as_str) {
                    writeln!(stdout, "Baseline detail: {}", escape(reason))?;
                }
            }
        }
        if let Some(findings) = result.get("findings").and_then(serde_json::Value::as_array) {
            for blocking in [true, false] {
                for finding in findings.iter().filter(|finding| {
                    finding.get("blocking").and_then(serde_json::Value::as_bool) == Some(blocking)
                }) {
                    writeln!(
                        stdout,
                        "{}: {}@{} — {}",
                        if blocking { "BLOCK" } else { "REVIEW" },
                        escape(
                            finding
                                .pointer("/package/name")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unknown")
                        ),
                        escape(
                            finding
                                .pointer("/package/version")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unknown")
                        ),
                        escape(
                            finding
                                .get("identity")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("unknown finding")
                        )
                    )?;
                    if blocking
                        && let Some(detail) = finding
                            .get("detail_sha256")
                            .and_then(serde_json::Value::as_str)
                    {
                        writeln!(stdout, "  Finding detail SHA256: {}", escape(detail))?;
                    }
                }
            }
            writeln!(
                stdout,
                "Findings: {} blocking, {} for human review",
                findings
                    .iter()
                    .filter(
                        |finding| finding.get("blocking") == Some(&serde_json::Value::Bool(true))
                    )
                    .count(),
                findings
                    .iter()
                    .filter(
                        |finding| finding.get("blocking") == Some(&serde_json::Value::Bool(false))
                    )
                    .count()
            )?;
        }
        if let Some(next) = result
            .get("next_action")
            .and_then(serde_json::Value::as_str)
        {
            writeln!(stdout, "{}", escape(next))?;
        }
        Ok(())
    } else {
        writeln!(
            stdout,
            "{}",
            escape(&serde_json::to_string_pretty(result).map_err(std::io::Error::other)?)
        )
    }
}
