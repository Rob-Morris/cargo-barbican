use crate::cli::{
    AuditOutputFormat, Cli, Command, IocCheckArgs, IocCommand, IocSelectionArgs, PinCommand,
};
use crate::controlled_process::{Budget, Result, err};
use crate::ioc_intake::{self, Context};
use barbican::{OffsetDateTime, ioc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicReport {
    pub schema_version: u32,
    pub operation: String,
    pub status: String,
    pub origin: Option<PathBuf>,
    pub inspection: ioc::Report,
    pub input: ioc_intake::CapturedInputs,
    pub decisions: Vec<ioc::Decision>,
    pub authority_records: Vec<ioc::IocRecordReference>,
    pub checker_sha256: barbican::Sha256Digest,
    pub detector_semantics: std::collections::BTreeSet<String>,
}
impl PublicReport {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.operation != "ioc-check"
            || !matches!(self.status.as_str(), "pass" | "blocked-or-unavailable")
        {
            return Err("unsupported IOC public report".into());
        }
        self.inspection.validate()?;
        self.input.validate(&self.inspection)?;
        if self.decisions.len() != self.inspection.sources.len()
            || self.detector_semantics
                != self
                    .inspection
                    .sources
                    .iter()
                    .map(|source| source.semantics.clone())
                    .collect()
        {
            return Err("IOC report decision/provenance binding mismatch".into());
        }
        let mut references = std::collections::BTreeSet::new();
        for reference in &self.authority_records {
            reference.validate()?;
            if !references.insert(&reference.record) {
                return Err("duplicate IOC authority reference".into());
            }
        }
        for (source, decision) in self.inspection.sources.iter().zip(&self.decisions) {
            let ids = source
                .findings
                .iter()
                .filter(|f| f.complete)
                .map(|f| f.id())
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            if !decision.allowed.is_disjoint(&decision.blocked)
                || decision
                    .allowed
                    .union(&decision.blocked)
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
                    != ids
                || (decision.complete && !matches!(source.coverage, ioc::Coverage::Complete))
                || decision.errors.iter().any(|error| error.len() > 16_384)
            {
                return Err("IOC report contains inconsistent finding decisions".into());
            }
        }
        let passed = self.inspection.errors.is_empty()
            && self.decisions.iter().all(ioc::Decision::is_success);
        if (self.status == "pass") != passed {
            return Err("IOC report verdict contradicts evidence".into());
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        ioc::encode_bounded(self)
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > ioc::MAX_REPORT_BYTES {
            return Err("IOC public report exceeds 8 MiB".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(err)?;
        value.validate()?;
        Ok(value)
    }
}

pub(crate) fn is_static(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        Command::Ioc { .. }
            | Command::Pin {
                command: PinCommand::Exception { ioc: true, .. }
            }
    )
}

pub(crate) fn run(
    cli: &Cli,
    current: &Path,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode> {
    let format = match &cli.command {
        Command::Ioc {
            command: IocCommand::Check(args),
        } => args.format,
        _ => AuditOutputFormat::Text,
    };
    let (result, failure_code) = match validate_arguments(cli) {
        Ok(()) => (run_inner(cli, current, now, stdout, stderr), 1),
        Err(error) => (Err(error), 2),
    };
    match result {
        Ok(exit) => Ok(exit),
        Err(error) => {
            match format {
                AuditOutputFormat::Json => writeln!(stdout, "{}", serde_json::json!({"schema_version":1,"operation":"ioc-check","status":if failure_code==2{"invalid-input"}else{"blocked-or-unavailable"},"diagnostic":error})),
                AuditOutputFormat::Text => writeln!(stderr, "FAIL IOC: {}", super::escape_diagnostic_for_terminal(&error)),
            }.map_err(err)?;
            Ok(ExitCode::from(failure_code))
        }
    }
}

fn validate_arguments(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Ioc {
            command: IocCommand::Check(args),
        } => {
            let selectors = usize::from(!args.specs.is_empty())
                + usize::from(args.git.is_some())
                + usize::from(args.lockfile.is_some());
            if selectors != 1 {
                return Err("choose exactly one registry, Git, or lockfile source selector".into());
            }
            for spec in &args.specs {
                spec.parse::<barbican::ExactCrateSpec>().map_err(err)?;
            }
            if let Some(url) = &args.git {
                barbican::GitSourceIdentity::new(url, args.rev.as_deref().ok_or("--rev required")?)
                    .map_err(err)?;
                if args
                    .package
                    .as_ref()
                    .is_none_or(|p| p.is_empty() || p.chars().any(char::is_control))
                {
                    return Err("--package requires an exact package name".into());
                }
            }
        }
        Command::Ioc {
            command: IocCommand::Review(args),
        } => validate_selection(&args.selection)?,
        Command::Pin {
            command:
                PinCommand::Exception {
                    ioc: true,
                    review_record,
                    record,
                    review_by,
                    source_id,
                    paths,
                    rules,
                    ..
                },
        } => {
            if review_record.is_some() == record.is_some() {
                return Err("choose exactly one --review-record or --record mode".into());
            }
            deadline_utc(review_by.as_deref())?;
            validate_selection(&IocSelectionArgs {
                package: None,
                source_id: source_id.clone(),
                paths: paths.clone(),
                rules: rules.clone(),
            })?;
            for path in review_record.iter().chain(record.iter()) {
                relative_record(path)?;
            }
        }
        _ => return Err("expected IOC command".into()),
    }
    Ok(())
}
fn validate_selection(selection: &IocSelectionArgs) -> Result<()> {
    if let Some(id) = &selection.source_id {
        barbican::Sha256Digest::try_from(id.as_str()).map_err(err)?;
    }
    for path in &selection.paths {
        ioc::relative_path(path)?;
    }
    for rule in &selection.rules {
        if ioc::rule(rule).is_none() {
            return Err("unknown IOC rule selector".into());
        }
    }
    Ok(())
}

fn run_inner(
    cli: &Cli,
    current: &Path,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode> {
    let ctx = Context::capture(
        current,
        cli.repo.as_deref(),
        cli.data_dir.as_deref(),
        cli.cache_dir.as_deref(),
    )?;
    match &cli.command {
        Command::Ioc {
            command: IocCommand::Check(args),
        } => check(&ctx, args, now, stdout, stderr),
        Command::Ioc {
            command: IocCommand::Review(args),
        } => {
            let report = read_report(&ctx, &args.inspection)?;
            let selected = ioc::select(&report.inspection, &selection(&args.selection))?;
            let text = ioc::scaffold_review(&selected)?;
            let path = write_new(&ctx.current, &args.review_record, text.as_bytes(), || {
                ctx.check()
            })?;
            writeln!(
                stdout,
                "IOC review: PENDING\nRecord: {}\nNo policy authority was written.",
                escape_path(&path)
            )
            .map_err(err)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Pin {
            command:
                PinCommand::Exception {
                    spec,
                    ioc: true,
                    inspection,
                    review_record,
                    record,
                    review_by,
                    source_id,
                    paths,
                    rules,
                    ..
                },
        } => {
            let report = read_report(&ctx, inspection.as_ref().ok_or("--inspection is required")?)?;
            let selected = ioc::select(
                &report.inspection,
                &ioc::Selection {
                    package: spec.clone(),
                    source_id: source_id.clone(),
                    paths: paths.iter().cloned().collect(),
                    rules: rules.iter().cloned().collect(),
                },
            )?;
            repository_exception(
                &ctx,
                &selected,
                review_record.as_deref(),
                record.as_deref(),
                review_by.as_deref(),
                now,
                stdout,
            )
        }
        _ => Err("expected static IOC operation".into()),
    }
}

pub(crate) fn selection(args: &IocSelectionArgs) -> ioc::Selection {
    ioc::Selection {
        package: args.package.clone(),
        source_id: args.source_id.clone(),
        paths: args.paths.iter().cloned().collect(),
        rules: args.rules.iter().cloned().collect(),
    }
}

fn check(
    ctx: &Context,
    args: &IocCheckArgs,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode> {
    let checker = crate::controlled_process::Executable::capture(
        &std::env::current_exe().map_err(err)?,
        &ctx.budget,
    )?;
    let selected = if let Some(path) = &args.lockfile {
        ioc_intake::Selection::Lockfile(path.clone())
    } else if let Some(url) = &args.git {
        ioc_intake::Selection::Git {
            url: url.clone(),
            rev: args.rev.clone().ok_or("--rev is required")?,
            package: args.package.clone().ok_or("--package is required")?,
        }
    } else {
        ioc_intake::Selection::Registry(
            args.specs
                .iter()
                .map(|s| s.parse().map_err(err))
                .collect::<Result<Vec<_>>>()?,
        )
    };
    let collected = ioc_intake::collect(ctx, &selected)?;
    let mut inspection = collected.report;
    let (allowances, references) = load_allowances(ctx)?;
    let observed_now = OffsetDateTime::now_utc().unix_timestamp();
    if observed_now < now.unix_timestamp() {
        return Err("clock rollback during IOC inspection".into());
    }
    let allowance_index =
        ioc::index_allowances_checked(&allowances, observed_now, &mut || ctx.budget.check())?;
    let decisions = inspection
        .sources
        .iter()
        .map(|source| ioc::adjudicate_indexed(source, &allowance_index))
        .collect::<Result<Vec<_>>>()?;
    if let Err(error) =
        ioc_intake::knowledge_check(ctx, &inspection, &allowance_index, observed_now)
    {
        inspection.errors.push(error);
    }
    let passed = inspection.errors.is_empty() && decisions.iter().all(ioc::Decision::is_success);
    let detector_semantics = inspection
        .sources
        .iter()
        .map(|source| source.semantics.clone())
        .collect();
    let public = PublicReport {
        input: collected.input,
        checker_sha256: checker.sha256.clone(),
        detector_semantics,
        schema_version: 1,
        operation: "ioc-check".into(),
        status: if passed {
            "pass"
        } else {
            "blocked-or-unavailable"
        }
        .into(),
        origin: ctx.origin.as_ref().map(|o| o.root.clone()),
        inspection,
        decisions,
        authority_records: references,
    };
    let bytes = public.encode()?;
    ctx.check()?;
    checker.recheck(&ctx.budget)?;
    recheck_allowances(ctx, &allowances)?;
    if let Some(path) = &args.output {
        let path = write_new(&ctx.current, path, &bytes, || {
            ctx.check()?;
            checker.recheck(&ctx.budget)?;
            recheck_allowances(ctx, &allowances)
        })?;
        writeln!(stderr, "IOC JSON report: {}", escape_path(&path)).map_err(err)?;
    }
    match args.format {
        AuditOutputFormat::Json => {
            stdout.write_all(&bytes).map_err(err)?;
            writeln!(stdout).map_err(err)?;
        }
        AuditOutputFormat::Text => render(&public, stdout)?,
    }
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

pub(crate) fn gate(
    current: &Path,
    data: Option<&Path>,
    cache: Option<&Path>,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode> {
    let ctx = Context::capture(current, Some(current), data, cache)?;
    check(
        &ctx,
        &IocCheckArgs {
            specs: vec![],
            git: None,
            rev: None,
            package: None,
            lockfile: Some(PathBuf::from("Cargo.lock")),
            format: AuditOutputFormat::Text,
            output: None,
        },
        now,
        stdout,
        stderr,
    )
}

fn render(report: &PublicReport, stdout: &mut dyn Write) -> Result<()> {
    writeln!(stdout, "IOC check: {}", report.status).map_err(err)?;
    writeln!(
        stdout,
        "Scope: {}",
        super::escape_diagnostic_for_terminal(&report.inspection.scope)
    )
    .map_err(err)?;
    writeln!(
        stdout,
        "Authority: {}",
        report
            .origin
            .as_ref()
            .map(|p| escape_path(p))
            .unwrap_or_else(|| "no repository; no repository allowances".into())
    )
    .map_err(err)?;
    if let Some(lock) = &report.input.lockfile {
        writeln!(
            stdout,
            "Captured lock: {} sha256={}",
            super::escape_diagnostic_for_terminal(&lock.path),
            lock.sha256
        )
        .map_err(err)?;
    }
    writeln!(
        stdout,
        "Requested external sources: {} source-set={}",
        report.input.requested_source_count, report.input.source_set_sha256
    )
    .map_err(err)?;
    for requested in &report.input.requested_sources {
        writeln!(
            stdout,
            "Requested: {} coverage={}",
            super::escape_diagnostic_for_terminal(
                &serde_json::to_string(&requested.source).map_err(err)?
            ),
            super::escape_diagnostic_for_terminal(
                &serde_json::to_string(&requested.coverage).map_err(err)?
            )
        )
        .map_err(err)?;
    }
    for (source, decision) in report.inspection.sources.iter().zip(&report.decisions) {
        writeln!(
            stdout,
            "{}@{} source={} coverage={:?}",
            source.source.name,
            source.source.version,
            source.source.id()?,
            super::escape_diagnostic_for_terminal(&format!("{:?}", source.coverage))
        )
        .map_err(err)?;
        for finding in &source.findings {
            let id = if finding.complete {
                Some(finding.id()?)
            } else {
                None
            };
            let disposition = if id.as_ref().is_some_and(|id| decision.allowed.contains(id)) {
                "reviewed-allowed"
            } else if id.is_none() {
                "incomplete occurrence set"
            } else {
                "unreviewed"
            };
            writeln!(
                stdout,
                "  {} {} {} [{}]",
                disposition,
                super::escape_diagnostic_for_terminal(&finding.path),
                finding.rule,
                id.map(|id| id.to_string())
                    .unwrap_or_else(|| "ID unavailable".into())
            )
            .map_err(err)?;
            for occurrence in &finding.occurrences {
                writeln!(
                    stdout,
                    "    bytes {}..{}: {}",
                    occurrence.start,
                    occurrence.end,
                    super::escape_diagnostic_for_terminal(&occurrence.snippet)
                )
                .map_err(err)?;
            }
        }
        for error in &decision.errors {
            writeln!(stdout, "  {}", super::escape_diagnostic_for_terminal(error)).map_err(err)?;
        }
    }
    for excluded in &report.inspection.excluded {
        writeln!(
            stdout,
            "Outside scope: {}",
            super::escape_diagnostic_for_terminal(excluded)
        )
        .map_err(err)?;
    }
    for error in &report.inspection.errors {
        writeln!(
            stdout,
            "Unavailable: {}",
            super::escape_diagnostic_for_terminal(error)
        )
        .map_err(err)?;
    }
    Ok(())
}

fn read_report(ctx: &Context, path: &Path) -> Result<PublicReport> {
    PublicReport::parse(&read_external(&ctx.current, path, &ctx.budget)?)
}

pub(crate) fn load_allowances(
    ctx: &Context,
) -> Result<(Vec<ioc::Allowance>, Vec<ioc::IocRecordReference>)> {
    let Some(origin) = &ctx.origin else {
        return Ok((vec![], vec![]));
    };
    read_allowances(
        &origin.root,
        origin.reviewed_targets.as_deref(),
        &ctx.budget,
    )
}

fn read_allowances(
    root: &Path,
    policy: Option<&[u8]>,
    budget: &Budget,
) -> Result<(Vec<ioc::Allowance>, Vec<ioc::IocRecordReference>)> {
    let Some(bytes) = policy else {
        return Ok((vec![], vec![]));
    };
    let targets = barbican::parse_reviewed_targets_toml(std::str::from_utf8(bytes).map_err(err)?)
        .map_err(err)?;
    let mut allowances = Vec::new();
    for reference in targets.ioc_records() {
        reference.validate()?;
        let bytes =
            crate::verified_source::read_optional(root, Path::new(&reference.record), budget)?
                .ok_or("IOC authority record is missing")?;
        if ioc::digest(&bytes) != reference.record_sha256 {
            return Err(
                "IOC authority record bytes changed; explicitly republish its current reference"
                    .into(),
            );
        }
        allowances.push(ioc::Allowance::from_text(
            std::str::from_utf8(&bytes).map_err(err)?,
        )?);
    }
    Ok((allowances, targets.ioc_records().to_vec()))
}

pub(crate) struct RepositoryAllowances {
    pub allowances: Vec<ioc::Allowance>,
    root: PathBuf,
    policy: Option<Vec<u8>>,
    budget: Budget,
}
impl RepositoryAllowances {
    pub fn capture(root: &Path) -> Result<Self> {
        let budget = Budget::new(false)?;
        let root = fs::canonicalize(root).map_err(err)?;
        let policy = crate::verified_source::read_optional(
            &root,
            Path::new("reviewed-targets.toml"),
            &budget,
        )?;
        let allowances = read_allowances(&root, policy.as_deref(), &budget)?.0;
        Ok(Self {
            allowances,
            root,
            policy,
            budget,
        })
    }
    pub fn check(&self) -> Result<()> {
        if crate::verified_source::read_optional(
            &self.root,
            Path::new("reviewed-targets.toml"),
            &self.budget,
        )? != self.policy
            || read_allowances(&self.root, self.policy.as_deref(), &self.budget)?.0
                != self.allowances
        {
            return Err("IOC repository authority changed during inspection".into());
        }
        Ok(())
    }
}

fn recheck_allowances(ctx: &Context, expected: &[ioc::Allowance]) -> Result<()> {
    if load_allowances(ctx)?.0 != expected {
        return Err("IOC authority changed during operation".into());
    }
    Ok(())
}

fn repository_exception(
    ctx: &Context,
    selected: &ioc::Inspection,
    scaffold: Option<&Path>,
    record: Option<&Path>,
    deadline: Option<&str>,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
) -> Result<ExitCode> {
    let origin = ctx
        .origin
        .as_ref()
        .ok_or("pin exception --ioc requires repository authority; supply --repo")?;
    let policy = origin.reviewed_targets.as_ref().ok_or(
        "reviewed-targets.toml is missing; adopt explicit policy before publishing IOC authority",
    )?;
    match (scaffold,record) {
        (Some(path),None)=>{
            let relative=relative_record(path)?;
            let mut review=ioc::parse_review(&ioc::scaffold_review(selected)?)?;
            review.review_by_utc=deadline_utc(deadline)?;
            let text=ioc::render_review(&review)?;
            let path=write_new(&origin.root,Path::new(&relative),text.as_bytes(),||ctx.check())?;
            let reference=ioc::IocRecordReference{record:relative,record_sha256:ioc::digest(text.as_bytes())};
            writeln!(stdout,"IOC exception scaffold: PENDING\nRecord: {}\nGrant fragment (not published; update its digest after completion):\n{}",escape_path(&path),serde_json::to_string_pretty(&reference).map_err(err)?).map_err(err)?;
            Ok(ExitCode::SUCCESS)
        }
        (None,Some(path))=>{
            let relative=relative_record(path)?;
            let bytes=ctx.read_origin(Path::new(&relative))?.ok_or("completed IOC record is missing")?;
            let allowance=ioc::Allowance::from_text(std::str::from_utf8(&bytes).map_err(err)?)?;
            validate_attachment(selected,&allowance,deadline,now)?;
            let current=ioc_intake::revalidate(ctx,selected)?;
            validate_current_selection(selected,&current)?;
            let reference=ioc::IocRecordReference{record:relative.clone(),record_sha256:ioc::digest(&bytes)};
            let next=barbican::append_ioc_record(std::str::from_utf8(policy).map_err(err)?,&reference).map_err(err)?;
            ctx.check()?;
            validate_attachment(selected,&allowance,deadline,current_time(now)?)?;
            if ctx.read_origin(Path::new(&relative))?.as_ref()!=Some(&bytes){return Err("IOC review record changed before publication".into());}
            if next.as_bytes()!=policy {
                super::lockfile_ops::write_file_atomically(&origin.root.join("reviewed-targets.toml"),&next).map_err(err)?;
            }
            writeln!(stdout,"IOC exception: current\nRecord: {}\nExact source: {}",escape_path(&origin.root.join(relative)),selected.source.id()?).map_err(err)?;
            Ok(ExitCode::SUCCESS)
        }
        _=>Err("choose exactly one of --review-record (PENDING scaffold only) or --record (completed authority publication)".into()),
    }
}

pub(crate) fn validate_attachment(
    selected: &ioc::Inspection,
    allowance: &ioc::Allowance,
    deadline: Option<&str>,
    now: OffsetDateTime,
) -> Result<()> {
    allowance.record.validate_completed(now.unix_timestamp())?;
    if deadline.is_some() && allowance.record.review_by_utc != deadline_utc(deadline)? {
        return Err(
            "--review-by differs from the completed record; edit and review the record explicitly"
                .into(),
        );
    }
    if allowance.record.source != selected.source || allowance.record.findings != selected.findings
    {
        return Err("completed record does not bind the exact selected finding set".into());
    }
    Ok(())
}

pub(crate) fn validate_current_selection(
    selected: &ioc::Inspection,
    current: &ioc::Inspection,
) -> Result<()> {
    if selected.source != current.source
        || !matches!(current.coverage, ioc::Coverage::Complete)
        || selected
            .findings
            .iter()
            .any(|finding| !current.findings.contains(finding))
    {
        return Err(
            "original source or selected IOC findings changed; recollect a current report".into(),
        );
    }
    Ok(())
}

pub(crate) fn deadline_utc(value: Option<&str>) -> Result<Option<i64>> {
    value
        .map(|value| {
            barbican::parse_iso_date(value)
                .map(|date| {
                    date.next_day()
                        .ok_or_else(|| "deadline exceeds supported date".to_owned())
                        .map(|next| next.midnight().assume_utc().unix_timestamp())
                })
                .map_err(err)?
        })
        .transpose()
}

pub(crate) fn relative_record(path: &Path) -> Result<String> {
    let value = path.to_str().ok_or("review record path is not UTF-8")?;
    ioc::relative_path(value)?;
    if super::pin_files::PROTECTED_INPUTS.contains(&value) {
        return Err("review record aliases a protected policy input".into());
    }
    Ok(value.into())
}

pub(crate) fn read_external(current: &Path, path: &Path, budget: &Budget) -> Result<Vec<u8>> {
    let absolute = checked_path(current, path)?;
    crate::verified_source::read_optional(
        Path::new("/"),
        absolute.strip_prefix("/").map_err(err)?,
        budget,
    )?
    .ok_or("required IOC input is missing".into())
}

fn checked_path(current: &Path, path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        current.join(path)
    };
    if absolute
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("IOC output/input path contains traversal".into());
    }
    let parent = absolute.parent().ok_or("IOC path has no parent")?;
    let mut checked = PathBuf::new();
    for component in parent.components() {
        checked.push(component);
        let metadata = fs::symlink_metadata(&checked).map_err(err)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("IOC path ancestor is not a regular directory".into());
        }
    }
    Ok(absolute)
}

pub(crate) fn write_new(
    current: &Path,
    path: &Path,
    bytes: &[u8],
    check: impl FnOnce() -> Result<()>,
) -> Result<PathBuf> {
    if bytes.len() > ioc::MAX_REPORT_BYTES {
        return Err("IOC output exceeds 8 MiB".into());
    }
    let absolute = checked_path(current, path)?;
    check()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&absolute)
        .map_err(err)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        return Err(format!(
            "partial IOC output at {}: {error}; inspect and remove the owned partial file before retrying",
            escape_path(&absolute)
        ));
    }
    Ok(absolute)
}
fn escape_path(path: &Path) -> String {
    super::escape_diagnostic_for_terminal(&path.to_string_lossy())
}

pub(crate) fn replace_policy(path: &Path, text: &str) -> Result<()> {
    super::lockfile_ops::write_file_atomically(path, text).map_err(err)
}

pub(crate) fn current_time(start: OffsetDateTime) -> Result<OffsetDateTime> {
    let now = OffsetDateTime::now_utc();
    if now < start {
        return Err("clock rollback during IOC authoring".into());
    }
    Ok(now)
}

pub(crate) fn begin_legacy(
    ctx: &Context,
    spec: &barbican::ExactCrateSpec,
    release: &barbican::CrateRelease,
) -> Result<()> {
    ctx.check()?;
    let source = ioc::Source {
        name: spec.crate_name().into(),
        version: spec.version().to_string(),
        origin: ioc::Origin::CratesIo {
            archive_sha256: release.checksum_sha256_hex.clone(),
        },
    };
    ctx.stores.begin_source(&ioc_intake::ioc_marker(&source)?)
}
pub(crate) fn remember_legacy(ctx: &Context, report: &barbican::RustInspectReport) -> Result<()> {
    ctx.check()?;
    if let Some(inspection) = report.ioc_inspection() {
        ioc_intake::remember_inspection(&ctx.stores, inspection)?;
        if matches!(inspection.coverage, ioc::Coverage::Complete) {
            ctx.stores
                .finish_source(&ioc_intake::ioc_marker(&inspection.source)?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn report() -> PublicReport {
        let source = ioc::Source {
            name: "owned-fixture".into(),
            version: "1.0.0".into(),
            origin: ioc::Origin::CratesIo {
                archive_sha256: ioc::digest(b"original"),
            },
        };
        let mut scan = ioc::ScanAccumulator::new(source).unwrap();
        let mut budget = ioc::ScanBudget::default();
        scan.scan_file(
            "build.rs",
            b"fn main() { Command::new(\"inert\"); }",
            &ioc::Scope {
                build_script_paths: ["build.rs".into()].into_iter().collect(),
                ..Default::default()
            },
            &mut budget,
        )
        .unwrap();
        let source = scan.finish(None);
        let decision = ioc::adjudicate(&source, &[], 1).unwrap();
        let inspection = ioc::Report {
            schema_version: 1,
            scope: "explicit-exact-source-set".into(),
            sources: vec![source.clone()],
            excluded: vec![],
            errors: vec![],
        };
        PublicReport {
            input: ioc_intake::CapturedInputs::fixture(&inspection),
            schema_version: 1,
            operation: "ioc-check".into(),
            status: "blocked-or-unavailable".into(),
            origin: None,
            detector_semantics: [source.semantics.clone()].into_iter().collect(),
            inspection,
            decisions: vec![decision],
            authority_records: vec![],
            checker_sha256: ioc::digest(b"checker"),
        }
    }

    #[test]
    fn ioc_cli_rejects_ambiguous_sources_and_authority_modes() {
        for args in [
            vec!["cargo-barbican", "ioc", "check"],
            vec![
                "cargo-barbican",
                "ioc",
                "check",
                "a@1.0.0",
                "--lockfile",
                "Cargo.lock",
            ],
            vec![
                "cargo-barbican",
                "ioc",
                "check",
                "--git",
                "https://example.test/repo",
                "--package",
                "a",
            ],
            vec![
                "cargo-barbican",
                "pin",
                "exception",
                "--ioc",
                "--inspection",
                "report.json",
            ],
            vec![
                "cargo-barbican",
                "pin",
                "exception",
                "--ioc",
                "--inspection",
                "report.json",
                "--record",
                "done.md",
                "--review-record",
                "pending.md",
            ],
            vec![
                "cargo-barbican",
                "pin",
                "exception",
                "a",
                "RUSTSEC-2020-0001",
                "--record",
                "done.md",
            ],
        ] {
            assert!(
                Cli::try_parse_from(args.clone()).is_err(),
                "accepted {args:?}"
            );
        }
        for args in [
            vec!["cargo-barbican", "ioc", "check", "--lockfile", "Cargo.lock"],
            vec![
                "cargo-barbican",
                "pin",
                "exception",
                "a",
                "RUSTSEC-2020-0001",
            ],
            vec![
                "cargo-barbican",
                "pin",
                "exception",
                "--ioc",
                "--inspection",
                "report.json",
                "--review-record",
                "pending.md",
            ],
            vec!["cargo-barbican", "gatehouse", "policy-check", "--ioc"],
        ] {
            Cli::try_parse_from(args.clone())
                .unwrap_or_else(|error| panic!("rejected {args:?}: {error}"));
        }
    }

    #[test]
    fn invalid_exact_spec_exits_two_before_filesystem_or_cargo() {
        let cli = Cli::try_parse_from([
            "cargo-barbican",
            "ioc",
            "check",
            "not-exact",
            "--format",
            "json",
        ])
        .unwrap();
        let mut out = Vec::new();
        let mut errors = Vec::new();
        let exit = run(
            &cli,
            Path::new("/unavailable-owned-context"),
            OffsetDateTime::now_utc(),
            &mut out,
            &mut errors,
        )
        .unwrap();
        assert_eq!(exit, ExitCode::from(2));
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["status"], "invalid-input");
        assert!(errors.is_empty());
    }

    #[test]
    fn machine_report_rejects_contradictory_verdict_and_unbound_decisions() {
        let mut report = report();
        PublicReport::parse(&report.encode().unwrap()).unwrap();
        report.status = "pass".into();
        assert!(report.encode().is_err());
        report.status = "blocked-or-unavailable".into();
        report.decisions[0].blocked.clear();
        assert!(report.encode().is_err());
    }

    #[test]
    fn pending_scaffold_does_not_publish_repository_authority() {
        let stage = crate::verified_source::Stage::new().unwrap();
        let root = stage.root.join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("reviewed-targets.toml"), "[rust]\n").unwrap();
        let ctx = Context::capture(
            &root,
            Some(&root),
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap();
        let original = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let mut out = Vec::new();
        repository_exception(
            &ctx,
            &report().inspection.sources[0],
            Some(Path::new("review.md")),
            None,
            None,
            OffsetDateTime::now_utc(),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            original
        );
        let record =
            ioc::parse_review(&fs::read_to_string(root.join("review.md")).unwrap()).unwrap();
        assert_eq!(record.conclusion, ioc::Conclusion::Pending);
        assert!(load_allowances(&ctx).unwrap().0.is_empty());
        assert!(
            repository_exception(
                &ctx,
                &report().inspection.sources[0],
                None,
                Some(Path::new("review.md")),
                None,
                OffsetDateTime::now_utc(),
                &mut out
            )
            .is_err()
        );
    }

    #[test]
    fn exclusive_output_preserves_existing_files_and_rejects_symlink_ancestors() {
        let stage = crate::verified_source::Stage::new().unwrap();
        fs::write(stage.root.join("existing"), b"original").unwrap();
        assert!(
            write_new(
                &stage.root,
                Path::new("existing"),
                b"replacement",
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(fs::read(stage.root.join("existing")).unwrap(), b"original");
        fs::create_dir(stage.root.join("real")).unwrap();
        std::os::unix::fs::symlink(stage.root.join("real"), stage.root.join("link")).unwrap();
        assert!(write_new(&stage.root, Path::new("link/output"), b"text", || Ok(())).is_err());
        assert!(!stage.root.join("real/output").exists());
    }

    #[test]
    fn authored_original_archive_publication_noop_and_revocation_use_real_authority_path() {
        use barbican::cargo_tool::{
            KnowledgeEntry, KnowledgeKey, PackageIdentity, SecurityStatus, SourceFact,
        };
        let stage = crate::verified_source::Stage::new().unwrap();
        let root = stage.root.join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("reviewed-targets.toml"), "[rust]\n").unwrap();
        let original = stage.root.join("original");
        fs::create_dir(&original).unwrap();
        let files = [
            (
                "Cargo.toml",
                "[package]\nname='owned-fixture'\nversion='1.0.0'\nedition='2021'\nbuild='build.rs'\n",
            ),
            (
                "build.rs",
                "// Command::new( is inert author-created fixture text\nfn main() {}\n",
            ),
        ];
        let mut archive = tar::Builder::new(Vec::new());
        for (path, text) in files {
            fs::write(original.join(path), text).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(text.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    format!("owned-fixture-1.0.0/{path}"),
                    text.as_bytes(),
                )
                .unwrap();
        }
        let tar = archive.into_inner().unwrap();
        let mut crc = 0xffff_ffff_u32;
        for byte in &tar {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ 0xedb8_8320_u32.wrapping_mul(crc & 1);
            }
        }
        let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        gzip.extend(miniz_oxide::deflate::compress_to_vec(&tar, 6));
        gzip.extend((!crc).to_le_bytes());
        gzip.extend((tar.len() as u32).to_le_bytes());
        let hash = ioc::digest(&gzip);
        let source = ioc::Source {
            name: "owned-fixture".into(),
            version: "1.0.0".into(),
            origin: ioc::Origin::CratesIo {
                archive_sha256: hash.clone(),
            },
        };
        let capture = || {
            Context::capture(
                &root,
                Some(&root),
                Some(&stage.root.join("data")),
                Some(&stage.root.join("cache")),
            )
            .unwrap()
        };
        let ctx = capture();
        ctx.stores
            .cache
            .publish(
                &PathBuf::from(format!("cargo-tools/v1/archives/{hash}.crate")),
                &gzip,
            )
            .unwrap();
        let now = OffsetDateTime::now_utc();
        ctx.stores
            .remember(
                KnowledgeEntry {
                    fact: SourceFact {
                        key: KnowledgeKey::Package {
                            package: PackageIdentity::from(&source),
                        },
                        facts_sha256: ioc::digest(
                            b"authored fixture authority; not public publisher evidence",
                        ),
                        status: SecurityStatus::Clear,
                        expires_at_utc: None,
                    },
                    source_version: 1,
                    checked_at_utc: now.unix_timestamp(),
                },
                now.unix_timestamp(),
            )
            .unwrap();
        let selected = ioc_intake::inspect_tree(
            &ctx.stores,
            &ctx.budget,
            &original,
            source,
            &mut ioc::ScanBudget::default(),
        )
        .unwrap();
        assert_eq!(selected.findings.len(), 1);
        let mut record = ioc::parse_review(&ioc::scaffold_review(&selected).unwrap()).unwrap();
        record.conclusion = ioc::Conclusion::ExpectedBehaviour;
        record.reviewer = "fixture author".into();
        record.reviewed_at_utc = Some(now.unix_timestamp());
        record.rationale="The matched token is in an authored inert comment; this test never executes package code.".into();
        fs::write(root.join("review.md"), ioc::render_review(&record).unwrap()).unwrap();
        let mut stdout = Vec::new();
        repository_exception(
            &ctx,
            &selected,
            None,
            Some(Path::new("review.md")),
            None,
            now,
            &mut stdout,
        )
        .unwrap();
        let published = fs::read(root.join("reviewed-targets.toml")).unwrap();
        drop(ctx);
        let ctx = capture();
        repository_exception(
            &ctx,
            &selected,
            None,
            Some(Path::new("review.md")),
            None,
            OffsetDateTime::now_utc(),
            &mut stdout,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            published
        );
        let allowances = load_allowances(&ctx).unwrap().0;
        assert!(
            ioc::adjudicate(
                &selected,
                &allowances,
                OffsetDateTime::now_utc().unix_timestamp()
            )
            .unwrap()
            .is_success()
        );
        assert!(
            ctx.stores
                .knowledge()
                .unwrap()
                .entries
                .iter()
                .any(|entry| matches!(entry.fact.key, KnowledgeKey::Ioc { .. })
                    && entry.fact.status == SecurityStatus::Adverse)
        );
        let record_path = root.join("review.md");
        let mut changed = fs::read_to_string(&record_path).unwrap();
        changed.push_str("\nChanged after publication\n");
        fs::write(record_path, changed).unwrap();
        assert!(load_allowances(&ctx).is_err());
    }

    #[test]
    fn current_repository_record_mutation_revokes_loaded_allowance() {
        let stage = crate::verified_source::Stage::new().unwrap();
        let mut record =
            ioc::parse_review(&ioc::scaffold_review(&report().inspection.sources[0]).unwrap())
                .unwrap();
        record.conclusion = ioc::Conclusion::ExpectedBehaviour;
        record.reviewer = "fixture reviewer".into();
        record.reviewed_at_utc = Some(1);
        record.rationale = "Owned fixture literal is inert source evidence.".into();
        let text = ioc::render_review(&record).unwrap();
        fs::write(stage.root.join("review.md"), &text).unwrap();
        let policy = barbican::append_ioc_record(
            "[rust]\n",
            &ioc::IocRecordReference {
                record: "review.md".into(),
                record_sha256: ioc::digest(text.as_bytes()),
            },
        )
        .unwrap();
        fs::write(stage.root.join("reviewed-targets.toml"), policy).unwrap();
        let authority = RepositoryAllowances::capture(&stage.root).unwrap();
        assert!(
            ioc::adjudicate(&report().inspection.sources[0], &authority.allowances, 2)
                .unwrap()
                .is_success()
        );
        fs::write(stage.root.join("review.md"), format!("{text}\nchanged")).unwrap();
        assert!(authority.check().is_err());
    }
}
