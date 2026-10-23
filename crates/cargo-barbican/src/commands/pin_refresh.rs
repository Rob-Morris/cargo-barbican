use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, Lockfile, OffsetDateTime, PinRefreshPlan, ReviewedTargets,
    drifted_registry_targets, parse_lockfile, parse_reviewed_targets_toml, plan_pin_refresh,
    resolve_workspace_requirements,
};

use super::loaders::{parse_manifest_requirements, parse_workspace_requirements};
use super::lockfile_ops::MemoizingCratesIoClient;
use super::{CommandError, age_lock, assess, escape_render_field, load_git_base_lockfile};
use crate::cli::AssessPolicyMode;
use crate::command_runner::CommandRunner;

mod files;
use files::{Inputs, Prepared, error};

struct Context {
    policy: ReviewedTargets,
    lockfile: Lockfile,
    requirements: Vec<barbican::CargoManifestDirectRequirement>,
}
impl Context {
    fn load(inputs: &Inputs) -> Result<Self, CommandError> {
        let root = inputs.root();
        let policy = parse_reviewed_targets_toml(inputs.text(root, "reviewed-targets.toml")?)
            .map_err(|source| error(source.to_string()))?;
        let lockfile = parse_lockfile(inputs.text(root, "Cargo.lock")?)
            .map_err(|source| error(source.to_string()))?;
        let manifests = inputs.manifests();
        let requirements = resolve_workspace_requirements(
            &parse_manifest_requirements(&manifests)?,
            &parse_workspace_requirements(&manifests)?,
        )
        .map_err(|source| error(source.to_string()))?;
        inputs.check()?;
        Ok(Self {
            policy,
            lockfile,
            requirements,
        })
    }
    fn plan(&self, requests: &[String]) -> Result<PinRefreshPlan, CommandError> {
        plan_pin_refresh(&self.policy, &self.lockfile, &self.requirements, requests)
            .map_err(|source| error(source.to_string()))
    }
}

pub(super) fn run_refresh<R: CommandRunner + ?Sized>(
    requests: &[String],
    root: &Path,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let inputs = Inputs::capture(root, runner)?;
    let context = Context::load(&inputs)?;
    let plan = context.plan(requests)?;
    let prepared = prepare(inputs, &context.policy, &plan, now, stdout)?;
    prepared.apply()?;
    render_success(&plan, &prepared, stdout)?;
    Ok(ExitCode::SUCCESS)
}

pub(super) fn run_re_pin<C: CratesIoClient + ?Sized, R: CommandRunner + ?Sized>(
    base_ref: Option<&str>,
    base_dir: Option<&Path>,
    root: &Path,
    client: &C,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let mut inputs = Inputs::capture(root, runner)?;
    let context = Context::load(&inputs)?;
    let root = inputs.root().to_path_buf();
    let pinned_ref = match (base_ref, base_dir) {
        (Some(reference), None) => Some(super::baseline::GitBaseline::capture(
            &root,
            runner,
            reference,
            "gatehouse re-pin requires an available explicit Git baseline or --base-dir",
        )?),
        (None, Some(_)) => None,
        _ => {
            return Err(error(
                "gatehouse re-pin requires exactly one explicit baseline",
            ));
        }
    };
    let baseline_directory = base_dir
        .map(|directory| std::fs::canonicalize(root.join(directory)))
        .transpose()
        .map_err(CommandError::Io)?;
    let baseline = if let Some(directory) = &baseline_directory {
        inputs.add_baseline(directory)?;
        parse_lockfile(inputs.text(directory, "Cargo.lock")?)
            .map_err(|source| error(source.to_string()))?
    } else {
        load_git_base_lockfile(
            &root,
            runner,
            pinned_ref.as_ref().expect("baseline selector validated"),
            Path::new("Cargo.lock"),
        )?
    };
    let requests =
        drifted_registry_targets(&context.policy, &context.requirements, &context.lockfile)
            .map_err(|source| error(source.to_string()))?;
    let memoized = MemoizingCratesIoClient::new(client);
    if requests.is_empty() {
        let exit = evidence(
            &inputs,
            pinned_ref.as_ref(),
            baseline_directory.as_deref(),
            &memoized,
            runner,
            now,
            stdout,
            stderr,
        )?;
        if exit == ExitCode::SUCCESS {
            writeln!(
                stdout,
                "Gatehouse re-pin: no refresh needed; this is not pin or release verification"
            )
            .map_err(CommandError::Io)?;
        }
        return Ok(exit);
    }
    let plan = context.plan(&requests)?;
    plan.validate_baseline(&context.lockfile, &baseline)
        .map_err(|source| error(source.to_string()))?;
    let prepared = prepare(inputs, &context.policy, &plan, now, stdout)?;
    let exit = evidence(
        &prepared.inputs,
        pinned_ref.as_ref(),
        baseline_directory.as_deref(),
        &memoized,
        runner,
        now,
        stdout,
        stderr,
    )?;
    if exit != ExitCode::SUCCESS {
        return Ok(exit);
    }
    prepared.apply()?;
    render_success(&plan, &prepared, stdout)?;
    writeln!(
        stdout,
        "Gatehouse re-pin: prepared; human review remains PENDING"
    )
    .map_err(CommandError::Io)?;
    Ok(ExitCode::SUCCESS)
}

fn evidence<C: CratesIoClient + ?Sized, R: CommandRunner + ?Sized>(
    inputs: &Inputs,
    baseline: Option<&super::baseline::GitBaseline>,
    base_dir: Option<&Path>,
    client: &C,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    inputs.check()?;
    let baseline_lock = base_dir.map(|directory| directory.join("Cargo.lock"));
    writeln!(stdout, "Gatehouse re-pin: age-lock (explicit baseline)").map_err(CommandError::Io)?;
    let exit = age_lock::run_age_lock_with_baseline(
        baseline,
        None,
        baseline_lock.as_deref(),
        None,
        Path::new("Cargo.lock"),
        inputs.root(),
        client,
        runner,
        now,
        stdout,
        stderr,
    )?;
    if exit != ExitCode::SUCCESS {
        writeln!(
            stdout,
            "Gatehouse re-pin: FAIL (age-lock; no refresh writes)"
        )
        .map_err(CommandError::Io)?;
        return Ok(exit);
    }
    inputs.check()?;
    writeln!(stdout, "Gatehouse re-pin: assess (strict)").map_err(CommandError::Io)?;
    let exit = assess::run_assess_with_baseline(
        baseline,
        None,
        base_dir,
        AssessPolicyMode::Strict,
        None,
        Path::new("Cargo.lock"),
        inputs.root(),
        client,
        runner,
        now,
        stdout,
        stderr,
    )?;
    inputs.check()?;
    if exit != ExitCode::SUCCESS {
        writeln!(stdout, "Gatehouse re-pin: FAIL (assess; no refresh writes)")
            .map_err(CommandError::Io)?;
    }
    Ok(exit)
}

fn prepare(
    inputs: Inputs,
    policy: &ReviewedTargets,
    plan: &PinRefreshPlan,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
) -> Result<Prepared, CommandError> {
    match Prepared::new(inputs, policy, plan, now.date()) {
        Ok(prepared) => Ok(prepared),
        Err(source) => {
            writeln!(
                stdout,
                "Proposed registry facts only; no refresh writes made:"
            )
            .map_err(CommandError::Io)?;
            render_changes(plan, stdout)?;
            for change in plan.changes() {
                writeln!(stdout, "# Family {} — withdraw its old grants before completing manual review\n[rust.families.resolved]\n{} = {{ version = \"{}\", checksum_sha256 = \"{}\" }}",
                    escape_render_field(change.family()), change.selected().spec().crate_name(),
                    change.selected().version(), change.selected().checksum_sha256().expect("planned checksum"))
                    .map_err(CommandError::Io)?;
            }
            Err(source)
        }
    }
}

fn render_changes(plan: &PinRefreshPlan, stdout: &mut dyn Write) -> Result<(), CommandError> {
    for change in plan.changes() {
        writeln!(
            stdout,
            "- {} / {}: {} → {}; checksum_sha256={}",
            escape_render_field(change.family()),
            change.selected().spec().crate_name(),
            change.previous().version(),
            change.selected().version(),
            change
                .selected()
                .checksum_sha256()
                .expect("planned checksum")
        )
        .map_err(CommandError::Io)?;
        for grant in change.withdrawn_grants() {
            writeln!(stdout, "  withdrawn: {}", escape_render_field(grant))
                .map_err(CommandError::Io)?;
        }
        if change.retained_direct() {
            writeln!(stdout, "  existing direct pin retained: declarations do not uniformly match the new exact pin").map_err(CommandError::Io)?;
        }
    }
    Ok(())
}

fn render_success(
    plan: &PinRefreshPlan,
    prepared: &Prepared,
    stdout: &mut dyn Write,
) -> Result<(), CommandError> {
    writeln!(stdout, "Pin refresh: prepared (not completed review)").map_err(CommandError::Io)?;
    render_changes(plan, stdout)?;
    for (path, families) in prepared.reopened() {
        writeln!(
            stdout,
            "- PENDING: {} — reopened families {}",
            escape_render_field(&path.display().to_string()),
            escape_render_field(&families.join(", "))
        )
        .map_err(CommandError::Io)?;
    }
    for mismatch in plan.remaining_mismatches() {
        writeln!(
            stdout,
            "- remaining mismatch: {}",
            escape_render_field(mismatch)
        )
        .map_err(CommandError::Io)?;
    }
    writeln!(stdout, "Complete the appended review and explicitly re-record any replacement grants before deleting PENDING. Run cargo barbican pin check, then the normal pre-release gate.\nFor diff evidence use age-lock / assess against an explicit pre-move --base-ref or baseline directory, not post-move HEAD.").map_err(CommandError::Io)
}
