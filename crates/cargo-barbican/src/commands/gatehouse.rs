use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, ExactCrateSpec, OffsetDateTime, ReleaseAgeGateVerdict,
    RustAssessmentClassification, classify_release_age_gate, evaluate_release_age,
    inspect_published_crate_at,
};

use crate::cli::{AuditOutputFormat, GatehouseCandidateArgs, GatehouseCommand};
use crate::command_runner::{CommandRunner, RunnerError};

use super::inspect::{InspectRenderContext, render_inspect_report};
use super::scratch_dir::ScratchDir;
use super::{
    CommandError, ReviewedReleaseAgeExceptions, audit, escape_diagnostic_for_terminal, fail,
    inventory, load_release_age_context, render_incomplete_release_age_exception_review_record,
    toolchain, verify,
};

const PRE_RELEASE_STEP_COUNT: u8 = 4;

pub(super) fn run_gatehouse<C, R>(
    command: GatehouseCommand,
    current_dir: &Path,
    client: &C,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn IoWrite,
    stderr: &mut dyn IoWrite,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    match command {
        GatehouseCommand::PreRelease => run_pre_release(current_dir, runner, now, stdout, stderr),
        GatehouseCommand::Candidate(args) => {
            run_candidate(args, current_dir, client, runner, now, stdout, stderr)
        }
    }
}

fn run_pre_release<R>(
    current_dir: &Path,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn IoWrite,
    stderr: &mut dyn IoWrite,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    writeln!(stdout, "Gatehouse pre-release:").map_err(CommandError::Io)?;
    write_pre_release_step(stdout, 1, "toolchain conformance (blocking)")?;
    let toolchain_preflight =
        match toolchain::run_toolchain_check(current_dir, runner, stdout, stderr)? {
            toolchain::ToolchainCheckOutcome::Passed(preflight) => preflight,
            toolchain::ToolchainCheckOutcome::Failed(exit_code) => {
                writeln!(stdout, "Gatehouse pre-release: FAIL (toolchain)")
                    .map_err(CommandError::Io)?;
                return Ok(exit_code);
            }
        };

    writeln!(stdout).map_err(CommandError::Io)?;
    write_pre_release_step(stdout, 2, "inventory coverage floor (blocking)")?;
    let inventory_exit = inventory::run_inventory(current_dir, runner, now, true, stdout)?;
    if inventory_exit != ExitCode::SUCCESS {
        writeln!(stdout, "Gatehouse pre-release: FAIL (inventory)").map_err(CommandError::Io)?;
        return Ok(inventory_exit);
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    write_pre_release_step(stdout, 3, "audit (blocking)")?;
    let audit_exit = audit::run_audit(
        AuditOutputFormat::Text,
        current_dir,
        None,
        runner,
        now,
        stdout,
        stderr,
    )?;
    if audit_exit != ExitCode::SUCCESS {
        writeln!(stdout, "Gatehouse pre-release: FAIL (audit)").map_err(CommandError::Io)?;
        return Ok(audit_exit);
    }

    writeln!(stdout).map_err(CommandError::Io)?;
    write_pre_release_step(stdout, 4, "verify (blocking; includes pin check)")?;
    let verify_exit = verify::run_verify_after_gatehouse_preflights(
        current_dir,
        runner,
        &toolchain_preflight,
        stdout,
        stderr,
    )?;
    if verify_exit != ExitCode::SUCCESS {
        writeln!(stdout, "Gatehouse pre-release: FAIL (verify)").map_err(CommandError::Io)?;
        return Ok(verify_exit);
    }

    writeln!(stdout, "Gatehouse pre-release: PASS").map_err(CommandError::Io)?;
    Ok(ExitCode::SUCCESS)
}

fn write_pre_release_step(
    stdout: &mut dyn IoWrite,
    number: u8,
    description: &str,
) -> Result<(), CommandError> {
    writeln!(
        stdout,
        "Step {number}/{PRE_RELEASE_STEP_COUNT} — {description}"
    )
    .map_err(CommandError::Io)
}

fn run_candidate<C, R>(
    args: GatehouseCandidateArgs,
    current_dir: &Path,
    client: &C,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn IoWrite,
    stderr: &mut dyn IoWrite,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    let spec = match args.spec.parse::<ExactCrateSpec>() {
        Ok(spec) => spec,
        Err(error) => return fail(stderr, error),
    };
    let (minimum_days, reviewed_release_age_exceptions) =
        load_release_age_context(current_dir, None)?;
    let mut dossier = CandidateDossier::new(&spec);

    match render_candidate_inspect(
        &spec,
        minimum_days,
        &reviewed_release_age_exceptions,
        client,
        now,
    ) {
        Ok((rendered, failed)) => {
            dossier.push_inspect(&rendered);
            if failed {
                dossier.mark_failed();
            }
        }
        Err(detail) => {
            dossier.push_failed_inspect(&detail);
            dossier.mark_failed();
        }
    }

    let sandbox = match CandidateSandbox::create(&spec, args.preserve_sandbox) {
        Ok(sandbox) => sandbox,
        Err(error) => {
            dossier.push_sandbox_failure(&error.to_string());
            dossier.mark_failed();
            dossier.push_next_step(args.preserve_sandbox);
            write!(stdout, "{}", dossier.finish()).map_err(CommandError::Io)?;
            return Ok(ExitCode::from(1));
        }
    };

    dossier.push_sandbox_path(sandbox.path(), args.preserve_sandbox);

    if let Err(error) = runner.cargo_generate_lockfile(sandbox.path()) {
        dossier.push_command_failure("Sandbox lockfile", &error);
        dossier.mark_failed();
        dossier.push_next_step(args.preserve_sandbox);
        write!(stdout, "{}", dossier.finish()).map_err(CommandError::Io)?;
        return Ok(ExitCode::from(1));
    }

    dossier.push_lockfile_success();

    match runner.cargo_tree(sandbox.path()) {
        Ok(output) => dossier.push_command_success("Cargo tree", &output),
        Err(error) => {
            dossier.push_command_failure("Cargo tree", &error);
            dossier.mark_failed();
        }
    }

    match runner.cargo_audit(sandbox.path()) {
        Ok(output) => dossier.push_command_success("Cargo audit", &output),
        Err(error) => {
            dossier.push_command_failure("Cargo audit", &error);
            dossier.mark_failed();
        }
    }

    dossier.push_next_step(args.preserve_sandbox);
    let failed = dossier.failed();
    write!(stdout, "{}", dossier.finish()).map_err(CommandError::Io)?;

    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn render_candidate_inspect<C>(
    spec: &ExactCrateSpec,
    minimum_days: u64,
    reviewed_release_age_exceptions: &ReviewedReleaseAgeExceptions,
    client: &C,
    now: OffsetDateTime,
) -> Result<(String, bool), String>
where
    C: CratesIoClient + ?Sized,
{
    let release = client
        .fetch_release(spec)
        .map_err(|error| format!("{spec}: {error}"))?;
    let age_exception = reviewed_release_age_exceptions
        .honoured()
        .iter()
        .find(|exception| exception.spec() == spec);
    let release_age = evaluate_release_age(
        spec.clone(),
        release.clone(),
        now,
        minimum_days,
        age_exception,
    );
    if let ReleaseAgeGateVerdict::IncompleteReviewRecord(exception) = classify_release_age_gate(
        release_age.outcome(),
        reviewed_release_age_exceptions.unsatisfied_for_spec(spec),
    ) {
        return Err(render_incomplete_release_age_exception_review_record(
            exception,
        ));
    }

    let tarball = client
        .fetch_release_tarball(spec)
        .map_err(|error| format!("{spec}: {error}"))?;
    let report = inspect_published_crate_at(
        spec.clone(),
        release,
        &tarball,
        now,
        minimum_days,
        age_exception,
    );
    let failed = !matches!(
        report.classification(),
        RustAssessmentClassification::RoutineSafe
    );

    Ok((
        render_inspect_report(&report, InspectRenderContext::GatehouseCandidate),
        failed,
    ))
}

struct CandidateDossier {
    rendered: String,
    failed: bool,
}

impl CandidateDossier {
    fn new(spec: &ExactCrateSpec) -> Self {
        let mut rendered = String::new();
        let _ = writeln!(rendered, "Gatehouse candidate: {spec}");
        let _ = writeln!(rendered);

        Self {
            rendered,
            failed: false,
        }
    }

    fn mark_failed(&mut self) {
        self.failed = true;
    }

    fn failed(&self) -> bool {
        self.failed
    }

    fn push_inspect(&mut self, rendered_inspect: &str) {
        let _ = writeln!(self.rendered, "Inspect evidence:");
        self.push_indented(rendered_inspect);
        let _ = writeln!(self.rendered);
    }

    fn push_failed_inspect(&mut self, detail: &str) {
        let _ = writeln!(self.rendered, "Inspect evidence:");
        let _ = writeln!(self.rendered, "  FAIL {detail}");
        let _ = writeln!(self.rendered);
    }

    fn push_sandbox_path(&mut self, path: &Path, preserved: bool) {
        let status = if preserved {
            "preserved for inspection"
        } else {
            "created; will be removed after the command"
        };
        let _ = writeln!(self.rendered, "Sandbox:");
        let _ = writeln!(self.rendered, "  path: {}", path.display());
        let _ = writeln!(self.rendered, "  status: {status}");
        let _ = writeln!(self.rendered);
    }

    fn push_sandbox_failure(&mut self, detail: &str) {
        let _ = writeln!(self.rendered, "Sandbox:");
        let _ = writeln!(
            self.rendered,
            "  FAIL unable to prepare candidate sandbox: {detail}"
        );
        let _ = writeln!(self.rendered);
    }

    fn push_lockfile_success(&mut self) {
        let _ = writeln!(self.rendered, "Sandbox lockfile:");
        let _ = writeln!(self.rendered, "  OK generated with cargo generate-lockfile");
        let _ = writeln!(self.rendered);
    }

    fn push_command_success(&mut self, heading: &str, output: &str) {
        let _ = writeln!(self.rendered, "{heading}:");
        let _ = writeln!(self.rendered, "  OK");
        if output.trim().is_empty() {
            let _ = writeln!(self.rendered, "  output: none");
        } else {
            // `output` is `cargo tree`/`cargo audit` stdout — it can carry
            // unicode from a candidate's transitive dependency source URLs
            // or RustSec advisory free text, so it is untrusted and routed
            // through the escape choke point before a reviewer reads it.
            self.push_indented(&escape_diagnostic_for_terminal(output));
        }
        let _ = writeln!(self.rendered);
    }

    fn push_command_failure(&mut self, heading: &str, error: &RunnerError) {
        // `RunnerError`'s `Display` embeds the failed subprocess's raw
        // stdout/stderr, which is exactly as untrusted as the success-path
        // output above, so it is escaped the same way.
        let error = escape_diagnostic_for_terminal(&error.to_string());
        let _ = writeln!(self.rendered, "{heading}:");
        let _ = writeln!(self.rendered, "  FAIL {error}");
        let _ = writeln!(self.rendered);
    }

    fn push_next_step(&mut self, preserved: bool) {
        let _ = writeln!(self.rendered, "Suggested next step:");
        if self.failed {
            let _ = writeln!(
                self.rendered,
                "  Do not admit this candidate until the failed evidence is reviewed."
            );
        } else if preserved {
            let _ = writeln!(
                self.rendered,
                "  Inspect the preserved sandbox if needed, then continue with the repo adoption workflow."
            );
        } else {
            let _ = writeln!(
                self.rendered,
                "  Continue with the repo adoption workflow if this dossier is acceptable."
            );
        }
    }

    fn finish(self) -> String {
        self.rendered
    }

    fn push_indented(&mut self, text: &str) {
        for line in text.trim_end().lines() {
            let _ = writeln!(self.rendered, "  {line}");
        }
    }
}

struct CandidateSandbox {
    scratch: ScratchDir,
}

impl CandidateSandbox {
    fn create(spec: &ExactCrateSpec, preserve: bool) -> Result<Self, std::io::Error> {
        let scratch = ScratchDir::create("cargo-barbican-gatehouse-candidate", preserve)?;
        write_candidate_project(scratch.path(), spec)?;

        Ok(Self { scratch })
    }

    fn path(&self) -> &Path {
        self.scratch.path()
    }
}

fn write_candidate_project(path: &Path, spec: &ExactCrateSpec) -> Result<(), std::io::Error> {
    fs::create_dir_all(path.join("src"))?;
    fs::write(path.join("Cargo.toml"), candidate_manifest(spec))?;
    fs::write(path.join("src/lib.rs"), "")?;
    Ok(())
}

fn candidate_manifest(spec: &ExactCrateSpec) -> String {
    format!(
        "[package]\nname = \"cargo-barbican-gatehouse-candidate\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\npath = \"src/lib.rs\"\n\n[dependencies]\n\"{}\" = \"={}\"\n",
        spec.crate_name(),
        spec.version()
    )
}
