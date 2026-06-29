use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, ExactCrateSpec, OffsetDateTime, ReleaseAgeOutcome,
    RustAssessmentClassification, evaluate_release_age, inspect_published_crate_at,
};

use crate::cli::{GatehouseCandidateArgs, GatehouseCommand, REVIEWED_TARGETS_CONFIG_FILE};
use crate::command_runner::{CommandRunner, RunnerError};

use super::inspect::render_inspect_report;
use super::scratch_dir::ScratchDir;
use super::{
    CommandError, ReviewedReleaseAgeExceptions, fail, load_config,
    load_reviewed_release_age_exceptions, render_missing_release_age_exception_review_record,
};

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
        GatehouseCommand::Candidate(args) => {
            run_candidate(args, current_dir, client, runner, now, stdout, stderr)
        }
    }
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
    let minimum_days = load_config(current_dir)?.release_age.minimum_days;
    let reviewed_release_age_exceptions =
        load_reviewed_release_age_exceptions(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
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
    if matches!(release_age.outcome(), ReleaseAgeOutcome::TooFresh)
        && let Some(exception) = reviewed_release_age_exceptions.missing_for_spec(spec)
    {
        return Err(render_missing_release_age_exception_review_record(
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

    Ok((render_inspect_report(&report), failed))
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
            self.push_indented(output);
        }
        let _ = writeln!(self.rendered);
    }

    fn push_command_failure(&mut self, heading: &str, error: &RunnerError) {
        let _ = writeln!(self.rendered, "{heading}:");
        let _ = writeln!(self.rendered, "  FAIL {}", render_runner_error(error));
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

fn render_runner_error(error: &RunnerError) -> String {
    match error {
        RunnerError::Spawn(source) => format!("unable to start command: {source}"),
        RunnerError::Exited {
            code,
            stdout,
            stderr,
        } => {
            let status = match code {
                Some(code) => format!("command exited with status {code}"),
                None => "command terminated without an exit code".to_owned(),
            };
            let mut parts = vec![status];
            if !stdout.is_empty() {
                parts.push(format!("stdout: {stdout}"));
            }
            if !stderr.is_empty() {
                parts.push(format!("stderr: {stderr}"));
            }
            parts.join("; ")
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
