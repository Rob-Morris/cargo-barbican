use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, parse_cargo_metadata,
    select_package_id,
};

use crate::command_runner::CommandRunner;

use super::age_lock::recheck_lockfile_age;
use super::{CommandError, fail, finish_release_age_checks, load_config, parse_specs};

pub(super) fn run_resolve<C, R>(
    raw_specs: Vec<String>,
    current_dir: &Path,
    client: &C,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    let memoized_client = MemoizingCratesIoClient::new(client);
    let minimum_days = load_config(current_dir)?.release_age.minimum_days;
    let parse_result = parse_specs(raw_specs, stderr)?;
    let age_exit = finish_release_age_checks(
        &parse_result.specs,
        minimum_days,
        &memoized_client,
        stdout,
        stderr,
    )?;

    if parse_result.failed || age_exit != ExitCode::SUCCESS {
        return Ok(ExitCode::from(1));
    }

    let metadata_text = match runner.cargo_metadata(current_dir) {
        Ok(text) => text,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let metadata = match parse_cargo_metadata(&metadata_text) {
        Ok(metadata) => metadata,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let mut selections = Vec::new();

    for spec in &parse_result.specs {
        match select_package_id(&metadata, spec.crate_name()) {
            Ok(package_id) => selections.push((spec.clone(), package_id)),
            Err(error) => return fail(stderr, format!("{}: {error}", spec.crate_name())),
        }
    }

    for (spec, package_id) in selections {
        if let Err(error) = runner.cargo_update_precise(current_dir, &package_id, spec.version()) {
            return fail(
                stderr,
                format!(
                    "{spec}: unable to update package spec {package_id} to {}: {error}",
                    spec.version()
                ),
            );
        }
    }

    recheck_lockfile_age(
        "HEAD",
        Path::new("Cargo.lock"),
        minimum_days,
        current_dir,
        &memoized_client,
        runner,
        stdout,
        stderr,
    )
}

struct MemoizingCratesIoClient<'a, C: ?Sized> {
    inner: &'a C,
    cache: RefCell<HashMap<String, Result<CrateRelease, CratesIoClientError>>>,
}

impl<'a, C: ?Sized> MemoizingCratesIoClient<'a, C> {
    fn new(inner: &'a C) -> Self {
        Self {
            inner,
            cache: RefCell::new(HashMap::new()),
        }
    }
}

impl<C> CratesIoClient for MemoizingCratesIoClient<'_, C>
where
    C: CratesIoClient + ?Sized,
{
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        if let Some(cached) = self.cache.borrow().get(&spec.to_string()) {
            return cached.clone();
        }

        let result = self.inner.fetch_release(spec);
        self.cache
            .borrow_mut()
            .insert(spec.to_string(), result.clone());
        result
    }
}
