pub(crate) use crate::controlled_process::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone)]
pub(crate) struct Evaluator {
    pub inspector: Executable,
    pub cargo: Executable,
    pub rustc: Executable,
    pub deny: Executable,
    pub audit: Option<Executable>,
    pub host: String,
    pub cargo_version: String,
    pub rustc_version: String,
}
impl Evaluator {
    pub fn capture(
        cargo: Option<&Path>,
        rustc: Option<&Path>,
        scratch: &Path,
        budget: &Budget,
        uses_audit: bool,
    ) -> Result<Self> {
        let host = native_host()?;
        let toolchain = match std::env::var_os("RUSTUP_HOME") {
            Some(value) => PathBuf::from(value),
            None => absolute_home()?.join(".rustup"),
        }
        .join("toolchains")
        .join(format!("1.95.0-{host}"));
        let cargo = capture_native_evaluator(cargo.unwrap_or(&toolchain.join("bin/cargo")), budget).map_err(|e| format!("trusted Cargo unavailable: {e}; supply --cargo /absolute/already-installed/cargo and --rustc /absolute/already-installed/rustc"))?;
        let rustc =
            capture_native_evaluator(rustc.unwrap_or(&toolchain.join("bin/rustc")), budget)?;
        let inspector = Executable::capture(&std::env::current_exe().map_err(err)?, budget)?;
        let deny = capture_native_evaluator(&lookup_trusted("cargo-deny")?, budget)?;
        let audit = if uses_audit {
            Some(capture_native_evaluator(
                &lookup_trusted("cargo-audit")?,
                budget,
            )?)
        } else {
            None
        };
        let environment = base_environment(scratch, scratch, &rustc.path);
        let cargo_version = version(&cargo, &["-vV"], scratch, &environment, budget)?;
        let rustc_version = version(&rustc, &["-vV"], scratch, &environment, budget)?;
        if !cargo_version
            .lines()
            .any(|line| line == "commit-hash: f2d3ce0bd7f24a49f8f72d9000448f8838c4e850")
            || !rustc_version
                .lines()
                .any(|line| line == "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860")
            || !cargo_version.starts_with("cargo 1.95.0 ")
            || !rustc_version.starts_with("rustc 1.95.0 ")
            || !rustc_version
                .lines()
                .any(|line| line == format!("host: {host}"))
            || !cargo_version
                .lines()
                .any(|line| line == format!("host: {host}"))
        {
            return Err("unqualified Cargo/rustc version or native host; exact 1.95.0 native tuple required".into());
        }
        let deny_version = version(&deny, &["--version"], scratch, &environment, budget)?;
        if deny_version.split_whitespace().take(2).collect::<Vec<_>>() != ["cargo-deny", "0.19.6"] {
            return Err("unqualified cargo-deny; trusted 0.19.6 required".into());
        }
        if let Some(audit) = &audit {
            let audit_version = version(audit, &["--version"], scratch, &environment, budget)?;
            if audit_version.split_whitespace().take(2).collect::<Vec<_>>()
                != ["cargo-audit", "0.22.1"]
            {
                return Err("unqualified cargo-audit; trusted 0.22.1 required".into());
            }
        }
        Ok(Self {
            inspector,
            cargo,
            rustc,
            deny,
            audit,
            host,
            cargo_version,
            rustc_version,
        })
    }
    pub fn recheck(&self, budget: &Budget) -> Result<()> {
        for executable in [&self.inspector, &self.cargo, &self.rustc, &self.deny]
            .into_iter()
            .chain(self.audit.iter())
        {
            executable.recheck(budget)?;
        }
        Ok(())
    }
}
fn capture_native_evaluator(path: &Path, budget: &Budget) -> Result<Executable> {
    if fs::symlink_metadata(path)
        .map_err(err)?
        .file_type()
        .is_symlink()
    {
        return Err("qualified evaluator cannot be a symlink or rustup proxy; select an absolute direct native executable".into());
    }
    let executable = Executable::capture(path, budget)?;
    super::output_files::require_native_executable(&executable.path)?;
    Ok(executable)
}
pub(crate) fn native_host() -> Result<String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin".into()),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu".into()),
        _ => Err("unqualified native Cargo tool host".into()),
    }
}
fn lookup_trusted(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or("PATH unavailable for trusted scanner discovery")?;
    for directory in std::env::split_paths(&path) {
        if !directory.is_absolute() {
            return Err("trusted scanner PATH contains empty or relative directory".into());
        }
        let candidate = directory.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "trusted {name} unavailable; provision the evaluator separately before tool review"
    ))
}
fn version(
    executable: &Executable,
    args: &[&str],
    cwd: &Path,
    env: &BTreeMap<OsString, OsString>,
    budget: &Budget,
) -> Result<String> {
    let output = run(executable, args, cwd, env, budget)?;
    if !output.status.success() {
        return Err("trusted evaluator identity probe failed".into());
    }
    String::from_utf8(output.stdout).map_err(err)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;
    #[test]
    fn aggregate_materialisation_budget_is_not_per_package() {
        let budget = Budget::new(false).unwrap();
        for _ in 0..8 {
            budget.materialise(FILE_LIMIT).unwrap();
        }
        assert!(budget.materialise(1).is_err());
    }
    #[test]
    fn cancellation_applies_to_native_and_collection_budgets() {
        let collection = Budget::new(false).unwrap();
        let native = Budget::native(collection.cancelled.clone());
        collection.cancelled.store(true, Ordering::SeqCst);
        assert!(collection.check().is_err());
        assert!(native.check().is_err());
    }
    #[test]
    fn controlled_child_environment_omits_wrappers_and_aliases() {
        let environment = base_environment(
            Path::new("/home/private"),
            Path::new("/cache/private"),
            Path::new("/trusted/rustc"),
        );
        assert!(!environment.contains_key(OsStr::new("RUSTC_WRAPPER")));
        assert!(!environment.contains_key(OsStr::new("CARGO_ALIAS_INSTALL")));
        assert_eq!(
            environment.get(OsStr::new("RUSTC")).unwrap(),
            "/trusted/rustc"
        );
    }
    #[test]
    fn captured_evaluator_copy_mutation_is_rejected_with_native_budget() {
        use std::os::unix::fs::PermissionsExt;
        let stage = super::super::source::Stage::new().unwrap();
        let path = stage.root.join("trusted-owned-fixture");
        fs::write(&path, b"authored inert executable bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let collection = Budget::new(false).unwrap();
        let executable = Executable::capture(&path, &collection).unwrap();
        let native = Budget::native(collection.cancelled.clone());
        executable.recheck(&native).unwrap();
        fs::write(&path, b"changed after native build").unwrap();
        assert!(executable.recheck(&native).is_err());
    }
    #[test]
    fn evaluator_refuses_script_compiler_before_any_version_probe() {
        let stage = super::super::source::Stage::new().unwrap();
        let wrapper = stage.root.join("cargo-wrapper");
        fs::write(&wrapper, b"#!/bin/sh\nprintf executed > wrapper-probed\n").unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        let budget = Budget::new(false).unwrap();
        let failure =
            Evaluator::capture(Some(&wrapper), None, &stage.root, &budget, false).unwrap_err();
        assert!(failure.contains("unqualified shim"), "{failure}");
        assert!(!stage.root.join("wrapper-probed").exists());
    }
    #[test]
    fn evaluator_refuses_symlink_to_native_program_before_version_discovery() {
        let stage = super::super::source::Stage::new().unwrap();
        let proxy = stage.root.join("cargo-proxy");
        std::os::unix::fs::symlink("/bin/sh", &proxy).unwrap();
        let budget = Budget::new(false).unwrap();
        let failure =
            Evaluator::capture(Some(&proxy), None, &stage.root, &budget, false).unwrap_err();
        assert!(
            failure.contains("cannot be a symlink or rustup proxy"),
            "{failure}"
        );
        assert!(!stage.root.join("wrapper-probed").exists());
    }
}
