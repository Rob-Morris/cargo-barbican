use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{output_files, process};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConsumerSnapshot {
    pub selected: PathBuf,
    pub cwd: PathBuf,
    pub path: OsString,
    pub cargo_home: Option<PathBuf>,
    pub cargo_executable: Option<(PathBuf, output_files::FileObservation)>,
    pub configurations: Vec<(PathBuf, barbican::Sha256Digest)>,
}

fn path_entries(path: &OsStr) -> Result<Vec<PathBuf>> {
    let entries: Vec<_> = std::env::split_paths(path).collect();
    if entries.is_empty()
        || entries
            .iter()
            .any(|entry| entry.as_os_str().is_empty() || !entry.is_absolute())
    {
        return Err("consumer PATH contains an empty or relative entry".into());
    }
    for entry in &entries {
        output_files::absolute(entry)?;
    }
    Ok(entries)
}

enum SearchSemantics {
    Process,
    CargoExternal,
}

fn first_executable(
    name: &str,
    entries: &[PathBuf],
    semantics: SearchSemantics,
    budget: &process::Budget,
) -> Result<PathBuf> {
    output_files::output_path(Path::new("/"), name)?;
    let test = match semantics {
        SearchSemantics::Process => Some(process::Executable::capture(
            Path::new("/bin/test"),
            budget,
        )?),
        SearchSemantics::CargoExternal => None,
    };
    for directory in entries {
        budget.check()?;
        let candidate = directory.join(name);
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("consumer lookup {}: {error}", candidate.display())),
        };
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "first consumer candidate uses unsupported symlink indirection: {}",
                candidate.display()
            ));
        }
        if metadata.is_file() {
            // Qualified Cargo selects by Unix mode bits, even when effective access
            // would deny execution. Process PATH lookup instead skips that file.
            let Some(test) = &test else {
                if metadata.permissions().mode() & 0o111 != 0 {
                    return Ok(candidate);
                }
                continue;
            };
            let result = process::run(
                test,
                &[OsStr::new("-x"), candidate.as_os_str()],
                Path::new("/"),
                &std::collections::BTreeMap::new(),
                budget,
            )?;
            match result.status.code() {
                Some(0) => return Ok(candidate),
                Some(1) => continue,
                _ => return Err("trusted executable-access probe failed".into()),
            }
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(format!(
                "unsupported consumer candidate type: {}",
                candidate.display()
            ));
        }
    }
    Err(format!("consumer executable is absent: {name}"))
}

pub(super) fn direct(path: &Path, cwd: &Path) -> Result<ConsumerSnapshot> {
    output_files::absolute(path)?;
    Ok(ConsumerSnapshot {
        selected: path.to_owned(),
        cwd: cwd.to_owned(),
        path: OsString::new(),
        cargo_home: None,
        cargo_executable: None,
        configurations: Vec::new(),
    })
}

pub(super) fn lookup(
    name: &str,
    path: &OsStr,
    cwd: &Path,
    budget: &process::Budget,
) -> Result<ConsumerSnapshot> {
    let selected = first_executable(name, &path_entries(path)?, SearchSemantics::Process, budget)?;
    Ok(ConsumerSnapshot {
        selected,
        cwd: cwd.to_owned(),
        path: path.to_owned(),
        cargo_home: None,
        cargo_executable: None,
        configurations: Vec::new(),
    })
}

pub(super) fn cargo(
    name: &str,
    bin: &str,
    path: &OsStr,
    cwd: &Path,
    cargo_home: &Path,
    uid: u32,
    budget: &process::Budget,
) -> Result<ConsumerSnapshot> {
    output_files::output_path(Path::new("/"), name)?;
    if bin != format!("cargo-{name}") {
        return Err("selected binary does not match the Cargo external command name".into());
    }
    const BUILTINS: &[&str] = &[
        "add",
        "b",
        "bench",
        "build",
        "c",
        "check",
        "clean",
        "config",
        "d",
        "doc",
        "fetch",
        "fix",
        "generate-lockfile",
        "help",
        "info",
        "init",
        "install",
        "locate-project",
        "login",
        "logout",
        "metadata",
        "new",
        "owner",
        "package",
        "pkgid",
        "publish",
        "r",
        "read-manifest",
        "remove",
        "report",
        "rm",
        "run",
        "rustc",
        "rustdoc",
        "search",
        "t",
        "test",
        "tree",
        "uninstall",
        "update",
        "vendor",
        "verify-project",
        "version",
        "yank",
    ];
    if BUILTINS.contains(&name) {
        return Err(
            "Cargo command is a builtin or standard alias, not the declared external tool".into(),
        );
    }
    if std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("CARGO_ALIAS_")) {
        return Err("Cargo consumer environment contains an alias".into());
    }
    let mut entries = path_entries(path)?;
    let home_bin = cargo_home.join("bin");
    // Cargo preserves an existing home/bin entry's position using Path equality.
    if !entries.contains(&home_bin) {
        entries.insert(0, home_bin);
    }
    let mut configuration_paths = Vec::new();
    for ancestor in cwd.ancestors() {
        configuration_paths.push(ancestor.join(".cargo/config"));
        configuration_paths.push(ancestor.join(".cargo/config.toml"));
    }
    configuration_paths.push(cargo_home.join("config"));
    configuration_paths.push(cargo_home.join("config.toml"));
    configuration_paths.sort();
    configuration_paths.dedup();
    let mut configurations = Vec::new();
    for config in configuration_paths {
        match fs::symlink_metadata(&config) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
            Ok(_) => {}
        }
        let bytes = output_files::read_record(&config, uid, 8 * 1024 * 1024, &budget.cancelled)?;
        let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
        barbican::cargo_tool::consumer_config_safe(text, name).map_err(|e| e.to_string())?;
        configurations.push((config, barbican::cargo_tool::sha256(&bytes)));
    }
    Ok(ConsumerSnapshot {
        selected: first_executable(bin, &entries, SearchSemantics::CargoExternal, budget)?,
        cwd: cwd.to_owned(),
        path: path.to_owned(),
        cargo_home: Some(cargo_home.to_owned()),
        cargo_executable: None,
        configurations,
    })
}

pub(super) fn trusted_cargo(
    path: &OsStr,
    expected: &barbican::Sha256Digest,
    uid: u32,
    budget: &process::Budget,
) -> Result<(PathBuf, output_files::FileObservation)> {
    let selected = first_executable(
        "cargo",
        &path_entries(path)?,
        SearchSemantics::Process,
        budget,
    )?;
    let observation = output_files::observe_trusted_executable(&selected, uid, &budget.cancelled)?;
    output_files::require_native_executable(&selected)?;
    if &observation.sha256 != expected {
        return Err("first process-PATH Cargo differs from the qualified trusted evaluator; proxies, wrappers and other Cargo binaries cannot establish this selection".into());
    }
    Ok((selected, observation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn scratch() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "barbican-consumer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::canonicalize(p).unwrap()
    }
    #[test]
    fn rejects_relative_empty_path_and_first_symlink_without_executing() {
        let budget = process::Budget::new(false).unwrap();
        let root = scratch();
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        fs::write(b.join("tool"), b"not executable code").unwrap();
        fs::set_permissions(b.join("tool"), fs::Permissions::from_mode(0o700)).unwrap();
        symlink(b.join("tool"), a.join("tool")).unwrap();
        assert!(lookup("tool", OsStr::new(":/bin"), &root, &budget).is_err());
        assert!(lookup("tool", OsStr::new("relative:/bin"), &root, &budget).is_err());
        let path = std::env::join_paths([&a, &b]).unwrap();
        assert!(
            lookup("tool", &path, &root, &budget)
                .unwrap_err()
                .contains("symlink")
        );
        fs::remove_file(a.join("tool")).unwrap();
        assert_eq!(
            lookup("tool", &path, &root, &budget).unwrap().selected,
            b.join("tool")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cargo_home_bin_is_prepended_only_when_absent_and_modes_select_first_file() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch();
        let shadow = root.join("shadow");
        let home = root.join("home");
        let home_bin = home.join("bin");
        fs::create_dir(&shadow).unwrap();
        fs::create_dir_all(&home_bin).unwrap();
        for directory in [&shadow, &home_bin] {
            let file = directory.join("cargo-fixture");
            fs::write(&file, b"inert file: never executed").unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = fs::metadata(&root).unwrap().uid();
        let budget = process::Budget::new(false).unwrap();
        let absent = std::env::join_paths([&shadow]).unwrap();
        assert_eq!(
            cargo(
                "fixture",
                "cargo-fixture",
                &absent,
                &root,
                &home,
                uid,
                &budget
            )
            .unwrap()
            .selected,
            home_bin.join("cargo-fixture")
        );
        let present_late = std::env::join_paths([&shadow, &home_bin]).unwrap();
        assert_eq!(
            cargo(
                "fixture",
                "cargo-fixture",
                &present_late,
                &root,
                &home,
                uid,
                &budget
            )
            .unwrap()
            .selected,
            shadow.join("cargo-fixture")
        );
        // Owner has no execute permission, but Cargo's mode111 predicate still
        // selects this file. An admission must never skip it to a later copy.
        fs::set_permissions(
            shadow.join("cargo-fixture"),
            fs::Permissions::from_mode(0o010),
        )
        .unwrap();
        assert_eq!(
            cargo(
                "fixture",
                "cargo-fixture",
                &present_late,
                &root,
                &home,
                uid,
                &budget
            )
            .unwrap()
            .selected,
            shadow.join("cargo-fixture")
        );
        if uid != 0 {
            assert_eq!(
                lookup("cargo-fixture", &present_late, &root, &budget)
                    .unwrap()
                    .selected,
                home_bin.join("cargo-fixture")
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn actual_first_path_cargo_must_match_trusted_native_bytes_without_execution() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch();
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        // Deliberately inert native-shaped bytes; this test never invokes either file.
        let accepted = b"\x7fELFaccepted inert Cargo identity fixture";
        let different = b"\x7fELFunknown inert Cargo shadow fixture";
        let write = |path: &Path, bytes: &[u8]| {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        };
        write(&b.join("cargo"), accepted);
        write(&a.join("cargo"), different);
        let path = std::env::join_paths([&a, &b]).unwrap();
        let digest = barbican::cargo_tool::sha256(accepted);
        let uid = fs::metadata(&root).unwrap().uid();
        let budget = process::Budget::new(false).unwrap();
        assert!(
            trusted_cargo(&path, &digest, uid, &budget)
                .unwrap_err()
                .contains("first process-PATH")
        );
        fs::set_permissions(a.join("cargo"), fs::Permissions::from_mode(0o001)).unwrap();
        if uid == 0 {
            assert!(trusted_cargo(&path, &digest, uid, &budget).is_err());
        } else {
            assert_eq!(
                trusted_cargo(&path, &digest, uid, &budget).unwrap().0,
                b.join("cargo")
            );
        }
        fs::set_permissions(a.join("cargo"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(a.join("cargo")).unwrap();
        symlink(b.join("cargo"), a.join("cargo")).unwrap();
        assert!(
            trusted_cargo(&path, &digest, uid, &budget)
                .unwrap_err()
                .contains("symlink")
        );
        fs::remove_file(a.join("cargo")).unwrap();
        write(&a.join("cargo"), b"#!/bin/sh\nexit 99\n");
        let shim_digest = barbican::cargo_tool::sha256(b"#!/bin/sh\nexit 99\n");
        assert!(
            trusted_cargo(&path, &shim_digest, uid, &budget)
                .unwrap_err()
                .contains("shim")
        );
        fs::remove_file(a.join("cargo")).unwrap();
        let original = trusted_cargo(&path, &digest, uid, &budget).unwrap();
        assert_eq!(original.0, b.join("cargo"));
        write(&a.join("cargo"), accepted);
        let selected_copy = trusted_cargo(&path, &digest, uid, &budget).unwrap();
        assert_ne!(original, selected_copy);
        write(&a.join("cargo"), different);
        assert!(trusted_cargo(&path, &digest, uid, &budget).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
