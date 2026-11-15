use super::process::{self, Budget, FILE_LIMIT, Result, err};
pub(crate) use crate::verified_source::*;
use barbican::cargo_tool::{InputFile, InputKind, MAX_DEPTH, MAX_PATH_BYTES, sha256};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
pub(crate) fn validate_execution_inputs(
    metadata: &serde_json::Value,
    root_id: &str,
    selected_ids: &BTreeSet<String>,
    selection: &barbican::cargo_tool::BuildSelection,
    inventories: &[(PathBuf, String, BTreeSet<InputFile>)],
    budget: &Budget,
) -> Result<()> {
    let mut files = std::collections::BTreeMap::new();
    for (directory, prefix, inventory) in inventories {
        for input in inventory {
            if input.kind == InputKind::RegularFile
                && let Some(relative) = input.path.strip_prefix(&format!("{prefix}/"))
            {
                files.insert(directory.join(relative), input);
            }
        }
    }
    for package in metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or("metadata packages missing")?
    {
        let id = package
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or("metadata package ID missing")?;
        if !selected_ids.contains(id) {
            continue;
        }
        for target in package
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .ok_or("metadata targets missing")?
        {
            budget.check()?;
            let name = target
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or("metadata target name missing")?;
            let kinds = target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .ok_or("metadata target kind missing")?;
            let required = kinds.iter().any(|kind| match kind.as_str() {
                Some("bin") => id == root_id && selection.bins.contains_key(name),
                Some(
                    "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
                    | "custom-build",
                ) => true,
                _ => false,
            });
            if !required {
                continue;
            }
            let path = Path::new(
                target
                    .get("src_path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("metadata target source missing")?,
            );
            let input = files.get(path).ok_or_else(|| format!("selected execution input {name:?} is absent from the verified regular-file inventory"))?;
            let actual = fs::symlink_metadata(path).map_err(|error| {
                format!("selected execution input {name:?} is unavailable: {error}")
            })?;
            if !actual.is_file() || actual.permissions().mode() & 0o777 != input.mode {
                return Err(format!(
                    "selected execution input {name:?} changed type or mode"
                ));
            }
            let bytes = process::read_bounded(path, FILE_LIMIT, budget)?;
            if bytes.len() as u64 != input.bytes || sha256(&bytes) != input.sha256 {
                return Err(format!(
                    "selected execution input {name:?} differs from verified inventory"
                ));
            }
        }
    }
    Ok(())
}

fn confined_auxiliary_path(parent: &Path, root: &Path, value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path.components().count() > MAX_DEPTH
        || path.is_absolute()
    {
        return Err(format!("unsafe manifest auxiliary path {value:?}"));
    }
    let mut resolved = parent.to_owned();
    for component in path.components() {
        match component {
            Component::Normal(name) => resolved.push(name),
            Component::CurDir => continue,
            Component::ParentDir if resolved != root => {
                resolved.pop();
            }
            _ => return Err(format!("manifest auxiliary path escapes source: {value:?}")),
        }
        if !resolved.starts_with(root) {
            return Err(format!("manifest auxiliary path escapes source: {value:?}"));
        }
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.is_file() || metadata.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "manifest auxiliary path contains a link or special file: {value:?}"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect manifest auxiliary path {value:?}: {error}"
                ));
            }
        }
    }
    Ok(resolved)
}

pub(crate) fn validate_manifests(
    root: &Path,
    budget: &Budget,
) -> Result<Vec<(PathBuf, serde_json::Value)>> {
    validate_source_manifests(root, budget, true)
}
pub(crate) fn validate_dependency_manifests(
    root: &Path,
    budget: &Budget,
) -> Result<Vec<(PathBuf, serde_json::Value)>> {
    validate_source_manifests(root, budget, false)
}
fn validate_source_manifests(
    root: &Path,
    budget: &Budget,
    command_workspace: bool,
) -> Result<Vec<(PathBuf, serde_json::Value)>> {
    let files = inventory(root, "root", budget)?;
    let candidates: Vec<PathBuf> = files
        .iter()
        .filter(|file| {
            file.kind == InputKind::RegularFile
                && Path::new(&file.path).file_name() == Some(std::ffi::OsStr::new("Cargo.toml"))
        })
        .map(|file| root.join(file.path.strip_prefix("root/").expect("inventory prefix")))
        .collect();
    let mut manifests = Vec::new();
    let mut pending = BTreeSet::from([root.join("Cargo.toml")]);
    let mut seen = BTreeSet::new();
    while let Some(manifest_path) = pending.pop_first() {
        if !seen.insert(manifest_path.clone()) {
            continue;
        }
        let parent = manifest_path
            .parent()
            .ok_or("manifest parent unavailable")?;
        for ancestor in parent.ancestors().take_while(|path| path.starts_with(root)) {
            for name in [".cargo/config", ".cargo/config.toml"] {
                if command_workspace && fs::symlink_metadata(ancestor.join(name)).is_ok() {
                    return Err(
                        "effective candidate Cargo configuration is outside the qualified context"
                            .into(),
                    );
                }
            }
        }
        let bytes = process::read_bounded(&manifest_path, 8 * 1024 * 1024, budget)?;
        let text = std::str::from_utf8(&bytes).map_err(err)?;
        let manifest = barbican::tool_inputs::source_manifest(text)?;
        if manifest.get("workspace").is_some() {
            for candidate in &candidates {
                if let Ok(relative) = candidate.strip_prefix(parent)
                    && barbican::classify_workspace_manifest_membership(
                        "Cargo.toml",
                        text,
                        relative,
                    )
                    .map_err(err)?
                        == barbican::WorkspaceManifestMembership::Included
                {
                    pending.insert(candidate.clone());
                }
            }
        }
        fn check_paths(
            value: &serde_json::Value,
            parent: &Path,
            root: &Path,
            pending: &mut BTreeSet<PathBuf>,
            dependency_source: bool,
        ) -> Result<()> {
            match value {
                serde_json::Value::Object(map) => {
                    if map.contains_key("registry")
                        || map.contains_key("registry-index")
                        || map.contains_key("replace")
                        || map.contains_key("patch")
                    {
                        return Err("unqualified manifest registry or replacement source".into());
                    }
                    if let Some(url) = map.get("git").and_then(|value| value.as_str()) {
                        let rev = map.get("rev").and_then(|value| value.as_str()).ok_or(
                            "Git dependency requires exact full commit before Cargo discovery",
                        )?;
                        barbican::GitSourceIdentity::new(url, rev).map_err(err)?;
                        if !url.starts_with("https://")
                            || map.contains_key("branch")
                            || map.contains_key("tag")
                        {
                            return Err("unqualified Git transport or mutable selector".into());
                        }
                    }
                    for name in ["build", "readme", "license-file"] {
                        if let Some(path) = map.get(name).and_then(|v| v.as_str()) {
                            confined_auxiliary_path(parent, root, path)?;
                        }
                    }
                    if let Some(path) = map.get("workspace").and_then(|value| value.as_str()) {
                        let resolved = fs::canonicalize(parent.join(path)).map_err(|error| {
                            format!("cannot resolve manifest workspace path {path:?}: {error}")
                        })?;
                        if !resolved.starts_with(root) {
                            return Err("package workspace points outside immutable source".into());
                        }
                        pending.insert(resolved.join("Cargo.toml"));
                    }
                    if let Some(path) = map.get("path").and_then(|v| v.as_str()) {
                        if dependency_source {
                            let resolved =
                                fs::canonicalize(parent.join(path)).map_err(|error| {
                                    format!(
                                        "cannot resolve manifest dependency path {path:?}: {error}"
                                    )
                                })?;
                            if !resolved.starts_with(root) {
                                return Err(
                                    "manifest dependency path escapes immutable source".into()
                                );
                            }
                            if !resolved.join("Cargo.toml").is_file() {
                                return Err(format!(
                                    "manifest dependency path has no Cargo.toml: {path:?}"
                                ));
                            }
                            pending.insert(resolved.join("Cargo.toml"));
                        } else {
                            // Published archives can omit tests, examples and auxiliary files.
                            // Their absence remains part of the captured source inventory.
                            confined_auxiliary_path(parent, root, path)?;
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for child in values {
                        check_paths(child, parent, root, pending, dependency_source)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        check_paths(
            &manifest,
            manifest_path
                .parent()
                .ok_or("manifest parent unavailable")?,
            root,
            &mut pending,
            false,
        )?;
        for package in [
            manifest.get("package"),
            manifest.pointer("/workspace/package"),
        ]
        .into_iter()
        .flatten()
        {
            check_paths(package, parent, root, &mut pending, false)?;
        }
        for table in std::iter::once(&manifest)
            .chain(manifest.get("workspace"))
            .chain(
                manifest
                    .get("target")
                    .and_then(serde_json::Value::as_object)
                    .into_iter()
                    .flat_map(|targets| targets.values()),
            )
        {
            for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
                if let Some(dependencies) = table.get(kind).and_then(serde_json::Value::as_object) {
                    for dependency in dependencies.values() {
                        check_paths(dependency, parent, root, &mut pending, true)?;
                    }
                }
            }
        }
        for kind in ["lib", "bin", "example", "test", "bench"] {
            if let Some(targets) = manifest.get(kind) {
                check_paths(targets, parent, root, &mut pending, false)?;
            }
        }
        manifests.push((manifest_path, manifest));
    }
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_stage_cleanup_does_not_follow_source_links() {
        use std::os::unix::fs::symlink;
        let outside = Stage::new().unwrap();
        fs::write(outside.root.join("retained"), b"outside").unwrap();
        let stage = Stage::new().unwrap();
        let stage_path = stage.root.clone();
        fs::create_dir(stage.root.join("readonly")).unwrap();
        fs::write(stage.root.join("readonly/file"), b"fixture").unwrap();
        symlink(&outside.root, stage.root.join("outside-link")).unwrap();
        drop(stage);
        assert!(!stage_path.exists());
        assert!(outside.root.join("retained").is_file());
    }
    #[test]
    fn materialisation_entry_budget_counts_directories_across_sources_and_implicit_parents() {
        fn archive(path: &str, directory: bool) -> Vec<u8> {
            let mut builder = tar::Builder::new(Vec::new());
            let manifest = b"[package]\nname = \"fixture\"\nversion = \"1.0.0\"\n";
            let mut manifest_header = tar::Header::new_gnu();
            manifest_header
                .set_path("fixture-1.0.0/Cargo.toml")
                .unwrap();
            manifest_header.set_mode(0o644);
            manifest_header.set_size(manifest.len() as u64);
            manifest_header.set_cksum();
            builder
                .append(&manifest_header, manifest.as_slice())
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("fixture-1.0.0/{path}")).unwrap();
            header.set_mode(if directory { 0o755 } else { 0o644 });
            header.set_entry_type(if directory {
                tar::EntryType::Directory
            } else {
                tar::EntryType::Regular
            });
            let bytes: &[u8] = if directory { b"" } else { b"x" };
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, bytes).unwrap();
            let tar = builder.into_inner().unwrap();
            let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
            gzip.extend(miniz_oxide::deflate::compress_to_vec(&tar, 6));
            gzip.extend([0, 0, 0, 0]);
            gzip.extend((tar.len() as u32).to_le_bytes());
            gzip
        }
        let stage = Stage::new().unwrap();
        let first = stage.root.join("first");
        let second = stage.root.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let budget = Budget::with_entry_limit(6).unwrap();
        let spec = "fixture@1.0.0".parse().unwrap();
        let first_archive = archive("empty", true);
        materialise_crate(
            &first,
            &spec,
            &first_archive,
            &sha256(&first_archive),
            &budget,
        )
        .unwrap();
        create_source_directory(&first, "empty", &budget).unwrap();
        let second_archive = archive("implicit/parent/file", false);
        materialise_crate(
            &second,
            &spec,
            &second_archive,
            &sha256(&second_archive),
            &budget,
        )
        .unwrap();
        assert!(create_source_directory(&second, "another", &budget).is_err());
        assert!(!second.join("another").exists());
        assert!(write_source(&first, "later", 0o644, b"x", &budget).is_err());
        assert!(!first.join("later").exists());
    }
    #[test]
    fn source_declarations_are_checked_by_manifest_role_not_dependency_names_or_metadata() {
        let stage = Stage::new().unwrap();
        let root = stage.root.join("source");
        fs::create_dir(&root).unwrap();
        let manifest = "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\n[package.metadata]\ngit = \"untrusted metadata only\"\npath = \"/outside\"\n[dependencies]\nbuild = \"1\"\nreadme = \"1\"\nregistry = \"1\"\npatch = \"1\"\n";
        fs::write(root.join("Cargo.toml"), manifest).unwrap();
        let budget = Budget::new(false).unwrap();
        assert!(validate_manifests(&root, &budget).is_ok());
        fs::write(root.join("Cargo.toml"), format!("{manifest}\n[target.'cfg(unix)'.build-dependencies.bad]\ngit = \"file:///outside\"\nrev = \"{}\"\n", "a".repeat(40))).unwrap();
        assert!(validate_manifests(&root, &budget).is_err());
        fs::write(
            root.join("Cargo.toml"),
            format!("{manifest}\n[dev-dependencies.bad]\npath = \"..\"\n"),
        )
        .unwrap();
        assert!(validate_manifests(&root, &budget).is_err());
    }
    #[test]
    fn dependency_local_configuration_is_retained_but_never_treated_as_command_configuration() {
        let stage = Stage::new().unwrap();
        fs::write(
            stage.root.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='1.0.0'\n",
        )
        .unwrap();
        fs::create_dir(stage.root.join(".cargo")).unwrap();
        fs::write(
            stage.root.join(".cargo/config.toml"),
            "[build]\nrustc-wrapper='candidate-wrapper'\n",
        )
        .unwrap();
        let budget = Budget::new(false).unwrap();
        assert!(validate_manifests(&stage.root, &budget).is_err());
        assert!(validate_dependency_manifests(&stage.root, &budget).is_ok());
        assert!(
            inventory(&stage.root, "fixture", &budget)
                .unwrap()
                .iter()
                .any(|input| input.path == "fixture/.cargo/config.toml")
        );
    }
    #[test]
    fn omitted_auxiliary_targets_preserve_absence_without_relaxing_dependency_sources() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        let manifest = "[package]\nname='fixture'\nversion='1.0.0'\nreadme='omitted/README.md'\n[[example]]\nname='benchmark'\npath='benches/benchmark.rs'\n[[test]]\nname='serde'\npath='tests/serde.rs'\n";
        fs::write(stage.root.join("Cargo.toml"), manifest).unwrap();
        let before = inventory(&stage.root, "root", &budget).unwrap();
        assert!(validate_dependency_manifests(&stage.root, &budget).is_ok());
        assert_eq!(inventory(&stage.root, "root", &budget).unwrap(), before);
        fs::write(
            stage.root.join("Cargo.toml"),
            format!("{manifest}\n[dependencies.missing]\npath='omitted'\n"),
        )
        .unwrap();
        assert!(
            validate_dependency_manifests(&stage.root, &budget)
                .unwrap_err()
                .contains("dependency path")
        );
        fs::write(
            stage.root.join("Cargo.toml"),
            manifest.replace("benches/benchmark.rs", "../outside.rs"),
        )
        .unwrap();
        assert!(
            validate_dependency_manifests(&stage.root, &budget)
                .unwrap_err()
                .contains("escapes source")
        );
    }
    #[test]
    fn auxiliary_paths_check_existing_ancestors_and_allow_confined_parent_paths() {
        let stage = Stage::new().unwrap();
        fs::create_dir(stage.root.join("member")).unwrap();
        assert_eq!(
            confined_auxiliary_path(
                &stage.root.join("member"),
                &stage.root,
                "../omitted/README.md"
            )
            .unwrap(),
            stage.root.join("omitted/README.md")
        );
        std::os::unix::fs::symlink("/tmp", stage.root.join("linked")).unwrap();
        assert!(
            confined_auxiliary_path(&stage.root, &stage.root, "linked/absent.rs")
                .unwrap_err()
                .contains("link")
        );
        for path in [
            "../../outside.rs",
            "/tmp/absent.rs",
            "../outside.rs",
            "missing/../../outside.rs",
            "bad\nname",
        ] {
            assert!(
                confined_auxiliary_path(&stage.root, &stage.root, path).is_err(),
                "{path:?}"
            );
        }
    }
    #[test]
    fn selected_execution_inputs_must_exist_while_unselected_targets_may_be_absent() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        write_source(&stage.root, "main.rs", 0o644, b"fn main() {}", &budget).unwrap();
        let inventories = vec![(
            stage.root.clone(),
            "root".into(),
            inventory(&stage.root, "root", &budget).unwrap(),
        )];
        let selection = barbican::cargo_tool::BuildSelection {
            bins: std::collections::BTreeMap::from([("selected".into(), BTreeSet::new())]),
            default_features: true,
            requested_features: BTreeSet::new(),
            all_features: false,
            profile: barbican::cargo_tool::BuildProfile::Release,
            host: "aarch64-apple-darwin".into(),
            target: "aarch64-apple-darwin".into(),
            resolver: 2,
        };
        let selected_ids = BTreeSet::from(["root".into()]);
        let target = |name: &str, kind: &str, path: &str| serde_json::json!({"name":name,"kind":[kind],"src_path":stage.root.join(path)});
        let metadata = |targets: Vec<serde_json::Value>| serde_json::json!({"packages":[{"id":"root","targets":targets}]});
        let present = target("selected", "bin", "main.rs");
        let unselected = vec![
            present.clone(),
            target("other", "bin", "other.rs"),
            target("test", "test", "tests/absent.rs"),
            target("example", "example", "examples/absent.rs"),
        ];
        validate_execution_inputs(
            &metadata(unselected),
            "root",
            &selected_ids,
            &selection,
            &inventories,
            &budget,
        )
        .unwrap();
        for kind in ["bin", "lib", "proc-macro", "custom-build"] {
            let targets = if kind == "bin" {
                vec![target("selected", kind, "absent.rs")]
            } else {
                vec![present.clone(), target("required", kind, "absent.rs")]
            };
            assert!(
                validate_execution_inputs(
                    &metadata(targets),
                    "root",
                    &selected_ids,
                    &selection,
                    &inventories,
                    &budget
                )
                .unwrap_err()
                .contains("absent from the verified regular-file inventory"),
                "{kind}"
            );
        }
    }
    #[test]
    fn source_paths_refuse_escape_and_control_characters() {
        for path in [
            "",
            "/etc/passwd",
            "../evil",
            "a/../evil",
            "a\\b",
            "a\nb",
            "./a",
        ] {
            assert!(safe_relative(path).is_err(), "{path:?}");
        }
        assert!(safe_relative("src/bin/main.rs").is_ok());
    }
    #[test]
    fn source_inventory_binds_empty_directories_and_detects_extra_files() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        fs::create_dir(stage.root.join("empty")).unwrap();
        write_source(&stage.root, "src/main.rs", 0o644, b"fn main() {}", &budget).unwrap();
        let before = inventory(&stage.root, "root", &budget).unwrap();
        assert!(
            before
                .iter()
                .any(|entry| entry.path == "root/empty" && entry.kind == InputKind::Directory)
        );
        write_source(&stage.root, "unexpected", 0o644, b"changed", &budget).unwrap();
        assert_ne!(before, inventory(&stage.root, "root", &budget).unwrap());
    }
    #[test]
    fn source_links_are_never_followed() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", stage.root.join("readme")).unwrap();
        assert!(inventory(&stage.root, "root", &budget).is_err());
    }
}
