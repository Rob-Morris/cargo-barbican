use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use barbican::{
    WorkspaceManifestMembership, WorkspaceRootDirective, classify_workspace_manifest_membership,
    parse_workspace_member_glob_roots, parse_workspace_member_manifest_paths,
    parse_workspace_root_directive,
};

use crate::command_runner::{CommandRunner, RunnerError};

use super::CommandError;
use super::loaders::{confined_directory, read_optional_text_no_symlink};

pub(crate) const REVIEW_ROOT_FILE_PATHS: [&str; 5] = [
    "Cargo.lock",
    "barbican.toml",
    "deny.toml",
    "reviewed-targets.toml",
    "rust-toolchain.toml",
];
pub(crate) const REVIEW_RECORDS_DIR: &str = "docs/dependency-reviews";

/// Resolves the workspace root cargo itself would select, so every command
/// anchors its policy inputs (`barbican.toml`, `reviewed-targets.toml`,
/// `Cargo.lock`, review records) identically from any directory inside a
/// consumer repo. Cargo selects the workspace for every parseable nearest
/// manifest, including membership and exclusion semantics. The local fallback
/// exists only so a malformed nearest manifest can reach its command-specific
/// parse diagnostic. Finding no `Cargo.toml` at all fails closed.
pub(crate) struct WorkspaceDiscovery {
    root: PathBuf,
    degradation_reason: Option<String>,
}

impl WorkspaceDiscovery {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn degradation_reason(&self) -> Option<&str> {
        self.degradation_reason.as_deref()
    }
}

pub(crate) fn discover_workspace_root<R: CommandRunner + ?Sized>(
    invocation_dir: &Path,
    runner: &R,
    allow_manifest_degradation: bool,
) -> Result<WorkspaceDiscovery, CommandError> {
    let invocation_for_cargo = invocation_dir;
    let canonical_invocation = invocation_dir.canonicalize().map_err(CommandError::Io)?;
    let invocation_dir = canonical_invocation.as_path();
    let mut ancestors = invocation_dir.ancestors();
    let Some(package_dir) = ancestors.by_ref().find(|dir| has_manifest(dir)) else {
        return Err(CommandError::WorkspaceRootNotFound {
            start_dir: invocation_dir.display().to_string(),
        });
    };
    let manifest_path = package_dir.join("Cargo.toml");
    let manifest_text = read_manifest(package_dir, Path::new("Cargo.toml"))?;
    let local_parse =
        parse_workspace_root_directive(&manifest_path.display().to_string(), &manifest_text);

    if let Ok(directive) = local_parse.as_ref() {
        let output = match runner
            .cargo_locate_project_workspace(invocation_for_cargo, &manifest_path)
        {
            Ok(output) => output,
            Err(source)
                if allow_manifest_degradation && matches!(source, RunnerError::Exited { .. }) =>
            {
                return Ok(WorkspaceDiscovery {
                    root: discover_workspace_root_fallback_for_directive(package_dir, directive)?,
                    degradation_reason: Some(source.to_string()),
                });
            }
            Err(source) => {
                return Err(CommandError::WorkspaceRootDiscovery {
                    start_dir: invocation_dir.display().to_string(),
                    source,
                });
            }
        };
        return Ok(WorkspaceDiscovery {
            root: workspace_root_from_cargo_output(invocation_for_cargo, &output)?,
            degradation_reason: None,
        });
    }

    Ok(WorkspaceDiscovery {
        root: discover_workspace_root_fallback(package_dir)?,
        degradation_reason: local_parse.err().map(|error| error.to_string()),
    })
}

fn discover_workspace_root_fallback_for_directive(
    package_dir: &Path,
    directive: &WorkspaceRootDirective,
) -> Result<PathBuf, CommandError> {
    match directive {
        WorkspaceRootDirective::WorkspaceRoot => Ok(package_dir.to_path_buf()),
        WorkspaceRootDirective::MemberOf { workspace_path } => {
            let pointed_root = normalise_lexically(&package_dir.join(workspace_path));
            let pointed_manifest = pointed_root.join("Cargo.toml");
            let is_workspace_root = match read_manifest(&pointed_root, Path::new("Cargo.toml")) {
                Ok(text) => matches!(
                    parse_workspace_root_directive(&pointed_manifest.display().to_string(), &text),
                    Ok(WorkspaceRootDirective::WorkspaceRoot)
                ),
                Err(CommandError::ManifestRead { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    false
                }
                Err(error) => return Err(error),
            };
            if is_workspace_root {
                Ok(pointed_root)
            } else {
                discover_workspace_root_fallback(package_dir)
            }
        }
        WorkspaceRootDirective::Standalone => discover_workspace_root_fallback(package_dir),
    }
}

fn discover_workspace_root_fallback(package_dir: &Path) -> Result<PathBuf, CommandError> {
    for candidate_root in package_dir
        .ancestors()
        .skip(1)
        .filter(|dir| has_manifest(dir))
    {
        let root_manifest_path = candidate_root.join("Cargo.toml");
        let root_text = read_manifest(candidate_root, Path::new("Cargo.toml"))?;
        if !matches!(
            parse_workspace_root_directive(&root_manifest_path.display().to_string(), &root_text,),
            Ok(WorkspaceRootDirective::WorkspaceRoot)
        ) {
            continue;
        }
        let child_manifest = package_dir.join("Cargo.toml");
        let Ok(relative_manifest) = child_manifest.strip_prefix(candidate_root) else {
            continue;
        };
        let membership = classify_workspace_manifest_membership(
            &root_manifest_path.display().to_string(),
            &root_text,
            relative_manifest,
        )
        .unwrap_or(WorkspaceManifestMembership::Unclaimed);
        if membership == WorkspaceManifestMembership::Excluded {
            return Ok(package_dir.to_path_buf());
        }
        // A malformed child cannot expose Cargo's implicit path-dependency
        // membership. Conservatively anchor to the nearest workspace unless
        // it explicitly excludes the child, so policy cannot be skipped.
        return Ok(candidate_root.to_path_buf());
    }

    Ok(package_dir.to_path_buf())
}

fn normalise_lexically(path: &Path) -> PathBuf {
    let mut normalised = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalised.pop() {
                    normalised.push(Component::ParentDir);
                }
            }
            component => normalised.push(component),
        }
    }
    normalised
}

fn workspace_root_from_cargo_output(
    invocation_dir: &Path,
    output: &str,
) -> Result<PathBuf, CommandError> {
    let manifest = PathBuf::from(output.trim());
    let manifest = if manifest.is_absolute() {
        manifest
    } else {
        invocation_dir.join(manifest)
    };
    if manifest.file_name().is_none_or(|name| name != "Cargo.toml") || !manifest.is_file() {
        return Err(CommandError::WorkspaceRootOutput {
            output: output.trim().to_owned(),
        });
    }

    let root = manifest.parent().expect("a Cargo.toml path has a parent");
    read_manifest(root, Path::new("Cargo.toml"))?;
    Ok(root.to_path_buf())
}

fn has_manifest(dir: &Path) -> bool {
    match fs::symlink_metadata(dir.join("Cargo.toml")) {
        Ok(metadata) => metadata.is_file() || metadata.file_type().is_symlink(),
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

pub(crate) fn workspace_manifest_paths(current_dir: &Path) -> Result<Vec<PathBuf>, CommandError> {
    let mut paths = BTreeSet::from([PathBuf::from("Cargo.toml")]);
    let root_manifest_text = read_manifest(current_dir, Path::new("Cargo.toml"))?;
    for member in parse_workspace_member_manifest_paths("Cargo.toml", &root_manifest_text).map_err(
        |source| CommandError::ManifestParse {
            path: "Cargo.toml".to_owned(),
            source,
        },
    )? {
        paths.insert(PathBuf::from(member));
    }

    let mut search_roots = parse_workspace_member_glob_roots("Cargo.toml", &root_manifest_text)
        .map_err(|source| CommandError::ManifestParse {
            path: "Cargo.toml".to_owned(),
            source,
        })?
        .into_iter()
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>();
    search_roots.insert(PathBuf::from("crates"));
    for relative_root in minimal_search_roots(search_roots) {
        let root = current_dir.join(&relative_root);
        if confined_directory(current_dir, &relative_root)
            .map_err(CommandError::Io)?
            .is_some()
        {
            collect_relative_files_matching(&root, current_dir, &mut paths, &mut |path| {
                path.file_name().is_some_and(|name| name == "Cargo.toml")
            })
            .map_err(CommandError::Io)?;
        }
    }

    Ok(paths.into_iter().collect())
}

fn read_manifest(root: &Path, relative: &Path) -> Result<String, CommandError> {
    read_optional_text_no_symlink(root, relative)
        .and_then(|text| {
            text.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "manifest missing"))
        })
        .map_err(|source| CommandError::ManifestRead {
            path: relative.display().to_string(),
            source,
        })
}

fn minimal_search_roots(roots: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    if roots.iter().any(|root| root == Path::new(".")) {
        return vec![PathBuf::from(".")];
    }

    let mut selected = Vec::new();

    for root in roots {
        if selected
            .iter()
            .any(|selected_root: &PathBuf| root.starts_with(selected_root))
        {
            continue;
        }
        selected.push(root);
    }

    selected
}

pub(crate) fn review_paths(current_dir: &Path) -> Result<Vec<PathBuf>, CommandError> {
    let mut paths = workspace_manifest_paths(current_dir)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    insert_review_root_paths(&mut paths);
    paths.insert(PathBuf::from(REVIEW_RECORDS_DIR));

    Ok(paths.into_iter().collect())
}

pub(crate) fn insert_review_root_paths(paths: &mut BTreeSet<PathBuf>) {
    paths.extend(REVIEW_ROOT_FILE_PATHS.into_iter().map(PathBuf::from));
}

pub(crate) fn collect_relative_files_matching<F>(
    directory: &Path,
    repo_root: &Path,
    paths: &mut BTreeSet<PathBuf>,
    include_file: &mut F,
) -> io::Result<()>
where
    F: FnMut(&Path) -> bool,
{
    collect_confined_files(
        directory,
        repo_root,
        paths,
        include_file,
        &mut BTreeSet::new(),
    )
}

fn collect_confined_files<F>(
    directory: &Path,
    repo_root: &Path,
    paths: &mut BTreeSet<PathBuf>,
    include_file: &mut F,
    ancestors: &mut BTreeSet<PathBuf>,
) -> io::Result<()>
where
    F: FnMut(&Path) -> bool,
{
    let relative = directory
        .strip_prefix(repo_root)
        .map_err(io::Error::other)?;
    let resolved = confined_directory(repo_root, relative)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "search directory missing"))?;
    if !ancestors.insert(resolved.clone()) {
        return Err(io::Error::other("cyclic workspace search directory"));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|name| name == ".git" || name == "target")
        {
            continue;
        }
        let kind = entry.file_type()?;
        let is_directory = kind.is_dir() || (kind.is_symlink() && fs::metadata(&path)?.is_dir());
        if is_directory {
            collect_confined_files(&path, repo_root, paths, include_file, ancestors)?;
        } else if (*include_file)(&path) {
            paths.insert(
                path.strip_prefix(repo_root)
                    .map_err(io::Error::other)?
                    .to_path_buf(),
            );
        }
    }
    ancestors.remove(&resolved);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::minimal_search_roots;

    #[cfg(unix)]
    #[test]
    fn workspace_search_and_member_reads_stay_inside_the_root() {
        use super::super::scratch_dir::ScratchDir;
        use std::fs;
        use std::os::unix::fs::symlink;
        let scratch = ScratchDir::create("barbican-confined-workspace", false).unwrap();
        let root = scratch.path().join("root");
        let outside = scratch.path().join("outside");
        fs::create_dir_all(root.join("actual/member")).unwrap();
        fs::create_dir_all(outside.join("member")).unwrap();
        fs::write(
            root.join("actual/member/Cargo.toml"),
            "[package]\nname='inside'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(
            outside.join("member/Cargo.toml"),
            "[package]\nname='outside'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['linked/*']\n",
        )
        .unwrap();
        symlink("actual", root.join("linked")).unwrap();
        assert!(
            super::workspace_manifest_paths(&root)
                .unwrap()
                .contains(&PathBuf::from("linked/member/Cargo.toml"))
        );
        assert!(super::super::loaders::load_manifest_texts_from_root(&root).is_ok());
        fs::remove_file(root.join("linked")).unwrap();
        symlink(&outside, root.join("linked")).unwrap();
        assert!(super::workspace_manifest_paths(&root).is_err());
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['linked/member']\n",
        )
        .unwrap();
        assert!(super::super::loaders::load_manifest_texts_from_root(&root).is_err());
        fs::remove_file(root.join("linked")).unwrap();
        symlink("absent", root.join("linked")).unwrap();
        assert!(super::super::loaders::load_manifest_texts_from_root(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn nested_search_links_preserve_inside_members_and_refuse_cycles() {
        use super::super::scratch_dir::ScratchDir;
        use std::fs;
        use std::os::unix::fs::symlink;
        let scratch = ScratchDir::create("barbican-search-links", false).unwrap();
        let root = scratch.path();
        fs::create_dir_all(root.join("actual/member")).unwrap();
        fs::create_dir(root.join("crates")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['crates/*']\n",
        )
        .unwrap();
        fs::write(
            root.join("actual/member/Cargo.toml"),
            "[package]\nname='member'\nversion='0.1.0'\n",
        )
        .unwrap();
        symlink("../actual/member", root.join("crates/member")).unwrap();
        assert!(
            super::workspace_manifest_paths(root)
                .unwrap()
                .contains(&PathBuf::from("crates/member/Cargo.toml"))
        );
        symlink(".", root.join("actual/member/cycle")).unwrap();
        assert!(
            super::workspace_manifest_paths(root)
                .unwrap_err()
                .to_string()
                .contains("cyclic")
        );
    }

    #[test]
    fn minimal_search_roots_collapses_nested_and_top_level_roots() {
        assert_eq!(
            minimal_search_roots(BTreeSet::from([
                PathBuf::from("libs"),
                PathBuf::from("libs/core"),
                PathBuf::from("tools"),
            ])),
            vec![PathBuf::from("libs"), PathBuf::from("tools")]
        );
        assert_eq!(
            minimal_search_roots(BTreeSet::from([
                PathBuf::from("."),
                PathBuf::from("crates"),
                PathBuf::from("libs"),
            ])),
            vec![PathBuf::from(".")]
        );
    }
}
