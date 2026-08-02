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

pub(crate) const REVIEW_ROOT_FILE_PATHS: [&str; 4] = [
    "Cargo.lock",
    "barbican.toml",
    "deny.toml",
    "reviewed-targets.toml",
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
    let mut ancestors = invocation_dir.ancestors();
    let Some(package_dir) = ancestors.by_ref().find(|dir| has_manifest(dir)) else {
        return Err(CommandError::WorkspaceRootNotFound {
            start_dir: invocation_dir.display().to_string(),
        });
    };
    let manifest_path = package_dir.join("Cargo.toml");
    let (manifest_text, manifest_read_error) = match fs::read_to_string(&manifest_path) {
        Ok(text) => (Some(text), None),
        Err(error) => (
            None,
            Some(format!(
                "{}: unable to read manifest: {error}",
                manifest_path.display()
            )),
        ),
    };
    let local_parse = manifest_text
        .as_deref()
        .map(|text| parse_workspace_root_directive(&manifest_path.display().to_string(), text));

    if let Some(Ok(directive)) = local_parse.as_ref() {
        let output = match runner.cargo_locate_project_workspace(invocation_dir, &manifest_path) {
            Ok(output) => output,
            Err(source)
                if allow_manifest_degradation && matches!(source, RunnerError::Exited { .. }) =>
            {
                return Ok(WorkspaceDiscovery {
                    root: discover_workspace_root_fallback_for_directive(package_dir, directive),
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
            root: workspace_root_from_cargo_output(invocation_dir, &output)?,
            degradation_reason: None,
        });
    }

    Ok(WorkspaceDiscovery {
        root: discover_workspace_root_fallback(package_dir),
        degradation_reason: local_parse
            .and_then(Result::err)
            .map(|error| error.to_string())
            .or(manifest_read_error),
    })
}

fn discover_workspace_root_fallback_for_directive(
    package_dir: &Path,
    directive: &WorkspaceRootDirective,
) -> PathBuf {
    match directive {
        WorkspaceRootDirective::WorkspaceRoot => package_dir.to_path_buf(),
        WorkspaceRootDirective::MemberOf { workspace_path } => {
            let pointed_root = normalise_lexically(&package_dir.join(workspace_path));
            let pointed_manifest = pointed_root.join("Cargo.toml");
            let is_workspace_root = fs::read_to_string(&pointed_manifest).is_ok_and(|text| {
                matches!(
                    parse_workspace_root_directive(&pointed_manifest.display().to_string(), &text,),
                    Ok(WorkspaceRootDirective::WorkspaceRoot)
                )
            });
            if is_workspace_root {
                pointed_root
            } else {
                discover_workspace_root_fallback(package_dir)
            }
        }
        WorkspaceRootDirective::Standalone => discover_workspace_root_fallback(package_dir),
    }
}

fn discover_workspace_root_fallback(package_dir: &Path) -> PathBuf {
    for candidate_root in package_dir
        .ancestors()
        .skip(1)
        .filter(|dir| has_manifest(dir))
    {
        let root_manifest_path = candidate_root.join("Cargo.toml");
        let Ok(root_text) = fs::read_to_string(&root_manifest_path) else {
            continue;
        };
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
            return package_dir.to_path_buf();
        }
        // A malformed child cannot expose Cargo's implicit path-dependency
        // membership. Conservatively anchor to the nearest workspace unless
        // it explicitly excludes the child, so policy cannot be skipped.
        return candidate_root.to_path_buf();
    }

    package_dir.to_path_buf()
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

    Ok(manifest
        .parent()
        .expect("a Cargo.toml path has a parent")
        .to_path_buf())
}

fn has_manifest(dir: &Path) -> bool {
    fs::metadata(dir.join("Cargo.toml"))
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

pub(crate) fn workspace_manifest_paths(current_dir: &Path) -> Result<Vec<PathBuf>, CommandError> {
    let mut paths = BTreeSet::from([PathBuf::from("Cargo.toml")]);
    let root_manifest_text =
        fs::read_to_string(current_dir.join("Cargo.toml")).map_err(|source| {
            CommandError::ManifestRead {
                path: "Cargo.toml".to_owned(),
                source,
            }
        })?;
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
        let root = current_dir.join(relative_root);
        if root.is_dir() {
            collect_relative_files_matching(&root, current_dir, &mut paths, &mut |path| {
                path.file_name().is_some_and(|name| name == "Cargo.toml")
            })
            .map_err(CommandError::Io)?;
        }
    }

    Ok(paths.into_iter().collect())
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
    debug_assert!(directory.is_dir());

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if entry.file_type()?.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == ".git" || name == "target")
            {
                continue;
            }
            collect_relative_files_matching(&path, repo_root, paths, include_file)?;
            continue;
        }

        if (*include_file)(&path) {
            let relative = path
                .strip_prefix(repo_root)
                .map_err(io::Error::other)?
                .to_path_buf();
            paths.insert(relative);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::minimal_search_roots;

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
