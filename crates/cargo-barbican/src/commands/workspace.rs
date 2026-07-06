use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use barbican::{parse_workspace_member_glob_roots, parse_workspace_member_manifest_paths};

use super::CommandError;

pub(crate) const REVIEW_ROOT_FILE_PATHS: [&str; 4] = [
    "Cargo.lock",
    "barbican.toml",
    "deny.toml",
    "reviewed-targets.toml",
];
pub(crate) const REVIEW_RECORDS_DIR: &str = "docs/dependency-reviews";

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
