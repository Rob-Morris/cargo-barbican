use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::command_runner::CommandRunner;

use super::diff_render::render_unified_file_diff;
use super::{
    CommandError, REVIEW_RECORDS_DIR, collect_relative_files_matching, fail,
    insert_review_root_paths, review_paths, workspace_manifest_paths,
};

pub(super) fn run_review<R>(
    base_dir: Option<&Path>,
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let diff = if let Some(base_dir) = base_dir {
        let base_root = match resolve_base_root(current_dir, base_dir) {
            Ok(base_root) => base_root,
            Err(error) => return fail(stderr, error),
        };
        render_non_git_review_diff(&base_root, current_dir)?
    } else {
        let paths = review_paths(current_dir).map_err(CommandError::Io)?;
        match runner.git_diff(current_dir, &paths) {
            Ok(diff) => diff,
            Err(error) => return fail(stderr, format!("git diff: {error}")),
        }
    };

    if diff.trim().is_empty() {
        writeln!(stdout, "No Rust dependency policy changes detected.")
            .map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    }

    writeln!(
        stdout,
        "Review checklist:\n  - Confirm the changed crates and versions are the ones you intended.\n  - Confirm the routine workflow only changed the root Cargo.lock.\n  - Check for unexpected registry, git, path, patch, or source-replacement changes.\n  - Check for new build-dependencies, proc-macro crates, or native -sys / FFI crates.\n  - Check that any reviewed family change updates both reviewed-targets.toml and the matching checked-in review record.\n"
    )
    .map_err(CommandError::Io)?;
    write!(stdout, "{diff}").map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}

fn resolve_base_root(current_dir: &Path, base_dir: &Path) -> Result<PathBuf, String> {
    let base_root = current_dir.join(base_dir);
    let base_dir_display = base_dir.display().to_string();

    match base_root.try_exists() {
        Ok(true) if base_root.is_dir() => Ok(base_root),
        Ok(true) => Err(format!(
            "{base_dir_display}: review baseline directory is not a directory"
        )),
        Ok(false) => Err(format!(
            "{base_dir_display}: review baseline directory not found"
        )),
        Err(error) => Err(format!(
            "{base_dir_display}: unable to inspect review baseline directory: {error}"
        )),
    }
}

fn render_non_git_review_diff(
    base_root: &Path,
    current_dir: &Path,
) -> Result<String, CommandError> {
    let review_file_paths =
        non_git_review_file_paths(base_root, current_dir).map_err(CommandError::Io)?;
    let mut rendered = String::new();

    for relative_path in review_file_paths {
        let base_text =
            read_optional_review_text(base_root, &relative_path).map_err(CommandError::Io)?;
        let current_text =
            read_optional_review_text(current_dir, &relative_path).map_err(CommandError::Io)?;

        if base_text == current_text {
            continue;
        }

        let diff = render_unified_file_diff(
            &relative_path,
            base_text.as_deref(),
            current_text.as_deref(),
        );
        rendered.push_str(&diff);
    }

    Ok(rendered)
}

fn non_git_review_file_paths(base_root: &Path, current_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    insert_review_root_paths(&mut paths);
    paths.extend(workspace_manifest_paths(current_dir)?);
    paths.extend(workspace_manifest_paths(base_root)?);
    collect_review_record_paths(current_dir, &mut paths)?;
    collect_review_record_paths(base_root, &mut paths)?;

    Ok(paths.into_iter().collect())
}

fn collect_review_record_paths(root_dir: &Path, paths: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    let review_dir = root_dir.join(REVIEW_RECORDS_DIR);

    match fs::metadata(&review_dir) {
        Ok(metadata) if metadata.is_dir() => {
            collect_relative_files_matching(&review_dir, root_dir, paths, &mut |_| true)
        }
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a directory",
            review_dir.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_optional_review_text(root_dir: &Path, relative_path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(root_dir.join(relative_path)) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
