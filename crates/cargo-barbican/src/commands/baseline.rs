use std::io;
use std::path::{Component, Path, PathBuf};

use super::CommandError;
use crate::command_runner::CommandRunner;

pub(super) struct CapturedCommit {
    pub(super) requested: String,
    pub(super) commit: String,
}

impl CapturedCommit {
    pub(super) fn capture<R: CommandRunner + ?Sized>(
        root: &Path,
        runner: &R,
        requested: &str,
        alternatives: &str,
    ) -> Result<Self, CommandError> {
        let output = runner.git_resolve_commit(root, requested).map_err(|e| {
            diagnostic(format!(
                "unable to resolve Git baseline {requested:?}: {e}; {alternatives}"
            ))
        })?;
        let commit = output.trim();
        if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(diagnostic(format!(
                "Git baseline {requested:?} did not resolve to a complete commit identity; {alternatives}"
            )));
        }
        Ok(Self {
            requested: requested.to_owned(),
            commit: commit.to_owned(),
        })
    }
}

pub(crate) struct GitBaseline {
    pub(super) identity: CapturedCommit,
    pub(super) alternatives: String,
    prefix: PathBuf,
}

impl GitBaseline {
    pub(super) fn capture<R: CommandRunner + ?Sized>(
        root: &Path,
        runner: &R,
        requested: &str,
        alternatives: &str,
    ) -> Result<Self, CommandError> {
        let identity = CapturedCommit::capture(root, runner, requested, alternatives)?;
        let output = runner.git_workspace_prefix(root).map_err(|e| {
            diagnostic(format!(
                "unable to locate Git workspace prefix for baseline {requested:?} ({}): {e}",
                identity.commit
            ))
        })?;
        let prefix = PathBuf::from(output.strip_suffix('\n').unwrap_or(&output));
        if prefix.is_absolute()
            || prefix
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(diagnostic(
                "Git workspace prefix is not a repository-relative directory",
            ));
        }
        Ok(Self {
            identity,
            prefix,
            alternatives: alternatives.to_owned(),
        })
    }

    pub(super) fn object(&self, root: &Path, path: &Path) -> Result<String, CommandError> {
        let logical = workspace_relative(root, path)?;
        let mapped = normalize(&self.prefix.join(logical))?;
        let path = mapped
            .to_str()
            .ok_or_else(|| diagnostic("Git baseline path is not UTF-8"))?;
        Ok(format!("{}:{path}", self.identity.commit))
    }

    pub(super) fn describe(&self, object: &str) -> String {
        format!(
            "{object} (requested baseline {:?})",
            self.identity.requested
        )
    }
}

pub(super) fn workspace_relative(root: &Path, path: &Path) -> Result<PathBuf, CommandError> {
    if !path.is_absolute() {
        return Ok(path.to_owned());
    }
    let path = normalize(path)?;
    let root = normalize(root)?;
    if let Ok(relative) = path.strip_prefix(&root) {
        return Ok(relative.to_owned());
    }
    // Cargo canonicalises its workspace root; match parent aliases such as
    // /var -> /private/var without resolving the selected leaf or a baseline file.
    let parent = path
        .parent()
        .ok_or_else(|| diagnostic("absolute lockfile has no parent"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| diagnostic("absolute lockfile has no filename"))?;
    let mapped = parent.canonicalize().map_err(CommandError::Io)?.join(leaf);
    let root = root.canonicalize().map_err(CommandError::Io)?;
    mapped.strip_prefix(root).map(Path::to_owned).map_err(|_| diagnostic(
        "absolute --lockfile is outside the workspace and has no parallel baseline path; use a workspace-relative --lockfile or age-lock --base-lockfile with an explicit file"))
}

fn normalize(path: &Path) -> Result<PathBuf, CommandError> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return Err(diagnostic(
                        "baseline path escapes its Git worktree or filesystem root",
                    ));
                }
            }
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}

pub(super) fn diagnostic(detail: impl Into<String>) -> CommandError {
    CommandError::Io(io::Error::other(detail.into()))
}
