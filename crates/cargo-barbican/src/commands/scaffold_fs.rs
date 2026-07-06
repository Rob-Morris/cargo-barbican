use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::CommandError;

pub(super) fn confined_scaffold_state(
    current_dir: &Path,
    relative_path: &Path,
) -> Result<ScaffoldState, CommandError> {
    if let Some(blocked_ancestor) = blocked_scaffold_ancestor(current_dir, relative_path)? {
        Ok(ScaffoldState::BlockedAncestor {
            path: blocked_ancestor,
        })
    } else {
        scaffold_state(current_dir, relative_path)
    }
}

pub(super) fn write_new_file(
    current_dir: &Path,
    relative_path: &Path,
    contents: &str,
) -> Result<(), CommandError> {
    if let Some(parent) = scaffold_parent(relative_path) {
        create_dir_all(current_dir, parent)?;
    }
    fs::write(current_dir.join(relative_path), contents).map_err(|source| {
        CommandError::ScaffoldIo {
            path: relative_path.display().to_string(),
            source,
        }
    })
}

pub(super) fn create_dir_all(current_dir: &Path, relative_path: &Path) -> Result<(), CommandError> {
    fs::create_dir_all(current_dir.join(relative_path)).map_err(|source| CommandError::ScaffoldIo {
        path: relative_path.display().to_string(),
        source,
    })
}

fn blocked_scaffold_ancestor(
    current_dir: &Path,
    relative_path: &Path,
) -> Result<Option<PathBuf>, CommandError> {
    let Some(parent) = scaffold_parent(relative_path) else {
        return Ok(None);
    };

    let mut ancestor = PathBuf::new();
    for component in parent.components() {
        ancestor.push(component.as_os_str());
        match fs::symlink_metadata(current_dir.join(&ancestor)) {
            Ok(metadata) if metadata.file_type().is_dir() => continue,
            Ok(_) => return Ok(Some(ancestor)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CommandError::ScaffoldIo {
                    path: ancestor.display().to_string(),
                    source,
                });
            }
        }
    }

    Ok(None)
}

fn scaffold_state(current_dir: &Path, relative_path: &Path) -> Result<ScaffoldState, CommandError> {
    match fs::symlink_metadata(current_dir.join(relative_path)) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                Ok(ScaffoldState::WrongType("symlink"))
            } else if file_type.is_file() {
                Ok(ScaffoldState::RegularFile)
            } else if file_type.is_dir() {
                Ok(ScaffoldState::RegularDirectory)
            } else {
                Ok(ScaffoldState::WrongType("special file"))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ScaffoldState::Missing),
        Err(source) => Err(CommandError::ScaffoldIo {
            path: relative_path.display().to_string(),
            source,
        }),
    }
}

fn scaffold_parent(relative_path: &Path) -> Option<&Path> {
    relative_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScaffoldState {
    Missing,
    RegularFile,
    RegularDirectory,
    WrongType(&'static str),
    BlockedAncestor { path: PathBuf },
}
