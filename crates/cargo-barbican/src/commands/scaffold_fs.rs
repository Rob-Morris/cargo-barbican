use std::fs;
use std::io::{self, Write};
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

pub(super) fn create_scaffold_file(
    current_dir: &Path,
    relative_path: &Path,
    contents: &str,
) -> Result<(), CommandError> {
    if let Some(parent) = scaffold_parent(relative_path) {
        create_dir_all(current_dir, parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(current_dir.join(relative_path))
        .map_err(|source| CommandError::ScaffoldIo {
            path: relative_path.display().to_string(),
            source,
        })?;
    write_created_scaffold(&mut file, relative_path, contents)
}

fn write_created_scaffold(
    file: &mut dyn Write,
    relative_path: &Path,
    contents: &str,
) -> Result<(), CommandError> {
    file.write_all(contents.as_bytes())
        .map_err(|source| CommandError::ScaffoldPartialWrite {
            path: relative_path.display().to_string(),
            source,
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "barbican-exclusive-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn exclusive_creation_refuses_late_leaves_without_following_or_clobbering() {
        let fixture = Fixture::new();
        for kind in ["file", "directory", "symlink", "fifo"] {
            let relative = Path::new(kind);
            assert_eq!(
                confined_scaffold_state(&fixture.0, relative).unwrap(),
                ScaffoldState::Missing
            );
            let path = fixture.0.join(relative);
            match kind {
                "file" => fs::write(&path, "consumer bytes").unwrap(),
                "directory" => fs::create_dir(&path).unwrap(),
                "symlink" => symlink("file", &path).unwrap(),
                "fifo" => assert!(
                    std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap()
                        .success()
                ),
                _ => unreachable!(),
            }
            let error = create_scaffold_file(&fixture.0, relative, "new bytes").unwrap_err();
            assert!(matches!(error, CommandError::ScaffoldIo { .. }));
        }
        assert_eq!(
            fs::read_to_string(fixture.0.join("file")).unwrap(),
            "consumer bytes"
        );
        assert!(
            fs::symlink_metadata(fixture.0.join("symlink"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn created_output_has_no_execute_bits_and_existing_modes_survive_conflict() {
        let fixture = Fixture::new();
        let relative = Path::new("hooks/pre-commit");
        create_scaffold_file(&fixture.0, relative, "disabled").unwrap();
        let path = fixture.0.join(relative);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o111, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o751)).unwrap();
        assert!(create_scaffold_file(&fixture.0, relative, "replacement").is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "disabled");
    }

    struct FailingWriter {
        file: fs::File,
        remaining: usize,
    }
    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("controlled write failure"));
            }
            let count = self.file.write(&bytes[..bytes.len().min(self.remaining)])?;
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    #[test]
    fn partial_write_retains_prefix_and_names_manual_recovery_before_rerun() {
        let fixture = Fixture::new();
        let relative = Path::new("record-template.md");
        let file = fs::File::create_new(fixture.0.join(relative)).unwrap();
        let mut writer = FailingWriter { file, remaining: 3 };
        let error = write_created_scaffold(&mut writer, relative, "abcdef").unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("record-template.md"));
        assert!(diagnostic.contains("controlled write failure"));
        assert!(diagnostic.contains("inspect it and remove it manually"));
        assert_eq!(fs::read(fixture.0.join(relative)).unwrap(), b"abc");
        assert_eq!(
            confined_scaffold_state(&fixture.0, relative).unwrap(),
            ScaffoldState::RegularFile
        );
        assert!(create_scaffold_file(&fixture.0, relative, "replacement").is_err());
        assert_eq!(fs::read(fixture.0.join(relative)).unwrap(), b"abc");
    }
}
