use std::collections::HashSet;

use serde::Deserialize;
use thiserror::Error;

use crate::{ExactCrateSpec, ExactCrateSpecError, Sha256Digest};

pub const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    packages: Vec<LockedPackage>,
}

impl Lockfile {
    pub fn packages(&self) -> &[LockedPackage] {
        &self.packages
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<Sha256Digest>,
}

impl LockedPackage {
    pub fn is_crates_io(&self) -> bool {
        self.source.as_deref() == Some(CRATES_IO_SOURCE)
    }

    pub fn exact_spec(&self) -> Result<ExactCrateSpec, LockfileError> {
        ExactCrateSpec::from_parts(&self.name, &self.version).map_err(|source| {
            LockfileError::InvalidPackageSpec {
                name: self.name.clone(),
                version: self.version.clone(),
                source,
            }
        })
    }
}

pub fn parse_lockfile(text: &str) -> Result<Lockfile, LockfileError> {
    let raw: RawLockfile = toml::from_str(text).map_err(LockfileError::Parse)?;
    let mut packages = Vec::with_capacity(raw.package.len());

    for package in raw.package {
        ExactCrateSpec::from_parts(&package.name, &package.version).map_err(|source| {
            LockfileError::InvalidPackageSpec {
                name: package.name.clone(),
                version: package.version.clone(),
                source,
            }
        })?;

        let checksum = package
            .checksum
            .map(|checksum| {
                Sha256Digest::try_from(checksum.as_str()).map_err(|_| {
                    LockfileError::InvalidChecksum {
                        name: package.name.clone(),
                        version: package.version.clone(),
                        checksum,
                    }
                })
            })
            .transpose()?;

        packages.push(LockedPackage {
            name: package.name,
            version: package.version,
            source: package.source,
            checksum,
        });
    }

    Ok(Lockfile { packages })
}

pub fn added_crates_io_specs(
    current: &Lockfile,
    base: &Lockfile,
) -> Result<Vec<ExactCrateSpec>, LockfileError> {
    let base_packages: HashSet<&LockedPackage> = base.packages.iter().collect();
    let mut added_specs = Vec::new();

    for package in &current.packages {
        if !package.is_crates_io() || base_packages.contains(package) {
            continue;
        }

        added_specs.push(
            package
                .exact_spec()
                .expect("parse_lockfile guarantees exact locked package specs"),
        );
    }

    added_specs.sort_by(|left, right| {
        left.crate_name()
            .cmp(right.crate_name())
            .then_with(|| left.version().cmp(right.version()))
    });

    Ok(added_specs)
}

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("unable to parse Cargo.lock: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("invalid locked package {name}@{version}: {source}")]
    InvalidPackageSpec {
        name: String,
        version: String,
        #[source]
        source: ExactCrateSpecError,
    },
    #[error("invalid Cargo.lock checksum for {name}@{version}: {checksum}")]
    InvalidChecksum {
        name: String,
        version: String,
        checksum: String,
    },
}

#[derive(Debug, Deserialize)]
struct RawLockfile {
    #[serde(default)]
    package: Vec<RawLockedPackage>,
}

#[derive(Debug, Deserialize)]
struct RawLockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::{
        CRATES_IO_SOURCE, ExactCrateSpec, Sha256Digest, added_crates_io_specs, parse_lockfile,
    };

    #[test]
    fn parses_lockfile_packages() {
        let lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "local-crate"
version = "0.1.0"
"#,
        )
        .expect("lockfile should parse");

        assert_eq!(lockfile.packages().len(), 2);
        assert_eq!(lockfile.packages()[0].name, "serde");
        assert_eq!(
            lockfile.packages()[0].source.as_deref(),
            Some(CRATES_IO_SOURCE)
        );
        assert_eq!(
            lockfile.packages()[0]
                .checksum
                .as_ref()
                .map(Sha256Digest::as_str),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(lockfile.packages()[1].source, None);
    }

    #[test]
    fn selects_only_added_crates_io_packages() {
        let base = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"
"#,
        )
        .expect("base lockfile should parse");

        let current = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"

[[package]]
name = "toml"
version = "0.8.23"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("current lockfile should parse");

        let added = added_crates_io_specs(&current, &base).expect("selection should succeed");

        assert_eq!(
            added,
            vec![
                ExactCrateSpec::from_parts("serde", "1.0.228").expect("spec should build"),
                ExactCrateSpec::from_parts("toml", "0.8.23").expect("spec should build"),
            ]
        );
    }

    #[test]
    fn rejects_non_exact_locked_versions() {
        let error = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "^1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect_err("lockfile with a version range should fail");

        assert!(matches!(
            error,
            crate::LockfileError::InvalidPackageSpec { .. }
        ));
    }

    #[test]
    fn rejects_invalid_lockfile_checksums() {
        let error = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "not-a-sha256"
"#,
        )
        .expect_err("invalid lockfile checksum should fail");

        assert!(matches!(
            error,
            crate::LockfileError::InvalidChecksum { .. }
        ));
    }
}
