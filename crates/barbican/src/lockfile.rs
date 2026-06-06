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
    exact_spec: ExactCrateSpec,
}

impl LockedPackage {
    pub fn is_crates_io(&self) -> bool {
        self.source.as_deref() == Some(CRATES_IO_SOURCE)
    }

    pub fn exact_spec(&self) -> &ExactCrateSpec {
        &self.exact_spec
    }

    pub fn checksum(&self) -> Option<&Sha256Digest> {
        self.checksum.as_ref()
    }

    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

pub fn parse_lockfile(text: &str) -> Result<Lockfile, LockfileError> {
    let raw: RawLockfile = toml::from_str(text).map_err(LockfileError::Parse)?;
    let mut packages = Vec::with_capacity(raw.package.len());

    for package in raw.package {
        let exact_spec =
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
            exact_spec,
        });
    }

    Ok(Lockfile { packages })
}

pub fn added_crates_io_specs(
    current: &Lockfile,
    base: &Lockfile,
) -> Result<Vec<ExactCrateSpec>, LockfileError> {
    let base_packages: HashSet<PackageIdentity<'_>> =
        base.packages.iter().map(LockedPackage::identity).collect();
    let mut added_specs = Vec::new();

    for package in &current.packages {
        if !package.is_crates_io() || base_packages.contains(&package.identity()) {
            continue;
        }

        added_specs.push(package.exact_spec().clone());
    }

    added_specs.sort_by(|left, right| {
        left.crate_name()
            .cmp(right.crate_name())
            .then_with(|| left.version().cmp(right.version()))
    });

    Ok(added_specs)
}

pub fn changed_crates_io_checksums<'a>(
    current: &'a Lockfile,
    base: &'a Lockfile,
) -> Vec<LockedChecksumChange<'a>> {
    let mut changes = Vec::new();

    for current_package in current
        .packages
        .iter()
        .filter(|package| package.is_crates_io())
    {
        let Some(current_checksum) = current_package.checksum() else {
            continue;
        };
        let Some(base_package) = base.packages.iter().find(|base_package| {
            base_package.is_crates_io() && base_package.identity() == current_package.identity()
        }) else {
            continue;
        };
        let Some(base_checksum) = base_package.checksum() else {
            continue;
        };

        if base_checksum != current_checksum {
            changes.push(LockedChecksumChange {
                spec: current_package.exact_spec(),
                base_checksum,
                current_checksum,
            });
        }
    }

    changes.sort_by(|left, right| {
        left.spec()
            .crate_name()
            .cmp(right.spec().crate_name())
            .then_with(|| left.spec().version().cmp(right.spec().version()))
    });
    changes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedChecksumChange<'a> {
    spec: &'a ExactCrateSpec,
    base_checksum: &'a Sha256Digest,
    current_checksum: &'a Sha256Digest,
}

impl<'a> LockedChecksumChange<'a> {
    pub fn spec(&self) -> &'a ExactCrateSpec {
        self.spec
    }

    pub fn base_checksum(&self) -> &'a Sha256Digest {
        self.base_checksum
    }

    pub fn current_checksum(&self) -> &'a Sha256Digest {
        self.current_checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PackageIdentity<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
}

impl LockedPackage {
    fn identity(&self) -> PackageIdentity<'_> {
        PackageIdentity {
            name: &self.name,
            version: &self.version,
            source: self.source.as_deref(),
        }
    }
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
    fn checksum_only_differences_do_not_mark_packages_as_added() {
        let base = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("base lockfile should parse");

        let current = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
        )
        .expect("current lockfile should parse");

        let added = added_crates_io_specs(&current, &base).expect("selection should succeed");

        assert!(added.is_empty());
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
