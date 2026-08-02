use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;
use thiserror::Error;

use crate::{ExactCrateSpec, ExactCrateSpecError, Sha256Digest};

pub const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const GIT_SOURCE_PREFIX: &str = "git+";
const SOURCE_PRECISE_SEPARATOR: char = '#';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    packages: Vec<LockedPackage>,
}

impl Lockfile {
    pub fn packages(&self) -> &[LockedPackage] {
        &self.packages
    }

    pub(crate) fn package_index(&self) -> LockedPackageIndex<'_> {
        LockedPackageIndex {
            packages: self
                .packages
                .iter()
                .fold(BTreeMap::new(), |mut by_identity, package| {
                    by_identity
                        .entry(package.identity())
                        .or_default()
                        .push(package);
                    by_identity
                }),
        }
    }
}

pub(crate) struct LockedPackageIndex<'a> {
    packages: BTreeMap<PackageIdentity<'a>, Vec<&'a LockedPackage>>,
}

impl LockedPackageIndex<'_> {
    pub(crate) fn find(
        &self,
        name: &str,
        version: &str,
        source: Option<&str>,
    ) -> LockedPackageLookup<'_> {
        let identity = PackageIdentity::new(name, version, source);
        match self.packages.get(&identity).map(Vec::as_slice) {
            None => LockedPackageLookup::NotFound,
            Some([package]) => LockedPackageLookup::Found(package),
            Some(_) => LockedPackageLookup::Ambiguous,
        }
    }
}

pub(crate) enum LockedPackageLookup<'a> {
    NotFound,
    Found(&'a LockedPackage),
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<Sha256Digest>,
    exact_spec: ExactCrateSpec,
    dependencies: Vec<LockedDependency>,
}

impl LockedPackage {
    pub fn is_crates_io(&self) -> bool {
        is_crates_io_source(self.source.as_deref())
    }

    pub fn exact_spec(&self) -> &ExactCrateSpec {
        &self.exact_spec
    }

    pub fn checksum(&self) -> Option<&Sha256Digest> {
        self.checksum.as_ref()
    }

    pub fn dependencies(&self) -> &[LockedDependency] {
        &self.dependencies
    }

    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockedDependency {
    spec: ExactCrateSpec,
    source: Option<String>,
}

impl LockedDependency {
    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn is_crates_io(&self) -> bool {
        is_crates_io_source(self.source())
    }
}

fn is_crates_io_source(source: Option<&str>) -> bool {
    source == Some(CRATES_IO_SOURCE)
}

pub(crate) fn resolved_sources_match(expected: &str, actual: &str) -> bool {
    expected == actual
        || (expected.starts_with(GIT_SOURCE_PREFIX)
            && actual.starts_with(GIT_SOURCE_PREFIX)
            && expected.split(SOURCE_PRECISE_SEPARATOR).next()
                == actual.split(SOURCE_PRECISE_SEPARATOR).next())
}

pub fn parse_lockfile(text: &str) -> Result<Lockfile, LockfileError> {
    let raw: RawLockfile = toml::from_str(text).map_err(LockfileError::Parse)?;
    if raw.root.is_some() || raw.metadata.keys().any(|key| key.starts_with("checksum ")) {
        return Err(LockfileError::UnsupportedLegacyFormat);
    }
    if raw.version.is_some_and(|version| !matches!(version, 3 | 4)) {
        return Err(LockfileError::UnsupportedVersion {
            version: raw.version.expect("checked as some"),
        });
    }
    let mut packages = Vec::with_capacity(raw.package.len());
    let mut dependency_references = Vec::with_capacity(raw.package.len());

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

        dependency_references.push(package.dependencies);
        packages.push(LockedPackage {
            name: package.name,
            version: package.version,
            source: package.source,
            checksum,
            exact_spec,
            dependencies: Vec::new(),
        });
    }

    let packages_by_name =
        packages
            .iter()
            .fold(BTreeMap::<&str, Vec<_>>::new(), |mut by_name, package| {
                by_name
                    .entry(package.name.as_str())
                    .or_default()
                    .push(package);
                by_name
            });
    let resolved_dependencies = dependency_references
        .into_iter()
        .enumerate()
        .map(|(parent_index, references)| {
            references
                .into_iter()
                .map(|reference| {
                    resolve_locked_dependency(
                        &packages_by_name,
                        &packages[parent_index],
                        &reference,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (package, dependencies) in packages.iter_mut().zip(resolved_dependencies) {
        package.dependencies = dependencies;
    }

    Ok(Lockfile { packages })
}

fn resolve_locked_dependency(
    packages_by_name: &BTreeMap<&str, Vec<&LockedPackage>>,
    parent: &LockedPackage,
    reference: &str,
) -> Result<LockedDependency, LockfileError> {
    let selector = LockedDependencySelector::parse(reference).ok_or_else(|| {
        LockfileError::InvalidDependencyReference {
            parent: parent.exact_spec().clone(),
            reference: reference.to_owned(),
        }
    })?;
    let matches = packages_by_name
        .get(selector.name)
        .into_iter()
        .flatten()
        .filter(|package| selector.matches(package))
        .collect::<Vec<_>>();
    let package = match matches.as_slice() {
        [package] => *package,
        [] => {
            return Err(LockfileError::UnknownDependencyReference {
                parent: parent.exact_spec().clone(),
                reference: reference.to_owned(),
            });
        }
        _ => {
            return Err(LockfileError::AmbiguousDependencyReference {
                parent: parent.exact_spec().clone(),
                reference: reference.to_owned(),
            });
        }
    };

    Ok(LockedDependency {
        spec: package.exact_spec().clone(),
        source: package.source.clone(),
    })
}

#[derive(Debug, Clone, Copy)]
struct LockedDependencySelector<'a> {
    name: &'a str,
    version: Option<&'a str>,
    source: Option<&'a str>,
}

impl<'a> LockedDependencySelector<'a> {
    fn parse(reference: &'a str) -> Option<Self> {
        let (identity, source) = match reference.strip_suffix(')') {
            Some(without_suffix) => {
                let (identity, source) = without_suffix.rsplit_once(" (")?;
                if source.is_empty() {
                    return None;
                }
                (identity, Some(source))
            }
            None if reference.contains('(') || reference.contains(')') => return None,
            None => (reference, None),
        };
        let mut parts = identity.split(' ');
        let name = parts.next()?;
        let version = parts.next();
        if name.is_empty()
            || version.is_some_and(str::is_empty)
            || parts.next().is_some()
            || (source.is_some() && version.is_none())
        {
            return None;
        }

        Some(Self {
            name,
            version,
            source,
        })
    }

    fn matches(self, package: &LockedPackage) -> bool {
        package.name == self.name
            && self
                .version
                .is_none_or(|version| package.version == version)
            && self.source.is_none_or(|source| {
                package
                    .source
                    .as_deref()
                    .is_some_and(|package_source| resolved_sources_match(source, package_source))
            })
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PackageIdentity<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
}

impl<'a> PackageIdentity<'a> {
    fn new(name: &'a str, version: &'a str, source: Option<&'a str>) -> Self {
        Self {
            name,
            version,
            source,
        }
    }
}

impl LockedPackage {
    fn identity(&self) -> PackageIdentity<'_> {
        PackageIdentity::new(&self.name, &self.version, self.source.as_deref())
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
    #[error("invalid dependency reference {reference:?} in locked package {parent}")]
    InvalidDependencyReference {
        parent: ExactCrateSpec,
        reference: String,
    },
    #[error("dependency reference {reference:?} in locked package {parent} matches no package")]
    UnknownDependencyReference {
        parent: ExactCrateSpec,
        reference: String,
    },
    #[error("dependency reference {reference:?} in locked package {parent} is ambiguous")]
    AmbiguousDependencyReference {
        parent: ExactCrateSpec,
        reference: String,
    },
    #[error("Cargo.lock version {version} is unsupported")]
    UnsupportedVersion { version: u64 },
    #[error("legacy Cargo.lock V1 format is unsupported")]
    UnsupportedLegacyFormat,
}

#[derive(Debug, Deserialize)]
struct RawLockfile {
    version: Option<u64>,
    root: Option<toml::Value>,
    #[serde(default)]
    metadata: BTreeMap<String, toml::Value>,
    #[serde(default)]
    package: Vec<RawLockedPackage>,
}

#[derive(Debug, Deserialize)]
struct RawLockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
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
    fn resolves_lockfile_dependency_references_to_exact_identities() {
        let lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
    "bare",
    "multi 2.0.0",
    "sourced 3.0.0 (registry+https://example.invalid/index)",
]

[[package]]
name = "bare"
version = "1.0.0"

[[package]]
name = "multi"
version = "1.0.0"

[[package]]
name = "multi"
version = "2.0.0"

[[package]]
name = "sourced"
version = "3.0.0"
source = "registry+https://example.invalid/index"
"#,
        )
        .expect("dependency references should resolve");

        let dependencies = lockfile.packages()[0].dependencies();
        assert_eq!(dependencies[0].spec().to_string(), "bare@1.0.0");
        assert_eq!(dependencies[1].spec().to_string(), "multi@2.0.0");
        assert_eq!(dependencies[2].spec().to_string(), "sourced@3.0.0");
        assert_eq!(
            dependencies[2].source(),
            Some("registry+https://example.invalid/index")
        );
    }

    #[test]
    fn resolves_cargo_git_references_without_precise_fragments() {
        let lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
    "foo 1.0.0 (git+file:///tmp/gita)",
    "foo 1.0.0 (git+file:///tmp/gitb)",
]

[[package]]
name = "foo"
version = "1.0.0"
source = "git+file:///tmp/gita#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "foo"
version = "1.0.0"
source = "git+file:///tmp/gitb#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#,
        )
        .expect("Cargo's fragment-less git dependency references should resolve");

        let dependencies = lockfile.packages()[0].dependencies();
        assert_eq!(dependencies.len(), 2);
        assert_eq!(
            dependencies[0].source(),
            Some("git+file:///tmp/gita#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            dependencies[1].source(),
            Some("git+file:///tmp/gitb#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn rejects_invalid_unknown_and_ambiguous_dependency_references() {
        let cases = [
            (
                "foo 1.0.0 unexpected",
                false,
                "invalid dependency reference",
            ),
            (
                "foo (registry+https://example.invalid/index)",
                false,
                "invalid dependency reference",
            ),
            ("foo  1.0.0", false, "invalid dependency reference"),
            ("absent", false, "matches no package"),
            ("foo", true, "is ambiguous"),
        ];

        for (reference, include_second_foo, expected) in cases {
            let second_foo = if include_second_foo {
                "\n[[package]]\nname = \"foo\"\nversion = \"2.0.0\"\n"
            } else {
                ""
            };
            let text = format!(
                "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"{reference}\"]\n\n[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\n{second_foo}"
            );

            let error = parse_lockfile(&text).expect_err("dependency reference should fail");
            assert!(error.to_string().contains(expected), "{error}");
        }

        let error = parse_lockfile(
            r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["foo 1.0.0"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://example.invalid/one"

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://example.invalid/two"
"#,
        )
        .expect_err("version-only reference with multiple sources should fail");
        assert!(error.to_string().contains("is ambiguous"), "{error}");
    }

    #[test]
    fn rejects_unsupported_lockfile_formats() {
        let error = parse_lockfile("version = 5\n").expect_err("version 5 should fail");
        assert!(matches!(
            error,
            crate::LockfileError::UnsupportedVersion { version: 5 }
        ));

        let error = parse_lockfile(
            r#"
[root]
name = "app"
version = "0.1.0"
"#,
        )
        .expect_err("legacy root table should fail");
        assert!(matches!(
            error,
            crate::LockfileError::UnsupportedLegacyFormat
        ));

        let error = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)" = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
        )
        .expect_err("rootless Cargo.lock V1 metadata checksums should fail closed");
        assert!(matches!(
            error,
            crate::LockfileError::UnsupportedLegacyFormat
        ));
    }

    #[test]
    fn accepts_v2_lockfile_without_a_version_field() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[metadata]
custom-key = "preserved by Cargo V2"
"#,
        )
        .expect("Cargo.lock V2 should parse");

        assert_eq!(lockfile.packages().len(), 2);
        assert_eq!(lockfile.packages()[0].dependencies().len(), 1);
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
