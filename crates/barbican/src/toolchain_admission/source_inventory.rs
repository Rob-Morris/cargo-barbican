//! Package facts from a supplier source lock. This deliberately does not resolve
//! dependency edges or assert that represented packages occur in shipped binaries.
use super::{AdmissionError, Result, require};
use crate::{ExactCrateSpec, Sha256Digest};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<Sha256Digest>,
    #[serde(default)]
    dependencies: Vec<String>,
}
impl SourcePackage {
    pub fn is_crates_io(&self) -> bool {
        self.source.as_deref() == Some(crate::CRATES_IO_SOURCE)
    }
}

/// Parse bounded, strict v3/v4 package identities without interpreting graph edges.
/// Ambiguous dependency shorthand remains source evidence, never a resolved edge.
pub fn parse_source_package_inventory(text: &str) -> Result<Vec<SourcePackage>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SourceLock {
        version: u32,
        package: Vec<SourcePackage>,
    }
    require(
        text.len() <= super::MAX_RECORD_BYTES,
        "source lock exceeds byte limit",
    )?;
    let raw: SourceLock = toml::from_str(text).map_err(|_| {
        AdmissionError("invalid source package inventory syntax or schema (source omitted)".into())
    })?;
    require(
        matches!(raw.version, 3 | 4),
        "unsupported source lock version",
    )?;
    require(
        !raw.package.is_empty() && raw.package.len() <= 20_000,
        "source package count limit",
    )?;
    let mut identities = BTreeSet::new();
    for package in &raw.package {
        ExactCrateSpec::from_parts(&package.name, &package.version)
            .map_err(|_| AdmissionError("invalid source package name or exact version".into()))?;
        require(
            identities.insert((&package.name, &package.version, &package.source)),
            "duplicate source package identity",
        )?;
        require(
            package.dependencies.len() <= 20_000
                && package
                    .dependencies
                    .iter()
                    .all(|d| !d.is_empty() && d.len() <= 4096 && !d.chars().any(char::is_control)),
            "invalid source dependency evidence",
        )?;
        match package.source.as_deref() {
            None => require(
                package.checksum.is_none(),
                "local source package has registry checksum",
            )?,
            Some(crate::CRATES_IO_SOURCE) => require(
                package.checksum.is_some(),
                "registry source package lacks checksum",
            )?,
            Some(source) => {
                let revision = source.rsplit_once('#').map(|(_, revision)| revision);
                require(
                    source.len() <= 4096
                        && source.starts_with("git+https://")
                        && !source.chars().any(char::is_whitespace)
                        && revision.is_some_and(|r| {
                            r.len() == 40
                                && r.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                        && package.checksum.is_none(),
                    "unsupported source package origin or revision",
                )?;
            }
        }
    }
    Ok(raw.package)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_source_edges_remain_inventory_without_weakening_consumer_graph_parser() {
        // Exact form observed in Rust's 1.99.1 source lock: clippy's shorthand
        // has both a workspace and registry rustc_tools_util@0.4.2 candidate.
        let source = format!(
            "version=4\n[[package]]\nname='clippy'\nversion='0.1.99'\ndependencies=['rustc_tools_util 0.4.2']\n[[package]]\nname='rustc_tools_util'\nversion='0.4.2'\n[[package]]\nname='rustc_tools_util'\nversion='0.4.2'\nsource='{}'\nchecksum='a3b75158011a63889ba12084cf1224baad7bcad50f6ee7c842f772b74aa148ed'\n",
            crate::CRATES_IO_SOURCE
        );
        assert!(crate::parse_lockfile(&source).is_err());
        let packages = parse_source_package_inventory(&source).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages.iter().filter(|p| p.is_crates_io()).count(), 1);
        assert!(
            parse_source_package_inventory(&source.replace("checksum=", "unrecognized=")).is_err()
        );
        assert!(
            parse_source_package_inventory(
                &source.replace("version='0.1.99'", "version='^0.1.99'")
            )
            .is_err()
        );
        assert!(
            parse_source_package_inventory(&format!(
                "{source}\n[[package]]\nname='clippy'\nversion='0.1.99'\n"
            ))
            .is_err()
        );
    }
}
