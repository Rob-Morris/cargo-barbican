use crate::controlled_process::Result;
use barbican::{Sha256Digest, ioc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapturedLock {
    pub path: String,
    pub sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum RequestedSource {
    CratesIo {
        name: String,
        version: String,
        checksum: Option<Sha256Digest>,
    },
    Git {
        url: String,
        rev: String,
        package: String,
        version: Option<String>,
    },
    Unsupported {
        name: String,
        version: String,
        source_sha256: Sha256Digest,
    },
}
impl RequestedSource {
    fn validate(&self) -> Result<()> {
        match self {
            Self::CratesIo { name, version, .. } | Self::Unsupported { name, version, .. } => {
                barbican::ExactCrateSpec::from_parts(name, version).map_err(|e| e.to_string())?;
            }
            Self::Git {
                url,
                rev,
                package,
                version,
            } => {
                barbican::GitSourceIdentity::new(url, rev).map_err(|e| e.to_string())?;
                barbican::ExactCrateSpec::from_parts(
                    package,
                    version.as_deref().unwrap_or("0.0.0"),
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
    pub fn matches(&self, source: &ioc::Source) -> bool {
        match (self, &source.origin) {
            (
                Self::CratesIo {
                    name,
                    version,
                    checksum,
                },
                ioc::Origin::CratesIo { archive_sha256 },
            ) => {
                name == &source.name
                    && version == &source.version
                    && checksum
                        .as_ref()
                        .is_none_or(|expected| expected == archive_sha256)
            }
            (
                Self::Git {
                    url,
                    rev,
                    package,
                    version,
                },
                ioc::Origin::Git {
                    url: actual_url,
                    rev: actual_rev,
                    ..
                },
            ) => {
                url == actual_url
                    && rev == actual_rev
                    && package == &source.name
                    && version
                        .as_ref()
                        .is_none_or(|expected| expected == &source.version)
            }
            _ => false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum RequestedCoverage {
    Uninspected,
    Unavailable { reason: String },
    Inspected { source_id: Sha256Digest },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestedInspection {
    pub source: RequestedSource,
    pub coverage: RequestedCoverage,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapturedInputs {
    pub lockfile: Option<CapturedLock>,
    pub requested_source_count: usize,
    pub source_set_sha256: Sha256Digest,
    pub requested_sources: Vec<RequestedInspection>,
}
impl CapturedInputs {
    pub fn new(
        lockfile: Option<CapturedLock>,
        sources: impl IntoIterator<Item = RequestedSource>,
    ) -> Result<Self> {
        let sources = sources
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if sources.len() > 100_000 {
            return Err("requested source count exceeds bound".into());
        }
        for source in &sources {
            source.validate()?;
        }
        Ok(Self {
            lockfile,
            requested_source_count: sources.len(),
            source_set_sha256: ioc::canonical_digest(&sources)?,
            requested_sources: sources
                .into_iter()
                .map(|source| RequestedInspection {
                    source,
                    coverage: RequestedCoverage::Uninspected,
                })
                .collect(),
        })
    }
    pub fn record(
        &mut self,
        requested: &RequestedSource,
        result: &Result<ioc::Inspection>,
    ) -> Result<()> {
        let index = self
            .requested_sources
            .binary_search_by(|row| row.source.cmp(requested))
            .map_err(|_| "source is outside captured request set")?;
        let row = &mut self.requested_sources[index];
        row.coverage = match result {
            Ok(inspection) => RequestedCoverage::Inspected {
                source_id: inspection.source.id()?,
            },
            Err(error) => RequestedCoverage::Unavailable {
                reason: error.chars().take(4096).collect(),
            },
        };
        Ok(())
    }
    pub fn validate(&self, report: &ioc::Report) -> Result<()> {
        match (report.scope.as_str(), &self.lockfile) {
            ("locked-external-source-set", Some(_)) | ("explicit-exact-source-set", None) => {}
            _ => return Err("IOC scope and captured lock identity differ".into()),
        }
        if self.requested_source_count != self.requested_sources.len()
            || self.requested_sources.len() > 100_000
        {
            return Err("requested source count mismatch".into());
        }
        if let Some(lock) = &self.lockfile
            && (lock.path.is_empty()
                || lock.path.len() > 4096
                || lock.path.chars().any(char::is_control))
        {
            return Err("invalid captured lock path".into());
        }
        let sources = self
            .requested_sources
            .iter()
            .map(|row| &row.source)
            .collect::<Vec<_>>();
        if !sources.windows(2).all(|pair| pair[0] < pair[1])
            || ioc::canonical_digest(&sources)? != self.source_set_sha256
        {
            return Err("requested source-set identity mismatch".into());
        }
        let evidence = report
            .sources
            .iter()
            .map(|inspection| Ok((inspection.source.id()?, inspection)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        let mut inspected = BTreeSet::new();
        for row in &self.requested_sources {
            row.source.validate()?;
            match &row.coverage {
                RequestedCoverage::Inspected { source_id } => {
                    let source = evidence
                        .get(source_id)
                        .ok_or("captured request refers to absent source evidence")?;
                    if !row.source.matches(&source.source) || !inspected.insert(source_id.clone()) {
                        return Err("requested source and inspection binding differ".into());
                    }
                }
                RequestedCoverage::Unavailable { reason } => {
                    if reason.trim().is_empty() || reason.len() > 16_384 || report.errors.is_empty()
                    {
                        return Err("unavailable requested source lacks failure evidence".into());
                    }
                }
                RequestedCoverage::Uninspected => {
                    if report.errors.is_empty() {
                        return Err(
                            "uninspected source cannot appear in complete collection".into()
                        );
                    }
                }
            }
        }
        if inspected.len() != report.sources.len() {
            return Err("source evidence is outside captured request set".into());
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn fixture(report: &ioc::Report) -> Self {
        let sources = report
            .sources
            .iter()
            .map(|inspection| match &inspection.source.origin {
                ioc::Origin::CratesIo { archive_sha256 } => RequestedSource::CratesIo {
                    name: inspection.source.name.clone(),
                    version: inspection.source.version.clone(),
                    checksum: Some(archive_sha256.clone()),
                },
                ioc::Origin::Git { url, rev, .. } => RequestedSource::Git {
                    url: url.clone(),
                    rev: rev.clone(),
                    package: inspection.source.name.clone(),
                    version: Some(inspection.source.version.clone()),
                },
            })
            .collect::<Vec<_>>();
        let mut result = Self::new(None, sources.clone()).unwrap();
        for (requested, inspection) in sources.into_iter().zip(&report.sources) {
            result.record(&requested, &Ok(inspection.clone())).unwrap();
        }
        result
    }
}

#[derive(Debug)]
pub(crate) struct CollectedReport {
    pub report: ioc::Report,
    pub input: CapturedInputs,
}
