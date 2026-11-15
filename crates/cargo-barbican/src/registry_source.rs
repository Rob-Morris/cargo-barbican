use crate::controlled_process::{Budget, FILE_LIMIT, Result, err};
use crate::crates_io_http::UreqCratesIoClient;
use crate::intake_store::{Stores, package_source_observation_key};
use barbican::cargo_tool::{
    KnowledgeEntry, KnowledgeKey, PackageFamily, PackageIdentity, PackageSource, SecurityStatus,
    SourceFact, sha256,
};
use barbican::{CrateRelease, ExactCrateSpec, OffsetDateTime, Sha256Digest};
use std::path::PathBuf;

pub(crate) struct OriginalRegistrySource {
    pub package: PackageIdentity,
    pub release: CrateRelease,
    pub fact: SourceFact,
    pub archive: Vec<u8>,
    pub pending_key: String,
}

pub(crate) fn acquire(
    stores: &Stores,
    budget: &Budget,
    client: &UreqCratesIoClient,
    spec: &ExactCrateSpec,
    expected: Option<&Sha256Digest>,
    started_at: i64,
) -> Result<OriginalRegistrySource> {
    budget.check()?;
    let pending_key = package_source_observation_key(
        &PackageFamily::CratesIo {
            name: spec.crate_name().into(),
        },
        spec.version(),
    )?;
    stores.begin_source(&pending_key)?;
    let (release, version) = client
        .fetch_release_observed(spec, || budget.check())
        .map_err(err)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if now < started_at {
        return Err("clock moved backwards during registry source observation".into());
    }
    if version / 1_000_000_000 > now as u64 {
        return Err("registry mutation timestamp is in the future".into());
    }
    let package = PackageIdentity {
        name: spec.crate_name().into(),
        version: spec.version().into(),
        source: PackageSource::CratesIo {
            archive_sha256: release.checksum_sha256_hex.clone(),
        },
    };
    let fact=SourceFact{key:KnowledgeKey::Package{package:package.clone()},facts_sha256:sha256(&serde_json::to_vec(&serde_json::json!({"checksum":release.checksum_sha256_hex,"published_at":release.published_at_raw,"yanked":release.yanked})).map_err(err)?),status:if release.yanked{SecurityStatus::Adverse}else{SecurityStatus::Clear},expires_at_utc:None};
    stores.remember(
        KnowledgeEntry {
            fact: fact.clone(),
            source_version: version,
            checked_at_utc: now,
        },
        now,
    )?;
    if expected.is_some_and(|checksum| checksum != &release.checksum_sha256_hex) {
        return Err("locked checksum differs from authenticated registry release".into());
    }
    let path = PathBuf::from(format!(
        "cargo-tools/v1/archives/{}.crate",
        release.checksum_sha256_hex
    ));
    let previous = stores.cache.read_optional(&path, FILE_LIMIT)?;
    let archive = match &previous {
        Some(captured) => captured.bytes().to_vec(),
        None => client
            .fetch_tarball_checked(spec, || budget.check())
            .map_err(err)?,
    };
    if barbican::ioc::digest_checked(&archive, &mut || budget.check())?
        != release.checksum_sha256_hex
    {
        return Err("original registry archive checksum mismatch".into());
    }
    if previous.is_none() {
        budget.materialise(archive.len() as u64)?;
        stores
            .cache
            .publish_checked(&path, &archive, || budget.check())?;
    }
    Ok(OriginalRegistrySource {
        package,
        release,
        fact,
        archive,
        pending_key,
    })
}
