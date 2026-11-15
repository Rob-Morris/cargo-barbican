use std::fmt;
use std::io::{Cursor, Read};
use std::path::Path;

use miniz_oxide::inflate::decompress_to_vec_with_limit;
use serde::Deserialize;
#[cfg(test)]
use sha2::{Digest, Sha256};
use tar::Archive;
use time::OffsetDateTime;

use crate::assessment::RustAssessmentClassification;
use crate::{
    CrateRelease, ExactCrateSpec, ReleaseAgeReport, ReviewedReleaseAgeException,
    evaluate_release_age, is_native_sys_execution_surface,
};

const GZIP_HEADER_LEN: usize = 10;
const GZIP_FOOTER_LEN: usize = 8;
const GZIP_FLAG_FEXTRA: u8 = 0b0000_0100;
const GZIP_FLAG_FNAME: u8 = 0b0000_1000;
const GZIP_FLAG_FCOMMENT: u8 = 0b0001_0000;
const GZIP_FLAG_FHCRC: u8 = 0b0000_0010;
const GZIP_FLAG_RESERVED: u8 = 0b1110_0000;
const MAX_DECOMPRESSED_CRATE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustInspectReport {
    spec: ExactCrateSpec,
    release_age: ReleaseAgeReport,
    local_checksum_sha256_hex: String,
    published_checksum_sha256_hex: String,
    checksum_matches: bool,
    vcs_info: Option<CrateVcsInfo>,
    build_script_paths: Vec<String>,
    proc_macro: bool,
    package_links: Option<String>,
    native_sys_crate: bool,
    native_source_paths: Vec<String>,
    ioc_hits: Vec<IocHit>,
    ioc_inspection: Option<crate::ioc::Inspection>,
    inspection_failures: Vec<String>,
}

impl RustInspectReport {
    pub fn classification(&self) -> RustAssessmentClassification {
        if !self.release_age.is_success()
            || !self.checksum_matches
            || !self.ioc_hits.is_empty()
            || !self.inspection_failures.is_empty()
        {
            RustAssessmentClassification::PolicyViolating
        } else if self.has_execution_surface() {
            RustAssessmentClassification::ElevatedRisk
        } else {
            RustAssessmentClassification::RoutineSafe
        }
    }

    pub fn classification_with_ioc_allowances(
        &self,
        allowances: &[crate::ioc::Allowance],
        now: i64,
    ) -> Result<RustAssessmentClassification, String> {
        let ioc_success = match &self.ioc_inspection {
            Some(inspection) => crate::ioc::adjudicate(inspection, allowances, now)?.is_success(),
            None => false,
        };
        Ok(
            if !self.release_age.is_success()
                || !self.checksum_matches
                || !self.inspection_failures.is_empty()
                || !ioc_success
            {
                RustAssessmentClassification::PolicyViolating
            } else if self.has_execution_surface() {
                RustAssessmentClassification::ElevatedRisk
            } else {
                RustAssessmentClassification::RoutineSafe
            },
        )
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn release_age(&self) -> &ReleaseAgeReport {
        &self.release_age
    }

    pub fn local_checksum_sha256_hex(&self) -> &str {
        &self.local_checksum_sha256_hex
    }

    pub fn published_checksum_sha256_hex(&self) -> &str {
        &self.published_checksum_sha256_hex
    }

    pub fn checksum_matches(&self) -> bool {
        self.checksum_matches
    }

    pub fn vcs_info(&self) -> Option<&CrateVcsInfo> {
        self.vcs_info.as_ref()
    }

    pub fn build_script_paths(&self) -> &[String] {
        &self.build_script_paths
    }

    pub fn proc_macro(&self) -> bool {
        self.proc_macro
    }

    pub fn package_links(&self) -> Option<&str> {
        self.package_links.as_deref()
    }

    pub fn native_sys_crate(&self) -> bool {
        self.native_sys_crate
    }

    pub fn native_source_paths(&self) -> &[String] {
        &self.native_source_paths
    }

    pub fn ioc_inspection(&self) -> Option<&crate::ioc::Inspection> {
        self.ioc_inspection.as_ref()
    }

    pub fn ioc_hits(&self) -> &[IocHit] {
        &self.ioc_hits
    }

    pub fn inspection_failures(&self) -> &[String] {
        &self.inspection_failures
    }

    fn has_execution_surface(&self) -> bool {
        has_execution_surface(
            !self.build_script_paths.is_empty(),
            self.proc_macro,
            self.native_sys_crate,
            self.package_links.is_some(),
            !self.native_source_paths.is_empty(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateVcsInfo {
    git_sha1: String,
    path_in_vcs: Option<String>,
}

impl CrateVcsInfo {
    pub fn git_sha1(&self) -> &str {
        &self.git_sha1
    }

    pub fn path_in_vcs(&self) -> Option<&str> {
        self.path_in_vcs.as_deref()
    }
}

impl fmt::Display for CrateVcsInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.path_in_vcs() {
            Some(path_in_vcs) => write!(formatter, "git {} ({path_in_vcs})", self.git_sha1),
            None => write!(formatter, "git {}", self.git_sha1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IocHit {
    path: String,
    category: String,
    pattern: String,
}

impl IocHit {
    fn new(path: String, category: String, pattern: String) -> Self {
        Self {
            path,
            category,
            pattern,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn indicator(&self) -> String {
        format!("{}: {}", self.category, self.pattern)
    }
}

impl fmt::Display for IocHit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The matched pattern is backtick-quoted because several patterns end
        // in `(` (e.g. `Command::new(`); without a distinct delimiter the
        // trailing paren collides with the surrounding `(...)` and the hit
        // reads ambiguously.
        write!(
            formatter,
            "{} ({}: `{}`)",
            self.path, self.category, self.pattern
        )
    }
}

pub fn inspect_published_crate_at(
    spec: ExactCrateSpec,
    release: CrateRelease,
    tarball_bytes: &[u8],
    now: OffsetDateTime,
    minimum_days: u64,
    exception: Option<&ReviewedReleaseAgeException>,
) -> RustInspectReport {
    inspect_published_crate_at_with_ioc_budget(
        spec,
        release,
        tarball_bytes,
        now,
        minimum_days,
        exception,
        crate::ioc::ScanControl {
            budget: &mut crate::ioc::ScanBudget::default(),
            check: &mut || Ok(()),
        },
    )
}

pub fn inspect_published_crate_at_with_ioc_budget(
    spec: ExactCrateSpec,
    release: CrateRelease,
    tarball_bytes: &[u8],
    now: OffsetDateTime,
    minimum_days: u64,
    exception: Option<&ReviewedReleaseAgeException>,
    ioc_control: crate::ioc::ScanControl<'_>,
) -> RustInspectReport {
    let published_checksum_sha256_hex = release.checksum_sha256_hex.to_string();
    let release_age = evaluate_release_age(spec.clone(), release, now, minimum_days, exception);
    let checksum = if tarball_bytes.len() > MAX_DECOMPRESSED_CRATE_BYTES {
        Err("crate archive compressed size exceeded".into())
    } else {
        crate::ioc::digest_checked(tarball_bytes, ioc_control.check)
    };
    let local_checksum_sha256_hex = checksum
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let checksum_matches = local_checksum_sha256_hex == published_checksum_sha256_hex;

    if !checksum_matches {
        return RustInspectReport {
            spec,
            release_age,
            local_checksum_sha256_hex,
            published_checksum_sha256_hex,
            checksum_matches,
            vcs_info: None,
            build_script_paths: Vec::new(),
            proc_macro: false,
            package_links: None,
            native_sys_crate: false,
            native_source_paths: Vec::new(),
            ioc_hits: Vec::new(),
            ioc_inspection: None,
            inspection_failures: checksum.err().into_iter().collect(),
        };
    }

    let verified_checksum = checksum.expect("matching checksum was verified");
    let tarball_inspection =
        inspect_verified_tarball(&spec, tarball_bytes, verified_checksum, ioc_control);

    RustInspectReport {
        spec,
        release_age,
        local_checksum_sha256_hex,
        published_checksum_sha256_hex,
        checksum_matches,
        vcs_info: tarball_inspection.vcs_info,
        build_script_paths: tarball_inspection.build_script_paths,
        proc_macro: tarball_inspection.proc_macro,
        package_links: tarball_inspection.package_links,
        native_sys_crate: tarball_inspection.native_sys_crate,
        native_source_paths: tarball_inspection.native_source_paths,
        ioc_hits: tarball_inspection.ioc_hits,
        ioc_inspection: tarball_inspection.ioc_inspection,
        inspection_failures: tarball_inspection.inspection_failures,
    }
}

#[derive(Default)]
struct TarballInspection {
    vcs_info: Option<CrateVcsInfo>,
    build_script_paths: Vec<String>,
    proc_macro: bool,
    package_links: Option<String>,
    native_sys_crate: bool,
    native_source_paths: Vec<String>,
    ioc_hits: Vec<IocHit>,
    ioc_inspection: Option<crate::ioc::Inspection>,
    inspection_failures: Vec<String>,
}

/// Inspect exact original archive bytes without inventing mutable release/API facts.
pub fn inspect_crate_archive_ioc(
    spec: &ExactCrateSpec,
    tarball_bytes: &[u8],
    expected_checksum: &crate::Sha256Digest,
    control: crate::ioc::ScanControl<'_>,
) -> Result<crate::ioc::Inspection, String> {
    let inspection =
        inspect_verified_tarball(spec, tarball_bytes, expected_checksum.clone(), control);
    let mut ioc = inspection.ioc_inspection.ok_or_else(|| {
        if inspection.inspection_failures.is_empty() {
            "registry IOC original-source evidence unavailable".into()
        } else {
            inspection.inspection_failures.join("; ")
        }
    })?;
    if !inspection.inspection_failures.is_empty() {
        ioc.coverage = crate::ioc::Coverage::Incomplete {
            reason: inspection.inspection_failures.join("; "),
        };
    }
    Ok(ioc)
}

fn has_execution_surface(
    has_build_script: bool,
    proc_macro: bool,
    native_sys_crate: bool,
    has_package_links: bool,
    has_native_source: bool,
) -> bool {
    has_build_script
        || proc_macro
        || is_native_sys_execution_surface(native_sys_crate, has_package_links)
        || has_native_source
}

fn inspect_verified_tarball(
    spec: &ExactCrateSpec,
    tarball_bytes: &[u8],
    checksum: crate::Sha256Digest,
    control: crate::ioc::ScanControl<'_>,
) -> TarballInspection {
    let mut inspection = TarballInspection {
        native_sys_crate: spec.is_native_sys(),
        ..TarballInspection::default()
    };

    let mut files = Vec::new();
    if let Err(error) = visit_verified_crate_archive_checked(
        spec,
        tarball_bytes,
        &checksum,
        control.check,
        |path, _, contents| {
            if let Some(contents) = contents {
                files.push(ArchiveFile {
                    path: path.into(),
                    contents: contents.to_vec(),
                });
            }
            Ok(())
        },
    ) {
        inspection.inspection_failures.push(
            if error.starts_with("unable to decode crate tarball: ") {
                error
            } else {
                format!("unable to inspect crate archive: {error}")
            },
        );
        return inspection;
    }

    let cargo_toml = match files.iter().find(|file| file.path == "Cargo.toml") {
        Some(file) => match std::str::from_utf8(&file.contents) {
            Ok(text) => text,
            Err(_) => {
                inspection
                    .inspection_failures
                    .push("published Cargo.toml is invalid: non-UTF8 manifest".into());
                return inspection;
            }
        },
        None => {
            inspection
                .inspection_failures
                .push("published crate is missing Cargo.toml".into());
            return inspection;
        }
    };

    let manifest = match parse_published_manifest(cargo_toml) {
        Ok(manifest) => manifest,
        Err(error) => {
            inspection
                .inspection_failures
                .push(format!("published Cargo.toml is invalid: {error}"));
            return inspection;
        }
    };

    if manifest.name.as_deref() != Some(spec.crate_name())
        || manifest.version.as_deref() != Some(spec.version())
    {
        inspection
            .inspection_failures
            .push("published manifest package identity differs from exact source".into());
        return inspection;
    }
    inspection.proc_macro = manifest.proc_macro;
    inspection.package_links = manifest.package_links;

    if let Some(file) = files
        .iter()
        .find(|file| file.path == ".cargo_vcs_info.json")
    {
        match std::str::from_utf8(&file.contents) {
            Ok(text) => match parse_cargo_vcs_info(text) {
                Ok(vcs_info) => inspection.vcs_info = Some(vcs_info),
                Err(error) => inspection
                    .inspection_failures
                    .push(format!("invalid .cargo_vcs_info.json: {error}")),
            },
            Err(_) => inspection
                .inspection_failures
                .push("invalid .cargo_vcs_info.json: non-UTF8 provenance file".into()),
        }
    }

    let file_paths: std::collections::BTreeSet<_> =
        files.iter().map(|file| file.path.as_str()).collect();
    let mut required_paths = std::collections::BTreeSet::new();
    let mut required_failure = None;
    let build_script = match &manifest.build_script {
        crate::ioc::BuildScriptRole::Auto => file_paths.contains("build.rs").then_some("build.rs"),
        crate::ioc::BuildScriptRole::Disabled => None,
        crate::ioc::BuildScriptRole::Path(path) => Some(path.as_str()),
    };
    for (role, path) in build_script.map(|p| ("build script", p)).into_iter().chain(
        manifest
            .proc_macro_path
            .as_deref()
            .map(|p| ("proc-macro library", p)),
    ) {
        let normalised = archive_required_path(path);
        if normalised
            .as_ref()
            .is_none_or(|path| !file_paths.contains(path.as_str()))
        {
            let error = format!(
                "required {role} path is missing or outside the captured archive: {path:?}"
            );
            inspection.inspection_failures.push(error.clone());
            required_failure = Some(error);
        } else if role == "build script" {
            inspection
                .build_script_paths
                .push(normalised.expect("qualified required path"));
        } else {
            required_paths.insert(normalised.expect("qualified required path"));
        }
    }

    inspection.native_source_paths = files
        .iter()
        .filter(|file| is_native_source_path(&file.path))
        .map(|file| file.path.clone())
        .collect();

    let scope = crate::ioc::Scope {
        package_prefix: String::new(),
        required_paths,
        explicit_paths: None,
        build_script_paths: inspection.build_script_paths.iter().cloned().collect(),
        proc_macro: inspection.proc_macro,
        native_sys: inspection.native_sys_crate,
        package_links: inspection.package_links.is_some(),
        native_source_paths: inspection.native_source_paths.iter().cloned().collect(),
    };
    let source = crate::ioc::Source {
        name: spec.crate_name().into(),
        version: spec.version().to_string(),
        origin: crate::ioc::Origin::CratesIo {
            archive_sha256: checksum,
        },
    };
    let mut scanner =
        crate::ioc::ScanAccumulator::new(source).expect("validated exact crate source");
    let mut failure = required_failure;
    for file in &files {
        if let Err(error) = scanner.scan_file_checked(
            &file.path,
            &file.contents,
            &scope,
            control.budget,
            control.check,
        ) {
            failure = Some(error);
            break;
        }
    }
    let report = scanner.finish(failure);
    if let crate::ioc::Coverage::Incomplete { reason } = &report.coverage {
        inspection.inspection_failures.push(reason.clone());
    }
    inspection.ioc_hits = report
        .findings
        .iter()
        .map(|finding| {
            let rule = crate::ioc::rule(&finding.rule).expect("scanner emits maintained rules");
            IocHit::new(
                finding.path.clone(),
                rule.category.into(),
                rule.pattern.into(),
            )
        })
        .collect();
    inspection.ioc_inspection = Some(report);
    inspection.build_script_paths.sort();
    inspection.native_source_paths.sort();
    inspection.ioc_hits.sort();
    inspection.inspection_failures.sort();

    inspection
}

fn is_native_source_path(path: &str) -> bool {
    crate::ioc::is_native_source_path(path)
}

fn archive_required_path(path: &str) -> Option<String> {
    if path.len() > 4096 || path.contains('\\') || path.chars().any(char::is_control) {
        return None;
    }
    let mut parts = Vec::new();
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_str()?),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                parts.pop()?;
            }
            _ => return None,
        }
        if parts.len() > 128 {
            return None;
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn parse_published_manifest(text: &str) -> Result<PublishedManifestSignals, String> {
    let manifest = crate::tool_inputs::source_manifest(text)?;
    let roles = crate::ioc::manifest_roles(&manifest)?;
    Ok(PublishedManifestSignals {
        name: manifest
            .pointer("/package/name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        version: manifest
            .pointer("/package/version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        build_script: roles.build_script,
        package_links: roles.package_links,
        proc_macro: roles.proc_macro,
        proc_macro_path: roles.proc_macro_path,
    })
}

fn parse_cargo_vcs_info(text: &str) -> Result<CrateVcsInfo, serde_json::Error> {
    let parsed: CargoVcsInfoFile = serde_json::from_str(text)?;
    Ok(CrateVcsInfo {
        git_sha1: parsed.git.sha1,
        path_in_vcs: parsed.path_in_vcs,
    })
}

/// Enumerate every original archive entry after verifying its independent digest.
/// The visitor can enforce cumulative budgets and cancellation during extraction.
pub fn visit_verified_crate_archive(
    spec: &ExactCrateSpec,
    compressed: &[u8],
    expected: &crate::Sha256Digest,
    visit: impl FnMut(&str, u32, Option<&[u8]>) -> Result<(), String>,
) -> Result<(), String> {
    visit_verified_crate_archive_checked(spec, compressed, expected, &mut || Ok(()), visit)
}

pub fn visit_verified_crate_archive_checked(
    spec: &ExactCrateSpec,
    compressed: &[u8],
    expected: &crate::Sha256Digest,
    check: &mut dyn FnMut() -> Result<(), String>,
    mut visit: impl FnMut(&str, u32, Option<&[u8]>) -> Result<(), String>,
) -> Result<(), String> {
    use std::collections::BTreeMap;
    if compressed.len() > MAX_DECOMPRESSED_CRATE_BYTES {
        return Err("crate archive compressed size exceeded".into());
    }
    let observed = crate::ioc::digest_checked(compressed, check)?;
    if &observed != expected {
        return Err("crate archive checksum mismatch".into());
    }
    let bytes = decompress_crate_gzip(compressed)
        .map_err(|error| format!("unable to decode crate tarball: {error}"))?;
    check()?;
    let mut archive = Archive::new(Cursor::new(bytes));
    let prefix = format!("{}-{}", spec.crate_name(), spec.version());
    let mut paths = BTreeMap::new();
    for entry in archive.entries().map_err(|e| e.to_string())? {
        check()?;
        let mut entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err("crate archive contains a link or unsupported entry type".into());
        }
        let raw = entry.path().map_err(|e| e.to_string())?;
        let raw = raw
            .to_str()
            .ok_or("non-UTF8 archive path")?
            .trim_end_matches('/');
        if raw.len() > 4096
            || raw.contains('\\')
            || raw.chars().any(char::is_control)
            || raw.split('/').count() > 129
            || raw
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("unsafe or excessive crate archive path".into());
        }
        if raw == prefix && kind.is_dir() {
            continue;
        }
        let path = raw
            .strip_prefix(&format!("{prefix}/"))
            .ok_or("archive entry outside exact crate root")?
            .to_owned();
        if paths.insert(path.clone(), kind.is_dir()).is_some() || paths.len() > 100_000 {
            return Err("duplicate or excessive archive entries".into());
        }
        let mut ancestor = Path::new(&path).parent();
        while let Some(parent) = ancestor {
            if parent
                .to_str()
                .is_some_and(|p| paths.get(p) == Some(&false))
            {
                return Err("archive file/directory path collision".into());
            }
            ancestor = parent.parent();
        }
        let descendant = format!("{path}/");
        if !kind.is_dir()
            && paths
                .range(descendant.clone()..)
                .next()
                .is_some_and(|(key, _)| key.starts_with(&descendant))
        {
            return Err("archive file/directory path collision".into());
        }
        let mode = entry.header().mode().map_err(|e| e.to_string())?;
        let file_type = mode & 0o170000;
        let expected_type = if kind.is_dir() { 0o040000 } else { 0o100000 };
        if mode & !0o170777 != 0 || (file_type != 0 && file_type != expected_type) {
            return Err("unsupported archive permission bits".into());
        }
        let mode = mode & 0o777;
        if kind.is_dir() {
            visit(&path, mode, None)?;
            continue;
        }
        if entry.size() > MAX_DECOMPRESSED_CRATE_BYTES as u64 {
            return Err("archive file exceeds 128 MiB".into());
        }
        let mut contents = Vec::new();
        let mut chunk = [0; 64 * 1024];
        loop {
            check()?;
            let count = entry.read(&mut chunk).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            if contents.len() + count > MAX_DECOMPRESSED_CRATE_BYTES {
                return Err("archive file exceeds 128 MiB".into());
            }
            contents.extend_from_slice(&chunk[..count]);
        }
        visit(&path, mode, Some(&contents))?;
    }
    if !paths.contains_key("Cargo.toml") {
        return Err("crate archive has no Cargo.toml".into());
    }
    let cursor = archive.into_inner();
    let position =
        usize::try_from(cursor.position()).map_err(|_| "archive position exceeds platform size")?;
    let bytes = cursor.into_inner();
    if bytes.len() % 512 != 0
        || position > bytes.len()
        || bytes[position..].iter().any(|byte| *byte != 0)
    {
        return Err("unsupported trailing data after archive entries".into());
    }
    Ok(())
}

fn decompress_crate_gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < GZIP_HEADER_LEN + GZIP_FOOTER_LEN {
        return Err("truncated gzip stream".to_owned());
    }
    if bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err("unexpected gzip magic".to_owned());
    }
    if bytes[2] != 8 {
        return Err("unsupported gzip compression method".to_owned());
    }

    let flags = bytes[3];
    if flags & GZIP_FLAG_RESERVED != 0 {
        return Err("unsupported gzip flags".to_owned());
    }

    let mut offset = GZIP_HEADER_LEN;
    if flags & GZIP_FLAG_FEXTRA != 0 {
        let extra_len = read_le_u16(bytes, offset)? as usize;
        offset = offset
            .checked_add(2 + extra_len)
            .ok_or_else(|| "gzip extra field overflow".to_owned())?;
    }
    if flags & GZIP_FLAG_FNAME != 0 {
        offset = skip_nul_terminated(bytes, offset)?;
    }
    if flags & GZIP_FLAG_FCOMMENT != 0 {
        offset = skip_nul_terminated(bytes, offset)?;
    }
    if flags & GZIP_FLAG_FHCRC != 0 {
        offset = offset
            .checked_add(2)
            .ok_or_else(|| "gzip header checksum overflow".to_owned())?;
    }

    if offset >= bytes.len().saturating_sub(GZIP_FOOTER_LEN) {
        return Err("gzip stream is missing deflate data".to_owned());
    }

    let footer_offset = bytes.len() - GZIP_FOOTER_LEN;
    decompress_to_vec_with_limit(&bytes[offset..footer_offset], MAX_DECOMPRESSED_CRATE_BYTES)
        .map_err(|error| error.to_string())
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| "gzip header overflow".to_owned())?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| "truncated gzip header".to_owned())?;

    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn skip_nul_terminated(bytes: &[u8], offset: usize) -> Result<usize, String> {
    let remainder = bytes
        .get(offset..)
        .ok_or_else(|| "truncated gzip header".to_owned())?;
    let nul_index = remainder
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "unterminated gzip header string".to_owned())?;

    offset
        .checked_add(nul_index + 1)
        .ok_or_else(|| "gzip header overflow".to_owned())
}

#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);

    for byte in digest {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }

    output
}

struct ArchiveFile {
    path: String,
    contents: Vec<u8>,
}

struct PublishedManifestSignals {
    name: Option<String>,
    version: Option<String>,
    build_script: crate::ioc::BuildScriptRole,
    proc_macro_path: Option<String>,
    package_links: Option<String>,
    proc_macro: bool,
}

#[derive(Debug, Deserialize)]
struct CargoVcsInfoFile {
    git: CargoVcsInfoGit,
    path_in_vcs: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoVcsInfoGit {
    sha1: String,
}

#[cfg(test)]
mod tests {
    use tar::{Builder, Header};
    use time::format_description::well_known::Rfc3339;

    use super::{CrateVcsInfo, RustInspectReport, inspect_published_crate_at, sha256_hex};
    use crate::{
        CrateRelease, ExactCrateSpec, Sha256Digest, assessment::RustAssessmentClassification,
    };

    fn build_crate_tarball(files: &[(&str, &str)]) -> Vec<u8> {
        let package = files
            .iter()
            .find(|(path, _)| *path == "Cargo.toml")
            .and_then(|(_, text)| toml::from_str::<toml::Value>(text).ok())
            .and_then(|value| {
                value
                    .get("package")?
                    .get("name")?
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "sample".into());
        let prefixed = files
            .iter()
            .map(|(path, contents)| (format!("{package}-0.1.0/{path}"), *contents))
            .collect::<Vec<_>>();
        let entries = prefixed
            .iter()
            .map(|(path, contents)| (path.as_str(), contents.as_bytes()))
            .collect::<Vec<_>>();

        gzip_wrap(&build_tar(&entries))
    }

    /// Builds a tar archive from entries whose paths are used verbatim (no
    /// `sample-0.1.0/` prefix), via `append_data`. `append_data` validates
    /// paths (rejecting `..` and leading `/`) before writing, so this is
    /// only suitable for well-formed relative names; hostile paths need
    /// [`append_entry_with_raw_name`] instead.
    fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tarball = Vec::new();
        {
            let mut builder = Builder::new(&mut tarball);
            for (path, bytes) in entries {
                let mut header = Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, *path, *bytes)
                    .expect("fixture tar append should succeed");
            }
            builder.finish().expect("fixture tar should finish");
        }
        tarball
    }

    /// Writes a tar header whose name field is the raw bytes given, bypassing
    /// `tar`'s own `set_path` validation (which refuses `..` and absolute
    /// paths at write time). This is how a hostile archive is simulated: a
    /// real attacker's encoder is not bound by this crate's writer safety
    /// checks, only the parser's.
    fn append_entry_with_raw_name(builder: &mut Builder<&mut Vec<u8>>, name: &[u8], data: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_cksum();
        builder
            .append(&header, data)
            .expect("raw-named fixture entry should append");
    }

    /// Writes a tar header whose declared `size` does not match the number
    /// of content bytes actually written, simulating a header that lies
    /// about how much data follows it.
    fn append_entry_with_lying_size(
        builder: &mut Builder<&mut Vec<u8>>,
        name: &str,
        declared_size: u64,
        actual_data: &[u8],
    ) {
        let mut header = Header::new_gnu();
        header.set_size(declared_size);
        header.set_mode(0o644);
        header
            .set_path(name)
            .expect("fixture entry name should be a valid tar path");
        header.set_cksum();
        builder
            .append(&header, actual_data)
            .expect("lying-size fixture entry should append");
    }

    fn gzip_wrap(tar_bytes: &[u8]) -> Vec<u8> {
        let deflated = miniz_oxide::deflate::compress_to_vec(tar_bytes, 6);
        gzip_wrap_deflated(&deflated, tar_bytes.len())
    }

    fn gzip_wrap_deflated(deflated: &[u8], decompressed_len: usize) -> Vec<u8> {
        let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        gzip.extend_from_slice(deflated);
        gzip.extend([0, 0, 0, 0]);
        gzip.extend((decompressed_len as u32).to_le_bytes());
        gzip
    }

    fn release_for_tarball(tarball: &[u8]) -> CrateRelease {
        CrateRelease {
            checksum_sha256_hex: Sha256Digest::try_from(sha256_hex(tarball).as_str())
                .expect("fixture checksum should parse"),
            published_at_raw: "2026-05-01T00:00:00Z".to_owned(),
            published_at: time::OffsetDateTime::parse("2026-05-01T00:00:00Z", &Rfc3339)
                .expect("timestamp should parse"),
            yanked: false,
        }
    }

    fn spec(name: &str) -> ExactCrateSpec {
        format!("{name}@0.1.0")
            .parse::<ExactCrateSpec>()
            .expect("spec should parse")
    }

    fn inspect(spec: ExactCrateSpec, tarball: &[u8]) -> RustInspectReport {
        inspect_published_crate_at(
            spec,
            release_for_tarball(tarball),
            tarball,
            time::OffsetDateTime::parse("2026-05-26T00:00:00Z", &Rfc3339)
                .expect("timestamp should parse"),
            7,
            None,
        )
    }

    #[test]
    fn routine_crate_is_routine_safe() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
            ),
            ("src/lib.rs", "pub fn ok() {}\n"),
            (
                ".cargo_vcs_info.json",
                "{\n  \"git\": {\"sha1\": \"abc123\"},\n  \"path_in_vcs\": \"sample\"\n}\n",
            ),
        ]);

        let report = inspect(spec("sample"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::RoutineSafe
        );
        assert!(report.checksum_matches());
        assert_eq!(
            report.vcs_info(),
            Some(&CrateVcsInfo {
                git_sha1: "abc123".to_owned(),
                path_in_vcs: Some("sample".to_owned()),
            })
        );
        assert!(report.build_script_paths().is_empty());
        assert!(!report.proc_macro());
        assert!(!report.native_sys_crate());
        assert!(report.native_source_paths().is_empty());
        assert!(report.ioc_hits().is_empty());
        assert!(report.inspection_failures().is_empty());
    }

    #[test]
    fn build_script_proc_macro_and_native_surface_are_elevated() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"native-sys\"\nversion = \"0.1.0\"\nlinks = \"native\"\n[lib]\nproc-macro = true\n",
            ),
            (
                "build.rs",
                "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n",
            ),
            ("src/lib.rs", "pub fn macro_bits() {}\n"),
            ("vendor/native.c", "int native(void) { return 0; }\n"),
        ]);

        let report = inspect(spec("native-sys"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::ElevatedRisk
        );
        assert_eq!(report.build_script_paths(), ["build.rs"]);
        assert!(report.proc_macro());
        assert!(report.native_sys_crate());
        assert_eq!(report.package_links(), Some("native"));
        assert_eq!(report.native_source_paths(), ["vendor/native.c"]);
    }

    #[test]
    fn package_build_true_uses_default_build_script_path() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\nbuild = true\n",
            ),
            ("build.rs", "fn main() {}\n"),
        ]);

        let report = inspect(spec("sample"), &tarball);

        assert_eq!(report.build_script_paths(), ["build.rs"]);
        assert!(report.inspection_failures().is_empty());
    }

    #[test]
    fn checksum_mismatch_blocks_and_skips_deep_inspection() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
            ),
            ("build.rs", "fn main() {}\n"),
        ]);
        let mut release = release_for_tarball(&tarball);
        release.checksum_sha256_hex = Sha256Digest::try_from(
            "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        )
        .expect("fixture checksum should parse");

        let report = inspect_published_crate_at(
            spec("sample"),
            release,
            &tarball,
            time::OffsetDateTime::parse("2026-05-26T00:00:00Z", &Rfc3339)
                .expect("timestamp should parse"),
            7,
            None,
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert!(!report.checksum_matches());
        assert!(report.build_script_paths().is_empty());
        assert!(report.ioc_hits().is_empty());
        assert!(report.inspection_failures().is_empty());
    }

    #[test]
    fn ioc_hits_block_after_verified_checksum() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
            ),
            (
                "build.rs",
                "fn main() { std::process::Command::new(\"curl\").arg(\"https://example.com\"); }\n",
            ),
        ]);

        let report = inspect(spec("sample"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.build_script_paths(), ["build.rs"]);
        assert_eq!(report.ioc_hits().len(), 2);
        assert!(
            report
                .ioc_hits()
                .iter()
                .any(|hit| hit.indicator().contains("std::process::Command"))
        );
        assert!(
            report
                .ioc_hits()
                .iter()
                .any(|hit| hit.indicator().contains("Command::new("))
        );
        let command_new_hit = report
            .ioc_hits()
            .iter()
            .find(|hit| hit.pattern() == "Command::new(")
            .expect("Command::new( hit should be present");
        assert_eq!(command_new_hit.category(), "process execution");
        assert_eq!(
            command_new_hit.to_string(),
            "build.rs (process execution: `Command::new(`)"
        );
    }

    #[test]
    fn build_script_helper_modules_are_ioc_scanned() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
            ),
            ("build.rs", "mod evil;\nfn main() { evil::run(); }\n"),
            (
                "evil.rs",
                "pub fn run() { std::process::Command::new(\"curl\"); }\n",
            ),
        ]);

        let report = inspect(spec("sample"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.build_script_paths(), ["build.rs"]);
        assert!(report.ioc_hits().iter().any(|hit| {
            hit.path() == "evil.rs" && hit.indicator().contains("std::process::Command")
        }));
    }

    #[test]
    fn native_source_ioc_hits_block_after_verified_checksum() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"native-sys\"\nversion = \"0.1.0\"\nlinks = \"native\"\n",
            ),
            (
                "vendor/native.c",
                "void run(void) { system(\"curl https://example.com\"); }\n",
            ),
        ]);

        let report = inspect(spec("native-sys"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.native_source_paths(), ["vendor/native.c"]);
        assert!(
            report.ioc_hits().iter().any(|hit| {
                hit.path() == "vendor/native.c" && hit.indicator().contains("curl ")
            })
        );
    }

    #[test]
    fn attacker_named_native_directories_are_ioc_scanned() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"native-sys\"\nversion = \"0.1.0\"\nlinks = \"native\"\n",
            ),
            (
                "integration/evil.c",
                "void run(void) { system(\"curl https://example.com\"); }\n",
            ),
        ]);

        let report = inspect(spec("native-sys"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.native_source_paths(), ["integration/evil.c"]);
        assert!(report.ioc_hits().iter().any(|hit| {
            hit.path() == "integration/evil.c" && hit.indicator().contains("curl ")
        }));
    }

    #[test]
    fn proc_macro_src_tests_are_ioc_scanned() {
        let tarball = build_crate_tarball(&[
            (
                "Cargo.toml",
                "[package]\nname = \"sample-macro\"\nversion = \"0.1.0\"\n\n[lib]\nproc-macro = true\n",
            ),
            (
                "src/tests/payload.rs",
                "fn run() { std::process::Command::new(\"curl\"); }\n",
            ),
        ]);

        let report = inspect(spec("sample-macro"), &tarball);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert!(report.ioc_hits().iter().any(|hit| {
            hit.path() == "src/tests/payload.rs"
                && hit.indicator().contains("std::process::Command")
        }));
    }

    fn inspect_hostile(spec_name: &str, tarball_bytes: &[u8]) -> RustInspectReport {
        inspect(spec(spec_name), tarball_bytes)
    }

    #[test]
    fn truncated_gzip_header_fails_closed_without_panic() {
        // Shorter than the fixed 10-byte gzip header plus 8-byte footer:
        // `decompress_crate_gzip` must reject this before ever touching a
        // tar reader, not panic on an out-of-bounds slice.
        let tarball_bytes = vec![0x1f, 0x8b, 8, 0, 0];

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert!(
            report.inspection_failures()[0]
                .contains("unable to decode crate tarball: truncated gzip stream")
        );
    }

    #[test]
    fn corrupt_deflate_stream_fails_closed_without_panic() {
        // A structurally valid gzip envelope (correct magic, method, header
        // length, and footer size) wrapped around bytes that are not a
        // valid deflate stream.
        let mut tarball_bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        tarball_bytes.extend([0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00]);
        tarball_bytes.extend([0, 0, 0, 0]);
        tarball_bytes.extend(4u32.to_le_bytes());

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert!(report.inspection_failures()[0].starts_with("unable to decode crate tarball: "));
    }

    #[test]
    fn decompression_exceeding_max_size_fails_closed_without_panic() {
        // A highly compressible payload (all zero bytes) whose decompressed
        // size sits just past `MAX_DECOMPRESSED_CRATE_BYTES`, but whose
        // compressed form is tiny — the classic decompression-bomb shape.
        const MAX_DECOMPRESSED_CRATE_BYTES: usize = 128 * 1024 * 1024;
        let oversized = vec![0u8; MAX_DECOMPRESSED_CRATE_BYTES + 4096];
        let deflated = miniz_oxide::deflate::compress_to_vec(&oversized, 1);
        assert!(
            deflated.len() < oversized.len() / 100,
            "fixture should compress far smaller than its decompressed size"
        );
        let tarball_bytes = gzip_wrap_deflated(&deflated, oversized.len());

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert!(report.inspection_failures()[0].starts_with("unable to decode crate tarball: "));
    }

    #[test]
    fn tar_entries_with_traversal_and_absolute_paths_fail_closed_without_panic() {
        let mut tarball = Vec::new();
        {
            let mut builder = Builder::new(&mut tarball);
            append_entry_with_raw_name(
                &mut builder,
                b"../../etc/passwd\0",
                b"attacker-controlled\n",
            );
            builder.finish().expect("fixture tar should finish");
        }
        let tarball_bytes = gzip_wrap(&tarball);

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert!(report.inspection_failures()[0].starts_with("unable to inspect crate archive: "));
    }

    #[test]
    fn tar_entry_with_absolute_path_fails_closed_without_panic() {
        let mut tarball = Vec::new();
        {
            let mut builder = Builder::new(&mut tarball);
            append_entry_with_raw_name(&mut builder, b"/etc/passwd\0", b"attacker-controlled\n");
            builder.finish().expect("fixture tar should finish");
        }
        let tarball_bytes = gzip_wrap(&tarball);

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert!(report.inspection_failures()[0].starts_with("unable to inspect crate archive: "));
    }

    #[test]
    fn tar_header_size_lying_about_content_length_fails_closed_without_panic() {
        let mut tarball = Vec::new();
        {
            let mut builder = Builder::new(&mut tarball);
            // Header claims far more content follows than the handful of
            // bytes actually written; a reader that trusts the declared
            // size will run past the real data.
            append_entry_with_lying_size(
                &mut builder,
                "sample-0.1.0/Cargo.toml",
                64 * 1024 * 1024,
                b"[package]\nname = \"sample\"\n",
            );
            builder.finish().expect("fixture tar should finish");
        }
        let tarball_bytes = gzip_wrap(&tarball);

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        // The declared size exceeds the archive's real remaining bytes, so
        // the tar reader hits end-of-stream while skipping ahead to where
        // it expects the next header (or archive end) to be.
        assert!(
            report.inspection_failures()[0].starts_with("unable to inspect crate archive: ")
                && report.inspection_failures()[0].contains("EOF")
        );
    }

    #[test]
    fn every_proc_macro_role_form_scans_its_required_target_even_in_excluded_directories() {
        for role in [
            "proc-macro = true",
            "proc_macro = true",
            "crate-type = ['proc-macro']",
            "crate_type = ['proc-macro']",
        ] {
            for (declared, actual) in [
                (None, "src/lib.rs"),
                (Some("tests/entry.rs"), "tests/entry.rs"),
                (Some("examples/entry.rs"), "examples/entry.rs"),
                (Some("./src/../src/entry.rs"), "src/entry.rs"),
            ] {
                let path = declared
                    .map(|path| format!("path={path:?}\n"))
                    .unwrap_or_default();
                let manifest = format!(
                    "[package]\nname='sample'\nversion='0.1.0'\nedition='2021'\n[lib]\n{role}\n{path}"
                );
                let tarball = build_crate_tarball(&[
                    ("Cargo.toml", &manifest),
                    (actual, "// inert original-byte fixture: Command::new(\n"),
                ]);
                let report = inspect(spec("sample"), &tarball);
                assert!(report.proc_macro(), "{role}");
                assert!(
                    report.inspection_failures().is_empty(),
                    "{:?}",
                    report.inspection_failures()
                );
                let ioc = report.ioc_inspection().unwrap();
                assert!(matches!(ioc.coverage, crate::ioc::Coverage::Complete));
                assert!(
                    ioc.findings
                        .iter()
                        .any(|finding| finding.path == actual
                            && finding.rule == "process-command-new")
                );
            }
        }
    }

    #[test]
    fn required_proc_macro_target_missing_or_outside_archive_is_incomplete() {
        for path in [None, Some("../outside.rs"), Some("tests/missing.rs")] {
            let path = path
                .map(|path| format!("path={path:?}\n"))
                .unwrap_or_default();
            let manifest = format!(
                "[package]\nname='sample'\nversion='0.1.0'\n[lib]\nproc_macro=true\n{path}"
            );
            let report = inspect(
                spec("sample"),
                &build_crate_tarball(&[("Cargo.toml", &manifest)]),
            );
            assert_eq!(
                report.classification(),
                RustAssessmentClassification::PolicyViolating
            );
            assert!(matches!(
                report.ioc_inspection().unwrap().coverage,
                crate::ioc::Coverage::Incomplete { .. }
            ));
        }
    }

    #[test]
    fn present_non_utf8_vcs_provenance_is_invalid_not_absent() {
        let entries: [(&str, &[u8]); 2] = [
            (
                "sample-0.1.0/Cargo.toml",
                b"[package]\nname=\"sample\"\nversion=\"0.1.0\"\n",
            ),
            ("sample-0.1.0/.cargo_vcs_info.json", &[0xff]),
        ];
        let report = inspect_hostile("sample", &gzip_wrap(&build_tar(&entries)));
        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(
            report.inspection_failures(),
            ["invalid .cargo_vcs_info.json: non-UTF8 provenance file"]
        );
        assert!(report.vcs_info().is_none());
        let absent = inspect_hostile("sample", &gzip_wrap(&build_tar(&entries[..1])));
        assert!(absent.inspection_failures().is_empty());
        assert_eq!(
            absent.classification(),
            RustAssessmentClassification::RoutineSafe
        );
    }

    #[test]
    fn non_utf8_cargo_toml_contents_fail_closed_without_panic() {
        let entries: [(&str, &[u8]); 1] = [("sample-0.1.0/Cargo.toml", &[0xff, 0xfe, 0x00, 0xff])];
        let tarball_bytes = gzip_wrap(&build_tar(&entries));

        let report = inspect_hostile("sample", &tarball_bytes);

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert!(report.inspection_failures()[0].starts_with("published Cargo.toml is invalid: "));
    }

    #[test]
    fn non_utf8_source_file_contents_are_lossily_scanned_without_panic() {
        // A non-UTF8 `.rs` file alongside a valid manifest: `from_utf8_lossy`
        // must substitute replacement characters rather than panicking, and
        // inspection must still complete deterministically.
        let entries: [(&str, &[u8]); 2] = [
            (
                "sample-0.1.0/Cargo.toml",
                b"[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
            ),
            ("sample-0.1.0/src/lib.rs", &[0xff, 0xfe, b'x', 0x00]),
        ];
        let tarball_bytes = gzip_wrap(&build_tar(&entries));

        let report = inspect_hostile("sample", &tarball_bytes);

        assert!(report.checksum_matches());
        assert!(report.inspection_failures().is_empty());
        assert!(report.ioc_hits().is_empty());
    }
    #[test]
    fn full_archive_custody_accepts_matching_legacy_type_bits_but_not_special_or_conflicting_modes()
    {
        for (mode, valid) in [
            (0o100644, true),
            (0o644, true),
            (0o104644, false),
            (0o102644, false),
            (0o101644, false),
            (0o040644, false),
        ] {
            let mut builder = Builder::new(Vec::new());
            let contents = b"[package]\nname='sample'\nversion='0.1.0'\n";
            let mut header = Header::new_gnu();
            header.set_path("sample-0.1.0/Cargo.toml").unwrap();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(contents.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            builder.append(&header, contents.as_slice()).unwrap();
            let archive = gzip_wrap(&builder.into_inner().unwrap());
            let digest = crate::cargo_tool::sha256(&archive);
            let result = super::visit_verified_crate_archive(
                &spec("sample"),
                &archive,
                &digest,
                |_, actual_mode, _| {
                    assert_eq!(actual_mode, 0o644);
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), valid, "mode {mode:o}: {result:?}");
        }
    }
    #[test]
    fn full_archive_custody_preserves_non_text_files_and_rejects_checksum_first() {
        let archive = gzip_wrap(&build_tar(&[
            (
                "sample-0.1.0/Cargo.toml",
                b"[package]\nname='sample'\nversion='0.1.0'\n",
            ),
            ("sample-0.1.0/asset.bin", &[0, 255, 1]),
        ]));
        let digest = crate::cargo_tool::sha256(&archive);
        let mut files = Vec::new();
        super::visit_verified_crate_archive(
            &spec("sample"),
            &archive,
            &digest,
            |path, mode, bytes| {
                files.push((path.to_owned(), mode, bytes.map(<[u8]>::to_vec)));
                Ok(())
            },
        )
        .unwrap();
        assert!(
            files
                .iter()
                .any(|(path, _, bytes)| path == "asset.bin"
                    && bytes.as_deref() == Some(&[0, 255, 1]))
        );
        let mut called = false;
        assert!(
            super::visit_verified_crate_archive(
                &spec("sample"),
                &archive,
                &crate::cargo_tool::sha256(b"wrong"),
                |_, _, _| {
                    called = true;
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(!called);
    }
    #[test]
    fn full_archive_custody_rejects_duplicate_paths_and_noncanonical_crate_root() {
        for entries in [
            vec![
                ("sample-0.1.0/Cargo.toml", b"first".as_slice()),
                ("sample-0.1.0/Cargo.toml", b"second".as_slice()),
            ],
            vec![("different-0.1.0/Cargo.toml", b"manifest".as_slice())],
        ] {
            let archive = gzip_wrap(&build_tar(&entries));
            let digest = crate::cargo_tool::sha256(&archive);
            assert!(
                super::visit_verified_crate_archive(
                    &spec("sample"),
                    &archive,
                    &digest,
                    |_, _, _| Ok(())
                )
                .is_err()
            );
        }
    }
    #[test]
    fn full_archive_custody_rejects_links_and_hidden_trailing_archive_data() {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("sample-0.1.0/Cargo.toml").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }
        let archive = gzip_wrap(&bytes);
        let digest = crate::cargo_tool::sha256(&archive);
        assert!(
            super::visit_verified_crate_archive(&spec("sample"), &archive, &digest, |_, _, _| Ok(
                ()
            ))
            .is_err()
        );
        let mut bytes = build_tar(&[("sample-0.1.0/Cargo.toml", b"manifest")]);
        bytes.extend_from_slice(&[42; 512]);
        let archive = gzip_wrap(&bytes);
        let digest = crate::cargo_tool::sha256(&archive);
        assert!(
            super::visit_verified_crate_archive(&spec("sample"), &archive, &digest, |_, _, _| Ok(
                ()
            ))
            .is_err()
        );
    }
}
