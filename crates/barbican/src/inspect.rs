use std::fmt;
use std::io::{Cursor, Read};
use std::path::{Component, Path};

use miniz_oxide::inflate::decompress_to_vec_with_limit;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;
use time::OffsetDateTime;
use toml::Value;

use crate::assessment::RustAssessmentClassification;
use crate::{
    CrateRelease, ExactCrateSpec, ReleaseAgeReport, ReviewedReleaseAgeException,
    evaluate_release_age,
};

const GZIP_HEADER_LEN: usize = 10;
const GZIP_FOOTER_LEN: usize = 8;
const GZIP_FLAG_FEXTRA: u8 = 0b0000_0100;
const GZIP_FLAG_FNAME: u8 = 0b0000_1000;
const GZIP_FLAG_FCOMMENT: u8 = 0b0001_0000;
const GZIP_FLAG_FHCRC: u8 = 0b0000_0010;
const GZIP_FLAG_RESERVED: u8 = 0b1110_0000;
const MAX_DECOMPRESSED_CRATE_BYTES: usize = 128 * 1024 * 1024;
const IOC_PATTERNS: [(&str, &str); 10] = [
    ("Command::new(", "process execution"),
    ("std::process::Command", "process execution"),
    ("TcpStream::connect", "direct network use"),
    ("UdpSocket::bind", "direct network use"),
    ("reqwest::blocking::", "HTTP client use"),
    ("reqwest::Client", "HTTP client use"),
    ("ureq::get(", "HTTP client use"),
    ("ureq::post(", "HTTP client use"),
    ("curl ", "shell downloader token"),
    ("wget ", "shell downloader token"),
];

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
    indicator: String,
}

impl IocHit {
    fn new(path: String, indicator: String) -> Self {
        Self { path, indicator }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn indicator(&self) -> &str {
        &self.indicator
    }
}

impl fmt::Display for IocHit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.path, self.indicator)
    }
}

pub fn inspect_published_crate(
    spec: ExactCrateSpec,
    release: CrateRelease,
    tarball_bytes: &[u8],
    minimum_days: u64,
) -> RustInspectReport {
    inspect_published_crate_at(
        spec,
        release,
        tarball_bytes,
        OffsetDateTime::now_utc(),
        minimum_days,
        None,
    )
}

pub fn inspect_published_crate_at(
    spec: ExactCrateSpec,
    release: CrateRelease,
    tarball_bytes: &[u8],
    now: OffsetDateTime,
    minimum_days: u64,
    exception: Option<&ReviewedReleaseAgeException>,
) -> RustInspectReport {
    let published_checksum_sha256_hex = release.checksum_sha256_hex.to_string();
    let release_age = evaluate_release_age(spec.clone(), release, now, minimum_days, exception);
    let local_checksum_sha256_hex = sha256_hex(tarball_bytes);
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
            inspection_failures: Vec::new(),
        };
    }

    let tarball_inspection = inspect_verified_tarball(&spec, tarball_bytes);

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
    inspection_failures: Vec<String>,
}

impl TarballInspection {
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

fn has_execution_surface(
    has_build_script: bool,
    proc_macro: bool,
    native_sys_crate: bool,
    has_package_links: bool,
    has_native_source: bool,
) -> bool {
    has_build_script || proc_macro || native_sys_crate || has_package_links || has_native_source
}

fn inspect_verified_tarball(spec: &ExactCrateSpec, tarball_bytes: &[u8]) -> TarballInspection {
    let mut inspection = TarballInspection {
        native_sys_crate: spec.is_native_sys(),
        ..TarballInspection::default()
    };

    let decompressed = match decompress_crate_gzip(tarball_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            inspection
                .inspection_failures
                .push(format!("unable to decode crate tarball: {error}"));
            return inspection;
        }
    };

    let files = match read_tar_text_files(&decompressed) {
        Ok(files) => files,
        Err(error) => {
            inspection
                .inspection_failures
                .push(format!("unable to inspect crate archive: {error}"));
            return inspection;
        }
    };

    let cargo_toml = match files
        .iter()
        .find(|file| file.path == "Cargo.toml")
        .map(|file| file.contents.as_str())
    {
        Some(text) => text,
        None => {
            inspection
                .inspection_failures
                .push("published crate is missing Cargo.toml".to_owned());
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

    inspection.proc_macro = manifest.proc_macro;
    inspection.package_links = manifest.package_links;

    if let Some(vcs_text) = files
        .iter()
        .find(|file| file.path == ".cargo_vcs_info.json")
        .map(|file| file.contents.as_str())
    {
        match parse_cargo_vcs_info(vcs_text) {
            Ok(vcs_info) => inspection.vcs_info = Some(vcs_info),
            Err(error) => inspection
                .inspection_failures
                .push(format!("invalid .cargo_vcs_info.json: {error}")),
        }
    }

    let file_paths = files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    if let Some(build_script_path) = manifest.build_script_path.as_deref() {
        if file_paths.iter().any(|path| *path == build_script_path) {
            inspection
                .build_script_paths
                .push(build_script_path.to_owned());
        } else {
            inspection.inspection_failures.push(format!(
                "declared build script path is missing: {build_script_path}"
            ));
        }
    } else if file_paths.iter().any(|path| *path == "build.rs") {
        inspection.build_script_paths.push("build.rs".to_owned());
    }

    inspection.native_source_paths = files
        .iter()
        .filter(|file| is_native_source_path(&file.path))
        .map(|file| file.path.clone())
        .collect();

    inspection.ioc_hits = scan_ioc_hits(
        &files,
        &inspection.build_script_paths,
        &inspection.native_source_paths,
        inspection.has_execution_surface(),
    );
    inspection.build_script_paths.sort();
    inspection.native_source_paths.sort();
    inspection.ioc_hits.sort();
    inspection.inspection_failures.sort();

    inspection
}

fn scan_ioc_hits(
    files: &[ArchiveTextFile],
    build_script_paths: &[String],
    native_source_paths: &[String],
    has_execution_surface: bool,
) -> Vec<IocHit> {
    files
        .iter()
        .filter(|file| {
            build_script_paths.iter().any(|path| path == &file.path)
                || native_source_paths.iter().any(|path| path == &file.path)
                || (has_execution_surface && is_source_like_path(&file.path))
        })
        .flat_map(|file| {
            IOC_PATTERNS.iter().filter_map(|(needle, description)| {
                file.contents
                    .contains(needle)
                    .then(|| IocHit::new(file.path.clone(), format!("{description}: {needle}")))
            })
        })
        .collect()
}

fn is_proc_macro_source_path(path: &str) -> bool {
    path.ends_with(".rs") && !is_non_production_path(path)
}

fn is_source_like_path(path: &str) -> bool {
    is_proc_macro_source_path(path) || is_native_source_path(path)
}

fn is_native_source_path(path: &str) -> bool {
    if is_non_production_path(path) {
        return false;
    }

    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension,
                "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "s" | "S" | "asm"
            )
        })
        .unwrap_or(false)
}

fn is_non_production_path(path: &str) -> bool {
    path.starts_with("tests/") || path.starts_with("examples/") || path.starts_with("benches/")
}

fn parse_published_manifest(text: &str) -> Result<PublishedManifestSignals, toml::de::Error> {
    let manifest: PublishedManifest = toml::from_str(text)?;
    let proc_macro = manifest.lib.and_then(|lib| lib.proc_macro).unwrap_or(false);
    let package_links = manifest
        .package
        .as_ref()
        .and_then(|package| package.links.clone());
    let build_script_path = match manifest.package.and_then(|package| package.build) {
        None => None,
        Some(Value::Boolean(true)) => Some("build.rs".to_owned()),
        Some(Value::Boolean(false)) => None,
        Some(Value::String(path)) => Some(path),
        Some(other) => Some(other.to_string()),
    };

    Ok(PublishedManifestSignals {
        build_script_path,
        package_links,
        proc_macro,
    })
}

fn parse_cargo_vcs_info(text: &str) -> Result<CrateVcsInfo, serde_json::Error> {
    let parsed: CargoVcsInfoFile = serde_json::from_str(text)?;
    Ok(CrateVcsInfo {
        git_sha1: parsed.git.sha1,
        path_in_vcs: parsed.path_in_vcs,
    })
}

fn read_tar_text_files(bytes: &[u8]) -> Result<Vec<ArchiveTextFile>, String> {
    let mut archive = Archive::new(Cursor::new(bytes));
    let mut files = Vec::new();
    let entries = archive.entries().map_err(|error| error.to_string())?;

    for entry in entries {
        let mut entry = entry.map_err(|error| error.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = entry.path().map_err(|error| error.to_string())?;
        let Some(normalized_path) = normalize_archive_path(&path)? else {
            continue;
        };

        let should_read = normalized_path == "Cargo.toml"
            || normalized_path == ".cargo_vcs_info.json"
            || normalized_path.ends_with(".rs")
            || is_native_source_path(&normalized_path);
        if !should_read {
            continue;
        }

        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|error| error.to_string())?;
        files.push(ArchiveTextFile {
            path: normalized_path,
            contents: String::from_utf8_lossy(&contents).into_owned(),
        });
    }

    Ok(files)
}

fn normalize_archive_path(path: &Path) -> Result<Option<String>, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("unsupported archive path: {}", path.display()));
            }
        }
    }

    if parts.len() < 2 {
        return Ok(None);
    }

    Ok(Some(parts[1..].join("/")))
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);

    for byte in digest {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }

    output
}

struct ArchiveTextFile {
    path: String,
    contents: String,
}

#[derive(Debug, Deserialize)]
struct PublishedManifest {
    package: Option<PublishedPackage>,
    lib: Option<PublishedLib>,
}

#[derive(Debug, Deserialize)]
struct PublishedPackage {
    build: Option<Value>,
    links: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublishedLib {
    #[serde(rename = "proc-macro")]
    proc_macro: Option<bool>,
}

struct PublishedManifestSignals {
    build_script_path: Option<String>,
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
        let mut tarball = Vec::new();
        {
            let mut builder = Builder::new(&mut tarball);
            for (path, contents) in files {
                let full_path = format!("sample-0.1.0/{path}");
                let bytes = contents.as_bytes();
                let mut header = Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, full_path, bytes)
                    .expect("fixture tar append should succeed");
            }
            builder.finish().expect("fixture tar should finish");
        }

        let deflated = miniz_oxide::deflate::compress_to_vec(&tarball, 6);
        let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        gzip.extend(deflated);
        gzip.extend([0, 0, 0, 0]);
        gzip.extend((tarball.len() as u32).to_le_bytes());
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
}
