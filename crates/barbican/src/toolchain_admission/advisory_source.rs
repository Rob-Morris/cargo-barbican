//! Bounded inert RustSec Git snapshots and stable-version source-range evidence.
//! Source inclusion is not proof of shipment, reachability or native coverage.
use super::*;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};

pub const MAX_ADVISORY_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXPANDED: u64 = 64 * 1024 * 1024;
const MAX_MEMBERS: usize = 20_000;
const MAX_BODY: u64 = 2 * 1024 * 1024;

pub fn read_advisory_archive(
    gzip: &[u8],
    expected_revision: &str,
) -> Result<BTreeMap<String, String>> {
    require(
        gzip.len() <= MAX_ADVISORY_ARCHIVE_BYTES,
        "advisory archive compressed limit",
    )?;
    require(
        expected_revision.len() == 40
            && expected_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected exact lowercase Git revision",
    )?;
    let decoder = crate::rust_distribution::GzipReader::new(Cursor::new(gzip)).map_err(io_error)?;
    read_advisory_tar(decoder, expected_revision)
}
fn read_advisory_tar(
    reader: impl Read,
    expected_revision: &str,
) -> Result<BTreeMap<String, String>> {
    let mut reader = SourceReader { reader, bytes: 0 };
    let root = format!("advisory-db-{expected_revision}");
    let mut paths = BTreeSet::new();
    let mut result = BTreeMap::new();
    let mut saw_revision = false;
    for index in 0..MAX_MEMBERS {
        let mut block = [0u8; 512];
        reader.read_exact(&mut block).map_err(io_error)?;
        if block == [0; 512] {
            reader.read_exact(&mut block).map_err(io_error)?;
            require(block == [0; 512], "advisory tar requires two terminators")?;
            let mut buffer = [0u8; 32768];
            loop {
                let n = reader.read(&mut buffer).map_err(io_error)?;
                if n == 0 {
                    break;
                }
                require(
                    buffer[..n].iter().all(|b| *b == 0),
                    "advisory tar trailing data",
                )?;
            }
            require(
                saw_revision && !result.is_empty(),
                "advisory archive lacks exact commit or corpus",
            )?;
            return Ok(result);
        }
        let header = tar::Header::from_byte_slice(&block);
        let checksum: u32 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u32::from(*b)
                }
            })
            .sum();
        require(
            header.cksum().map_err(io_error)? == checksum,
            "advisory tar checksum",
        )?;
        let size = header.size().map_err(io_error)?;
        require(size <= MAX_BODY, "advisory tar member body limit")?;
        let kind = header.entry_type();
        require(
            header.link_name_bytes().is_none(),
            "advisory tar link target",
        )?;
        let name = String::from_utf8(header.path_bytes().into_owned())
            .map_err(|e| AdmissionError(e.to_string()))?;
        let name = if kind.is_dir() {
            name.strip_suffix('/').unwrap_or(&name)
        } else {
            &name
        };
        require(
            name.len() <= 4096
                && !name.starts_with('/')
                && !name.contains('\\')
                && !name.contains(':')
                && !name.chars().any(char::is_control)
                && name
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != ".."),
            "advisory archive path",
        )?;
        require(
            paths.insert(name.to_owned()),
            "duplicate advisory archive path",
        )?;
        let mut body = Vec::new();
        if kind.as_byte() == b'g' {
            require(
                index == 0 && size <= 128,
                "unsupported advisory PAX metadata",
            )?;
            reader
                .by_ref()
                .take(size)
                .read_to_end(&mut body)
                .map_err(io_error)?;
            let expected = format!("52 comment={expected_revision}\n");
            require(
                body == expected.as_bytes(),
                "advisory Git revision comment mismatch",
            )?;
            saw_revision = true;
        } else {
            require(
                kind.is_file() || kind.is_dir(),
                "unsupported advisory archive member",
            )?;
            require(!kind.is_dir() || size == 0, "nonempty advisory directory")?;
            let relative = if name == root {
                ""
            } else {
                name.strip_prefix(&format!("{root}/"))
                    .ok_or_else(|| AdmissionError("wrong advisory archive root".into()))?
            };
            let keep = kind.is_file()
                && (relative.starts_with("crates/") || relative.starts_with("rust/"))
                && relative.ends_with(".md");
            if keep {
                reader
                    .by_ref()
                    .take(size)
                    .read_to_end(&mut body)
                    .map_err(io_error)?;
                require(body.len() as u64 == size, "truncated advisory body")?;
                let text = String::from_utf8(body).map_err(|e| AdmissionError(e.to_string()))?;
                parse_source_advisory(relative, &text)?;
                result.insert(relative.to_owned(), text);
            } else {
                let copied = std::io::copy(&mut reader.by_ref().take(size), &mut std::io::sink())
                    .map_err(io_error)?;
                require(copied == size, "truncated advisory body")?;
            }
        }
        let padding = ((512 - size % 512) % 512) as usize;
        let mut pad = [0u8; 512];
        reader.read_exact(&mut pad[..padding]).map_err(io_error)?;
        require(
            pad[..padding].iter().all(|b| *b == 0),
            "advisory tar padding",
        )?;
    }
    Err(AdmissionError("advisory physical header limit".into()))
}
fn io_error(error: std::io::Error) -> AdmissionError {
    AdmissionError(error.to_string())
}
struct SourceReader<R> {
    reader: R,
    bytes: u64,
}
impl<R: Read> Read for SourceReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let take = MAX_EXPANDED
            .saturating_sub(self.bytes)
            .saturating_add(1)
            .min(output.len() as u64) as usize;
        let n = self.reader.read(&mut output[..take])?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .filter(|n| *n <= MAX_EXPANDED)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "advisory expanded byte limit",
                )
            })?;
        Ok(n)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryCorpus {
    Crates,
    Rust,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceVersionStatus {
    Affected,
    Patched,
    Unaffected,
    Withdrawn,
}
#[derive(Debug, Clone)]
pub struct SourceAdvisory {
    pub corpus: AdvisoryCorpus,
    pub id: String,
    pub package: String,
    pub date: String,
    pub withdrawn: Option<String>,
    pub informational: Option<String>,
    pub expect_deleted: bool,
    pub affected_arch: Vec<String>,
    pub affected_os: Vec<String>,
    pub affected_functions: BTreeMap<String, Vec<String>>,
    patched: Vec<semver::VersionReq>,
    unaffected: Vec<semver::VersionReq>,
}
impl SourceAdvisory {
    /// Stable package versions only. Build metadata does not affect applicability;
    /// prerelease *targets* still require a separately qualified evaluator.
    pub fn version_status(
        &self,
        exact_version: &str,
        checked_at: i64,
    ) -> Result<SourceVersionStatus> {
        timestamp(checked_at)?;
        let today = time::OffsetDateTime::from_unix_timestamp(checked_at)
            .map_err(|e| AdmissionError(e.to_string()))?
            .date();
        let published =
            crate::parse_iso_date(&self.date).map_err(|e| AdmissionError(e.to_string()))?;
        require(published <= today, "future advisory publication date")?;
        if let Some(day) = &self.withdrawn {
            let withdrawn =
                crate::parse_iso_date(day).map_err(|e| AdmissionError(e.to_string()))?;
            require(
                withdrawn >= published && withdrawn <= today,
                "inconsistent or future advisory withdrawal",
            )?;
        }
        let mut version =
            semver::Version::parse(exact_version).map_err(|e| AdmissionError(e.to_string()))?;
        require(
            version.to_string() == exact_version && version.pre.is_empty(),
            "unsupported nonstable source package version",
        )?;
        version.build = semver::BuildMetadata::EMPTY;
        if self.withdrawn.is_some() {
            return Ok(SourceVersionStatus::Withdrawn);
        }
        if self.patched.iter().any(|r| r.matches(&version)) {
            return Ok(SourceVersionStatus::Patched);
        }
        if self.unaffected.iter().any(|r| r.matches(&version)) {
            return Ok(SourceVersionStatus::Unaffected);
        }
        Ok(SourceVersionStatus::Affected)
    }
}

// RustSec's OSV adapter fills omitted minor/patch numbers with zero for
// relational/exact bounds. Cargo's selectors instead treat `>0` or `=1.2`
// as major/minor families. For stable targets this precision adaptation is
// sufficient; semver's prerelease opt-in rule never applies to a stable target.
struct SourceRange {
    requirement: semver::VersionReq,
    lower: Option<(semver::Version, bool)>,
    upper: Option<(semver::Version, bool)>,
}

fn start_precedes_end(
    start: &Option<(semver::Version, bool)>,
    end: &Option<(semver::Version, bool)>,
) -> bool {
    match (start, end) {
        (Some((start, inclusive_start)), Some((end, inclusive_end))) => {
            start < end || start == end && *inclusive_start && *inclusive_end
        }
        _ => true,
    }
}

fn rustsec_source_range(range: &semver::VersionReq) -> Result<SourceRange> {
    use semver::Op;
    let fail = || AdmissionError(format!("unsupported or invalid RustSec range {range:?}"));
    if range.comparators.len() > 2 {
        return Err(fail());
    }
    let mut adapted = range.clone();
    let mut lower = None;
    let mut upper = None;
    for comparator in &mut adapted.comparators {
        match comparator.op {
            Op::Greater | Op::GreaterEq | Op::Less | Op::LessEq | Op::Exact => {
                comparator.minor.get_or_insert(0);
                comparator.patch.get_or_insert(0);
                let bound = semver::Version {
                    major: comparator.major,
                    minor: comparator.minor.unwrap(),
                    patch: comparator.patch.unwrap(),
                    pre: comparator.pre.clone(),
                    build: semver::BuildMetadata::EMPTY,
                };
                match comparator.op {
                    Op::Greater | Op::GreaterEq => {
                        if lower
                            .replace((bound, comparator.op == Op::GreaterEq))
                            .is_some()
                        {
                            return Err(fail());
                        }
                    }
                    Op::Less | Op::LessEq => {
                        if upper
                            .replace((bound, comparator.op == Op::LessEq))
                            .is_some()
                        {
                            return Err(fail());
                        }
                    }
                    Op::Exact => {
                        if range.comparators.len() != 1 {
                            return Err(fail());
                        }
                        lower = Some((bound.clone(), true));
                        upper = Some((bound, true));
                    }
                    _ => unreachable!(),
                }
            }
            Op::Caret | Op::Tilde => {
                if range.comparators.len() != 1
                    || comparator.major == u64::MAX
                    || comparator.minor == Some(u64::MAX)
                    || comparator.patch == Some(u64::MAX)
                {
                    return Err(fail());
                }
                let start = semver::Version {
                    major: comparator.major,
                    minor: comparator.minor.unwrap_or(0),
                    patch: comparator.patch.unwrap_or(0),
                    pre: comparator.pre.clone(),
                    build: semver::BuildMetadata::EMPTY,
                };
                let mut end = match comparator.op {
                    Op::Caret if comparator.major > 0 => {
                        semver::Version::new(comparator.major + 1, 0, 0)
                    }
                    Op::Caret => match (comparator.minor, comparator.patch) {
                        (Some(0), Some(patch)) => semver::Version::new(0, 0, patch + 1),
                        (Some(minor), _) => semver::Version::new(0, minor + 1, 0),
                        (None, _) => semver::Version::new(1, 0, 0),
                    },
                    Op::Tilde => match comparator.minor {
                        Some(minor) => semver::Version::new(comparator.major, minor + 1, 0),
                        None => semver::Version::new(comparator.major + 1, 0, 0),
                    },
                    _ => unreachable!(),
                };
                // RustSec excludes *all* prereleases of the next compatible
                // family too. Stable-only interval helpers lose this boundary.
                end.pre = semver::Prerelease::new("0").expect("minimum prerelease");
                lower = Some((start, true));
                upper = Some((end, false));
            }
            _ => return Err(fail()),
        }
    }
    if !start_precedes_end(&lower, &upper) {
        return Err(fail());
    }
    Ok(SourceRange {
        requirement: adapted,
        lower,
        upper,
    })
}

pub fn parse_source_advisory(path: &str, markdown: &str) -> Result<SourceAdvisory> {
    require(markdown.len() <= MAX_BODY as usize, "advisory text limit")?;
    let pieces: Vec<_> = path.split('/').collect();
    require(
        pieces.len() == 3 && pieces[2].ends_with(".md"),
        "advisory corpus path",
    )?;
    let corpus = match pieces[0] {
        "crates" => AdvisoryCorpus::Crates,
        "rust" => AdvisoryCorpus::Rust,
        _ => return Err(AdmissionError("unsupported advisory corpus".into())),
    };
    let front = markdown
        .strip_prefix("```toml\n")
        .ok_or_else(|| AdmissionError("missing advisory TOML frontmatter".into()))?;
    let (front, body) = front
        .split_once("\n```")
        .ok_or_else(|| AdmissionError("unterminated advisory frontmatter".into()))?;
    require(!body.trim().is_empty(), "missing advisory explanation")?;
    let raw: RawAdvisory = toml::from_str(front).map_err(|e| AdmissionError(e.to_string()))?;
    require(
        raw.advisory.package == pieces[1] && format!("{}.md", raw.advisory.id) == pieces[2],
        "advisory path identity mismatch",
    )?;
    text(&raw.advisory.id)?;
    text(&raw.advisory.package)?;
    require(
        raw.advisory
            .package
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid advisory package identity",
    )?;
    match corpus {
        AdvisoryCorpus::Crates => {
            crate::RustSecAdvisoryId::parse(&raw.advisory.id)
                .map_err(|e| AdmissionError(e.to_string()))?;
        }
        AdvisoryCorpus::Rust => {
            let id: Vec<_> = raw.advisory.id.split('-').collect();
            require(
                id.len() == 3
                    && id[0] == "CVE"
                    && id[1].len() == 4
                    && id[2].len() >= 4
                    && id[1]
                        .bytes()
                        .chain(id[2].bytes())
                        .all(|b| b.is_ascii_digit()),
                "invalid Rust corpus CVE identity",
            )?;
        }
    }
    for values in [
        &raw.advisory.aliases,
        &raw.advisory.categories,
        &raw.advisory.keywords,
        &raw.advisory.references,
        &raw.advisory.related,
    ] {
        require(values.len() <= 128, "advisory metadata count limit")?;
        for value in values {
            text(value)?;
        }
    }
    for value in [
        &raw.advisory.cvss,
        &raw.advisory.license,
        &raw.advisory.url,
        &raw.advisory.informational,
    ]
    .into_iter()
    .flatten()
    {
        text(value)?;
    }
    crate::parse_iso_date(&raw.advisory.date).map_err(|e| AdmissionError(e.to_string()))?;
    if let Some(date) = &raw.advisory.withdrawn {
        crate::parse_iso_date(date).map_err(|e| AdmissionError(e.to_string()))?;
    }
    let ranges = |values: Vec<String>| -> Result<Vec<semver::VersionReq>> {
        require(values.len() <= 128, "advisory range count limit")?;
        values
            .into_iter()
            .map(|s| {
                text(&s)?;
                semver::VersionReq::parse(&s).map_err(|e| AdmissionError(e.to_string()))
            })
            .collect()
    };
    let affected = raw.affected.unwrap_or_default();
    for values in affected.functions.values() {
        ranges(values.clone())?;
    }
    let qualify = |values: Vec<String>| -> Result<Vec<SourceRange>> {
        ranges(values)?.iter().map(rustsec_source_range).collect()
    };
    let patched = qualify(raw.versions.patched)?;
    let unaffected = qualify(raw.versions.unaffected)?;
    let combined: Vec<_> = patched.iter().chain(&unaffected).collect();
    for (i, left) in combined.iter().enumerate() {
        for right in &combined[i + 1..] {
            require(
                !(start_precedes_end(&left.lower, &right.upper)
                    && start_precedes_end(&right.lower, &left.upper)),
                &format!(
                    "{}: overlapping RustSec ranges {:?} and {:?}",
                    raw.advisory.id, left.requirement, right.requirement
                ),
            )?;
        }
    }
    Ok(SourceAdvisory {
        corpus,
        id: raw.advisory.id,
        package: raw.advisory.package,
        date: raw.advisory.date,
        withdrawn: raw.advisory.withdrawn,
        informational: raw.advisory.informational,
        expect_deleted: raw.advisory.expect_deleted.unwrap_or(false),
        affected_arch: affected.arch,
        affected_os: affected.os,
        affected_functions: affected.functions,
        patched: patched.into_iter().map(|r| r.requirement).collect(),
        unaffected: unaffected.into_iter().map(|r| r.requirement).collect(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdvisory {
    advisory: Metadata,
    versions: Versions,
    affected: Option<Affected>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    id: String,
    package: String,
    date: String,
    withdrawn: Option<String>,
    informational: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
    cvss: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    license: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    related: Vec<String>,
    url: Option<String>,
    #[serde(rename = "expect-deleted")]
    expect_deleted: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Versions {
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Affected {
    #[serde(default)]
    arch: Vec<String>,
    #[serde(default)]
    os: Vec<String>,
    #[serde(default)]
    functions: BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    const REV: &str = "1111111111111111111111111111111111111111";
    fn advisory(patched: &str, unaffected: &str, extra: &str) -> String {
        format!(
            "```toml\n[advisory]\nid='RUSTSEC-2026-0001'\npackage='example'\ndate='2026-01-01'\n{extra}\n[versions]\npatched={patched}\nunaffected={unaffected}\n```\n\n# Source evidence, exposure unknown\n"
        )
    }
    fn archive() -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let comment = format!("52 comment={REV}\n");
        let mut header = tar::Header::new_ustar();
        header.set_size(comment.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::new(b'g'));
        header.set_cksum();
        tar.append_data(&mut header, "pax_global_header", comment.as_bytes())
            .unwrap();
        let body = advisory("['>= 1.2.3']", "['< 1.0.0']", "");
        let mut header = tar::Header::new_ustar();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(
            &mut header,
            format!("advisory-db-{REV}/crates/example/RUSTSEC-2026-0001.md"),
            body.as_bytes(),
        )
        .unwrap();
        tar.into_inner().unwrap()
    }
    fn edit(bytes: &mut [u8], f: impl FnOnce(&mut tar::Header)) {
        let h = tar::Header::from_byte_slice(&bytes[..512]);
        let mut h = h.clone();
        f(&mut h);
        h.set_cksum();
        bytes[..512].copy_from_slice(h.as_bytes());
    }
    #[test]
    fn exact_git_corpus_and_stable_ranges_preserve_semantics() {
        let corpus = read_advisory_tar(archive().as_slice(), REV).unwrap();
        let a = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &corpus["crates/example/RUSTSEC-2026-0001.md"],
        )
        .unwrap();
        let now = 1793750400;
        assert_eq!(
            a.version_status("0.9.9", now).unwrap(),
            SourceVersionStatus::Unaffected
        );
        assert_eq!(
            a.version_status("1.2.2", now).unwrap(),
            SourceVersionStatus::Affected
        );
        assert_eq!(
            a.version_status("1.2.3", now).unwrap(),
            SourceVersionStatus::Patched
        );
        assert!(a.version_status("1.2.3-rc.1", now).is_err());
        let pre = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &advisory("['>= 1.2.3-rc.1']", "[]", ""),
        )
        .unwrap();
        assert_eq!(
            pre.version_status("1.2.3", now).unwrap(),
            SourceVersionStatus::Patched
        );
    }
    #[test]
    fn withdrawn_informational_and_future_dates_are_distinct() {
        let a = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &advisory(
                "[]",
                "[]",
                "withdrawn='2026-02-01'\ninformational='unmaintained'\n",
            ),
        )
        .unwrap();
        assert_eq!(a.informational.as_deref(), Some("unmaintained"));
        assert_eq!(
            a.version_status("1.0.0", 1793750400).unwrap(),
            SourceVersionStatus::Withdrawn
        );
        assert!(a.version_status("1.0.0", 1767225600).is_err());
        let bad = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &advisory("[]", "[]", "withdrawn='2025-12-31'\n"),
        )
        .unwrap();
        assert!(bad.version_status("1.0.0", 1793750400).is_err());
    }
    #[test]
    fn malformed_required_schema_and_range_cannot_become_no_findings() {
        let text = advisory("[]", "[]", "");
        for bad in [
            text.replace("patched=[]", "unknown=[]"),
            text.replace("patched=[]", "patched=['not a version']"),
            text.replace("package='example'", "package='other'"),
            text.replace("date='2026-01-01'", "date='2026-02-30'"),
            text.replace("[versions]", "[versions]\nunknown=true"),
        ] {
            assert!(parse_source_advisory("crates/example/RUSTSEC-2026-0001.md", &bad).is_err());
        }
        assert!(parse_source_advisory("rust/example/RUSTSEC-2026-0001.md", &text).is_err());
        assert!(read_advisory_archive(&vec![0; MAX_ADVISORY_ARCHIVE_BYTES + 1], REV).is_err());
    }

    #[test]
    fn caret_and_exact_stable_ranges_use_existing_semver_rules() {
        let a = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &advisory("['^0.6.4']", "['=0.2.0']", ""),
        )
        .unwrap();
        let now = 1793750400;
        assert_eq!(
            a.version_status("0.6.5", now).unwrap(),
            SourceVersionStatus::Patched
        );
        assert_eq!(
            a.version_status("0.7.0", now).unwrap(),
            SourceVersionStatus::Affected
        );
        assert_eq!(
            a.version_status("0.2.0", now).unwrap(),
            SourceVersionStatus::Unaffected
        );
        assert_eq!(
            a.version_status("0.2.1", now).unwrap(),
            SourceVersionStatus::Affected
        );
    }

    #[test]
    fn stable_targets_follow_rustsec_bound_precision_and_ignore_build_metadata() {
        let now = 1793750400;
        for (range, version, expected) in [
            (">0", "0.1.0", SourceVersionStatus::Patched),
            (">0", "0.0.0+vendor.1", SourceVersionStatus::Affected),
            ("<=1.2", "1.2.1", SourceVersionStatus::Affected),
            ("=1.2", "1.2.0+vendor.1", SourceVersionStatus::Patched),
            ("=1.2", "1.2.1", SourceVersionStatus::Affected),
            (
                ">=0.8.0-rc.1",
                "0.8.0+source.1",
                SourceVersionStatus::Patched,
            ),
            ("<0.8.0-rc.1", "0.8.0", SourceVersionStatus::Affected),
            ("<0.8.0-rc.1", "0.7.9", SourceVersionStatus::Patched),
            ("*", "7.8.9+anything", SourceVersionStatus::Patched),
            ("^0.0", "0.0.9", SourceVersionStatus::Patched),
            ("^0.0", "0.1.0", SourceVersionStatus::Affected),
            ("~1.2", "1.2.9", SourceVersionStatus::Patched),
            ("~1.2", "1.3.0", SourceVersionStatus::Affected),
        ] {
            let a = parse_source_advisory(
                "crates/example/RUSTSEC-2026-0001.md",
                &advisory(&format!("['{range}']"), "[]", ""),
            )
            .unwrap();
            assert_eq!(
                a.version_status(version, now).unwrap(),
                expected,
                "{range} vs {version}"
            );
        }
        for range in ["1.*", ">=1,>=2", ">=2,<1", "=1,<2", ">1,<=1"] {
            assert!(
                parse_source_advisory(
                    "crates/example/RUSTSEC-2026-0001.md",
                    &advisory(&format!("['{range}']"), "[]", ""),
                )
                .is_err(),
                "{range}"
            );
        }
    }

    #[test]
    fn overlapping_source_ranges_refuse_before_any_version_can_be_called_clean() {
        for (patched, unaffected) in [
            ("['>=1']", "['>=1.2']"),
            ("['>=1','>=1.2']", "[]"),
            ("[]", "['>=1','>=1.2']"),
            ("['<=1']", "['>=1']"),
            ("['=1.2']", "['>=1.2.0,<=1.2.0']"),
            ("['*']", "['=0.0.0']"),
            ("['>=1.0.0-alpha,<1.0.0']", "['>=1.0.0-beta,<1.0.0']"),
            ("['^1.0']", "['>=1.9.0-alpha,<1.9.0']"),
            ("['~1.2']", "['=1.2.9']"),
        ] {
            let error = parse_source_advisory(
                "crates/example/RUSTSEC-2026-0001.md",
                &advisory(patched, unaffected, ""),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("overlapping RustSec ranges"),
                "{patched} {unaffected}: {error}"
            );
        }
    }

    #[test]
    fn nonoverlapping_touching_empty_and_prerelease_boundaries_remain_valid() {
        for (patched, unaffected) in [
            ("[]", "[]"),
            ("['*']", "[]"),
            ("['<1']", "['>=1']"),
            ("['<=1']", "['>1']"),
            ("['<1']", "['>1']"),
            ("['^1.2.3']", "['>=2.0.0-alpha,<2.0.0']"),
            ("['~1.2']", "['=1.3.0-0']"),
            ("['=1.0.0-alpha']", "['>=1.0.0-beta,<1.0.0']"),
        ] {
            parse_source_advisory(
                "crates/example/RUSTSEC-2026-0001.md",
                &advisory(patched, unaffected, ""),
            )
            .unwrap_or_else(|e| panic!("{patched} {unaffected}: {e}"));
        }
        let empty = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &advisory("[]", "[]", ""),
        )
        .unwrap();
        assert_eq!(
            empty.version_status("1.3.0", 1793750400).unwrap(),
            SourceVersionStatus::Affected
        );
        let gap = parse_source_advisory(
            "crates/example/RUSTSEC-2026-0001.md",
            &advisory("['<1']", "['>1']", ""),
        )
        .unwrap();
        assert_eq!(
            gap.version_status("1.0.0", 1793750400).unwrap(),
            SourceVersionStatus::Affected
        );
    }

    #[test]
    fn physical_header_and_expanded_byte_budgets_bound_inert_source_work() {
        let mut tar = tar::Builder::new(Vec::new());
        for i in 0..MAX_MEMBERS {
            let mut header = tar::Header::new_ustar();
            header.set_size(0);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            tar.append_data(
                &mut header,
                format!("advisory-db-{REV}/dir{i}"),
                std::io::empty(),
            )
            .unwrap();
        }
        let bytes = tar.into_inner().unwrap();
        assert!(
            read_advisory_tar(bytes.as_slice(), REV)
                .unwrap_err()
                .to_string()
                .contains("physical header limit")
        );
        let mut reader = SourceReader {
            reader: std::io::repeat(0),
            bytes: MAX_EXPANDED,
        };
        let mut buffer = [0; 512];
        assert!(reader.read(&mut buffer).is_err());
    }
    #[test]
    fn archive_refuses_links_pax_overrides_wrong_identity_truncation_and_trailing_data() {
        let valid = archive();
        for kind in [b'1', b'2', b'3', b'6', b'L', b'x', b'g'] {
            let mut bad = valid.clone();
            edit(&mut bad[1024..], |h| {
                h.set_entry_type(tar::EntryType::new(kind))
            });
            assert!(read_advisory_tar(bad.as_slice(), REV).is_err());
        }
        let mut bad = valid.clone();
        bad[512 + 11] = b'2';
        assert!(read_advisory_tar(bad.as_slice(), REV).is_err());
        let mut bad = valid.clone();
        bad[0] ^= 1;
        assert!(read_advisory_tar(bad.as_slice(), REV).is_err());
        let mut bad = valid.clone();
        edit(&mut bad[1024..], |h| h.set_size(MAX_BODY + 1));
        assert!(read_advisory_tar(bad.as_slice(), REV).is_err());
        assert!(read_advisory_tar(&valid[..valid.len() - 1024], REV).is_err());
        let mut bad = valid.clone();
        bad.extend(b"hidden trailing payload");
        assert!(read_advisory_tar(bad.as_slice(), REV).is_err());
        let mut bad = valid.clone();
        edit(&mut bad[1024..], |h| {
            h.as_mut_bytes()[..100].fill(0);
            h.as_mut_bytes()[..9].copy_from_slice(b"../escape");
        });
        assert!(read_advisory_tar(bad.as_slice(), REV).is_err());
    }
}
