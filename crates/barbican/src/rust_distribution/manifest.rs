use super::{DistributionError, digest, invalid, path};
use crate::Sha256Digest;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const HOSTS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
];
const PACKAGES: [&str; 6] = [
    "rustc",
    "cargo",
    "rust-std",
    "rust-docs",
    "rustfmt-preview",
    "clippy-preview",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Xz,
    Gzip,
}
impl Encoding {
    fn suffix(self) -> &'static str {
        match self {
            Self::Xz => "xz",
            Self::Gzip => "gz",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Minimal,
    Default,
}
impl Profile {
    fn name(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Default => "default",
        }
    }
}
#[derive(Debug, Clone)]
pub struct SelectionRequest {
    pub host: String,
    pub profile: Profile,
    pub components: Vec<String>,
    pub targets: Vec<String>,
    /// Must be chosen by a separately qualified evaluator, never by fallback.
    pub encoding: Encoding,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIdentity {
    pub package: String,
    pub target: String,
    pub component: String,
    pub root: String,
    pub encoding: Encoding,
    pub url: String,
    pub sha256: Sha256Digest,
}
#[derive(Debug, Clone)]
pub struct Selection {
    pub release: String,
    pub date: String,
    pub manifest_sha256: Sha256Digest,
    pub host: String,
    pub profile: Profile,
    pub archives: Vec<ArchiveIdentity>,
    pub host_inapplicable_profile_members: Vec<String>,
}
/// Original bytes remain distinct from parsed values and any installer-normalised metadata.
#[derive(Debug, Clone)]
pub struct Manifest {
    original: Vec<u8>,
    raw: RawManifest,
    release: String,
}
#[derive(Debug, Clone, Deserialize)]
struct RawManifest {
    #[serde(rename = "manifest-version")]
    version: String,
    date: String,
    pkg: BTreeMap<String, Package>,
    profiles: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    renames: BTreeMap<String, Rename>,
}
#[derive(Debug, Clone, Deserialize)]
struct Rename {
    to: String,
}
#[derive(Debug, Clone, Deserialize)]
struct Package {
    version: String,
    #[serde(default)]
    git_commit_hash: Option<String>,
    target: BTreeMap<String, Target>,
}

/// Advertised metadata only. In particular Cargo's commit can name the Rust tree;
/// resolving the actual Cargo submodule/source identity is a separate evidence step.
#[derive(Debug, Clone, Copy)]
pub struct PackageSourceMetadata<'a> {
    pub version: &'a str,
    pub git_commit_hash: Option<&'a str>,
}
#[derive(Debug, Clone, Deserialize)]
struct Target {
    available: bool,
    url: Option<String>,
    hash: Option<String>,
    xz_url: Option<String>,
    xz_hash: Option<String>,
    zst_url: Option<String>,
    zst_hash: Option<String>,
    #[serde(default)]
    components: Vec<Component>,
    #[serde(default)]
    extensions: Vec<Component>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveEncodings {
    pub gzip: bool,
    pub xz: bool,
    /// True even for an incomplete pair: do not silently fall back from an
    /// unsupported or malformed preferred encoding in an evaluator adapter.
    pub zstd_advertised: bool,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Component {
    pkg: String,
    target: String,
}
impl Manifest {
    pub fn archive_encodings(&self, package: &str, target: &str) -> Option<ArchiveEncodings> {
        self.raw
            .pkg
            .get(package)?
            .target
            .get(target)
            .map(|entry| ArchiveEncodings {
                gzip: entry.url.is_some() && entry.hash.is_some(),
                xz: entry.xz_url.is_some() && entry.xz_hash.is_some(),
                zstd_advertised: entry.zst_url.is_some() || entry.zst_hash.is_some(),
            })
    }
    pub fn package_source_metadata(&self, package: &str) -> Option<PackageSourceMetadata<'_>> {
        self.raw
            .pkg
            .get(package)
            .map(|metadata| PackageSourceMetadata {
                version: &metadata.version,
                git_commit_hash: metadata.git_commit_hash.as_deref(),
            })
    }
    /// Syntax and identity validation only: no signature or publisher authority is established.
    pub fn parse(original: &[u8], exact_release: &str) -> Result<Self, DistributionError> {
        let version = semver::Version::parse(exact_release)
            .map_err(|_| invalid("expected exact stable release"))?;
        if !version.pre.is_empty()
            || !version.build.is_empty()
            || version.to_string() != exact_release
        {
            return Err(invalid("expected exact stable release"));
        }
        if original.len() > MAX_MANIFEST_BYTES {
            return Err(invalid("manifest byte limit"));
        }
        let text = std::str::from_utf8(original).map_err(|_| invalid("manifest is not UTF-8"))?;
        let raw: RawManifest =
            toml::from_str(text).map_err(|e| invalid(format!("manifest TOML: {e}")))?;
        if raw.version != "2" {
            return Err(invalid("manifest version must be 2"));
        }
        let fields: Vec<_> = raw.date.split('-').collect();
        if fields.len() != 3 || fields[0].len() != 4 || fields[1].len() != 2 || fields[2].len() != 2
        {
            return Err(invalid("manifest date must be YYYY-MM-DD"));
        }
        let year = fields[0]
            .parse::<i32>()
            .map_err(|_| invalid("invalid date"))?;
        let month = fields[1]
            .parse::<u8>()
            .ok()
            .and_then(|m| time::Month::try_from(m).ok())
            .ok_or_else(|| invalid("invalid date"))?;
        let day = fields[2]
            .parse::<u8>()
            .map_err(|_| invalid("invalid date"))?;
        time::Date::from_calendar_date(year, month, day).map_err(|_| invalid("invalid date"))?;
        let rust = raw
            .pkg
            .get("rust")
            .ok_or_else(|| invalid("missing rust package"))?;
        if rust.version.split_whitespace().next() != Some(exact_release) {
            return Err(invalid("release identity mismatch"));
        }
        Ok(Self {
            original: original.to_vec(),
            raw,
            release: exact_release.to_owned(),
        })
    }
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }
    pub fn sha256(&self) -> Sha256Digest {
        digest(&self.original)
    }
    fn canonical<'a>(&'a self, name: &'a str) -> Result<&'a str, DistributionError> {
        let expected = match name {
            "rustfmt" => "rustfmt-preview",
            "clippy" => "clippy-preview",
            other => other,
        };
        if let Some(rename) = self.raw.renames.get(name) {
            if rename.to != expected {
                return Err(invalid("unsupported component rename"));
            }
        } else if expected != name {
            return Err(invalid("missing component rename"));
        }
        Ok(expected)
    }
    pub fn select(&self, request: &SelectionRequest) -> Result<Selection, DistributionError> {
        if !HOSTS.contains(&request.host.as_str()) {
            return Err(invalid("unsupported host"));
        }
        if request.components.len() + request.targets.len() > 256 {
            return Err(invalid("selection request limit"));
        }
        let rust = self.raw.pkg["rust"]
            .target
            .get(&request.host)
            .filter(|t| t.available)
            .ok_or_else(|| invalid("host unavailable"))?;
        let closure: BTreeSet<_> = rust
            .components
            .iter()
            .chain(&rust.extensions)
            .cloned()
            .collect();
        let mut wanted = BTreeSet::new();
        let mut skipped = Vec::new();
        let profile = self
            .raw
            .profiles
            .get(request.profile.name())
            .ok_or_else(|| invalid("missing requested profile"))?;
        for member in profile {
            let package = self.canonical(member)?;
            let component = Component {
                pkg: package.to_owned(),
                target: request.host.clone(),
            };
            if package == "rust-mingw" && !closure.contains(&component) {
                skipped.push(member.clone());
                continue;
            }
            if !closure.contains(&component) {
                return Err(invalid("profile component absent from host closure"));
            }
            wanted.insert(component);
        }
        for member in &request.components {
            path(member)?;
            wanted.insert(Component {
                pkg: self.canonical(member)?.to_owned(),
                target: request.host.clone(),
            });
        }
        for target in &request.targets {
            path(target)?;
            wanted.insert(Component {
                pkg: "rust-std".to_owned(),
                target: target.clone(),
            });
        }
        // Signed profiles may add supported components, but cannot omit the minimal compiler closure.
        for required in ["rustc", "cargo", "rust-std"] {
            if !wanted.contains(&Component {
                pkg: required.to_owned(),
                target: request.host.clone(),
            }) {
                return Err(invalid("profile omits required compiler closure"));
            }
        }
        let mut archives = Vec::new();
        for component in wanted {
            if !PACKAGES.contains(&component.pkg.as_str()) || !closure.contains(&component) {
                return Err(invalid(format!(
                    "unsupported or unavailable requested component {} for {}",
                    component.pkg, component.target
                )));
            }
            let target = self
                .raw
                .pkg
                .get(&component.pkg)
                .and_then(|p| p.target.get(&component.target))
                .filter(|t| t.available)
                .ok_or_else(|| invalid("selected component unavailable"))?;
            let (url, hash) = match request.encoding {
                Encoding::Xz => (&target.xz_url, &target.xz_hash),
                Encoding::Gzip => (&target.url, &target.hash),
            };
            let url = url
                .as_ref()
                .ok_or_else(|| invalid("selected encoding unavailable"))?;
            let sha256 = Sha256Digest::try_from(
                hash.as_deref()
                    .ok_or_else(|| invalid("missing archive digest"))?,
            )
            .map_err(|_| invalid("invalid archive digest"))?;
            let archive_package = match component.pkg.as_str() {
                "rustfmt-preview" => "rustfmt",
                "clippy-preview" => "clippy",
                other => other,
            };
            let root = format!("{archive_package}-{}-{}", self.release, component.target);
            let expected_url = format!(
                "https://static.rust-lang.org/dist/{}/{}.tar.{}",
                self.raw.date,
                root,
                request.encoding.suffix()
            );
            if *url != expected_url {
                return Err(invalid("non-canonical official archive URL or identity"));
            }
            let name = if component.pkg == "rust-std" {
                format!("rust-std-{}", component.target)
            } else {
                component.pkg.clone()
            };
            archives.push(ArchiveIdentity {
                package: component.pkg,
                target: component.target,
                component: name,
                root,
                encoding: request.encoding,
                url: url.clone(),
                sha256,
            });
        }
        Ok(Selection {
            release: self.release.clone(),
            date: self.raw.date.clone(),
            manifest_sha256: self.sha256(),
            host: request.host.clone(),
            profile: request.profile,
            archives,
            host_inapplicable_profile_members: skipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> String {
        let mut text = String::from(
            "manifest-version='2'\ndate='2026-10-15'\n[profiles]\nminimal=['rustc','cargo','rust-std','rust-mingw']\ndefault=['rustc','cargo','rust-std','rust-mingw','rust-docs','rustfmt','clippy']\n[renames.rustfmt]\nto='rustfmt-preview'\n[renames.clippy]\nto='clippy-preview'\n[pkg.rust]\nversion='1.99.1 (abc 2026-10-13)'\n[pkg.rust.target.aarch64-apple-darwin]\navailable=true\ncomponents=[{pkg='rustc',target='aarch64-apple-darwin'},{pkg='cargo',target='aarch64-apple-darwin'},{pkg='rust-std',target='aarch64-apple-darwin'}]\nextensions=[{pkg='rust-docs',target='aarch64-apple-darwin'},{pkg='rustfmt-preview',target='aarch64-apple-darwin'},{pkg='clippy-preview',target='aarch64-apple-darwin'},{pkg='rust-std',target='x86_64-unknown-linux-gnu'}]\n",
        );
        for package in PACKAGES {
            text.push_str(&format!("[pkg.{package}]\nversion='component-version'\n"));
            let alias = package.strip_suffix("-preview").unwrap_or(package);
            for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
                text.push_str(&format!("[pkg.{package}.target.{target}]\navailable=true\nxz_url='https://static.rust-lang.org/dist/2026-10-15/{alias}-1.99.1-{target}.tar.xz'\nxz_hash='{}'\nurl='https://static.rust-lang.org/dist/2026-10-15/{alias}-1.99.1-{target}.tar.gz'\nhash='{}'\n", "a".repeat(64), "b".repeat(64)));
            }
        }
        text
    }
    fn request() -> SelectionRequest {
        SelectionRequest {
            host: "aarch64-apple-darwin".into(),
            profile: Profile::Minimal,
            components: vec![],
            targets: vec![],
            encoding: Encoding::Xz,
        }
    }
    #[test]
    fn additive_selection_aliases_identity_and_host_conditional_profile() {
        let original = manifest();
        let manifest = Manifest::parse(original.as_bytes(), "1.99.1").unwrap();
        assert_eq!(manifest.original_bytes(), original.as_bytes());
        let mut req = request();
        assert_eq!(manifest.select(&req).unwrap().archives.len(), 3);
        req.profile = Profile::Default;
        req.components = vec!["rustfmt".into(), "rustfmt-preview".into()];
        req.targets = vec!["x86_64-unknown-linux-gnu".into()];
        let selected = manifest.select(&req).unwrap();
        assert_eq!(selected.archives.len(), 7);
        assert_eq!(selected.host_inapplicable_profile_members, ["rust-mingw"]);
        assert!(
            selected
                .archives
                .iter()
                .any(|a| a.component == "rustfmt-preview" && a.root.starts_with("rustfmt-1.99.1-"))
        );
        assert!(
            selected
                .archives
                .iter()
                .any(|a| a.component == "rust-std-x86_64-unknown-linux-gnu")
        );
        req.components.push("rust-mingw".into());
        assert!(manifest.select(&req).is_err());
    }
    #[test]
    fn encoding_digest_and_exact_official_url_are_bound() {
        let text = manifest();
        let manifest = Manifest::parse(text.as_bytes(), "1.99.1").unwrap();
        let mut req = request();
        req.encoding = Encoding::Gzip;
        assert!(
            manifest
                .select(&req)
                .unwrap()
                .archives
                .iter()
                .all(|a| a.sha256.as_str() == "b".repeat(64) && a.url.ends_with(".tar.gz"))
        );
        for changed in [
            text.replace("https://static.rust-lang.org/", "https://other.example/"),
            text.replace(".tar.xz'", ".tar.xz?x=1'"),
            text.replace("xz_hash", "unknown_hash"),
            text.replace("available=true", "available=false"),
        ] {
            assert!(
                Manifest::parse(changed.as_bytes(), "1.99.1")
                    .unwrap()
                    .select(&request())
                    .is_err()
            );
        }
    }
    #[test]
    fn unsupported_stable_identity_closure_and_dates_refuse() {
        let text = manifest();
        for release in ["stable", "1.99", "1.99.1-beta.1", "1.99.1+custom", "1.99.0"] {
            assert!(Manifest::parse(text.as_bytes(), release).is_err());
        }
        for changed in [
            text.replace("2026-10-15", "2026-02-30"),
            text.replace("manifest-version='2'", "manifest-version='3'"),
        ] {
            assert!(Manifest::parse(changed.as_bytes(), "1.99.1").is_err());
        }
        let changed = text.replace(
            "minimal=['rustc','cargo','rust-std','rust-mingw']",
            "minimal=['rustc','cargo']",
        );
        assert!(
            Manifest::parse(changed.as_bytes(), "1.99.1")
                .unwrap()
                .select(&request())
                .is_err()
        );
    }
}
