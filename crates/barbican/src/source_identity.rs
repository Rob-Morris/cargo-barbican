use std::fmt;

use thiserror::Error;

use crate::{CRATES_IO_SOURCE, ExactCrateSpec};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitSourceIdentity {
    url: String,
    rev: String,
}

impl GitSourceIdentity {
    pub fn new(url: &str, rev: &str) -> Result<Self, GitSourceError> {
        if !canonical_repository_url(url) {
            return Err(GitSourceError::UnsupportedRepositoryUrl);
        }
        if rev.len() != 40
            || !rev
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GitSourceError::RevisionNotExact);
        }
        Ok(Self {
            url: url.to_owned(),
            rev: rev.to_owned(),
        })
    }

    pub fn from_locked_source(source: &str) -> Result<Self, GitSourceError> {
        let (url, selector) = source
            .strip_prefix("git+")
            .and_then(|source| source.split_once("?rev="))
            .ok_or(GitSourceError::SourceNotExact)?;
        let (requested, resolved) = selector
            .split_once('#')
            .ok_or(GitSourceError::SourceNotExact)?;
        let identity = Self::new(url, requested)?;
        if requested != resolved {
            return Err(GitSourceError::SourceNotExact);
        }
        Ok(identity)
    }

    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn rev(&self) -> &str {
        &self.rev
    }
    pub fn locked_source(&self) -> String {
        format!("git+{}?rev={}#{}", self.url, self.rev, self.rev)
    }
    pub fn declaration_source(&self) -> String {
        format!("git+{}?rev={}", self.url, self.rev)
    }
}

impl fmt::Display for GitSourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} rev {}", self.url, self.rev)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GitSourceError {
    #[error(
        "unsupported Git repository URL; use canonical credential-free HTTPS or ssh:// ASCII host/path spelling"
    )]
    UnsupportedRepositoryUrl,
    #[error(
        "Git revision must be a full lower-case 40-hex commit ID; branches, tags and abbreviated revisions are unsupported"
    )]
    RevisionNotExact,
    #[error("Git source must request and resolve the same full commit with ?rev=<commit>#<commit>")]
    SourceNotExact,
}

fn canonical_repository_url(url: &str) -> bool {
    let (ssh, rest) = match url.strip_prefix("https://") {
        Some(rest) => (false, rest),
        None => match url.strip_prefix("ssh://") {
            Some(rest) => (true, rest),
            None => return false,
        },
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    let host_port = if let Some((user, host)) = authority.split_once('@') {
        if !ssh
            || user.is_empty()
            || !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return false;
        }
        host
    } else {
        authority
    };
    let host = if let Some((host, port)) = host_port.split_once(':') {
        if port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().is_none_or(|port| port == 0)
        {
            return false;
        }
        host
    } else {
        host_port
    };
    if host.is_empty()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return false;
    }
    !path.is_empty()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._~-".contains(&byte))
        && path
            .strip_suffix('/')
            .unwrap_or(path)
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn source_diagnostic(source: Option<&str>) -> String {
    match source {
        Some(CRATES_IO_SOURCE) => "crates.io".to_owned(),
        Some(source) if source.starts_with("git+") => GitSourceIdentity::from_locked_source(source)
            .map_or_else(
                |_| "(unsupported Git source)".to_owned(),
                |identity| identity.to_string(),
            ),
        Some(_) => "(unsupported external source)".to_owned(),
        None => "(no source: path or workspace member)".to_owned(),
    }
}

pub fn is_source_spec_input(input: &str) -> bool {
    input.contains("://")
        || input.starts_with("git+")
        || (input.starts_with("git@") && input.contains(':'))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolvedPackageIdentity {
    spec: ExactCrateSpec,
    source: Option<String>,
}

impl ResolvedPackageIdentity {
    pub fn new(spec: ExactCrateSpec, source: Option<&str>) -> Self {
        Self {
            spec,
            source: source.map(str::to_owned),
        }
    }
    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const REV: &str = "901f9946efdaaa289e6b1c5bd56dc67f4b651e51";

    #[test]
    fn exact_git_identity_preserves_repository_spelling() {
        for url in [
            "https://example.org/team/repo.git",
            "https://example.org/team/repo",
            "https://example.org/team/repo.git/",
            "ssh://git@example.org:2222/Team/Repo.git",
        ] {
            let identity = GitSourceIdentity::new(url, REV).unwrap();
            assert_eq!(
                GitSourceIdentity::from_locked_source(&identity.locked_source()).unwrap(),
                identity
            );
        }
        assert_ne!(
            GitSourceIdentity::new("https://example.org/repo", REV).unwrap(),
            GitSourceIdentity::new("https://example.org/repo.git", REV).unwrap()
        );
    }

    #[test]
    fn mutable_or_contradictory_sources_never_become_reviewed_identities() {
        for source in [
            format!("git+https://example.org/repo?branch=main#{REV}"),
            format!("git+https://example.org/repo?rev=901f9946#{REV}"),
            format!("git+https://example.org/repo?rev={REV}#{}", "0".repeat(40)),
            format!("git+https://example.org/repo?rev={REV}&tag=x#{REV}"),
            format!("git+https://example.org/repo#{REV}"),
        ] {
            assert!(GitSourceIdentity::from_locked_source(&source).is_err());
        }
    }

    #[test]
    fn unsupported_url_diagnostics_do_not_echo_credentials() {
        for url in [
            "https://user:SECRET@example.org/repo",
            "https://example.org/repo?token=SECRET",
            "file:///tmp/repo",
            "http://example.org/repo",
            "https://EXAMPLE.org/repo",
            "https://example.org/a/../repo",
            "ssh://git:SECRET@example.org/repo",
            "https://example.org/a%20b",
        ] {
            assert!(GitSourceIdentity::new(url, REV).is_err());
            assert!(
                !source_diagnostic(Some(&format!("git+{url}?rev={REV}#{REV}"))).contains("SECRET")
            );
        }
    }
}
