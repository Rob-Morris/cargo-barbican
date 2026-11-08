use super::{DistributionError, Encoding, Profile, SelectionRequest, invalid};
use crate::ExactRustToolchainChannel;
use serde::Deserialize;
use std::collections::BTreeSet;

/// Admission's explicit selection policy. An omitted profile means minimal;
/// no ambient Rustup profile, target or installed component changes this request.
/// The older conformance parser intentionally retains its broader syntax.
pub fn parse_repository_selection(
    text: &str,
    host: &str,
    encoding: Encoding,
) -> Result<(ExactRustToolchainChannel, SelectionRequest), DistributionError> {
    if text.len() > 8 * 1024 * 1024 {
        return Err(invalid("toolchain declaration byte limit"));
    }
    let raw: Declaration =
        toml::from_str(text).map_err(|e| invalid(format!("toolchain declaration: {e}")))?;
    let version = semver::Version::parse(&raw.toolchain.channel)
        .map_err(|_| invalid("admission requires exact stable release"))?;
    if !version.pre.is_empty()
        || !version.build.is_empty()
        || version.to_string() != raw.toolchain.channel
    {
        return Err(invalid("admission requires exact stable release"));
    }
    let channel = raw
        .toolchain
        .channel
        .parse()
        .map_err(|e: crate::RustToolchainError| invalid(e.to_string()))?;
    let profile = match raw.toolchain.profile.as_deref() {
        None | Some("minimal") => Profile::Minimal,
        Some("default") => Profile::Default,
        _ => return Err(invalid("unsupported admission profile")),
    };
    let values = |input: Vec<String>| -> Result<Vec<String>, DistributionError> {
        if input.len() > 64 {
            return Err(invalid("selection declaration count limit"));
        }
        let mut unique = BTreeSet::new();
        for value in input {
            if value.is_empty()
                || value.len() > 256
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !unique.insert(value)
            {
                return Err(invalid("invalid or duplicate selection declaration"));
            }
        }
        Ok(unique.into_iter().collect())
    };
    let host = values(vec![host.to_owned()])?
        .pop()
        .expect("one validated host");
    Ok((
        channel,
        SelectionRequest {
            host,
            profile,
            components: values(raw.toolchain.components)?,
            targets: values(raw.toolchain.targets)?,
            encoding,
        },
    ))
}
#[derive(Deserialize)]
struct Declaration {
    toolchain: DeclaredSelection,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredSelection {
    channel: String,
    profile: Option<String>,
    #[serde(default)]
    components: Vec<String>,
    #[serde(default)]
    targets: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_scope_and_omitted_minimal_do_not_consult_ambient_configuration() {
        let (channel,selection)=parse_repository_selection("[toolchain]\nchannel='1.99.1'\ncomponents=['clippy','rustfmt']\ntargets=['aarch64-apple-darwin']","aarch64-apple-darwin",Encoding::Xz).unwrap();
        assert_eq!(channel.as_str(), "1.99.1");
        assert_eq!(selection.profile, Profile::Minimal);
        assert_eq!(selection.components, vec!["clippy", "rustfmt"]);
        assert_eq!(selection.targets, vec!["aarch64-apple-darwin"]);
        assert_eq!(
            parse_repository_selection(
                "[toolchain]\nchannel='1.99.1'\nprofile='default'",
                "aarch64-apple-darwin",
                Encoding::Xz
            )
            .unwrap()
            .1
            .profile,
            Profile::Default
        );
    }
    #[test]
    fn unsupported_admission_shapes_refuse_without_narrowing_legacy_parser() {
        for fields in [
            "channel='nightly-2026-01-01'",
            "channel='1.99.1-beta.1'",
            "channel='stable'",
            "channel='1.99.1'\npath='elsewhere'",
            "channel='1.99.1'\nprofile='complete'",
            "channel='1.99.1'\ncomponents=['clippy','clippy']",
            "channel='1.99.1'\ntargets=['../target']",
            "channel='1.99.1'\nunknown=true",
        ] {
            assert!(
                parse_repository_selection(
                    &format!("[toolchain]\n{fields}"),
                    "aarch64-apple-darwin",
                    Encoding::Xz
                )
                .is_err()
            );
        }
        assert!(
            crate::parse_rust_toolchain_toml("[toolchain]\nchannel='nightly-2026-01-01'").is_ok()
        );
    }
}
