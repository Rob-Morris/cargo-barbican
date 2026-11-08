use super::{DistributionError, invalid};
use serde::Deserialize;

#[derive(Deserialize)]
struct Intent {
    toolchain: Toolchain,
}
#[derive(Deserialize)]
struct Toolchain {
    channel: toml::Spanned<String>,
}

/// Plan only an existing channel value replacement; filesystem publication belongs to the binary.
/// All other bytes, including comments and unrelated declarations, are retained verbatim.
pub fn replace_channel(text: &str, exact_release: &str) -> Result<String, DistributionError> {
    if text.len() > 2 * 1024 * 1024 {
        return Err(invalid("toolchain intent byte limit"));
    }
    let release = semver::Version::parse(exact_release)
        .map_err(|_| invalid("expected exact stable release"))?;
    if !release.pre.is_empty() || !release.build.is_empty() || release.to_string() != exact_release
    {
        return Err(invalid("expected exact stable release"));
    }
    let parsed: Intent =
        toml::from_str(text).map_err(|e| invalid(format!("toolchain intent: {e}")))?;
    let before: toml::Value = toml::from_str(text).map_err(|e| invalid(e.to_string()))?;
    if parsed.toolchain.channel.get_ref() == exact_release {
        return Ok(text.to_owned());
    }
    let span = parsed.toolchain.channel.span();
    if text.get(span.clone()).is_none() {
        return Err(invalid("invalid channel source span"));
    }
    // Exact stable release syntax contains only digits and dots: quoted output cannot inject TOML.
    let mut output = String::with_capacity(text.len() + exact_release.len() + 2);
    output.push_str(&text[..span.start]);
    output.push('"');
    output.push_str(exact_release);
    output.push('"');
    output.push_str(&text[span.end..]);
    let after: toml::Value =
        toml::from_str(&output).map_err(|e| invalid(format!("edited toolchain intent: {e}")))?;
    let mut expected = before;
    expected
        .get_mut("toolchain")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| invalid("missing toolchain table"))?
        .insert("channel".into(), toml::Value::String(exact_release.into()));
    if after != expected {
        return Err(invalid("channel edit changed unrelated TOML values"));
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_every_byte_outside_parsed_value_in_supported_forms() {
        for (source, old) in [
            (
                "# 🦀\n[toolchain]\nchannel = '1.95.0' # preserve\nprofile='minimal'\n",
                "'1.95.0'",
            ),
            ("toolchain.channel=\"1.95.0\"\n", "\"1.95.0\""),
            (
                "toolchain = { channel = '1.95.0', profile = 'default' }\n",
                "'1.95.0'",
            ),
            (
                "['toolchain']\n'channel'=\"\"\"1.95.0\"\"\"\n",
                "\"\"\"1.95.0\"\"\"",
            ),
            ("[toolchain]\nchannel='''1.95.0'''\n", "'''1.95.0'''"),
        ] {
            assert_eq!(
                replace_channel(source, "1.99.1").unwrap(),
                source.replacen(old, "\"1.99.1\"", 1)
            );
        }
    }
    #[test]
    fn refuses_missing_invalid_or_nonstable_and_preserves_noop() {
        for source in [
            "",
            "[toolchain]\nprofile='minimal'",
            "toolchain='x'",
            "[toolchain]\nchannel=123",
            "[toolchain]\nchannel='a'\nchannel='b'",
        ] {
            assert!(replace_channel(source, "1.99.1").is_err());
        }
        let source = "[toolchain]\nchannel='1.99.1' # keep\n";
        assert_eq!(replace_channel(source, "1.99.1").unwrap(), source);
        assert!(replace_channel(source, "stable").is_err());
    }
}
