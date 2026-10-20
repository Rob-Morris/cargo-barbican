use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use toml::Spanned;

use super::{PinRefreshError, PinRefreshPlan};
use crate::parse_reviewed_targets_toml;

#[derive(Deserialize)]
struct Document {
    rust: Rust,
}
#[derive(Deserialize)]
struct Rust {
    families: Vec<Family>,
}
#[derive(Deserialize)]
struct Family {
    name: String,
    #[serde(default)]
    resolved: BTreeMap<Spanned<String>, Spanned<Resolved>>,
    #[serde(default)]
    direct: BTreeMap<Spanned<String>, Spanned<toml::Value>>,
    #[serde(default)]
    allowed_surfaces: BTreeMap<Spanned<String>, Spanned<toml::Value>>,
    #[serde(default)]
    allowed_age_exceptions: BTreeMap<Spanned<String>, Spanned<toml::Value>>,
    #[serde(default)]
    allowed_advisories: BTreeMap<Spanned<String>, Spanned<toml::Value>>,
}

enum Resolved {
    Version,
    Structured(Fields),
}
#[derive(Deserialize)]
struct Fields {
    version: Spanned<String>,
    checksum_sha256: Option<Spanned<String>>,
}

impl<'de> Deserialize<'de> for Resolved {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ResolvedVisitor;
        impl<'de> Visitor<'de> for ResolvedVisitor {
            type Value = Resolved;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a reviewed resolved target")
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Resolved, E> {
                Ok(Resolved::Version)
            }
            fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Resolved, A::Error> {
                Fields::deserialize(serde::de::value::MapAccessDeserializer::new(access))
                    .map(Resolved::Structured)
            }
        }
        deserializer.deserialize_any(ResolvedVisitor)
    }
}

struct Edit {
    span: Range<usize>,
    replacement: String,
}

pub(super) fn edit_policy(source: &str, plan: &PinRefreshPlan) -> Result<String, PinRefreshError> {
    let parsed = parse_reviewed_targets_toml(source).map_err(|_| unsupported())?;
    if parsed != plan.original {
        return Err(PinRefreshError::reject(
            "policy changed after refresh planning",
        ));
    }
    let document: Document = toml::from_str(source).map_err(|_| unsupported())?;
    let mut edits = Vec::new();
    for change in &plan.changes {
        let family = document
            .rust
            .families
            .iter()
            .find(|family| family.name == change.family)
            .ok_or_else(unsupported)?;
        let name = change.selected.spec().crate_name();
        let (_, entry) = family
            .resolved
            .iter()
            .find(|(key, _)| key.get_ref() == name)
            .ok_or_else(unsupported)?;
        let version = change.selected.version();
        let checksum = change
            .selected
            .checksum_sha256()
            .expect("planned registry refresh has a checksum")
            .as_str();
        match entry.get_ref() {
            Resolved::Version => edits.push(Edit {
                span: entry.span(),
                replacement: format!(
                    "{{ version = \"{version}\", checksum_sha256 = \"{checksum}\" }}"
                ),
            }),
            Resolved::Structured(fields) => {
                edits.push(Edit {
                    span: fields.version.span(),
                    replacement: format!("\"{version}\""),
                });
                edits.push(Edit {
                    span: fields
                        .checksum_sha256
                        .as_ref()
                        .ok_or_else(unsupported)?
                        .span(),
                    replacement: format!("\"{checksum}\""),
                });
            }
        }
        if let Some(direct) = &change.direct {
            let (_, value) = family
                .direct
                .iter()
                .find(|(key, _)| key.get_ref() == name)
                .ok_or_else(unsupported)?;
            edits.push(Edit {
                span: value.span(),
                replacement: format!("\"{direct}\""),
            });
        }
        for grants in [
            &family.allowed_surfaces,
            &family.allowed_age_exceptions,
            &family.allowed_advisories,
        ] {
            if let Some((key, value)) = grants.iter().find(|(key, _)| key.get_ref() == name) {
                let start = key.span().start;
                let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
                if !source[line_start..start].trim().is_empty()
                    || source
                        .get(key.span().end..value.span().start)
                        .map(str::trim)
                        != Some("=")
                {
                    return Err(unsupported());
                }
                edits.push(Edit {
                    span: start..value.span().end,
                    replacement: String::new(),
                });
            }
        }
    }
    edits.sort_by_key(|edit| edit.span.start);
    let mut result = String::with_capacity(source.len());
    let mut cursor = 0;
    for edit in edits {
        if edit.span.start < cursor
            || edit.span.end < edit.span.start
            || !source.is_char_boundary(edit.span.start)
            || !source.is_char_boundary(edit.span.end)
        {
            return Err(unsupported());
        }
        result.push_str(&source[cursor..edit.span.start]);
        result.push_str(&edit.replacement);
        cursor = edit.span.end;
    }
    result.push_str(&source[cursor..]);
    if parse_reviewed_targets_toml(&result).ok().as_ref() != Some(&plan.expected) {
        return Err(PinRefreshError::reject(
            "refresh editor did not produce exactly the approved policy changes; no writes made",
        ));
    }
    Ok(result)
}

fn unsupported() -> PinRefreshError {
    PinRefreshError::reject(
        "unsupported source-preserving TOML layout; use the printed registry target facts for manual review; no writes made",
    )
}
