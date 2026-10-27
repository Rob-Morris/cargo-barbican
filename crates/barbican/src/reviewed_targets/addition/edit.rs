use serde::Deserialize;
use toml::Spanned;

use super::{
    FamilyAdditionError, FamilyAdditionPlan, ReviewedDirectTarget, parse_reviewed_targets_toml,
};

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
    name: Spanned<String>,
}

struct Header<'a> {
    start: usize,
    end: usize,
    text: &'a str,
}

pub(super) fn edit_policy(
    source: &str,
    plan: &FamilyAdditionPlan,
) -> Result<String, FamilyAdditionError> {
    if parse_reviewed_targets_toml(source).ok().as_ref() != Some(&plan.original) {
        return Err(FamilyAdditionError::reject(
            "policy changed after addition planning",
        ));
    }
    if plan.is_noop() {
        return Ok(source.to_owned());
    }
    let document: Document = toml::from_str(source).map_err(|_| unsupported())?;
    let mut offset = 0;
    let mut headers = Vec::new();
    for line in source.split_inclusive('\n') {
        let text = line.trim();
        if text.starts_with('[') {
            let text = text.split('#').next().unwrap_or_default().trim();
            if !text.ends_with(']') {
                return Err(unsupported());
            }
            headers.push(Header {
                start: offset,
                end: offset + line.len(),
                text,
            });
        }
        offset += line.len();
    }
    let family_headers = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.text == "[[rust.families]]")
        .collect::<Vec<_>>();
    if family_headers.len() != document.rust.families.len() {
        return Err(unsupported());
    }
    for (index, (_, header)) in family_headers.iter().enumerate() {
        let end = family_headers
            .get(index + 1)
            .map_or(source.len(), |(_, next)| next.start);
        let family = &document.rust.families[index];
        if family.name.span().start < header.end
            || family.name.span().end > end
            || family.name.get_ref() != plan.original.rust_families[index].name()
        {
            return Err(unsupported());
        }
    }
    let (header_index, first) = family_headers[plan.family_index];
    let next_family = family_headers
        .get(plan.family_index + 1)
        .map_or(source.len(), |(_, next)| next.start);
    let end = headers
        .iter()
        .skip(header_index + 1)
        .find(|header| header.start >= next_family || !header.text.starts_with("[rust.families."))
        .map_or(next_family, |header| header.start);
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut direct = String::new();
    let mut tables = String::new();
    for member in plan.members.iter().filter(|member| !member.already_present) {
        let target = member.selected();
        let key = quote(target.spec().crate_name());
        if let Some(value) = member.direct() {
            match value {
                ReviewedDirectTarget::Registry(requirement) => direct.push_str(&format!("{key} = {}{newline}", quote(requirement))),
                ReviewedDirectTarget::Git(git) => tables.push_str(&format!("{newline}[rust.families.direct.{key}]{newline}source = \"git\"{newline}url = {}{newline}rev = {}{newline}", quote(git.url()), quote(git.rev()))),
            }
        }
        tables.push_str(&format!(
            "{newline}[rust.families.resolved.{key}]{newline}version = {}{newline}",
            quote(target.version())
        ));
        if let Some(git) = target.git() {
            tables.push_str(&format!(
                "source = \"git\"{newline}url = {}{newline}rev = {}{newline}",
                quote(git.url()),
                quote(git.rev())
            ));
        } else {
            tables.push_str(&format!(
                "checksum_sha256 = {}{newline}",
                quote(
                    &target
                        .checksum_sha256()
                        .expect("planned registry addition has a checksum")
                        .to_string()
                )
            ));
        }
    }
    let mut insertions = Vec::new();
    if !direct.is_empty() {
        if let Some((index, _)) = headers.iter().enumerate().find(|(_, header)| {
            header.start > first.start
                && header.start < end
                && header.text == "[rust.families.direct]"
        }) {
            let position = headers
                .get(index + 1)
                .map_or(end, |next| next.start.min(end));
            insertions.push((position, format!("{newline}{direct}")));
        } else {
            tables.push_str(&format!("{newline}[rust.families.direct]{newline}{direct}"));
        }
    }
    insertions.push((end, tables));
    insertions.sort_by_key(|(position, _)| *position);
    let mut result = String::new();
    let mut cursor = 0;
    for (position, insertion) in insertions {
        if position < cursor || !source.is_char_boundary(position) {
            return Err(unsupported());
        }
        result.push_str(&source[cursor..position]);
        if !result.ends_with('\n') {
            result.push_str(newline);
        }
        result.push_str(&insertion);
        cursor = position;
    }
    result.push_str(&source[cursor..]);
    if parse_reviewed_targets_toml(&result).ok().as_ref() != Some(&plan.expected) {
        return Err(unsupported());
    }
    Ok(result)
}

fn quote(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn unsupported() -> FamilyAdditionError {
    FamilyAdditionError::reject(
        "unsupported source-preserving TOML layout; use the non-applying proposal for manual pending-first review; no writes made",
    )
}
