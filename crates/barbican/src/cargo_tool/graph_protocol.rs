use super::{MAX_DEPTH, MAX_GRAPH_NODES, MAX_LINE_BYTES, MAX_RECORD_BYTES, ToolError, require};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub depth: usize,
    pub build_edge: bool,
    pub display: String,
    pub features: BTreeSet<String>,
}

/// Parses only the qualified Cargo ASCII tree protocol; source binding belongs to metadata.
pub fn parse_tree_protocol(input: &str) -> Result<Vec<TreeEntry>, ToolError> {
    require(
        input.len() <= MAX_RECORD_BYTES,
        "Cargo tree output exceeds 8 MiB",
    )?;
    require(!input.is_empty(), "Cargo tree root missing")?;
    let mut entries = Vec::new();
    let mut frames: Vec<String> = Vec::new();
    let mut build_children: Vec<bool> = Vec::new();
    let mut pending_header: Option<usize> = None;
    for line in input.strip_suffix('\n').unwrap_or(input).split('\n') {
        require(
            !line.is_empty() && line.len() <= MAX_LINE_BYTES,
            "empty or overlong Cargo tree line",
        )?;
        require(
            !line.chars().any(char::is_control),
            "control character in Cargo tree protocol",
        )?;
        if let Some(prefix) = line.strip_suffix("[build-dependencies]") {
            let depth = indent_depth(prefix, false)?;
            require(depth < frames.len(), "orphan build-dependencies header")?;
            require(
                pending_header.is_none() && !build_children[depth],
                "duplicate or empty build-dependencies section",
            )?;
            build_children[depth] = true;
            pending_header = Some(depth);
            continue;
        }
        let (prefix, payload) = line
            .split_once("||B1||")
            .ok_or_else(|| ToolError("unexpected Cargo tree record".into()))?;
        let depth = indent_depth(prefix, true)?;
        require(
            depth <= MAX_DEPTH && depth <= frames.len(),
            "Cargo tree depth jump or depth budget exceeded",
        )?;
        if let Some(header) = pending_header.take() {
            require(
                depth == header + 1,
                "build-dependencies header without child",
            )?;
        }
        require(
            depth != 0 || entries.is_empty(),
            "multiple Cargo tree roots",
        )?;
        let (display, feature_text) = payload
            .split_once("||")
            .ok_or_else(|| ToolError("missing Cargo tree feature delimiter".into()))?;
        require(
            !feature_text.contains("||"),
            "extra Cargo tree record field",
        )?;
        tree_display_identity(display)?;
        require(
            !frames[..depth].iter().any(|ancestor| ancestor == display),
            "cyclic Cargo tree",
        )?;
        let feature_values: Vec<_> = if feature_text.is_empty() {
            Vec::new()
        } else {
            feature_text.split(',').collect()
        };
        require(
            feature_values.windows(2).all(|pair| pair[0] < pair[1]),
            "Cargo tree features are not unique and sorted",
        )?;
        for feature in &feature_values {
            super::identity::feature_name(feature)?;
        }
        let build_edge = depth > 0 && build_children[depth - 1];
        frames.truncate(depth);
        frames.push(display.into());
        build_children.truncate(depth);
        build_children.push(false);
        entries.push(TreeEntry {
            depth,
            build_edge,
            display: display.into(),
            features: feature_values.into_iter().map(str::to_owned).collect(),
        });
        require(
            entries.len() <= MAX_GRAPH_NODES,
            "Cargo tree node budget exceeded",
        )?;
    }
    require(
        pending_header.is_none(),
        "truncated Cargo tree build-dependencies section",
    )?;
    require(
        entries.first().is_some_and(|entry| entry.depth == 0),
        "Cargo tree root missing",
    )?;
    Ok(entries)
}
fn indent_depth(prefix: &str, node: bool) -> Result<usize, ToolError> {
    if prefix.is_empty() {
        return Ok(0);
    }
    require(
        prefix.is_ascii() && prefix.len().is_multiple_of(4),
        "malformed Cargo tree indentation",
    )?;
    let mut chunks = prefix.as_bytes().chunks_exact(4).collect::<Vec<_>>();
    if node {
        require(
            matches!(chunks.pop(), Some(b"|-- " | b"`-- ")),
            "Cargo tree node lacks branch marker",
        )?;
    }
    require(
        chunks
            .iter()
            .all(|chunk| matches!(*chunk, b"|   " | b"    ")),
        "unknown Cargo tree indentation",
    )?;
    Ok(prefix.len() / 4)
}
pub fn tree_display_identity(display: &str) -> Result<(&str, &str), ToolError> {
    require(
        !display.contains("(*)")
            && !display.contains("||")
            && !display.chars().any(char::is_control),
        "cycle/truncation or delimiter in Cargo tree identity",
    )?;
    let (package, rest) = display
        .split_once(" v")
        .ok_or_else(|| ToolError("invalid Cargo tree package display".into()))?;
    super::record::name(package)?;
    let (version, mut suffix) = rest
        .split_once(' ')
        .map_or((rest, ""), |(version, suffix)| (version, suffix));
    let parsed = semver::Version::parse(version)
        .map_err(|_| ToolError("invalid Cargo tree exact version".into()))?;
    require(
        parsed.to_string() == version,
        "noncanonical Cargo tree version",
    )?;
    while !suffix.is_empty() {
        let tail = suffix
            .strip_prefix('(')
            .ok_or_else(|| ToolError("unknown Cargo tree display suffix".into()))?;
        let (group, rest) = tail
            .split_once(')')
            .ok_or_else(|| ToolError("unclosed Cargo tree display suffix".into()))?;
        require(
            !group.is_empty() && !group.contains(['(', ')']),
            "malformed Cargo tree display group",
        )?;
        require(
            group == "proc-macro"
                || group.starts_with('/')
                || group.starts_with("https://")
                || group.starts_with("ssh://"),
            "unqualified Cargo tree display group",
        )?;
        suffix = if rest.is_empty() {
            ""
        } else {
            rest.strip_prefix(' ')
                .ok_or_else(|| ToolError("malformed Cargo tree display spacing".into()))?
        };
    }
    Ok((package, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROOT: &str = "||B1||tool v1.0.0 (/tmp/tool)||";
    #[test]
    fn preserves_normal_build_hierarchy_and_feature_contexts() {
        let text = format!(
            "{ROOT}\n|-- ||B1||mac v1.0.0 (proc-macro) (/tmp/mac)||\n|   `-- ||B1||shared v1.0.0 (/tmp/shared)||build,mac\n`-- ||B1||shared v1.0.0 (/tmp/shared)||target\n[build-dependencies]\n`-- ||B1||shared v1.0.0 (/tmp/shared)||build,mac\n"
        );
        let nodes = parse_tree_protocol(&text).unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|n| (n.depth, n.build_edge))
                .collect::<Vec<_>>(),
            vec![(0, false), (1, false), (2, false), (1, false), (1, true)]
        );
        assert_eq!(
            nodes[2].features,
            BTreeSet::from(["build".into(), "mac".into()])
        );
    }
    #[test]
    fn nested_build_headers_do_not_change_siblings() {
        let text = format!(
            "{ROOT}\n|-- ||B1||helper v1.0.0||\n|   [build-dependencies]\n|   `-- ||B1||build v1.0.0||\n`-- ||B1||normal v1.0.0||\n"
        );
        let nodes = parse_tree_protocol(&text).unwrap();
        assert!(nodes[2].build_edge);
        assert!(!nodes[3].build_edge);
    }
    #[test]
    fn unknown_cycles_truncation_and_depth_jumps_refuse() {
        for text in [
            "".into(),
            "unknown".into(),
            format!("{ROOT}\n[build-dependencies]\n"),
            format!("{ROOT}\n`-- ||B1||tool v1.0.0 (/tmp/tool)||"),
            format!("{ROOT}\n|   `-- ||B1||child v1.0.0||"),
            format!("{ROOT}\n`-- ||B1||child v1.0.0 (*)||"),
            format!("{ROOT}\n`-- ||B1||child v1.0.0||z,a"),
            format!("{ROOT}\n`-- ||B1||child v1.0.0||a,a"),
            format!("{ROOT}\n{ROOT}"),
            format!("{ROOT}\n[dev-dependencies]"),
            format!("{ROOT}\n\n"),
        ] {
            assert!(parse_tree_protocol(&text).is_err(), "{text:?}");
        }
    }
    #[test]
    fn output_line_and_depth_budgets_are_inclusive() {
        assert!(parse_tree_protocol(&"x".repeat(MAX_RECORD_BYTES + 1)).is_err());
        assert!(parse_tree_protocol(&format!("{ROOT}{}", "x".repeat(MAX_LINE_BYTES))).is_err());
        let mut graph = ROOT.to_owned();
        for depth in 1..=MAX_DEPTH {
            graph.push_str(&format!(
                "\n{}`-- ||B1||p{depth} v1.0.0||",
                "    ".repeat(depth - 1)
            ));
        }
        assert!(parse_tree_protocol(&graph).is_ok());
        graph.push_str(&format!(
            "\n{}`-- ||B1||overflow v1.0.0||",
            "    ".repeat(MAX_DEPTH)
        ));
        assert!(parse_tree_protocol(&graph).is_err());
    }
    #[test]
    fn node_budget_is_inclusive_and_counts_repeated_tree_occurrences() {
        let mut graph = ROOT.to_owned();
        for _ in 1..MAX_GRAPH_NODES {
            graph.push_str("\n|-- ||B1||shared v1.0.0||");
        }
        assert_eq!(parse_tree_protocol(&graph).unwrap().len(), MAX_GRAPH_NODES);
        graph.push_str("\n`-- ||B1||shared v1.0.0||");
        assert!(parse_tree_protocol(&graph).is_err());
    }
}
