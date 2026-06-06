use std::path::Path;

use similar::TextDiff;

pub(super) fn render_unified_file_diff(
    relative_path: &Path,
    base_text: Option<&str>,
    current_text: Option<&str>,
) -> String {
    let relative_display = relative_path.display().to_string();
    let base_label = format!("a/{relative_display}");
    let current_label = format!("b/{relative_display}");
    let old_header = if base_text.is_some() {
        base_label.as_str()
    } else {
        "/dev/null"
    };
    let new_header = if current_text.is_some() {
        current_label.as_str()
    } else {
        "/dev/null"
    };

    let mut rendered = format!("diff --git {base_label} {current_label}\n");
    let diff = TextDiff::from_lines(base_text.unwrap_or(""), current_text.unwrap_or(""));
    let unified = diff
        .unified_diff()
        .context_radius(3)
        .header(old_header, new_header)
        .to_string();

    if unified.is_empty() {
        rendered.push_str(&format!("--- {old_header}\n+++ {new_header}\n"));
    } else {
        rendered.push_str(&unified);
    }

    rendered
}
