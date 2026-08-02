//! Classification of dependency review-record files for the reviewed-target
//! gate.
//!
//! `pin add` and `pin exception` scaffold a review-record stub carrying the
//! [`REVIEW_RECORD_SCAFFOLD_MARKER`]. A reviewer completes the record and
//! deletes the marker line. Until then the record is an unreviewed scaffold:
//! it must not satisfy any gate, or the tool would automate approving its own
//! intake. Blank records fail closed for the same reason.

/// Greppable sentinel emitted into every scaffolded review-record stub. A
/// completed review deletes the line carrying it; while it remains, the record
/// is an unreviewed scaffold that [`classify_review_record`] reports as a
/// [`ReviewRecordStatus::ScaffoldPlaceholder`]. It is deliberately distinctive
/// so a real completed review never carries it by accident.
pub const REVIEW_RECORD_SCAFFOLD_MARKER: &str = "BARBICAN-REVIEW-PENDING";

/// The gate-relevant state of a family's review-record file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewRecordStatus {
    /// No regular, non-symlink file at the configured path.
    Missing,
    /// The file is present but empty or whitespace-only.
    Empty,
    /// The file still carries [`REVIEW_RECORD_SCAFFOLD_MARKER`]: an unreviewed
    /// scaffold stub.
    ScaffoldPlaceholder,
    /// A present record with reviewed content and no scaffold marker.
    Completed,
}

impl ReviewRecordStatus {
    /// Only a completed record satisfies the reviewed-target gate. Missing,
    /// empty, and scaffold-placeholder records all fail closed, so an
    /// unfinished `pin add` / `pin exception` scaffold cannot satisfy the gate
    /// it was written to prepare.
    pub fn is_satisfied(&self) -> bool {
        matches!(self, ReviewRecordStatus::Completed)
    }
}

/// Classifies review-record content the shell has already read. `None` is a
/// missing or non-regular file; the shell maps a refused symlink to `None`
/// too, so a swapped symlink cannot satisfy the gate.
pub fn classify_review_record(content: Option<&str>) -> ReviewRecordStatus {
    match content {
        None => ReviewRecordStatus::Missing,
        Some(text) if text.trim().is_empty() => ReviewRecordStatus::Empty,
        Some(text) if text.contains(REVIEW_RECORD_SCAFFOLD_MARKER) => {
            ReviewRecordStatus::ScaffoldPlaceholder
        }
        Some(_) => ReviewRecordStatus::Completed,
    }
}

#[cfg(test)]
mod tests {
    use super::{REVIEW_RECORD_SCAFFOLD_MARKER, ReviewRecordStatus, classify_review_record};

    #[test]
    fn missing_content_is_not_satisfied() {
        let status = classify_review_record(None);
        assert_eq!(status, ReviewRecordStatus::Missing);
        assert!(!status.is_satisfied());
    }

    #[test]
    fn empty_and_whitespace_only_records_are_not_satisfied() {
        for content in ["", "   ", "\n\t\n", "\r\n \r\n"] {
            let status = classify_review_record(Some(content));
            assert_eq!(
                status,
                ReviewRecordStatus::Empty,
                "expected {content:?} to classify as empty"
            );
            assert!(!status.is_satisfied());
        }
    }

    #[test]
    fn a_record_still_carrying_the_scaffold_marker_is_not_satisfied() {
        let stub = format!(
            "# Dependency Review: serde 1.0.228\n\n<!-- {REVIEW_RECORD_SCAFFOLD_MARKER}: complete this. -->\n\n## Summary\n"
        );
        let status = classify_review_record(Some(&stub));
        assert_eq!(status, ReviewRecordStatus::ScaffoldPlaceholder);
        assert!(!status.is_satisfied());
    }

    #[test]
    fn a_completed_record_without_the_marker_is_satisfied() {
        let record = "# Dependency Review: serde 1.0.228\n\n## Summary\n\n- Reviewer: someone\n";
        let status = classify_review_record(Some(record));
        assert_eq!(status, ReviewRecordStatus::Completed);
        assert!(status.is_satisfied());
    }

    #[test]
    fn the_marker_is_detected_anywhere_in_the_record() {
        let record =
            format!("# Dependency Review\n\n## Follow-ups\n\n{REVIEW_RECORD_SCAFFOLD_MARKER}\n");
        assert_eq!(
            classify_review_record(Some(&record)),
            ReviewRecordStatus::ScaffoldPlaceholder
        );
    }
}
