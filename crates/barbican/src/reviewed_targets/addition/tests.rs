use super::*;
use crate::{
    ExactCrateSpec, Sha256Digest, classify_review_record, compose_pin_family_stub,
    parse_manifest_direct_requirements,
};

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REV: &str = "0123456789abcdef0123456789abcdef01234567";

fn lock(extra: &str) -> Lockfile {
    crate::parse_lockfile(&format!("version=4\n[[package]]\nname='old'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{HASH}'\n[[package]]\nname='new'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{HASH}'\n{extra}")).unwrap()
}

fn policy() -> String {
    compose_pin_family_stub(
        "family",
        "review.md",
        &ExactCrateSpec::from_parts("old", "1.0.0").unwrap(),
        Some(&Sha256Digest::try_from(HASH).unwrap()),
        Some("=1.0.0"),
        &[],
    )
}

fn plan(source: &str, requests: &[&str]) -> Result<FamilyAdditionPlan, FamilyAdditionError> {
    plan_family_addition(
        &parse_reviewed_targets_toml(source).unwrap(),
        &lock(""),
        &[],
        "family",
        &requests
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn generated_create_extend_extend_again_preserves_history_and_grants() {
    let original =
        policy() + "\n# retained comment\n[rust.families.allowed_surfaces]\nold=['build-rs']\n";
    let plan = plan(&original, &["old", "new"]).unwrap();
    assert!(plan.members()[0].already_present());
    let edited = plan.edit_policy(&original).unwrap();
    assert!(edited.starts_with(&original));
    let parsed = parse_reviewed_targets_toml(&edited).unwrap();
    assert_eq!(
        parsed.rust_families()[0]
            .execution_surface_allowances()
            .len(),
        1
    );
    assert_eq!(parsed.rust_families()[0].resolved().len(), 2);
    assert!(
        super::tests::plan(&edited, &["old", "new"])
            .unwrap()
            .is_noop()
    );
    assert_eq!(
        super::tests::plan(&edited, &["old", "new"])
            .unwrap()
            .edit_policy(&edited)
            .unwrap(),
        edited
    );
}

#[test]
fn exact_new_direct_and_direct_only_intent_are_preserved() {
    for direct in ["", "[rust.families.direct]\nnew='=1.0.0'\n"] {
        let source = format!(
            "[[rust.families]]\nname='family'\nreview_record='review.md'\n[rust.families.resolved]\nold={{version='1.0.0',checksum_sha256='{HASH}'}}\n{direct}"
        );
        let requirements =
            parse_manifest_direct_requirements("Cargo.toml", "[dependencies]\nnew='=1.0.0'\n")
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>();
        let plan = plan_family_addition(
            &parse_reviewed_targets_toml(&source).unwrap(),
            &lock(""),
            &requirements,
            "family",
            &["new".to_owned()],
        )
        .unwrap();
        let edited = plan.edit_policy(&source).unwrap();
        assert_eq!(
            parse_reviewed_targets_toml(&edited)
                .unwrap()
                .rust_families()[0]
                .direct()["new"]
                .requirement(),
            Some("=1.0.0")
        );
    }
    let source = "[[rust.families]]\nname='family'\nreview_record='review.md'\n[rust.families.resolved]\nold='1.0.0'\n[rust.families.direct]\nnew='=2.0.0'\n";
    assert!(
        plan(source, &["new"])
            .unwrap_err()
            .to_string()
            .contains("direct intent")
    );
}

#[test]
fn conflicting_and_duplicate_requests_refuse_the_entire_plan() {
    let source = policy();
    for requests in [
        &["new", "absent"][..],
        &["new", "new@1.0.0"],
        &["old@2.0.0"],
    ] {
        assert!(plan(&source, requests).is_err());
    }
    let foreign = source.clone()
        + "\n[[rust.families]]\nname='other'\nreview_record='other.md'\n[rust.families.resolved]\nnew='1.0.0'\n";
    assert!(
        plan(&foreign, &["new"])
            .unwrap_err()
            .to_string()
            .contains("another family")
    );
    let legacy = source[..source.find("[rust.families.resolved.old]").unwrap()].to_owned()
        + "[rust.families.resolved]\nold='1.0.0'\n";
    assert!(plan(&legacy, &["old"]).is_err());
}

#[test]
fn selected_version_cannot_hide_siblings_or_missing_checksum() {
    let source = parse_reviewed_targets_toml(&policy()).unwrap();
    for extra in [format!("[[package]]\nname='new'\nversion='2.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{HASH}'\n"), "[[package]]\nname='new'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n".to_owned()] {
        assert!(plan_family_addition(&source, &lock(&extra), &[], "family", &["new@1.0.0".to_owned()]).is_err());
    }
}

#[test]
fn exact_git_and_mixed_family_layouts_repeat_without_source_migration() {
    let extra = format!(
        "[[package]]\nname='gittool'\nversion='1.2.3'\nsource='git+https://example.invalid/tool?rev={REV}#{REV}'\n"
    );
    let source = policy();
    let requirements = parse_manifest_direct_requirements("Cargo.toml", &format!("[dependencies]\ngittool={{git='https://example.invalid/tool',rev='{REV}',version='^1'}}\n")).unwrap().into_iter().collect::<Vec<_>>();
    let plan = plan_family_addition(
        &parse_reviewed_targets_toml(&source).unwrap(),
        &lock(&extra),
        &requirements,
        "family",
        &["gittool".to_owned()],
    )
    .unwrap();
    let edited = plan.edit_policy(&source).unwrap();
    let parsed = parse_reviewed_targets_toml(&edited).unwrap();
    assert!(
        parsed.rust_families()[0].resolved()["gittool"]
            .git()
            .is_some()
    );
    assert!(
        plan_family_addition(
            &parsed,
            &lock(&extra),
            &requirements,
            "family",
            &["gittool".to_owned()]
        )
        .unwrap()
        .is_noop()
    );
    let next = plan_family_addition(
        &parsed,
        &lock(&extra),
        &requirements,
        "family",
        &["new".to_owned()],
    )
    .unwrap()
    .edit_policy(&edited)
    .unwrap();
    assert_eq!(
        parse_reviewed_targets_toml(&next).unwrap().rust_families()[0]
            .resolved()
            .len(),
        3
    );
}

#[test]
fn registry_direct_addition_extends_actual_generated_implicit_git_parent() {
    let extra = format!(
        "[[package]]\nname='gittool'\nversion='1.2.3'\nsource='git+https://example.invalid/tool?rev={REV}#{REV}'\n"
    );
    let requirements = parse_manifest_direct_requirements("Cargo.toml", &format!("[dependencies]\ngittool={{git='https://example.invalid/tool',rev='{REV}'}}\nnew='=1.0.0'\n")).unwrap().into_iter().collect::<Vec<_>>();
    let initial = crate::plan_pin_add(
        &lock(&extra),
        &ReviewedTargets::default(),
        &requirements,
        &parse_pin_add_target("gittool").unwrap(),
        "family".to_owned(),
        "review.md".to_owned(),
        Date::from_calendar_date(2026, time::Month::October, 27).unwrap(),
    )
    .unwrap();
    let source = initial.family_stub();
    assert!(source.contains("[rust.families.direct.gittool]"));
    assert!(!source.contains("[rust.families.direct]\n"));
    let first = plan_family_addition(
        &parse_reviewed_targets_toml(source).unwrap(),
        &lock(&extra),
        &requirements,
        "family",
        &["new".to_owned()],
    )
    .unwrap()
    .edit_policy(source)
    .unwrap();
    assert_eq!(
        parse_reviewed_targets_toml(&first).unwrap().rust_families()[0].direct()["new"]
            .requirement(),
        Some("=1.0.0")
    );
    let second = plan_family_addition(
        &parse_reviewed_targets_toml(&first).unwrap(),
        &lock(&extra),
        &requirements,
        "family",
        &["old".to_owned()],
    )
    .unwrap()
    .edit_policy(&first)
    .unwrap();
    assert_eq!(
        parse_reviewed_targets_toml(&second)
            .unwrap()
            .rust_families()[0]
            .resolved()
            .len(),
        3
    );
}

#[test]
fn edits_only_selected_first_middle_last_family_and_preserves_crlf() {
    for position in 0..3 {
        let mut source = String::new();
        for index in 0..3 {
            source.push_str(&format!("# before {index}\n[[rust.families]]\nname='{}'\nreview_record='{index}.md'\n[rust.families.resolved]\nold='1.0.0'\n", if index==position { "family".to_owned() } else {format!("other{index}")}));
        }
        source.push_str("\n# unrelated trailing comment\n");
        source = source.replace('\n', "\r\n");
        let edited = plan(&source, &["new"])
            .unwrap()
            .edit_policy(&source)
            .unwrap();
        let parsed = parse_reviewed_targets_toml(&edited).unwrap();
        for (index, family) in parsed.rust_families().iter().enumerate() {
            assert_eq!(family.resolved().contains_key("new"), index == position);
        }
        assert!(edited.contains("# unrelated trailing comment\r\n"));
        assert!(!edited.replace("\r\n", "").contains('\n'));
    }
}

#[test]
fn unsupported_inline_policy_has_no_automatic_edit_but_matching_noop_is_valid() {
    let source = format!(
        "[rust]\nfamilies=[{{name='family',review_record='r.md',resolved={{old={{version='1.0.0',checksum_sha256='{HASH}'}}}}}}]\n"
    );
    assert!(
        plan(&source, &["new"])
            .unwrap()
            .edit_policy(&source)
            .is_err()
    );
    let noop = plan(&source, &["old"]).unwrap();
    assert!(noop.is_noop());
    assert_eq!(noop.edit_policy(&source).unwrap(), source);
}

#[test]
fn record_append_preserves_pending_and_history_and_cannot_inject_marker() {
    let source = policy().replace("family", "BARBICAN-REVIEW-PENDING <scope>");
    let name = "BARBICAN-REVIEW-PENDING <scope>";
    let plan = plan_family_addition(
        &parse_reviewed_targets_toml(&source).unwrap(),
        &lock(""),
        &[],
        name,
        &["new".to_owned()],
    )
    .unwrap();
    let date = Date::from_calendar_date(2026, time::Month::October, 27).unwrap();
    let original = "# Evidence\nHistorical bytes unchanged\n";
    let first = plan.compose_record(original, &[name.to_owned()], date);
    assert!(first.contains("Historical bytes unchanged\n"));
    assert_eq!(first.matches(REVIEW_RECORD_SCAFFOLD_MARKER).count(), 1);
    assert!(!first.contains("<scope>"));
    let second = plan.compose_record(&first, &[name.to_owned()], date);
    assert!(second.starts_with(&first));
    assert_eq!(second.matches(REVIEW_RECORD_SCAFFOLD_MARKER).count(), 1);
    assert!(!classify_review_record(Some(&second)).is_satisfied());
}
