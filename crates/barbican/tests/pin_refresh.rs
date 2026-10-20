use barbican::{
    parse_lockfile, parse_manifest_direct_requirements, parse_reviewed_targets_toml,
    plan_pin_refresh,
};

#[test]
fn same_name_siblings_cannot_be_hidden_by_explicit_version() {
    let source = policy(false, false);
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    let mut first = String::from(
        "version=4\n[[package]]\nname='demo'\nversion='1.1.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='",
    );
    first.push_str(NEW);
    first.push_str("'\n");
    for (version, source, checksum) in [
        (
            "1.1.0",
            Some(
                "git+https://example.invalid/repo?rev=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            None,
        ),
        ("1.1.0", None, None),
        (
            "1.1.0",
            Some("registry+https://example.invalid/index"),
            Some(NEW),
        ),
        ("1.2.0", Some(barbican::CRATES_IO_SOURCE), Some(NEW)),
        ("1.1.0", Some(barbican::CRATES_IO_SOURCE), None),
        ("1.1.0", Some(barbican::CRATES_IO_SOURCE), Some(OLD)),
    ] {
        let mut raw = format!("{first}[[package]]\nname='demo'\nversion='{version}'\n");
        if let Some(source) = source {
            raw.push_str(&format!("source='{source}'\n"));
        }
        if let Some(checksum) = checksum {
            raw.push_str(&format!("checksum='{checksum}'\n"));
        }
        assert!(
            plan_pin_refresh(
                &parsed,
                &parse_lockfile(&raw).unwrap(),
                &[],
                &["demo@1.1.0".into()]
            )
            .is_err()
        );
    }
}

#[test]
fn ambiguous_family_coverage_and_unrelated_added_identity_do_not_authorise_refresh() {
    let source = policy(false, false);
    let extra = format!(
        "[[rust.families]]\nname='second'\nreview_record='other.md'\n[rust.families.resolved]\ndemo={{version='1.0.0',checksum_sha256='{OLD}'}}\n"
    );
    let parsed = parse_reviewed_targets_toml(&format!("{source}{extra}")).unwrap();
    assert!(plan_pin_refresh(&parsed, &lock("1.1.0", NEW), &[], &["demo".into()]).is_err());
    let source = policy(false, false);
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    let current = lock("1.1.0", NEW);
    let plan = plan_pin_refresh(&parsed, &current, &[], &["demo".into()]).unwrap();
    let raw = format!(
        "version=4\n[[package]]\nname='demo'\nversion='1.1.0'\nsource='{}'\nchecksum='{NEW}'\n[[package]]\nname='unrelated'\nversion='1.0.0'\nsource='{}'\nchecksum='{NEW}'\n",
        barbican::CRATES_IO_SOURCE,
        barbican::CRATES_IO_SOURCE
    );
    let changed = parse_lockfile(&raw).unwrap();
    assert!(plan.validate_baseline(&changed, &current).is_err());
}

#[test]
fn untouched_grants_and_git_targets_survive_a_multi_target_family_edit() {
    let source = policy(false, true);
    let extra = format!(
        "other=[{{id='RUSTSEC-2020-0002',review_by='2099-01-01'}}]\n[rust.families.resolved.other]\nversion='1.0.0'\nchecksum_sha256='{OLD}'\n[rust.families.resolved.git_child]\nsource='git'\nversion='1.0.0'\nurl='https://example.invalid/untouched'\nrev='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"
    );
    let parsed = parse_reviewed_targets_toml(&format!("{source}{extra}")).unwrap();
    let plan = plan_pin_refresh(&parsed, &lock("1.1.0", NEW), &[], &["demo".into()]).unwrap();
    let updated = plan.edit_policy(&format!("{source}{extra}")).unwrap();
    let result = parse_reviewed_targets_toml(&updated).unwrap();
    assert_eq!(result.advisory_exceptions().len(), 1);
    assert_eq!(result.advisory_exceptions()[0].spec().crate_name(), "other");
    assert_eq!(
        result.rust_families()[0].resolved()["git_child"],
        parsed.rust_families()[0].resolved()["git_child"]
    );
    assert!(updated.ends_with(&extra));
}

#[test]
fn pending_record_history_is_grouped_and_marker_like_data_does_not_create_a_second_sentinel() {
    let source = policy(false, false).replace("name='family'", "name='BARBICAN-REVIEW-PENDING'");
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    let plan = plan_pin_refresh(&parsed, &lock("1.1.0", NEW), &[], &["demo".into()]).unwrap();
    let text = barbican::compose_refresh_record(
        "# Old review\n",
        &[&plan.changes()[0]],
        &["BARBICAN-REVIEW-PENDING".into()],
        barbican::parse_iso_date("2026-10-20").unwrap(),
    );
    assert_eq!(
        text.matches(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
            .count(),
        1
    );
    let retry = barbican::compose_refresh_record(
        &text,
        &[&plan.changes()[0]],
        &["BARBICAN-REVIEW-PENDING".into()],
        barbican::parse_iso_date("2026-10-20").unwrap(),
    );
    assert_eq!(
        retry
            .matches(barbican::REVIEW_RECORD_SCAFFOLD_MARKER)
            .count(),
        1
    );
    assert!(retry.starts_with(&text));
}

#[test]
fn unsupported_grant_table_layout_refuses_instead_of_dropping_unrelated_policy() {
    let source = format!(
        "{}\n[[rust.families.allowed_advisories.demo]]\nid='RUSTSEC-2020-0001'\nreview_by='2099-01-01'\n",
        policy(false, false)
    );
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    let plan = plan_pin_refresh(&parsed, &lock("1.1.0", NEW), &[], &["demo".into()]).unwrap();
    assert!(plan.edit_policy(&source).is_err());
}

const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn lock(version: &str, digest: &str) -> barbican::Lockfile {
    parse_lockfile(&format!("version=4\n[[package]]\nname='demo'\nversion='{version}'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{digest}'\n")).unwrap()
}
fn policy(nested: bool, grants: bool) -> String {
    let target = if nested {
        format!(
            "[rust.families.resolved.demo]\nversion = '1.0.0' # version comment\nchecksum_sha256 = '{OLD}'\n"
        )
    } else {
        format!(
            "[rust.families.resolved]\n'demo' = {{ version = '1.0.0', checksum_sha256 = '{OLD}' }} # target comment\n"
        )
    };
    let grants = if grants {
        "[rust.families.allowed_surfaces]\ndemo = ['build-rs'] # surface comment\n[rust.families.allowed_age_exceptions]\ndemo = '1.0.0'\n[rust.families.allowed_advisories]\ndemo = [{ id = 'RUSTSEC-2020-0001', review_by = '2099-01-01' }]\n"
    } else {
        ""
    };
    format!(
        "# retain header\n[[rust.families]]\nname='family'\nreview_record='review.md'\n[rust.families.direct]\ndemo='=1.0.0'\n{target}{grants}"
    )
}
#[test]
fn refresh_withdraws_grants_and_preserves_inline_and_nested_source() {
    for nested in [false, true] {
        let source = policy(nested, true);
        let parsed = parse_reviewed_targets_toml(&source).unwrap();
        let declarations = parse_manifest_direct_requirements(
            "Cargo.toml",
            "[dependencies]\nalias={package='demo',version='=1.1.0'}\n",
        )
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
        let plan = plan_pin_refresh(
            &parsed,
            &lock("1.1.0", NEW),
            &declarations,
            &["demo".into()],
        )
        .unwrap();
        assert_eq!(plan.changes()[0].withdrawn_grants().len(), 3);
        let updated = plan.edit_policy(&source).unwrap();
        let actual = parse_reviewed_targets_toml(&updated).unwrap();
        assert!(actual.execution_surface_allowances().is_empty());
        assert!(actual.release_age_exceptions().is_empty());
        assert!(actual.advisory_exceptions().is_empty());
        assert!(updated.starts_with("# retain header\n"));
        assert!(updated.contains("# surface comment"));
        assert!(updated.contains("# version comment") || updated.contains("# target comment"));
        assert!(updated.contains(NEW));
        assert_eq!(
            actual.rust_families()[0].direct()["demo"].to_string(),
            "=1.1.0"
        );
    }
}
#[test]
fn legacy_checksum_backfill_is_manual_and_old_age_grant_cannot_survive_checksum_change() {
    let source = policy(false, true);
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    let current = lock("1.0.0", NEW);
    let plan = plan_pin_refresh(&parsed, &current, &[], &["demo".into()]).unwrap();
    assert!(
        plan.validate_baseline(&current, &lock("1.0.0", OLD))
            .is_err()
    );
    let updated = plan.edit_policy(&source).unwrap();
    assert!(
        parse_reviewed_targets_toml(&updated)
            .unwrap()
            .release_age_exceptions()
            .is_empty()
    );
    let legacy = source.replace(
        &format!("{{ version = '1.0.0', checksum_sha256 = '{OLD}' }}"),
        "'1.0.0'",
    );
    let legacy = legacy
        .split("[rust.families.allowed_surfaces]")
        .next()
        .unwrap();
    let plan = plan_pin_refresh(
        &parse_reviewed_targets_toml(legacy).unwrap(),
        &current,
        &[],
        &["demo".into()],
    )
    .unwrap();
    assert!(plan.edit_policy(legacy).unwrap().contains(NEW));
}
#[test]
fn baseline_requires_previous_pin_and_new_current_identity_for_each_target() {
    let source = policy(false, false);
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    let current = lock("1.1.0", NEW);
    let plan = plan_pin_refresh(&parsed, &current, &[], &["demo".into()]).unwrap();
    assert!(
        plan.validate_baseline(&current, &lock("1.0.0", OLD))
            .is_ok()
    );
    assert!(plan.validate_baseline(&current, &current).is_err());
    assert!(
        plan.validate_baseline(&current, &parse_lockfile("version=4\n").unwrap())
            .is_err()
    );
    assert!(
        plan.validate_baseline(&current, &lock("1.0.0", NEW))
            .is_err()
    );
}
#[test]
fn duplicate_clean_and_unsupported_sources_never_plan_a_rewrite() {
    let source = policy(false, false);
    let parsed = parse_reviewed_targets_toml(&source).unwrap();
    assert!(plan_pin_refresh(&parsed, &lock("1.0.0", OLD), &[], &["demo".into()]).is_err());
    assert!(
        plan_pin_refresh(
            &parsed,
            &lock("1.1.0", NEW),
            &[],
            &["demo".into(), "demo@1.1.0".into()]
        )
        .is_err()
    );
    let current = lock("1.1.0", NEW);
    let git_source=source.replace(&format!("{{ version = '1.0.0', checksum_sha256 = '{OLD}' }}"),"{ source='git',version='1.0.0',url='https://example.invalid/demo',rev='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }");
    assert!(
        plan_pin_refresh(
            &parse_reviewed_targets_toml(&git_source).unwrap(),
            &current,
            &[],
            &["demo".into()]
        )
        .is_err()
    );
}
