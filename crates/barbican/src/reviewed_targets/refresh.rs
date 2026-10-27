use std::collections::BTreeSet;
use std::fmt::Write as _;

use thiserror::Error;

use super::{
    ReviewedDirectTarget, ReviewedResolvedSource, ReviewedResolvedTarget, ReviewedTargets,
};
use crate::scaffold::{exact_direct_requirement, select_locked_package};
use crate::{
    CargoManifestDirectRequirement, Date, Lockfile, REVIEW_RECORD_SCAFFOLD_MARKER,
    added_crates_io_specs, check_reviewed_rust_targets, format_iso_date, parse_pin_add_target,
};

mod edit;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct PinRefreshError(String);

impl PinRefreshError {
    fn reject(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Debug, Clone)]
pub struct PinRefreshChange {
    family: String,
    record: String,
    previous: ReviewedResolvedTarget,
    selected: ReviewedResolvedTarget,
    direct: Option<String>,
    retained_direct: bool,
    withdrawn: Vec<String>,
}

impl PinRefreshChange {
    pub fn family(&self) -> &str {
        &self.family
    }
    pub fn record(&self) -> &str {
        &self.record
    }
    pub fn previous(&self) -> &ReviewedResolvedTarget {
        &self.previous
    }
    pub fn selected(&self) -> &ReviewedResolvedTarget {
        &self.selected
    }
    pub fn direct(&self) -> Option<&str> {
        self.direct.as_deref()
    }
    pub fn retained_direct(&self) -> bool {
        self.retained_direct
    }
    pub fn withdrawn_grants(&self) -> &[String] {
        &self.withdrawn
    }
}

#[derive(Debug)]
pub struct PinRefreshPlan {
    original: ReviewedTargets,
    expected: ReviewedTargets,
    changes: Vec<PinRefreshChange>,
    remaining: Vec<String>,
}

impl PinRefreshPlan {
    pub fn changes(&self) -> &[PinRefreshChange] {
        &self.changes
    }
    pub fn remaining_mismatches(&self) -> &[String] {
        &self.remaining
    }

    pub fn edit_policy(&self, original: &str) -> Result<String, PinRefreshError> {
        edit::edit_policy(original, self)
    }

    pub fn validate_baseline(
        &self,
        current: &Lockfile,
        baseline: &Lockfile,
    ) -> Result<(), PinRefreshError> {
        let report = check_reviewed_rust_targets(&self.original, &[], baseline);
        let added = added_crates_io_specs(current, baseline).map_err(|_| {
            PinRefreshError::reject("unable to establish newly selected registry identities")
        })?;
        for change in &self.changes {
            let name = change.selected.spec().crate_name();
            let matches = report
                .families()
                .iter()
                .find(|family| family.name() == change.family)
                .and_then(|family| {
                    family
                        .resolved_checks()
                        .iter()
                        .find(|check| check.crate_name() == name)
                })
                .is_some_and(crate::ReviewedResolvedDependencyCheck::is_success);
            if !matches || !added.contains(change.selected.spec()) {
                return Err(PinRefreshError::reject(format!(
                    "baseline does not explain {name}: require the previous reviewed identity in the baseline and a newly selected current identity; use pin refresh for deliberate manual recovery"
                )));
            }
        }
        Ok(())
    }
}

pub fn drifted_registry_targets(
    policy: &ReviewedTargets,
    requirements: &[CargoManifestDirectRequirement],
    lockfile: &Lockfile,
) -> Result<Vec<String>, PinRefreshError> {
    let report = check_reviewed_rust_targets(policy, requirements, lockfile);
    let mut names = BTreeSet::new();
    for family in report.families() {
        for check in family.resolved_checks() {
            if !check.is_success() {
                if check.expected_target().git().is_some() {
                    return Err(PinRefreshError::reject(
                        "Git drift requires the manual exact-source review workflow",
                    ));
                }
                names.insert(check.crate_name().to_owned());
            }
        }
    }
    Ok(names.into_iter().collect())
}

pub fn plan_pin_refresh(
    policy: &ReviewedTargets,
    lockfile: &Lockfile,
    requirements: &[CargoManifestDirectRequirement],
    requests: &[String],
) -> Result<PinRefreshPlan, PinRefreshError> {
    if requests.is_empty() {
        return Err(PinRefreshError::reject(
            "pin refresh requires at least one target",
        ));
    }
    let mut expected = policy.clone();
    let mut seen = BTreeSet::new();
    let mut changes = Vec::new();
    for request in requests {
        if crate::is_source_spec_input(request) {
            return Err(PinRefreshError::reject(
                "pin refresh takes resolved registry package names, not source URLs",
            ));
        }
        let target = parse_pin_add_target(request)
            .map_err(|error| PinRefreshError::reject(error.to_string()))?;
        let name = target.crate_name();
        if !seen.insert(name.to_owned()) {
            return Err(PinRefreshError::reject(format!(
                "duplicate or overlapping refresh request for {name}"
            )));
        }
        let packages = lockfile
            .packages()
            .iter()
            .filter(|package| package.name == name)
            .collect::<Vec<_>>();
        if packages.is_empty() {
            return Err(PinRefreshError::reject(format!(
                "{name}: not present in Cargo.lock; refresh cannot remove family members"
            )));
        }
        let package = select_locked_package(&packages, &target).map_err(|_| {
            PinRefreshError::reject(format!(
                "{name}: cannot select the requested unique locked target"
            ))
        })?;
        if !package.is_crates_io() || package.checksum().is_none() {
            return Err(PinRefreshError::reject(format!(
                "{name}: refresh requires a crates.io target with a checksum; use manual source review"
            )));
        }
        let selected = ReviewedResolvedTarget {
            spec: package.exact_spec().clone(),
            version: package.version.clone(),
            source: ReviewedResolvedSource::CratesIo {
                checksum_sha256: package.checksum().cloned(),
            },
        };
        if packages
            .iter()
            .any(|package| !selected.matches_package(package))
        {
            return Err(PinRefreshError::reject(format!(
                "{name}: conflicting locked source/version/checksum siblings; an explicit version cannot hide them"
            )));
        }
        let covering = policy
            .rust_families
            .iter()
            .enumerate()
            .filter(|(_, family)| family.resolved.contains_key(name))
            .collect::<Vec<_>>();
        if covering.len() != 1 {
            let families = covering
                .iter()
                .map(|(_, family)| family.name.as_str())
                .collect::<Vec<_>>();
            return Err(PinRefreshError::reject(format!(
                "{name}: expected one covering family, found {families:?}; use pin add for uncovered targets"
            )));
        }
        let (index, family) = covering[0];
        let previous = family.resolved[name].clone();
        if previous.git().is_some() {
            return Err(PinRefreshError::reject(format!(
                "{name}: previous reviewed source is Git; refresh cannot migrate sources"
            )));
        }
        if previous == selected {
            return Err(PinRefreshError::reject(format!(
                "{name}: reviewed pin already matches; finish any existing pending review"
            )));
        }
        let observed = requirements
            .iter()
            .filter(|requirement| requirement.name() == name)
            .collect::<Vec<_>>();
        let direct = family
            .direct
            .contains_key(name)
            .then(|| exact_direct_requirement(&observed, selected.spec()))
            .flatten();
        let retained_direct = family.direct.contains_key(name) && direct.is_none();
        let mut withdrawn = Vec::new();
        for allowance in &family.execution_surface_allowances {
            if allowance.spec().crate_name() == name {
                withdrawn.push(format!("allowed_surfaces: {allowance}"));
            }
        }
        for allowance in &family.release_age_exceptions {
            if allowance.spec().crate_name() == name {
                withdrawn.push(format!("allowed_age_exceptions: {allowance}"));
            }
        }
        for allowance in &family.advisory_exceptions {
            if allowance.spec().crate_name() == name {
                withdrawn.push(format!("allowed_advisories: {allowance}"));
            }
        }
        let updated = &mut expected.rust_families[index];
        updated.resolved.insert(name.to_owned(), selected.clone());
        if let Some(requirement) = &direct {
            updated.direct.insert(
                name.to_owned(),
                ReviewedDirectTarget::Registry(requirement.clone()),
            );
        }
        updated
            .execution_surface_allowances
            .retain(|allowance| allowance.spec().crate_name() != name);
        updated
            .release_age_exceptions
            .retain(|allowance| allowance.spec().crate_name() != name);
        updated
            .advisory_exceptions
            .retain(|allowance| allowance.spec().crate_name() != name);
        changes.push(PinRefreshChange {
            family: family.name.clone(),
            record: family.review_record.clone(),
            previous,
            selected,
            direct,
            retained_direct,
            withdrawn,
        });
    }
    let report = check_reviewed_rust_targets(&expected, requirements, lockfile);
    let mut remaining = Vec::new();
    for family in report.families() {
        for check in family
            .resolved_checks()
            .iter()
            .filter(|check| !check.is_success())
        {
            remaining.push(format!(
                "{}: resolved {}",
                family.name(),
                check.crate_name()
            ));
        }
        for check in family
            .direct_checks()
            .iter()
            .filter(|check| !check.is_success())
        {
            remaining.push(format!("{}: direct {}", family.name(), check.crate_name()));
        }
    }
    Ok(PinRefreshPlan {
        original: policy.clone(),
        expected,
        changes,
        remaining,
    })
}

pub fn compose_refresh_record(
    original: &str,
    changes: &[&PinRefreshChange],
    reopened_families: &[String],
    date: Date,
) -> String {
    let mut record = original.to_owned();
    if !record.contains(REVIEW_RECORD_SCAFFOLD_MARKER) {
        let marker = format!(
            "\n<!-- {REVIEW_RECORD_SCAFFOLD_MARKER}: complete the appended re-pin review before removing this line. -->\n"
        );
        let offset = if original.starts_with('#') {
            original
                .find('\n')
                .map_or(original.len(), |index| index + 1)
        } else {
            0
        };
        record.insert_str(offset, &marker);
    }
    let _ = writeln!(record, "\n## Re-pin review — {}\n", format_iso_date(date));
    let _ = writeln!(
        record,
        "- Reopened families: {}",
        reopened_families
            .iter()
            .map(|name| record_field(name))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for change in changes {
        let _ = writeln!(
            record,
            "- Family {}: {} → {}",
            record_field(&change.family),
            record_field(&target_fact(&change.previous)),
            record_field(&target_fact(&change.selected))
        );
        if let Some(direct) = &change.direct {
            let _ = writeln!(record, "  - Direct pin: {}", record_field(direct));
        }
        if change.retained_direct {
            let _ = writeln!(
                record,
                "  - Existing direct pin retained; reconcile manifest/policy before the final gate."
            );
        }
        for grant in &change.withdrawn {
            let _ = writeln!(record, "  - Withdrawn: {}", record_field(grant));
        }
    }
    let commands = changes
        .iter()
        .map(|change| change.selected.spec().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let _ = writeln!(
        record,
        "\n### Commands Run\n\n- cargo barbican pin refresh {commands}\n\n### Classification\n\n- Reviewer:\n- Evidence and pre-move baseline:\n- Classification and reason:\n- Replacement grants explicitly reviewed, if any:\n\nReview is unfinished. Complete this append and run cargo barbican pin check, then the normal gate.\n"
    );
    record
}

fn target_fact(target: &ReviewedResolvedTarget) -> String {
    format!(
        "{} (crates.io, checksum_sha256 {})",
        target.spec(),
        target
            .checksum_sha256()
            .map_or("not previously recorded", crate::Sha256Digest::as_str)
    )
}

pub(super) fn record_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() || matches!(ch, ' ' | '-' | '_' | '.' | '/' | '@' | ':' | '=') {
                ch.to_string()
            } else {
                format!("&#{};", u32::from(ch))
            }
        })
        .collect::<String>()
        .replace(REVIEW_RECORD_SCAFFOLD_MARKER, "BARBICAN&#45;REVIEW-PENDING")
}
