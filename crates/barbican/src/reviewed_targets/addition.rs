use std::collections::BTreeSet;
use std::fmt::Write as _;

use thiserror::Error;

use super::{
    ReviewedDirectTarget, ReviewedResolvedSource, ReviewedResolvedTarget, ReviewedTargets,
};
use crate::scaffold::{pin_direct_requirement, select_locked_package};
use crate::{
    CargoManifestDirectRequirement, Date, GitSourceIdentity, Lockfile,
    REVIEW_RECORD_SCAFFOLD_MARKER, format_iso_date, parse_pin_add_target,
    parse_reviewed_targets_toml,
};

mod edit;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct FamilyAdditionError(String);

impl FamilyAdditionError {
    fn reject(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Debug)]
pub struct FamilyAdditionMember {
    selected: ReviewedResolvedTarget,
    direct: Option<ReviewedDirectTarget>,
    already_present: bool,
    omitted_direct: bool,
}

impl FamilyAdditionMember {
    pub fn selected(&self) -> &ReviewedResolvedTarget {
        &self.selected
    }
    pub fn direct(&self) -> Option<&ReviewedDirectTarget> {
        self.direct.as_ref()
    }
    pub fn already_present(&self) -> bool {
        self.already_present
    }
    pub fn omitted_direct(&self) -> bool {
        self.omitted_direct
    }
}

#[derive(Debug)]
pub struct FamilyAdditionPlan {
    original: ReviewedTargets,
    expected: ReviewedTargets,
    family_index: usize,
    members: Vec<FamilyAdditionMember>,
}

impl FamilyAdditionPlan {
    pub fn family(&self) -> &str {
        self.original.rust_families[self.family_index].name()
    }
    pub fn record(&self) -> &str {
        self.original.rust_families[self.family_index].review_record()
    }
    pub fn members(&self) -> &[FamilyAdditionMember] {
        &self.members
    }
    pub fn is_noop(&self) -> bool {
        self.members.iter().all(|member| member.already_present)
    }
    pub fn edit_policy(&self, source: &str) -> Result<String, FamilyAdditionError> {
        edit::edit_policy(source, self)
    }

    pub fn compose_record(&self, original: &str, families: &[String], date: Date) -> String {
        let mut record = original.to_owned();
        if !record.contains(REVIEW_RECORD_SCAFFOLD_MARKER) {
            let offset = if record.starts_with('#') {
                record.find('\n').map_or(record.len(), |index| index + 1)
            } else {
                0
            };
            record.insert_str(offset, &format!("\n<!-- {REVIEW_RECORD_SCAFFOLD_MARKER}: complete the appended family addition review before removing this line. -->\n"));
        }
        let _ = writeln!(
            record,
            "\n## Family addition review — {}\n",
            format_iso_date(date)
        );
        let _ = writeln!(record, "- Selected family: {}", field(self.family()));
        let _ = writeln!(
            record,
            "- Reopened families: {}",
            families
                .iter()
                .map(|name| field(name))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for member in &self.members {
            let target = member.selected();
            let _ = writeln!(
                record,
                "- {}: {} ({})",
                if member.already_present {
                    "Already a member, unchanged"
                } else {
                    "Added"
                },
                field(&target.spec().to_string()),
                field(&target.source_string())
            );
            if let Some(checksum) = target.checksum_sha256() {
                let _ = writeln!(record, "  - checksum_sha256: {checksum}");
            }
        }
        let specs = self
            .members
            .iter()
            .map(|member| member.selected.spec().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            record,
            "\n### Commands Run\n\n- cargo barbican pin add --family={} {specs}\n\n### Classification\n\n- Reviewer:\n- Source and advisory evidence:\n- Classification and reason:\n- Decision:\n\nReview is unfinished. Existing grants and deadlines are unchanged; no new grants were created. Complete the expanded review, then run cargo barbican pin check and the normal gate.\n",
            field(&shell_argument(self.family()))
        );
        record
    }
}

pub fn plan_family_addition(
    policy: &ReviewedTargets,
    lockfile: &Lockfile,
    requirements: &[CargoManifestDirectRequirement],
    family_name: &str,
    requests: &[String],
) -> Result<FamilyAdditionPlan, FamilyAdditionError> {
    let index = policy
        .rust_families
        .iter()
        .position(|family| family.name() == family_name)
        .ok_or_else(|| {
            FamilyAdditionError::reject(
                "selected family does not exist; use cargo barbican pin list",
            )
        })?;
    if requests.is_empty() {
        return Err(FamilyAdditionError::reject(
            "family addition requires at least one resolved crate",
        ));
    }
    let family = &policy.rust_families[index];
    let mut expected = policy.clone();
    let mut seen = BTreeSet::new();
    let mut members = Vec::new();
    for request in requests {
        if crate::is_source_spec_input(request) {
            return Err(FamilyAdditionError::reject(
                "family addition takes resolved package names, not source URLs",
            ));
        }
        let target = parse_pin_add_target(request)
            .map_err(|error| FamilyAdditionError::reject(error.to_string()))?;
        let name = target.crate_name();
        if !seen.insert(name.to_owned()) {
            return Err(FamilyAdditionError::reject(format!(
                "duplicate or overlapping request for {name}"
            )));
        }
        let packages = lockfile
            .packages()
            .iter()
            .filter(|package| package.name == name)
            .collect::<Vec<_>>();
        if packages.is_empty() {
            return Err(FamilyAdditionError::reject(format!(
                "{name}: not present in Cargo.lock"
            )));
        }
        let package = select_locked_package(&packages, &target).map_err(|_| {
            FamilyAdditionError::reject(format!("{name}: cannot select a unique locked identity"))
        })?;
        let git = if package.is_crates_io() {
            None
        } else {
            Some(
                GitSourceIdentity::from_locked_source(
                    package.source.as_deref().unwrap_or_default(),
                )
                .map_err(|error| FamilyAdditionError::reject(format!("{name}: {error}")))?,
            )
        };
        if git.is_none() && package.checksum().is_none() {
            return Err(FamilyAdditionError::reject(format!(
                "{name}: registry addition requires a checksum"
            )));
        }
        let selected = ReviewedResolvedTarget {
            spec: package.exact_spec().clone(),
            version: package.version.clone(),
            source: git.clone().map_or_else(
                || ReviewedResolvedSource::CratesIo {
                    checksum_sha256: package.checksum().cloned(),
                },
                ReviewedResolvedSource::Git,
            ),
        };
        if packages
            .iter()
            .any(|package| !selected.matches_package(package))
        {
            return Err(FamilyAdditionError::reject(format!(
                "{name}: conflicting locked source/version/checksum siblings"
            )));
        }
        if policy
            .rust_families
            .iter()
            .enumerate()
            .any(|(other, family)| other != index && family.resolved.contains_key(name))
        {
            return Err(FamilyAdditionError::reject(format!(
                "{name}: already covered by another family; ownership cannot be transferred"
            )));
        }
        let already_present = match family.resolved.get(name) {
            Some(previous) if previous == &selected => true,
            Some(_) => {
                return Err(FamilyAdditionError::reject(format!(
                    "{name}: existing member has different reviewed facts; use refresh or manual source review"
                )));
            }
            None => false,
        };
        if let Some(direct) = family.direct.get(name) {
            let compatible = match direct {
                ReviewedDirectTarget::Registry(value) => {
                    git.is_none() && value == &format!("={}", selected.version())
                }
                ReviewedDirectTarget::Git(previous) => git.as_ref() == Some(previous),
            };
            if !compatible {
                return Err(FamilyAdditionError::reject(format!(
                    "{name}: incompatible existing direct intent; reconcile manually"
                )));
            }
        }
        let observed = requirements
            .iter()
            .filter(|requirement| requirement.name() == name)
            .collect::<Vec<_>>();
        let requirement =
            pin_direct_requirement(package, git.as_ref(), &observed).map_err(|_| {
                FamilyAdditionError::reject(format!(
                    "{name}: direct Git declarations must match the selected source and version"
                ))
            })?;
        let direct = if already_present || family.direct.contains_key(name) {
            None
        } else {
            requirement.map(|value| {
                git.clone().map_or(
                    ReviewedDirectTarget::Registry(value),
                    ReviewedDirectTarget::Git,
                )
            })
        };
        let omitted_direct = !already_present
            && !family.direct.contains_key(name)
            && direct.is_none()
            && !observed.is_empty();
        if !already_present {
            expected.rust_families[index]
                .resolved
                .insert(name.to_owned(), selected.clone());
            if let Some(value) = &direct {
                expected.rust_families[index]
                    .direct
                    .insert(name.to_owned(), value.clone());
            }
        }
        members.push(FamilyAdditionMember {
            selected,
            direct,
            already_present,
            omitted_direct,
        });
    }
    Ok(FamilyAdditionPlan {
        original: policy.clone(),
        expected,
        family_index: index,
        members,
    })
}

fn field(value: &str) -> String {
    super::refresh::record_field(value)
}

pub(crate) fn shell_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
