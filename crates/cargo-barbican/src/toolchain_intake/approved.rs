use super::repo::{RepoContext, read_optional};
use barbican::Sha256Digest;
use barbican::toolchain_admission::{
    PortableReview, ReviewedToolchainAdmission, digest_bytes, parse_record,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, String>;

/// Origin is the applying controller's responsibility, not a property of prose.
pub(super) struct ApprovedInputs {
    approved: RepoContext,
    candidate: RepoContext,
    inputs: Vec<(PathBuf, Sha256Digest)>,
}

impl ApprovedInputs {
    pub fn capture(
        candidate: &RepoContext,
        approved_root: &Path,
        id: &Sha256Digest,
        record: &Path,
    ) -> Result<Self> {
        let approved = RepoContext::capture(approved_root)?;
        if approved.root == candidate.root {
            return Err(
                "approved inputs require an independent checkout, not the candidate itself".into(),
            );
        }
        if !candidate.config.toolchain.require_admission
            || candidate.config.toolchain != approved.config.toolchain
            || candidate.config.release_age != approved.config.release_age
        {
            return Err("candidate toolchain governance differs from independently approved inputs (admission must be enabled)".into());
        }
        let expected = selected_admission(&approved, id)?;
        if selected_admission(candidate, id)? != expected {
            return Err(
                "candidate toolchain admission differs from independently approved inputs".into(),
            );
        }
        let evidence = required(&approved.root, Path::new(&expected.evidence_record))?;
        expected
            .evidence()
            .verify(&evidence)
            .map_err(|e| e.to_string())?;
        let portable: PortableReview = parse_record(&evidence).map_err(|e| e.to_string())?;
        if portable.assessment.review != expected.review()
            || portable.assessment.subject_id != expected.subject_id
        {
            return Err(
                "approved portable evidence does not match its admission references".into(),
            );
        }
        let mut paths: BTreeSet<PathBuf> = [
            PathBuf::from("rust-toolchain.toml"),
            PathBuf::from(&expected.evidence_record),
            PathBuf::from(&expected.review_record),
        ]
        .into_iter()
        .collect();
        for name in ["manifest.toml", "manifest.asc", "certificate.pgp"] {
            paths.insert(PathBuf::from(format!(
                "docs/dependency-reviews/toolchains/{id}/{name}"
            )));
        }
        for source in &portable.evidence.observations {
            paths.insert(PathBuf::from(&source.snapshot.path));
        }
        if let Some(exception) = &expected.age_exception {
            paths.insert(PathBuf::from(&exception.review.path));
        }
        let mut inputs = Vec::new();
        for relative in paths {
            let bytes = required(&approved.root, &relative)?;
            if required(&candidate.root, &relative)? != bytes {
                return Err(format!(
                    "candidate toolchain input differs from approved bytes: {}",
                    relative.display()
                ));
            }
            inputs.push((relative, digest_bytes(&bytes)));
        }
        if record != approved.root.join(&expected.review_record) {
            return Err(
                "--approved-repo requires --record to name its exact protected review path".into(),
            );
        }
        let captured = Self {
            approved,
            candidate: candidate.clone(),
            inputs,
        };
        captured.recheck()?;
        Ok(captured)
    }

    pub fn recheck(&self) -> Result<()> {
        self.approved.recheck()?;
        self.candidate.recheck()?;
        for (relative, digest) in &self.inputs {
            for root in [&self.approved.root, &self.candidate.root] {
                if digest_bytes(&required(root, relative)?) != *digest {
                    return Err("approved toolchain inputs changed during acceptance".into());
                }
            }
        }
        Ok(())
    }
}

fn required(root: &Path, relative: &Path) -> Result<Vec<u8>> {
    read_optional(root, relative)?.ok_or_else(|| {
        format!(
            "required approved toolchain input is missing: {}",
            relative.display()
        )
    })
}

fn selected_admission(repo: &RepoContext, id: &Sha256Digest) -> Result<ReviewedToolchainAdmission> {
    let bytes = required(&repo.root, Path::new("reviewed-targets.toml"))?;
    let targets = barbican::parse_reviewed_targets_toml(
        std::str::from_utf8(&bytes).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let path = format!("docs/dependency-reviews/toolchains/{id}/evidence.json");
    let matching: Vec<_> = targets
        .rust_toolchains()
        .iter()
        .filter(|entry| entry.evidence_record == path)
        .collect();
    match matching.as_slice() {
        [admission] => Ok((*admission).clone()),
        _ => Err(
            "approved-input comparison requires exactly one matching toolchain admission".into(),
        ),
    }
}
