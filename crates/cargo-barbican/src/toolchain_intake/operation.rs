use super::store::PrivateStore;
use barbican::Sha256Digest;
use barbican::toolchain_admission::{Eligibility, EligibilityMode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Mode {
    Online,
    ExplicitCached {
        reason: String,
        oldest_check: i64,
        expires_at: i64,
    },
    ContinuingLocal,
    StaticInspection,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationEvidence {
    pub schema_version: u32,
    pub operation: String,
    pub subject_id: Sha256Digest,
    pub policy_id: Sha256Digest,
    pub evidence_id: Sha256Digest,
    pub age_exception_id: Option<Sha256Digest>,
    pub evaluated_at: i64,
    pub eligibility: Mode,
}
impl OperationEvidence {
    pub fn new(operation: &str, eligibility: &Eligibility, now: i64) -> Self {
        Self {
            schema_version: 1,
            operation: operation.into(),
            subject_id: eligibility.subject_id.clone(),
            policy_id: eligibility.policy_id.clone(),
            evidence_id: eligibility.evidence_id.clone(),
            age_exception_id: eligibility.age_exception_id.clone(),
            evaluated_at: now,
            eligibility: match &eligibility.mode {
                EligibilityMode::Online => Mode::Online,
                EligibilityMode::ExplicitCached {
                    reason,
                    oldest_check,
                    expires_at,
                } => Mode::ExplicitCached {
                    reason: reason.clone(),
                    oldest_check: *oldest_check,
                    expires_at: *expires_at,
                },
                EligibilityMode::ContinuingLocal => Mode::ContinuingLocal,
                EligibilityMode::StaticInspection => Mode::StaticInspection,
            },
        }
    }
    pub fn retain(&self, data: &PrivateStore) -> Result<(), String> {
        let path = format!(
            "operations/{}-{}-{}.json",
            self.evaluated_at,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        data.publish(
            Path::new(&path),
            &serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?,
        )
    }
}
