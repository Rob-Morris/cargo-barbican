// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) mod info;
pub(crate) mod status;
pub(crate) mod summary;

pub use summary::{
    CertStatusSummary,
    ComponentKeySummary,
    Status,
    UserAttributeSummary,
    UserIdSummary,
};

use crate::certificate::Checked;

pub fn status_summary(checked: &Checked) -> CertStatusSummary {
    status::transform::to_cert_status(checked).into()
}
