//! Static toolchain evidence, per-user trust and explicitly governed native effects.
mod verifier;

mod acceptance;
mod admission;
mod approved;
mod collection;
mod frontend;
#[cfg(unix)]
mod installation;
mod paths;
mod repo;
mod review;
mod sources;
mod store;
mod trust;
pub(crate) use frontend::{gate_preflight, is_static, policy_init_root, run};
mod operation;
#[cfg(test)]
mod workflow_tests;
