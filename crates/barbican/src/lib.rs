//! Library for Rust supply-chain hardening.
//!
//! Provides primitives the `cargo-barbican` binary composes into subcommands:
//! crates.io release-age checks, `Cargo.lock` diffing, policy assessment.
//!
//! See `docs/architecture/overview.md` in the repo root for the design brief.

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_builds() {}
}
