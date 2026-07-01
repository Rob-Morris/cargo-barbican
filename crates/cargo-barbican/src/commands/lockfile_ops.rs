use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use barbican::{CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec};

use super::CommandError;

pub(super) fn restore_base_lockfile(
    current_dir: &Path,
    base_lockfile_text: &str,
) -> Result<(), CommandError> {
    let path = current_dir.join("Cargo.lock");
    fs::write(&path, base_lockfile_text).map_err(|source| CommandError::LockfileRestore {
        path: path.display().to_string(),
        source,
    })
}

pub(super) struct MemoizingCratesIoClient<'a, C: ?Sized> {
    inner: &'a C,
    cache: RefCell<HashMap<ExactCrateSpec, Result<CrateRelease, CratesIoClientError>>>,
}

impl<'a, C: ?Sized> MemoizingCratesIoClient<'a, C> {
    pub(super) fn new(inner: &'a C) -> Self {
        Self {
            inner,
            cache: RefCell::new(HashMap::new()),
        }
    }
}

impl<C> CratesIoClient for MemoizingCratesIoClient<'_, C>
where
    C: CratesIoClient + ?Sized,
{
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        if let Some(cached) = self.cache.borrow().get(spec) {
            return cached.clone();
        }

        let result = self.inner.fetch_release(spec);
        self.cache.borrow_mut().insert(spec.clone(), result.clone());
        result
    }

    fn fetch_release_tarball(&self, spec: &ExactCrateSpec) -> Result<Vec<u8>, CratesIoClientError> {
        self.inner.fetch_release_tarball(spec)
    }
}
