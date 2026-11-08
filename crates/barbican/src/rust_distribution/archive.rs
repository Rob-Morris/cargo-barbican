use super::{
    ArchiveIdentity, DistributionError, MAX_ENTRIES, MAX_EXPANDED_BYTES, MAX_METADATA_BYTES,
    MAX_SELECTION_BYTES, invalid, path,
};
use crate::Sha256Digest;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File { size: u64, sha256: Sha256Digest },
    Directory,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedEntry {
    pub kind: EntryKind,
    pub mode: u32,
}
#[derive(Debug, Clone)]
pub struct ArchiveInventory {
    pub identity: ArchiveIdentity,
    pub expanded_bytes: u64,
    pub physical_headers: usize,
    pub effective_entries: usize,
    pub payload: BTreeMap<String, ExpectedEntry>,
    pub package_metadata: BTreeMap<String, ExpectedEntry>,
    /// The three already bounded UTF-8 installer bodies used by `inspect_tar`.
    pub installer_metadata: BTreeMap<String, String>,
}
#[derive(Debug, Default)]
pub struct SelectionInventory {
    pub expanded_bytes: u64,
    pub payload: BTreeMap<String, ExpectedEntry>,
    archives: BTreeSet<(String, String)>,
}
impl SelectionInventory {
    pub fn add(&mut self, archive: ArchiveInventory) -> Result<(), DistributionError> {
        let total = self
            .expanded_bytes
            .checked_add(archive.expanded_bytes)
            .filter(|n| *n <= MAX_SELECTION_BYTES)
            .ok_or_else(|| invalid("selection expanded byte limit"))?;
        let key = (
            archive.identity.package.clone(),
            archive.identity.target.clone(),
        );
        if self.archives.contains(&key) {
            return Err(invalid("duplicate selected archive"));
        }
        for (name, entry) in &archive.payload {
            check_collision(&self.payload, name, entry)?;
        }
        self.payload.extend(archive.payload);
        self.archives.insert(key);
        self.expanded_bytes = total;
        Ok(())
    }
}
fn check_collision(
    entries: &BTreeMap<String, ExpectedEntry>,
    name: &str,
    entry: &ExpectedEntry,
) -> Result<(), DistributionError> {
    if entries.contains_key(name) {
        return Err(invalid(format!("duplicate destination {name}")));
    }
    for (position, _) in name.match_indices('/') {
        if entries
            .get(&name[..position])
            .is_some_and(|e| e.kind != EntryKind::Directory)
        {
            return Err(invalid("non-directory destination ancestor"));
        }
    }
    if entry.kind != EntryKind::Directory {
        let prefix = format!("{name}/");
        if entries
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(n, _)| n.starts_with(&prefix))
        {
            return Err(invalid("destination replaces directory ancestor"));
        }
    }
    Ok(())
}
struct Bounded<R> {
    reader: R,
    bytes: u64,
}
impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let max =
            ((MAX_EXPANDED_BYTES - self.bytes).saturating_add(1)).min(buf.len() as u64) as usize;
        let n = self.reader.read(&mut buf[..max])?;
        self.bytes += n as u64;
        if self.bytes > MAX_EXPANDED_BYTES {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "expanded archive byte limit",
            ));
        }
        Ok(n)
    }
}
const ROOT_METADATA: [&str; 12] = [
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "LICENSE-THIRD-PARTY",
    "COPYRIGHT",
    "README.md",
    "builder-config",
    "install.sh",
    "git-commit-hash",
    "git-commit-info",
    "rust-installer-version",
    "version",
    "components",
];

/// Inspect an already decoded tar stream; the caller separately verifies compressed identity and decoder completion.
/// No bytes are extracted and archive ownership IDs never become local ownership requirements.
pub fn inspect_tar(
    reader: impl Read,
    identity: &ArchiveIdentity,
) -> Result<ArchiveInventory, DistributionError> {
    path(&identity.root)?;
    path(&identity.component)?;
    if identity.root.contains('/') || identity.component.contains('/') {
        return Err(invalid("invalid archive identity"));
    }
    let mut reader = Bounded { reader, bytes: 0 };
    let mut entries = BTreeMap::new();
    let mut metadata = BTreeMap::new();
    let mut texts = BTreeMap::new();
    let mut pending_name = None;
    let mut physical = 0;
    let mut effective = 0;
    loop {
        let mut block = [0u8; 512];
        reader.read_exact(&mut block)?;
        if block.iter().all(|b| *b == 0) {
            if pending_name.is_some() {
                return Err(invalid("orphan GNU long name"));
            }
            let mut second = [0u8; 512];
            reader.read_exact(&mut second)?;
            if second.iter().any(|b| *b != 0) {
                return Err(invalid("missing second tar terminator"));
            }
            let mut tail = [0u8; 32768];
            loop {
                let n = reader.read(&mut tail)?;
                if n == 0 {
                    break;
                }
                if tail[..n].iter().any(|b| *b != 0) {
                    return Err(invalid("nonzero trailing tar data"));
                }
            }
            if reader.bytes % 512 != 0 {
                return Err(invalid("unaligned tar trailer"));
            }
            break;
        }
        physical += 1;
        if physical > MAX_ENTRIES {
            return Err(invalid("physical tar header limit"));
        }
        let header = tar::Header::from_byte_slice(&block);
        let checksum: u32 = block[..148]
            .iter()
            .chain(&block[156..])
            .map(|b| *b as u32)
            .sum::<u32>()
            + 8 * 32;
        if header.cksum()? != checksum {
            return Err(invalid("tar header checksum mismatch"));
        }
        let size = header.entry_size()?;
        if size > MAX_EXPANDED_BYTES.saturating_sub(reader.bytes) {
            return Err(invalid("tar body exceeds expanded byte limit"));
        }
        let kind = header.entry_type();
        if kind.is_gnu_longname() {
            if header.as_gnu().is_none()
                || pending_name.is_some()
                || size == 0
                || size > MAX_METADATA_BYTES as u64
            {
                return Err(invalid("unsupported or oversized GNU name"));
            }
            let mut body = vec![0; size as usize];
            reader.read_exact(&mut body)?;
            if body.pop() != Some(0) {
                return Err(invalid("unterminated GNU name"));
            }
            let name = String::from_utf8(body).map_err(|_| invalid("GNU name is not UTF-8"))?;
            path(name.trim_end_matches('/'))?;
            pending_name = Some(name);
            padding(&mut reader, size)?;
            continue;
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(invalid(
                "unqualified tar entry type (links, PAX, sparse and special entries refuse)",
            ));
        }
        if kind.is_dir() && size != 0 {
            return Err(invalid("directory has body"));
        }
        if header.link_name_bytes().is_some() {
            return Err(invalid("unexpected tar link name"));
        }
        let raw = match pending_name.take() {
            Some(name) => name,
            None => String::from_utf8(header.path_bytes().into_owned())
                .map_err(|_| invalid("tar path is not UTF-8"))?,
        };
        let name = if kind.is_dir() {
            raw.strip_suffix('/').unwrap_or(&raw)
        } else {
            &raw
        };
        path(name)?;
        let relative = if name == identity.root {
            ""
        } else {
            name.strip_prefix(&format!("{}/", identity.root))
                .ok_or_else(|| invalid("wrong archive root"))?
        };
        let mode = header.mode()?;
        if !matches!(mode, 0o400 | 0o600 | 0o644 | 0o700 | 0o755) {
            return Err(invalid("unqualified archive mode"));
        }
        if kind.is_dir() && mode != 0o755 {
            return Err(invalid("unqualified directory mode"));
        }
        effective += 1;
        if effective > MAX_ENTRIES {
            return Err(invalid("effective tar entry limit"));
        }
        let capture = relative == "components"
            || relative == "rust-installer-version"
            || relative == format!("{}/manifest.in", identity.component);
        if capture && size > MAX_METADATA_BYTES as u64 {
            return Err(invalid("installer metadata body limit"));
        }
        let mut text = Vec::new();
        let mut hash = Sha256::new();
        let mut remaining = size;
        let mut buffer = [0u8; 32768];
        while remaining != 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..take])?;
            hash.update(&buffer[..take]);
            if capture {
                text.extend_from_slice(&buffer[..take]);
            }
            remaining -= take as u64;
        }
        padding(&mut reader, size)?;
        let entry = ExpectedEntry {
            kind: if kind.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::File {
                    size,
                    sha256: Sha256Digest::try_from(format!("{:x}", hash.finalize()).as_str())
                        .expect("SHA256 hex"),
                }
            },
            mode,
        };
        check_collision(&entries, relative, &entry)?;
        entries.insert(relative.to_owned(), entry.clone());
        if capture {
            texts.insert(
                relative.to_owned(),
                String::from_utf8(text).map_err(|_| invalid("installer metadata is not UTF-8"))?,
            );
            metadata.insert(relative.to_owned(), entry.clone());
        }
        if !relative.contains('/') && !relative.is_empty() && relative != identity.component {
            if !ROOT_METADATA.contains(&relative) || kind.is_dir() {
                return Err(invalid(format!(
                    "unknown package-root metadata {relative:?}"
                )));
            }
            metadata.insert(relative.to_owned(), entry);
        }
    }
    if texts.get("rust-installer-version").map(String::as_str) != Some("3\n") {
        return Err(invalid("unsupported installer format"));
    }
    if texts.get("components").map(String::as_str) != Some(&format!("{}\n", identity.component)) {
        return Err(invalid("archive component identity mismatch"));
    }
    if entries
        .get("")
        .is_none_or(|e| e.kind != EntryKind::Directory)
        || entries
            .get(&identity.component)
            .is_none_or(|e| e.kind != EntryKind::Directory)
    {
        return Err(invalid("missing archive/component directory"));
    }
    let manifest = texts
        .get(&format!("{}/manifest.in", identity.component))
        .ok_or_else(|| invalid("missing component manifest"))?;
    let prefix = format!("{}/", identity.component);
    let mut payload = BTreeMap::new();
    for action in manifest.lines() {
        let (kind, destination) = action
            .split_once(':')
            .ok_or_else(|| invalid("malformed installer action"))?;
        path(destination)?;
        let source = format!("{prefix}{destination}");
        let entry = entries
            .get(&source)
            .ok_or_else(|| invalid("installer action source absent"))?;
        match kind {
            "file" if matches!(entry.kind, EntryKind::File { .. }) => {
                check_collision(&payload, destination, entry)?;
                payload.insert(destination.to_owned(), entry.clone());
            }
            "dir" if entry.kind == EntryKind::Directory => {
                check_collision(&payload, destination, entry)?;
                payload.insert(destination.to_owned(), entry.clone());
                let descendant = format!("{source}/");
                for (name, entry) in entries
                    .range(descendant.clone()..)
                    .take_while(|(n, _)| n.starts_with(&descendant))
                {
                    let dest = &name[prefix.len()..];
                    check_collision(&payload, dest, entry)?;
                    payload.insert(dest.to_owned(), entry.clone());
                }
            }
            _ => return Err(invalid("unsupported installer action or source type")),
        }
    }
    for (name, entry) in &entries {
        if let Some(dest) = name.strip_prefix(&prefix) {
            if dest != "manifest.in"
                && entry.kind != EntryKind::Directory
                && !payload.contains_key(dest)
            {
                return Err(invalid("unlisted component payload"));
            }
        } else if name.contains('/') {
            return Err(invalid("unknown component subtree"));
        }
    }
    Ok(ArchiveInventory {
        identity: identity.clone(),
        expanded_bytes: reader.bytes,
        physical_headers: physical,
        effective_entries: effective,
        payload,
        package_metadata: metadata,
        installer_metadata: texts,
    })
}
fn padding(reader: &mut impl Read, size: u64) -> Result<(), DistributionError> {
    let count = ((512 - size % 512) % 512) as usize;
    let mut pad = [0u8; 511];
    reader.read_exact(&mut pad[..count])?;
    if pad[..count].iter().any(|b| *b != 0) {
        return Err(invalid("nonzero tar body padding"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::Encoding;
    use super::*;
    fn identity() -> ArchiveIdentity {
        ArchiveIdentity { package: "rust-docs".into(), target: "aarch64-apple-darwin".into(), component: "rust-docs".into(), root: "rust-docs-1.99.1-aarch64-apple-darwin".into(), encoding: Encoding::Xz, url: "https://static.rust-lang.org/dist/2026-10-15/rust-docs-1.99.1-aarch64-apple-darwin.tar.xz".into(), sha256: Sha256Digest::try_from("a".repeat(64).as_str()).unwrap() }
    }
    fn fixture(actions: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let id = identity();
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            for name in [
                id.root.clone(),
                format!("{}/{}", id.root, id.component),
                format!("{}/{}/share", id.root, id.component),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                tar.append_data(&mut h, name, std::io::empty()).unwrap();
            }
            for (name, body) in [
                (
                    "components".to_owned(),
                    format!("{}\n", id.component).into_bytes(),
                ),
                ("rust-installer-version".to_owned(), b"3\n".to_vec()),
                (
                    format!("{}/manifest.in", id.component),
                    actions.as_bytes().to_vec(),
                ),
            ]
            .into_iter()
            .chain(
                files
                    .iter()
                    .map(|(n, b)| (format!("{}/{n}", id.component), b.to_vec())),
            ) {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                tar.append_data(&mut h, format!("{}/{name}", id.root), body.as_slice())
                    .unwrap();
            }
            tar.finish().unwrap();
        }
        out
    }
    #[test]
    fn recursive_directory_mapping_and_gnu_names() {
        let long = format!("share/{}", "x".repeat(160));
        let data = fixture(
            "dir:share\n",
            &[("share/index.html", b"hello"), (&long, b"long")],
        );
        let result = inspect_tar(data.as_slice(), &identity()).unwrap();
        assert_eq!(result.payload.len(), 3);
        assert!(result.physical_headers > result.effective_entries);
        assert_eq!(
            result.payload["share/index.html"].kind,
            EntryKind::File {
                size: 5,
                sha256: super::super::digest(b"hello")
            }
        );
        assert!(!result.payload.contains_key("components"));
        assert_eq!(
            result.installer_metadata["components"],
            format!("{}\n", identity().component)
        );
        assert!(
            result
                .package_metadata
                .contains_key(&format!("{}/manifest.in", identity().component))
        );
    }
    #[test]
    fn retains_only_observed_single_user_file_modes_for_qualified_native_mapping() {
        for mode in [0o400, 0o600, 0o700] {
            let mut data = fixture("file:share/item\n", &[("share/item", b"bytes")]);
            let position = tar::Archive::new(data.as_slice())
                .entries()
                .unwrap()
                .map(|e| e.unwrap())
                .find(|e| e.path().unwrap().ends_with("share/item"))
                .unwrap()
                .raw_header_position() as usize;
            edit_header(&mut data[position..position + 512], |h| h.set_mode(mode));
            assert_eq!(
                inspect_tar(data.as_slice(), &identity()).unwrap().payload["share/item"].mode,
                mode
            );
        }
    }
    #[test]
    fn malformed_scope_paths_padding_and_trailers_refuse() {
        for actions in [
            "file:share/missing\n",
            "file:share\n",
            "dir:share/index.html\n",
            "file:../escape\n",
            "file:share/index.html\nfile:share/index.html\n",
            "",
        ] {
            assert!(
                inspect_tar(
                    fixture(actions, &[("share/index.html", b"hello")]).as_slice(),
                    &identity()
                )
                .is_err()
            );
        }
        let data = fixture("file:share/index.html\n", &[("share/index.html", b"hello")]);
        let mut changed = data.clone();
        changed.extend_from_slice(&[1; 512]);
        assert!(inspect_tar(changed.as_slice(), &identity()).is_err());
        assert!(inspect_tar(&data[..data.len() - 1024], &identity()).is_err());
        let mut changed = data;
        changed[0] ^= 1;
        assert!(inspect_tar(changed.as_slice(), &identity()).is_err());
    }
    #[test]
    fn cross_component_duplicate_and_ancestor_collisions_are_atomic() {
        let a = inspect_tar(
            fixture("file:share/index.html\n", &[("share/index.html", b"hello")]).as_slice(),
            &identity(),
        )
        .unwrap();
        let mut all = SelectionInventory::default();
        all.add(a.clone()).unwrap();
        let old = all.expanded_bytes;
        let mut b = a.clone();
        b.identity.package = "cargo".into();
        assert!(all.add(b).is_err());
        assert_eq!(all.expanded_bytes, old);
        let mut b = a;
        b.identity.package = "cargo".into();
        let value = b.payload.remove("share/index.html").unwrap();
        b.payload.insert("share".into(), value);
        assert!(all.add(b).is_err());
        assert_eq!(all.payload.len(), 1);
    }
    fn edit_header(bytes: &mut [u8], edit: impl FnOnce(&mut tar::Header)) {
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes().copy_from_slice(bytes);
        edit(&mut header);
        header.set_cksum();
        bytes.copy_from_slice(header.as_bytes());
    }
    #[test]
    fn oversized_bodies_special_types_modes_and_repeated_gnu_names_refuse() {
        let data = fixture("file:share/index.html\n", &[("share/index.html", b"hello")]);
        for ty in [b'1', b'2', b'3', b'4', b'6', b'S', b'x', b'g'] {
            let mut bytes = data.clone();
            edit_header(&mut bytes[..512], |h| {
                h.set_entry_type(tar::EntryType::new(ty))
            });
            assert!(inspect_tar(bytes.as_slice(), &identity()).is_err());
        }
        let mut bytes = data.clone();
        edit_header(&mut bytes[..512], |h| h.set_mode(0o4755));
        assert!(inspect_tar(bytes.as_slice(), &identity()).is_err());
        let mut bytes = data;
        edit_header(&mut bytes[..512], |h| {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(MAX_EXPANDED_BYTES + 1);
        });
        assert!(inspect_tar(bytes.as_slice(), &identity()).is_err());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNULongName);
        h.set_path("././@LongLink").unwrap();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        let mut repeated = h.as_bytes().to_vec();
        repeated.extend([b'a', 0]);
        repeated.extend([0; 510]);
        repeated.extend(h.as_bytes());
        repeated.extend([b'b', 0]);
        repeated.extend([0; 510]);
        assert!(
            inspect_tar(repeated.as_slice(), &identity())
                .unwrap_err()
                .to_string()
                .contains("GNU")
        );
        h.set_size(MAX_METADATA_BYTES as u64 + 1);
        h.set_cksum();
        assert!(inspect_tar(h.as_bytes().as_slice(), &identity()).is_err());
    }
    #[test]
    fn path_traversal_and_oversized_effective_gnu_paths_refuse() {
        for name in [
            "../escape",
            "/absolute",
            "a\\b",
            "C:drive",
            "a//b",
            "a/./b",
            "a/../b",
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o755);
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Directory);
            h.as_mut_bytes()[..100].fill(0);
            h.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            assert!(inspect_tar(h.as_bytes().as_slice(), &identity()).is_err());
        }
        let long = format!("share/{}", "x".repeat(super::super::MAX_PATH_BYTES));
        let data = fixture("dir:share\n", &[(&long, b"x")]);
        assert!(inspect_tar(data.as_slice(), &identity()).is_err());
    }
    #[test]
    fn a_large_individual_file_is_hashed_as_a_stream() {
        let mut bytes = fixture("file:share/llvm\n", &[("share/llvm", b"")]);
        let offset = bytes
            .chunks_exact(512)
            .position(|b| {
                b.starts_with(
                    format!("{}/{}/share/llvm", identity().root, identity().component).as_bytes(),
                )
            })
            .unwrap()
            * 512;
        let size = 128 * 1024 * 1024 + 1;
        edit_header(&mut bytes[offset..offset + 512], |h| h.set_size(size));
        bytes.truncate(offset + 512);
        let stream = std::io::Cursor::new(bytes)
            .chain(std::io::repeat(0).take(size))
            .chain(std::io::repeat(0).take((512 - size % 512) % 512 + 1024));
        let result = inspect_tar(stream, &identity()).unwrap();
        assert!(matches!(result.payload["share/llvm"].kind,EntryKind::File{size:s,..} if s==size));
    }

    struct HeaderFlood {
        index: usize,
        offset: usize,
        block: [u8; 512],
        longnames: bool,
    }
    impl Read for HeaderFlood {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if out.is_empty() {
                return Ok(0);
            }
            if self.offset == 512 {
                let id = identity();
                let mut h = tar::Header::new_gnu();
                h.set_mode(0o755);
                h.set_size(0);
                h.set_entry_type(tar::EntryType::Directory);
                let i = self.index;
                self.index += 1;
                self.offset = 0;
                if i < 2 {
                    h.set_path(if i == 0 {
                        id.root.clone()
                    } else {
                        format!("{}/{}", id.root, id.component)
                    })
                    .unwrap();
                } else {
                    let seq = if self.longnames { (i - 2) / 3 } else { i - 2 };
                    let name = format!("{}/{}/directory-{seq}", id.root, id.component);
                    if self.longnames && (i - 2) % 3 == 1 {
                        self.block = [0; 512];
                        self.block[..name.len()].copy_from_slice(name.as_bytes());
                        return self.read(out);
                    }
                    if self.longnames && (i - 2).is_multiple_of(3) {
                        h.set_entry_type(tar::EntryType::GNULongName);
                        h.set_size(name.len() as u64 + 1);
                        h.set_path("././@LongLink").unwrap();
                    } else {
                        h.set_path(name).unwrap();
                    }
                }
                h.set_cksum();
                self.block.copy_from_slice(h.as_bytes());
            }
            let n = (512 - self.offset).min(out.len());
            out[..n].copy_from_slice(&self.block[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        }
    }
    #[test]
    fn physical_gnu_work_and_effective_entries_have_finite_budgets() {
        for longnames in [true, false] {
            let reader = HeaderFlood {
                index: 0,
                offset: 512,
                block: [0; 512],
                longnames,
            };
            let error = inspect_tar(reader, &identity()).unwrap_err().to_string();
            // Physical headers are counted first, so a file-only flood reaches that cap too.
            assert!(error.contains("physical tar header limit"), "{error}");
        }
    }
}
