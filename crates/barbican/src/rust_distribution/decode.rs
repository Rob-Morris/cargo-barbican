use super::{
    ArchiveIdentity, ArchiveInventory, DistributionError, Encoding, MAX_COMPRESSED_BYTES,
    MAX_DECODER_MEMORY_BYTES, MAX_METADATA_BYTES, inspect_tar, invalid,
};
use miniz_oxide::{
    DataFormat, MZFlush, MZStatus,
    inflate::stream::{InflateState, inflate},
};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

/// Verify the complete compressed identity before decoding a retained input snapshot.
/// The caller owns snapshot isolation. This is data inspection, not signature authentication or installation.
pub fn inspect_archive(
    mut input: impl Read + Seek,
    identity: &ArchiveIdentity,
) -> Result<ArchiveInventory, DistributionError> {
    input.seek(SeekFrom::Start(0))?;
    let mut total = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 32768];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_COMPRESSED_BYTES {
            return Err(invalid("compressed archive byte limit"));
        }
        hash.update(&buffer[..n]);
    }
    if format!("{:x}", hash.finalize()) != identity.sha256.as_str() {
        return Err(invalid("compressed archive digest mismatch"));
    }
    input.seek(SeekFrom::Start(0))?;
    let mut input = BufReader::with_capacity(32768, input.take(total));
    let inventory = match identity.encoding {
        Encoding::Xz => {
            // Reserve margin for fixed filter/input/state buffers; the upstream limit is per-block LZMA2 memory.
            let mut decoder = lzma_rust2::XzReader::new_mem_limit(
                &mut input,
                false,
                ((MAX_DECODER_MEMORY_BYTES - 1024 * 1024) / 1024) as u32,
            );
            let inventory = inspect_tar(&mut decoder, identity)?;
            drop(decoder);
            let mut padding = 0u64;
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                if buffer[..n].iter().any(|b| *b != 0) {
                    return Err(invalid("concatenated XZ streams or trailing data"));
                }
                padding += n as u64;
            }
            if !padding.is_multiple_of(4) {
                return Err(invalid("unaligned XZ padding"));
            }
            inventory
        }
        Encoding::Gzip => {
            let mut decoder = GzipReader::new(&mut input)?;
            inspect_tar(&mut decoder, identity)?
        }
    };
    if !input.fill_buf()?.is_empty() {
        return Err(invalid("unconsumed compressed bytes"));
    }
    // A snapshot that shrank since hashing must not turn a byte-limited reader into a successful EOF.
    if input.get_ref().limit() != 0 {
        return Err(invalid("compressed snapshot changed during inspection"));
    }
    Ok(inventory)
}
fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(value & 1));
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
};
fn crc32(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ *byte as u32) & 255) as usize];
    }
    crc
}
pub(crate) struct GzipReader<R> {
    input: R,
    state: Box<InflateState>,
    crc: u32,
    size: u32,
    finished: bool,
}
impl<R: BufRead> GzipReader<R> {
    pub(crate) fn new(mut input: R) -> io::Result<Self> {
        let mut header = [0u8; 10];
        input.read_exact(&mut header)?;
        if header[..3] != [31, 139, 8] || header[3] & 0xe0 != 0 {
            return Err(bad("unsupported gzip header"));
        }
        let flags = header[3];
        let mut crc = crc32(!0, &header);
        let mut count = 10usize;
        let mut byte = |input: &mut R| -> io::Result<u8> {
            if count == MAX_METADATA_BYTES {
                return Err(bad("gzip header metadata limit"));
            }
            let mut b = [0];
            input.read_exact(&mut b)?;
            count += 1;
            crc = crc32(crc, &b);
            Ok(b[0])
        };
        if flags & 4 != 0 {
            let lo = byte(&mut input)?;
            let hi = byte(&mut input)?;
            for _ in 0..u16::from_le_bytes([lo, hi]) {
                byte(&mut input)?;
            }
        }
        for flag in [8, 16] {
            if flags & flag != 0 {
                while byte(&mut input)? != 0 {}
            }
        }
        if flags & 2 != 0 {
            let mut hcrc = [0; 2];
            input.read_exact(&mut hcrc)?;
            if u16::from_le_bytes(hcrc) != (!crc as u16) {
                return Err(bad("gzip header CRC mismatch"));
            }
        }
        Ok(Self {
            input,
            state: InflateState::new_boxed(DataFormat::Raw),
            crc: !0,
            size: 0,
            finished: false,
        })
    }
}
impl<R: BufRead> Read for GzipReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }
        loop {
            let bytes = self.input.fill_buf()?;
            let result = inflate(&mut self.state, bytes, output, MZFlush::None);
            self.input.consume(result.bytes_consumed);
            self.crc = crc32(self.crc, &output[..result.bytes_written]);
            self.size = self.size.wrapping_add(result.bytes_written as u32);
            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    let mut trailer = [0; 8];
                    self.input.read_exact(&mut trailer)?;
                    if u32::from_le_bytes(trailer[..4].try_into().unwrap()) != !self.crc
                        || u32::from_le_bytes(trailer[4..].try_into().unwrap()) != self.size
                    {
                        return Err(bad("gzip trailer CRC or size mismatch"));
                    }
                    if !self.input.fill_buf()?.is_empty() {
                        return Err(bad("concatenated gzip members or trailing data"));
                    }
                    self.finished = true;
                    return Ok(result.bytes_written);
                }
                Ok(_) => {}
                Err(_) => return Err(bad("invalid or truncated gzip deflate stream")),
            }
            if result.bytes_written != 0 {
                return Ok(result.bytes_written);
            }
            if result.bytes_consumed == 0 {
                return Err(bad("gzip decoder made no progress"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn identity(data: &[u8], encoding: Encoding) -> ArchiveIdentity {
        ArchiveIdentity { package:"rust-docs".into(),target:"aarch64-apple-darwin".into(),component:"rust-docs".into(),root:"rust-docs-1.99.1-aarch64-apple-darwin".into(),encoding,url:"https://static.rust-lang.org/dist/2026-10-15/rust-docs-1.99.1-aarch64-apple-darwin.tar.xz".into(),sha256:super::super::digest(data) }
    }
    fn gzip(input: &[u8]) -> Vec<u8> {
        let mut out = vec![31, 139, 8, 0, 0, 0, 0, 0, 0, 255];
        out.extend(miniz_oxide::deflate::compress_to_vec(input, 6));
        out.extend((!crc32(!0, input)).to_le_bytes());
        out.extend((input.len() as u32).to_le_bytes());
        out
    }
    #[test]
    fn xz_and_gzip_decode_identical_payload_without_extraction() {
        let xz = include_bytes!("fixtures/docs.tar.xz");
        let a = inspect_archive(Cursor::new(xz), &identity(xz, Encoding::Xz)).unwrap();
        let mut raw = Vec::new();
        lzma_rust2::XzReader::new_mem_limit(xz.as_slice(), false, 1024 * 64)
            .read_to_end(&mut raw)
            .unwrap();
        let gz = gzip(&raw);
        let b = inspect_archive(Cursor::new(&gz), &identity(&gz, Encoding::Gzip)).unwrap();
        assert_eq!(a.payload, b.payload);
        assert_eq!(a.expanded_bytes, b.expanded_bytes);
    }
    #[test]
    fn payload_corruption_truncation_concatenation_and_trailing_data_refuse() {
        let xz = include_bytes!("fixtures/docs.tar.xz").to_vec();
        let mut corrupt = xz.clone();
        corrupt[30] ^= 1;
        for bytes in [
            corrupt,
            xz[..xz.len() - 1].to_vec(),
            [xz.clone(), xz.clone()].concat(),
            [xz.clone(), vec![1]].concat(),
            [xz.clone(), vec![0]].concat(),
        ] {
            assert!(inspect_archive(Cursor::new(&bytes), &identity(&bytes, Encoding::Xz)).is_err());
        }
        let padded = [xz.clone(), vec![0; 4]].concat();
        assert!(inspect_archive(Cursor::new(&padded), &identity(&padded, Encoding::Xz)).is_ok());
        let mut raw = Vec::new();
        lzma_rust2::XzReader::new_mem_limit(xz.as_slice(), false, 1024 * 64)
            .read_to_end(&mut raw)
            .unwrap();
        let gz = gzip(&raw);
        let mut corrupt = gz.clone();
        let i = corrupt.len() - 8;
        corrupt[i] ^= 1;
        for bytes in [
            corrupt,
            gz[..gz.len() - 1].to_vec(),
            [gz.clone(), gz.clone()].concat(),
            [gz, vec![0]].concat(),
        ] {
            assert!(
                inspect_archive(Cursor::new(&bytes), &identity(&bytes, Encoding::Gzip)).is_err()
            );
        }
    }
    #[test]
    fn sha256_identity_precedes_decoder_and_dictionary_is_bounded() {
        let xz = include_bytes!("fixtures/docs.tar.xz");
        let mut id = identity(xz, Encoding::Xz);
        id.sha256 = super::super::digest(b"wrong");
        assert!(
            inspect_archive(Cursor::new(xz), &id)
                .unwrap_err()
                .to_string()
                .contains("digest")
        );
        let mut decoder = lzma_rust2::XzReader::new_mem_limit(xz.as_slice(), false, 1);
        let mut out = [0; 512];
        assert!(decoder.read(&mut out).is_err());
    }
    #[test]
    fn index_only_metadata_is_not_payload_or_budget_authority() {
        let original = include_bytes!("fixtures/docs.tar.xz").to_vec();
        let expected =
            inspect_archive(Cursor::new(&original), &identity(&original, Encoding::Xz)).unwrap();
        let mut changed = original.clone();
        let end = changed.len();
        let backwards = u32::from_le_bytes(changed[end - 8..end - 4].try_into().unwrap());
        changed[end - 8..end - 4].copy_from_slice(&(backwards + 1).to_le_bytes());
        let crc = !crc32(!0, &changed[end - 8..end - 2]);
        changed[end - 12..end - 8].copy_from_slice(&crc.to_le_bytes());
        let actual =
            inspect_archive(Cursor::new(&changed), &identity(&changed, Encoding::Xz)).unwrap();
        assert_eq!(actual.payload, expected.payload);
        assert_eq!(actual.expanded_bytes, expected.expanded_bytes);
    }
    #[test]
    fn gzip_optional_header_crc_and_metadata_limits() {
        let base = gzip(b"hello");
        let mut bytes = base[..10].to_vec();
        bytes[3] = 8 | 16 | 2;
        bytes.extend(b"name\0comment\0");
        let hcrc = (!crc32(!0, &bytes)) as u16;
        bytes.extend(hcrc.to_le_bytes());
        bytes.extend(&base[10..]);
        let mut out = Vec::new();
        GzipReader::new(Cursor::new(&bytes))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"hello");
        bytes[10] ^= 1;
        assert!(GzipReader::new(Cursor::new(bytes)).is_err());
        let mut huge = base[..10].to_vec();
        huge[3] = 8;
        huge.resize(MAX_METADATA_BYTES + 1, b'x');
        assert!(GzipReader::new(Cursor::new(huge)).is_err());
    }
}
