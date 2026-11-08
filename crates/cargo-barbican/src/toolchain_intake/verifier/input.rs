use super::Result;
use pgp::{
    armor::{Dearmor, DearmorOptions},
    composed::{Deserializable, PacketBodyReader, SignedPublicKey},
    packet::{Packet, PacketHeader},
    ser::Serialize,
    types::{KeyDetails, KeyVersion, PacketLength, PublicParams, Tag},
};
use std::io::{Cursor, Read};
const LIMIT: usize = 64 * 1024;

pub(super) fn packets(raw: &[u8], certificate: bool) -> Result<Vec<Packet>> {
    if raw.len() > LIMIT {
        return Err("input size limit".into());
    }
    let bytes = decode(raw)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let mut packets = Vec::new();
    while cursor.position() < bytes.len() as u64 {
        if packets.len() >= 64 {
            return Err("packet count limit".into());
        }
        let header = PacketHeader::try_from_reader(&mut cursor).map_err(|e| e.to_string())?;
        if !matches!(header.packet_length(), PacketLength::Fixed(n) if n as usize <= LIMIT) {
            return Err("unsupported packet length".into());
        }
        let allowed = if certificate {
            matches!(
                header.tag(),
                Tag::PublicKey | Tag::PublicSubkey | Tag::Signature | Tag::UserId
            )
        } else {
            header.tag() == Tag::Signature
        };
        if !allowed {
            return Err("unsupported packet type".into());
        }
        let reader = PacketBodyReader::new(header, &mut cursor).map_err(|e| e.to_string())?;
        packets.push(Packet::from_reader(header, reader).map_err(|e| e.to_string())?);
    }
    Ok(packets)
}

fn decode(raw: &[u8]) -> Result<Vec<u8>> {
    if !raw.starts_with(b"-----BEGIN PGP ") {
        return Ok(raw.to_vec());
    }
    let mut decoder =
        Dearmor::with_options(Cursor::new(raw), DearmorOptions::new().set_limit(LIMIT));
    let mut bytes = Vec::new();
    (&mut decoder)
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > LIMIT {
        return Err("decoded size limit".into());
    }
    let (_, _, _, mut tail) = decoder.into_parts();
    let mut trailing = Vec::new();
    tail.read_to_end(&mut trailing).map_err(|e| e.to_string())?;
    if trailing.iter().any(|x| !x.is_ascii_whitespace()) {
        return Err("trailing armour input".into());
    }
    Ok(bytes)
}

pub(super) fn certificate(input: &[Packet]) -> Result<SignedPublicKey> {
    if !matches!(input.first(), Some(Packet::PublicKey(_)))
        || input
            .iter()
            .filter(|x| matches!(x, Packet::PublicKey(_)))
            .count()
            != 1
    {
        return Err("exactly one public certificate required".into());
    }
    let mut keys = SignedPublicKey::from_packets(input.iter().cloned().map(Ok).peekable());
    let key = keys
        .next()
        .ok_or("missing certificate")?
        .map_err(|e| e.to_string())?;
    if keys.next().is_some() {
        return Err("extra certificate".into());
    }
    if key.public_subkeys.len() > 8 {
        return Err("subkey limit".into());
    }
    if key.primary_key.version() != KeyVersion::V4
        || !matches!(key.primary_key.public_params(), PublicParams::RSA(_))
        || key.public_subkeys.iter().any(|x| {
            x.key.version() != KeyVersion::V4
                || !matches!(x.key.public_params(), PublicParams::RSA(_))
        })
    {
        return Err("only v4 public RSA certificates supported".into());
    }
    // The composed parser drops unbound/unsupported components; never silently approve that projection.
    let mut serialised = Vec::new();
    key.to_writer(&mut serialised).map_err(|e| e.to_string())?;
    if packets(&serialised, true)? != input {
        return Err("noncanonical or unconsumed certificate packets".into());
    }
    Ok(key)
}
