use super::{ToolError, require};
use crate::Sha256Digest;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_FILES: usize = 100_000;
pub const MAX_GRAPH_NODES: usize = 100_000;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_DEPTH: usize = 128;
pub const MAX_LINE_BYTES: usize = 16 * 1024;
pub const MAX_CAPTURE_BYTES: u64 = 128 * 1024 * 1024;
pub const COLLECTION_DEADLINE_SECONDS: i64 = 30 * 60;
pub const MAX_CACHE_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKind {
    Subject,
    OriginPolicy,
    EvidenceContent,
    Observation,
    Review,
    Assessment,
    LocalAcceptance,
    RepoAdmission,
    InstallIntent,
    InstalledBinding,
    SourceKnowledge,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordId {
    pub kind: RecordKind,
    pub schema_version: u32,
    pub sha256: Sha256Digest,
}
impl RecordId {
    pub fn require_kind(&self, kind: RecordKind) -> Result<(), ToolError> {
        require(
            self.kind == kind && self.schema_version == SCHEMA_VERSION,
            "wrong tool record kind or schema",
        )
    }
}
impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = serde_json::to_value(self.kind).map_err(|_| std::fmt::Error)?;
        write!(
            f,
            "cargo-tool:{}:v{}:{}",
            kind.as_str().ok_or(std::fmt::Error)?,
            self.schema_version,
            self.sha256
        )
    }
}
impl std::str::FromStr for RecordId {
    type Err = ToolError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let fields: Vec<_> = value.split(':').collect();
        require(
            fields.len() == 4 && fields[0] == "cargo-tool" && fields[2] == "v1",
            "invalid tool record ID",
        )?;
        let kind = serde_json::from_value(serde_json::Value::String(fields[1].into()))
            .map_err(|_| ToolError("invalid tool record kind".into()))?;
        let sha256 = Sha256Digest::try_from(fields[3])
            .map_err(|_| ToolError("invalid tool record digest".into()))?;
        require(sha256.as_str() == fields[3], "noncanonical digest")?;
        Ok(Self {
            kind,
            schema_version: SCHEMA_VERSION,
            sha256,
        })
    }
}

pub trait ToolRecord: Serialize + DeserializeOwned {
    const KIND: RecordKind;
    fn validate(&self) -> Result<(), ToolError>;
    fn id(&self) -> Result<RecordId, ToolError> {
        self.validate()?;
        let bytes = canonical_bytes(self)?;
        let mut hash = Sha256::new();
        hash.update(b"barbican/cargo-tool/v1\0");
        hash.update(serde_json::to_vec(&Self::KIND).map_err(json_error)?);
        hash.update(b"\0");
        hash.update(bytes);
        Ok(RecordId {
            kind: Self::KIND,
            schema_version: SCHEMA_VERSION,
            sha256: digest_from_hash(hash),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    schema_version: u32,
    kind: RecordKind,
    record: T,
}

pub fn encode_record<T: ToolRecord>(record: &T) -> Result<Vec<u8>, ToolError> {
    record.validate()?;
    canonical_bytes(&Envelope {
        schema_version: SCHEMA_VERSION,
        kind: T::KIND,
        record,
    })
}
pub fn parse_record<T: ToolRecord>(bytes: &[u8]) -> Result<T, ToolError> {
    require(bytes.len() <= MAX_RECORD_BYTES, "tool record exceeds 8 MiB")?;
    let raw = serde_json::from_slice::<UniqueValue>(bytes)
        .map_err(json_error)?
        .0;
    let envelope: Envelope<T> = serde_json::from_slice(bytes).map_err(json_error)?;
    require(
        envelope.schema_version == SCHEMA_VERSION && envelope.kind == T::KIND,
        "wrong tool record kind or schema",
    )?;
    envelope.record.validate()?;
    let canonical: serde_json::Value =
        serde_json::from_slice(&encode_record(&envelope.record)?).map_err(json_error)?;
    require(raw == canonical, "noncanonical sets or record values")?;
    Ok(envelope.record)
}
pub fn canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ToolError> {
    let value = serde_json::to_value(value).map_err(json_error)?;
    validate_json_numbers(&value)?;
    let bytes = serde_json::to_vec(&value).map_err(json_error)?;
    require(bytes.len() <= MAX_RECORD_BYTES, "tool record exceeds 8 MiB")?;
    Ok(bytes)
}
fn validate_json_numbers(value: &serde_json::Value) -> Result<(), ToolError> {
    match value {
        serde_json::Value::Number(number) => require(
            number.is_i64() || number.is_u64(),
            "floating-point tool record values are unsupported",
        ),
        serde_json::Value::Array(values) => {
            for value in values {
                validate_json_numbers(value)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                validate_json_numbers(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    let mut h = Sha256::new();
    h.update(bytes);
    digest_from_hash(h)
}
fn digest_from_hash(hash: Sha256) -> Sha256Digest {
    Sha256Digest::try_from(format!("{:x}", hash.finalize())).expect("SHA256 produces 64 hex digits")
}
fn json_error(error: serde_json::Error) -> ToolError {
    ToolError(format!("invalid tool record: {error}"))
}
pub(crate) fn schema(version: u32) -> Result<(), ToolError> {
    require(version == SCHEMA_VERSION, "unsupported tool schema")
}
pub(crate) fn text(value: &str) -> Result<(), ToolError> {
    require(
        !value.trim().is_empty()
            && !value
                .chars()
                .any(|c| c == '\0' || (c.is_control() && c != '\n' && c != '\t')),
        "missing or invalid text",
    )
}
pub(crate) fn name(value: &str) -> Result<(), ToolError> {
    require(
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
        "invalid package or binary name",
    )
}
pub(crate) fn relative_path(value: &str) -> Result<(), ToolError> {
    require(
        !value.is_empty()
            && value.len() <= MAX_PATH_BYTES
            && !value.starts_with('/')
            && !value.contains('\\')
            && !value.chars().any(char::is_control)
            && value.split('/').count() <= MAX_DEPTH
            && value
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".."),
        "invalid relative tool path",
    )
}
pub(crate) fn absolute_path(value: &str) -> Result<(), ToolError> {
    require(value.starts_with('/'), "tool path must be absolute")?;
    require(value.len() <= MAX_PATH_BYTES, "tool path too long")?;
    relative_path(value.strip_prefix('/').unwrap_or(value))
}
pub(crate) fn time(value: i64) -> Result<(), ToolError> {
    require(value >= 0, "invalid UTC Unix timestamp")
}

struct UniqueValue(serde_json::Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded JSON with unique object keys and integer numbers")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    if values.len() >= MAX_GRAPH_NODES * 8 {
                        return Err(serde::de::Error::custom(
                            "record sequence exceeds item budget",
                        ));
                    }
                    values.push(value.0);
                }
                Ok(UniqueValue(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.len() >= MAX_GRAPH_NODES * 8 {
                        return Err(serde::de::Error::custom(
                            "record object exceeds item budget",
                        ));
                    }
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                }
                Ok(UniqueValue(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
