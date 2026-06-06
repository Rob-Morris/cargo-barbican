use std::fmt::{self, Display, Formatter};

use thiserror::Error;

const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Sha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = Sha256DigestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != SHA256_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Sha256DigestError);
        }

        Ok(Self(value.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("not a valid SHA-256 digest")]
pub struct Sha256DigestError;

#[cfg(test)]
mod tests {
    use super::Sha256Digest;

    #[test]
    fn rejects_non_hex_or_wrong_length_values() {
        assert!(Sha256Digest::try_from("").is_err());
        assert!(Sha256Digest::try_from(&"a".repeat(63) as &str).is_err());
        assert!(Sha256Digest::try_from(&"a".repeat(65) as &str).is_err());
        assert!(
            Sha256Digest::try_from(
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            )
            .is_err()
        );
    }

    #[test]
    fn lowercases_valid_hex_values() {
        let digest = Sha256Digest::try_from(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        )
        .expect("digest should parse");

        assert_eq!(
            digest.as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }
}
