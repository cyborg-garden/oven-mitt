//! Object handles (PRD R-OBJ-1): `v_` + 12 lowercase hex characters from the
//! OS CSPRNG. Handles are identifiers, not secrets — `list` returns them —
//! so 48 bits is a collision bound, not a security one.

use std::fmt;

use serde::{Deserialize, Serialize};

const PREFIX: &str = "v_";
const HEX_LEN: usize = 12;

/// A validated object handle.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Handle(String);

/// Why a handle string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid handle; expected v_ followed by 12 lowercase hex characters")]
pub struct InvalidHandle;

impl Handle {
    /// Generate a fresh random handle.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; HEX_LEN / 2];
        getrandom::fill(&mut bytes)?;
        Ok(Self(format!("{PREFIX}{}", hex::encode(bytes))))
    }

    /// Validate a handle received from a client.
    pub fn parse(s: &str) -> Result<Self, InvalidHandle> {
        let Some(rest) = s.strip_prefix(PREFIX) else {
            return Err(InvalidHandle);
        };
        if rest.len() != HEX_LEN
            || !rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(InvalidHandle);
        }
        Ok(Self(s.to_owned()))
    }

    /// The handle as text, e.g. `v_9c1e4a0b2d31`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The handle's bytes, used as AEAD associated data to bind ciphertext
    /// to the object it belongs to.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({})", self.0)
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_handles_validate_and_differ() {
        let a = Handle::generate().unwrap_or_else(|e| panic!("{e}"));
        let b = Handle::generate().unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 14);
        assert_eq!(Handle::parse(a.as_str()), Ok(a.clone()));
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        for bad in [
            "",
            "v_",
            "9c1e4a0b2d31",
            "v_9c1e4a0b2d3",
            "v_9c1e4a0b2d311",
            "v_9C1E4A0B2D31",
            "v_9c1e4a0b2d3g",
            "x_9c1e4a0b2d31",
            "v_9c1e4a0b2d31/../x",
            " v_9c1e4a0b2d31",
        ] {
            assert_eq!(Handle::parse(bad), Err(InvalidHandle), "{bad:?}");
        }
        assert!(Handle::parse("v_000000000000").is_ok());
        assert!(Handle::parse("v_ffffffffffff").is_ok());
    }

    #[test]
    fn serde_round_trip_and_rejects_invalid() {
        let h = Handle::parse("v_9c1e4a0b2d31").unwrap_or_else(|e| panic!("{e}"));
        let json = serde_json::to_string(&h).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(json, "\"v_9c1e4a0b2d31\"");
        let back: Handle = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back, h);
        assert!(serde_json::from_str::<Handle>("\"nope\"").is_err());
    }
}
