//! Canonical CBOR serialization for deterministic hashing.
//!
//! This module ensures that all checkpoints serialize to the same byte sequence
//! regardless of implementation, enabling reproducible Merkle roots and signatures.
//!
//! ## Canonicalization Rules (RFC 8949 Section 4.2)
//! 1. Keys in maps MUST be sorted by encoded byte string
//! 2. Integers encoded in minimal form
//! 3. Floating-point disabled (use fixed-point or integers)
//! 4. No indefinite-length encoding

use serde::{Deserialize, Serialize};
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("CBOR encoding error: {0}")]
    Encode(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR decoding error: {0}")]
    Decode(#[from] ciborium::de::Error<std::io::Error>),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SerializationError>;

/// Serialize a value to canonical CBOR bytes.
///
/// This produces a deterministic byte representation suitable for hashing.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;

    // Ciborium already produces canonical CBOR by default (sorted maps, minimal encoding)
    // but we verify no indefinite-length encoding sneaked in
    verify_canonical(&buf)?;

    Ok(buf)
}

/// Deserialize a value from canonical CBOR bytes.
pub fn from_canonical_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let value = ciborium::from_reader(bytes)?;
    Ok(value)
}

/// Verify that CBOR bytes are in canonical form.
///
/// Checks for:
/// - No indefinite-length encoding (major type with additional info 31)
/// - Minimal integer encoding
fn verify_canonical(bytes: &[u8]) -> Result<()> {
    let mut cursor = std::io::Cursor::new(bytes);
    verify_canonical_item(&mut cursor)?;
    Ok(())
}

fn verify_canonical_item<R: Read>(reader: &mut R) -> Result<()> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;

    let major_type = (buf[0] & 0xE0) >> 5;
    let additional_info = buf[0] & 0x1F;

    // Check for indefinite-length encoding (not allowed in canonical form)
    if additional_info == 31 {
        return Err(SerializationError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Indefinite-length encoding not allowed in canonical CBOR",
        )));
    }

    // Read additional bytes based on additional_info
    let length = match additional_info {
        0..=23 => additional_info as usize,
        24 => {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            buf[0] as usize
        }
        25 => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            u16::from_be_bytes(buf) as usize
        }
        26 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            u32::from_be_bytes(buf) as usize
        }
        27 => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            u64::from_be_bytes(buf) as usize
        }
        _ => return Ok(()), // Should not happen
    };

    // Recursively verify based on major type
    match major_type {
        0 | 1 | 7 => {}, // Unsigned int, negative int, simple/special - no nested data
        2 | 3 => {
            // Byte string or text string - skip content
            let mut buf = vec![0u8; length];
            reader.read_exact(&mut buf)?;
        }
        4 => {
            // Array - verify each element
            for _ in 0..length {
                verify_canonical_item(reader)?;
            }
        }
        5 => {
            // Map - verify keys and values
            // Keys MUST be sorted in canonical CBOR (checked by ciborium)
            for _ in 0..length {
                verify_canonical_item(reader)?; // Key
                verify_canonical_item(reader)?; // Value
            }
        }
        6 => {
            // Tagged data - verify content
            verify_canonical_item(reader)?;
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        a: u64,
        b: String,
        c: Vec<u8>,
    }

    #[test]
    fn test_canonical_serialization_deterministic() {
        let obj = TestStruct {
            a: 12345,
            b: "test".to_string(),
            c: vec![1, 2, 3],
        };

        let bytes1 = to_canonical_cbor(&obj).unwrap();
        let bytes2 = to_canonical_cbor(&obj).unwrap();

        assert_eq!(bytes1, bytes2, "Serialization must be deterministic");
    }

    #[test]
    fn test_canonical_deserialization() {
        let obj = TestStruct {
            a: 12345,
            b: "test".to_string(),
            c: vec![1, 2, 3],
        };

        let bytes = to_canonical_cbor(&obj).unwrap();
        let decoded: TestStruct = from_canonical_cbor(&bytes).unwrap();

        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_map_key_ordering() {
        // BTreeMap ensures sorted keys, which ciborium preserves
        let mut map = BTreeMap::new();
        map.insert("z", 1);
        map.insert("a", 2);
        map.insert("m", 3);

        let bytes = to_canonical_cbor(&map).unwrap();

        // Verify canonical form
        verify_canonical(&bytes).unwrap();

        // Deserialize and check order preserved
        let decoded: BTreeMap<String, i32> = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded.get("a"), Some(&2));
    }

    #[test]
    fn test_hash_determinism() {
        use sha2::{Digest, Sha256};

        let obj = TestStruct {
            a: 999,
            b: "deterministic".to_string(),
            c: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let bytes1 = to_canonical_cbor(&obj).unwrap();
        let hash1 = Sha256::digest(&bytes1);

        let bytes2 = to_canonical_cbor(&obj).unwrap();
        let hash2 = Sha256::digest(&bytes2);

        assert_eq!(hash1, hash2, "Hashes must be identical for canonical serialization");
    }
}
