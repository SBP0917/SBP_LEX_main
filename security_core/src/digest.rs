use serde_json::Value;
use sha2::{Digest, Sha512};

use crate::{canonical::canonical_integrity_bytes, BoundaryError};

pub fn sha512_hex(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    let mut output = String::with_capacity(128);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn canonical_digest(value: &Value) -> Result<String, BoundaryError> {
    Ok(sha512_hex(&canonical_integrity_bytes(value)?))
}

pub fn is_sha512(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn constant_time_hex_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
