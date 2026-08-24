#![forbid(unsafe_code)]

use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::io::{self, Read};

const MAX_INPUT_BYTES: u64 = 1_048_577;
const ENVELOPE_VERSION: &str = "sbp.v2.assurance-envelope/1";
const VERDICT_VERSION: &str = "sbp.v2.assurance-verdict/1";
const VERIFIER_VERSION: &str = "sbp-v2-assurance-kernel/0.1.0";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssuranceEnvelope {
    schema_version: String,
    request_fingerprint: String,
    checkpoint: String,
    sequence: u64,
    previous_envelope_sha512: String,
    canonical_state_b64: String,
    canonical_state_sha512: String,
}

#[derive(Debug, Serialize)]
struct Verdict {
    schema_version: &'static str,
    verifier_version: &'static str,
    accepted: bool,
    reason_code: &'static str,
    request_fingerprint: Option<String>,
    checkpoint: Option<String>,
    observed_state_sha512: Option<String>,
    envelope_sha512: Option<String>,
}

impl Verdict {
    fn reject(reason_code: &'static str) -> Self {
        Self {
            schema_version: VERDICT_VERSION,
            verifier_version: VERIFIER_VERSION,
            accepted: false,
            reason_code,
            request_fingerprint: None,
            checkpoint: None,
            observed_state_sha512: None,
            envelope_sha512: None,
        }
    }
}

fn sha512_hex(payload: &[u8]) -> String {
    let digest = Sha512::digest(payload);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha512(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha512_or_genesis(value: &str) -> bool {
    value == "GENESIS" || is_sha512(value)
}

fn checkpoint_is_known(value: &str) -> bool {
    matches!(
        value,
        "state_construction"
            | "authority_first"
            | "governance_grc"
            | "domain_aurion_convergence"
            | "execution_gate_input"
            | "terminal_audit"
    )
}

fn contains_float(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_i64().is_none() && number.as_u64().is_none(),
        Value::Array(values) => values.iter().any(contains_float),
        Value::Object(values) => values.values().any(contains_float),
        _ => false,
    }
}

fn verify(input: &[u8]) -> Verdict {
    let envelope: AssuranceEnvelope = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => return Verdict::reject("MALFORMED_ENVELOPE"),
    };

    let mut verdict = Verdict::reject("INTERNAL_VERIFIER_ERROR");
    verdict.request_fingerprint = Some(envelope.request_fingerprint.clone());
    verdict.checkpoint = Some(envelope.checkpoint.clone());

    if envelope.schema_version != ENVELOPE_VERSION {
        verdict.reason_code = "UNSUPPORTED_VERSION";
        return verdict;
    }
    if !is_sha512(&envelope.request_fingerprint) {
        verdict.reason_code = "INVALID_REQUEST_FINGERPRINT";
        return verdict;
    }
    if !checkpoint_is_known(&envelope.checkpoint) {
        verdict.reason_code = "INVALID_CHECKPOINT";
        return verdict;
    }
    if !is_sha512_or_genesis(&envelope.previous_envelope_sha512) {
        verdict.reason_code = "INVALID_PREVIOUS_DIGEST";
        return verdict;
    }

    let canonical_state = match BASE64_STANDARD.decode(&envelope.canonical_state_b64) {
        Ok(value) => value,
        Err(_) => {
            verdict.reason_code = "INVALID_BASE64";
            return verdict;
        }
    };
    if BASE64_STANDARD.encode(&canonical_state) != envelope.canonical_state_b64 {
        verdict.reason_code = "NON_CANONICAL_BASE64";
        return verdict;
    }

    let observed_state_sha512 = sha512_hex(&canonical_state);
    verdict.observed_state_sha512 = Some(observed_state_sha512.clone());
    if observed_state_sha512 != envelope.canonical_state_sha512 {
        verdict.reason_code = "STATE_DIGEST_MISMATCH";
        return verdict;
    }

    let state_value: Value = match serde_json::from_slice(&canonical_state) {
        Ok(value) => value,
        Err(_) => {
            verdict.reason_code = "INVALID_CANONICAL_STATE";
            return verdict;
        }
    };
    if contains_float(&state_value) {
        verdict.reason_code = "FLOAT_FORBIDDEN";
        return verdict;
    }
    let recanonicalised = match serde_jcs::to_vec(&state_value) {
        Ok(value) => value,
        Err(_) => {
            verdict.reason_code = "INVALID_CANONICAL_STATE";
            return verdict;
        }
    };
    if recanonicalised != canonical_state {
        verdict.reason_code = "NON_CANONICAL_STATE";
        return verdict;
    }

    let canonical_envelope = match serde_jcs::to_vec(&envelope) {
        Ok(value) => value,
        Err(_) => return verdict,
    };
    verdict.envelope_sha512 = Some(sha512_hex(&canonical_envelope));
    verdict.accepted = true;
    verdict.reason_code = "VERIFIED";
    verdict
}

fn main() {
    let mut input = Vec::new();
    let read_result = io::stdin()
        .lock()
        .take(MAX_INPUT_BYTES)
        .read_to_end(&mut input);

    let verdict = match read_result {
        Ok(size) if size as u64 == MAX_INPUT_BYTES => Verdict::reject("INPUT_TOO_LARGE"),
        Ok(_) => verify(&input),
        Err(_) => Verdict::reject("INTERNAL_VERIFIER_ERROR"),
    };
    let accepted = verdict.accepted;
    let encoded = serde_json::to_string(&verdict).unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":\"{VERDICT_VERSION}\",\"verifier_version\":\"{VERIFIER_VERSION}\",\"accepted\":false,\"reason_code\":\"INTERNAL_VERIFIER_ERROR\"}}"
        )
    });
    println!("{encoded}");
    std::process::exit(if accepted { 0 } else { 2 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_checkpoint() {
        assert!(!checkpoint_is_known("invented"));
    }

    #[test]
    fn rejects_floating_point_state() {
        let value: Value = serde_json::from_str(r#"{"risk":0.5}"#).unwrap();
        assert!(contains_float(&value));
    }

    #[test]
    fn validates_lowercase_sha512_only() {
        assert!(is_sha512(&"a".repeat(128)));
        assert!(!is_sha512(&"A".repeat(128)));
        assert!(!is_sha512(&"a".repeat(64)));
        assert!(!is_sha512("GENESIS"));
    }

    #[test]
    fn computes_the_sha512_abc_vector() {
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a".to_owned()
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }
}
