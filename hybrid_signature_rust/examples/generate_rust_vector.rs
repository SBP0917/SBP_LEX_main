use std::{env, fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sbp_lex_v2_hybrid_signature::{SUITE_ID, SoftwareHybridSigningKey, VERIFICATION_RULE, sha512};
use serde_json::{Value, json};

fn decode(record: &Value, field: &str) -> Vec<u8> {
    STANDARD
        .decode(record[field].as_str().expect("vector string"))
        .expect("canonical base64")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let python_path = root.join("tests/vectors/python_v2.json");
    let output_path = env::args_os()
        .nth(1)
        .map_or_else(|| root.join("tests/vectors/rust_v2.json"), PathBuf::from);
    let record: Value =
        serde_json::from_str(&fs::read_to_string(&python_path).expect("read Python vector"))
            .expect("parse Python vector");
    assert_eq!(record["suite"], SUITE_ID);
    assert_eq!(record["verification_rule"], VERIFICATION_RULE);
    let purpose = record["purpose"].as_str().expect("purpose");
    let epoch = record["authority_epoch"].as_u64().expect("epoch");
    let payload = decode(&record, "payload_b64");
    let context = decode(&record, "application_context_b64");
    let signer = SoftwareHybridSigningKey::from_seed_slices(
        &(0u8..32).collect::<Vec<_>>(),
        &(0u8..57).collect::<Vec<_>>(),
    )
    .expect("fixed signing keys");
    let signature = signer
        .sign(purpose, epoch, &context, &payload)
        .expect("strict dual signature");
    let preimage = sbp_lex_v2_hybrid_signature::canonical_preimage(
        &signer.public_key(),
        purpose,
        epoch,
        &context,
        &payload,
    )
    .expect("strict dual preimage");
    let output = json!({
        "suite": SUITE_ID,
        "verification_rule": VERIFICATION_RULE,
        "purpose": purpose,
        "authority_epoch": epoch,
        "payload_b64": STANDARD.encode(&payload),
        "preimage_sha512": hex_lower(&sha512(&preimage)),
        "mldsa87_signature_b64": STANDARD.encode(signature.ml_dsa_87_bytes()),
        "ed448_signature_b64": STANDARD.encode(signature.ed448_bytes()),
    });
    fs::write(
        &output_path,
        format!(
            "{}\n",
            serde_json::to_string(&output).expect("serialize vector")
        ),
    )
    .expect("write Rust vector");
    println!("{}", output_path.display());
}
