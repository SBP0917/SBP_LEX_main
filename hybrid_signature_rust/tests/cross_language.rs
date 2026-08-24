use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(feature = "software-signing")]
use sbp_lex_v2_hybrid_signature::SoftwareHybridSigningKey;
use sbp_lex_v2_hybrid_signature::{
    HybridPublicKey, HybridSignature, SUITE_ID, VERIFICATION_RULE, canonical_preimage, sha512,
};
use serde_json::Value;

const PYTHON_VECTOR: &str = include_str!("vectors/python_v2.json");
#[cfg(feature = "software-signing")]
const RUST_VECTOR: &str = include_str!("vectors/rust_v2.json");

fn decode(record: &Value, field: &str) -> Vec<u8> {
    STANDARD
        .decode(record[field].as_str().expect("vector string"))
        .expect("canonical base64")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[test]
fn python_generated_vector_verifies_in_rust_exactly() {
    let record: Value = serde_json::from_str(PYTHON_VECTOR).expect("vector json");
    let purpose = record["purpose"].as_str().expect("purpose");
    assert_eq!(record["suite"].as_str(), Some(SUITE_ID));
    assert_eq!(
        record["verification_rule"].as_str(),
        Some(VERIFICATION_RULE)
    );
    let epoch = record["authority_epoch"].as_u64().expect("epoch");
    let payload = decode(&record, "payload_b64");
    let context = decode(&record, "application_context_b64");
    let expected_preimage = decode(&record, "preimage_b64");
    let ml_public = decode(&record, "mldsa87_public_key_b64");
    let ed_public = decode(&record, "ed448_public_key_b64");
    let ml_signature = decode(&record, "mldsa87_signature_b64");
    let ed_signature = decode(&record, "ed448_signature_b64");

    let public_key = HybridPublicKey::from_slices(&ml_public, &ed_public).expect("public keys");
    let signature =
        HybridSignature::from_slices(&ml_signature, &ed_signature).expect("canonical signatures");
    let observed_preimage = canonical_preimage(&public_key, purpose, epoch, &context, &payload)
        .expect("canonical preimage");
    assert_eq!(observed_preimage, expected_preimage);
    assert_eq!(
        hex(&sha512(&observed_preimage)),
        "5aa72dcb91c9a88c3442c0b9a95b97c2788e393ccc46e448f218bb67281a1a42cd998f23e1b182318ba84e3335d6f6f3b574def3779b5f90ef70e46490c9dd84"
    );
    assert_eq!(
        hex(&public_key.ml_dsa_87_key_id()),
        "31ff0591a266672f9c8fcf07bab8a4377486e42592fb0788d6daa32e676568a917f4306035281ab54fd71a6f38fa245ee38f2e7848dd355ccba8c4a2c7645eca"
    );
    assert_eq!(
        hex(&public_key.ed448_key_id()),
        "40a3a896fc8363284526480f0101cc016044aaea0552862ab07a3307d36d5eb1f947569f55449e29fd951790b4d836b08f7064c1aebedfd00f497c6043cf798a"
    );
    assert_eq!(
        hex(&public_key.ordered_key_set_digest()),
        "4bae1c67385eaf6313bd0b29c57dd0bee68ef2ae73a5b4f423912727f464548a923f2560d4f58bf61d85a49d36435223fff6b2a3c673f007778b117642c17fe1"
    );
    public_key
        .verify(purpose, epoch, &context, &payload, &signature)
        .expect("Python vector dual-lane verification");
}

#[cfg(feature = "software-signing")]
#[test]
fn rust_fixed_seed_signature_is_reciprocal_vector_material() {
    let record: Value = serde_json::from_str(PYTHON_VECTOR).expect("vector json");
    let rust_record: Value = serde_json::from_str(RUST_VECTOR).expect("Rust vector json");
    let purpose = record["purpose"].as_str().expect("purpose");
    assert_eq!(rust_record["suite"].as_str(), Some(SUITE_ID));
    assert_eq!(
        rust_record["verification_rule"].as_str(),
        Some(VERIFICATION_RULE)
    );
    let epoch = record["authority_epoch"].as_u64().expect("epoch");
    let payload = decode(&record, "payload_b64");
    let context = decode(&record, "application_context_b64");
    let signer = SoftwareHybridSigningKey::from_seed_slices(
        &(0u8..32).collect::<Vec<_>>(),
        &(0u8..57).collect::<Vec<_>>(),
    )
    .expect("fixed seeds");
    assert_eq!(
        signer.public_key().ml_dsa_87_bytes().as_slice(),
        decode(&record, "mldsa87_public_key_b64")
    );
    assert_eq!(
        signer.public_key().ed448_bytes().as_slice(),
        decode(&record, "ed448_public_key_b64")
    );
    let signature = signer
        .sign(purpose, epoch, &context, &payload)
        .expect("deterministic Rust vector signature");
    signer
        .public_key()
        .verify(purpose, epoch, &context, &payload, &signature)
        .expect("reciprocal Rust signature");
    assert_eq!(
        rust_record["preimage_sha512"].as_str(),
        Some(
            hex(&sha512(
                &canonical_preimage(&signer.public_key(), purpose, epoch, &context, &payload,)
                    .expect("canonical preimage")
            ))
            .as_str()
        )
    );
    assert_eq!(
        signature.ml_dsa_87_bytes().as_slice(),
        decode(&rust_record, "mldsa87_signature_b64")
    );
    assert_eq!(
        signature.ed448_bytes().as_slice(),
        decode(&rust_record, "ed448_signature_b64")
    );
}
