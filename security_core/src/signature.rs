use base64::{engine::general_purpose::STANDARD, Engine as _};
use sbp_lex_v2_hybrid_signature::{
    sha512, HybridPublicKey, HybridSignature, ED448_SIGNATURE_BYTES, ML_DSA_87_SIGNATURE_BYTES,
    SECURITY_PROFILE, SUITE_ID, SUITE_VERSION, TRANSITION_POLICY, VERIFICATION_RULE,
};
use serde_json::{json, Map, Value};

use crate::{
    canonical::canonical_assurance_bytes,
    digest::{constant_time_hex_equal, is_sha512, sha512_hex},
    BoundaryError, Gap,
};

const RESERVED: [&str; 3] = ["digest", "signature", "verified"];
pub const TEST_ONLY_CUSTODY_CLASS: &str = "TEST_ONLY_NONPRODUCTION_SOFTWARE_KEY";
pub const PRODUCTION_DUAL_CUSTODY_CLASS: &str = "INDEPENDENT_EXTERNAL_TWO_LANE_CUSTODY";
const ACTIVE_LIFECYCLE_STATUS: &str = "ACTIVE";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneCustodyExpectation {
    pub algorithm: String,
    pub provider_id: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub rotation_epoch: u64,
    pub custody_class: String,
    pub custody_reference: String,
    pub lifecycle_status: String,
    pub revoked_at_epoch: Option<u64>,
    pub external_custody_admitted: bool,
    pub custody_admission_sha512: String,
    pub non_exportable: bool,
}

impl LaneCustodyExpectation {
    pub fn record_sha512(&self) -> Result<String, BoundaryError> {
        let record = json!({
            "algorithm": self.algorithm,
            "provider_id": self.provider_id,
            "key_id": self.key_id,
            "key_epoch": self.key_epoch,
            "rotation_epoch": self.rotation_epoch,
            "custody_class": self.custody_class,
            "custody_reference": self.custody_reference,
            "lifecycle_status": self.lifecycle_status,
            "revoked_at_epoch": self.revoked_at_epoch,
            "external_custody_admitted": self.external_custody_admitted,
            "custody_admission_sha512": self.custody_admission_sha512,
            "non_exportable": self.non_exportable,
        });
        Ok(sha512_hex(&canonical_assurance_bytes(&record)?))
    }

    fn validate(
        &self,
        expected_algorithm: &str,
        expected_key_id: &str,
        expected_epoch: u64,
        test_only: bool,
    ) -> Result<(), BoundaryError> {
        if self.algorithm != expected_algorithm
            || self.provider_id.is_empty()
            || self.key_id != expected_key_id
            || self.key_epoch != expected_epoch
            || self.rotation_epoch == 0
            || self.rotation_epoch > expected_epoch
            || self.custody_class.is_empty()
            || self.custody_reference.is_empty()
            || self.lifecycle_status != ACTIVE_LIFECYCLE_STATUS
            || self.revoked_at_epoch.is_some()
        {
            return Err(BoundaryError::SignerMismatch);
        }
        if test_only {
            if self.external_custody_admitted
                || self.non_exportable
                || self.custody_admission_sha512 != "NONE"
                || self.custody_class != TEST_ONLY_CUSTODY_CLASS
            {
                return Err(BoundaryError::SignerMismatch);
            }
        } else if !self.external_custody_admitted
            || !self.non_exportable
            || !is_sha512(&self.custody_admission_sha512)
            || self.custody_class == TEST_ONLY_CUSTODY_CLASS
        {
            return Err(BoundaryError::SignerMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerExpectation {
    pub provider_id: String,
    pub algorithm: String,
    pub ml_dsa_87_key_id: String,
    pub ed448_key_id: String,
    pub ordered_key_set_digest: String,
    pub custody_class: String,
    pub dual_custody_admission_sha512: String,
    pub ml_dsa_87_custody: LaneCustodyExpectation,
    pub ed448_custody: LaneCustodyExpectation,
    pub effect_authority: bool,
    pub authority_epoch: u64,
    pub purpose: String,
    pub application_context: Vec<u8>,
    pub public_key: HybridPublicKey,
}

impl SignerExpectation {
    pub fn validate(&self) -> Result<(), BoundaryError> {
        if self.provider_id.is_empty()
            || self.algorithm != SUITE_ID
            || self.custody_class.is_empty()
            || self.purpose.is_empty()
            || self.authority_epoch == 0
            || self.application_context.is_empty()
            || !is_sha512(&self.ml_dsa_87_key_id)
            || !is_sha512(&self.ed448_key_id)
            || !is_sha512(&self.ordered_key_set_digest)
        {
            return Err(BoundaryError::SignerMismatch);
        }
        let test_only = self.provider_id.starts_with("TEST-ONLY-NONPRODUCTION:");
        self.ml_dsa_87_custody.validate(
            "ML-DSA-87",
            &self.ml_dsa_87_key_id,
            self.authority_epoch,
            test_only,
        )?;
        self.ed448_custody.validate(
            "Ed448",
            &self.ed448_key_id,
            self.authority_epoch,
            test_only,
        )?;
        if self.ml_dsa_87_custody.provider_id == self.ed448_custody.provider_id
            || self.ml_dsa_87_custody.custody_reference == self.ed448_custody.custody_reference
        {
            return Err(BoundaryError::SignerMismatch);
        }
        if test_only {
            if self.custody_class != TEST_ONLY_CUSTODY_CLASS
                || self.dual_custody_admission_sha512 != "NONE"
            {
                return Err(BoundaryError::SignerMismatch);
            }
        } else if self.custody_class != PRODUCTION_DUAL_CUSTODY_CLASS
            || !is_sha512(&self.dual_custody_admission_sha512)
            || self.dual_custody_admission_sha512 == self.ml_dsa_87_custody.custody_admission_sha512
            || self.dual_custody_admission_sha512 == self.ed448_custody.custody_admission_sha512
            || self.ml_dsa_87_custody.custody_admission_sha512
                == self.ed448_custody.custody_admission_sha512
        {
            return Err(BoundaryError::SignerMismatch);
        }
        #[cfg(not(test))]
        {
            let metadata = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                self.provider_id,
                self.algorithm,
                self.ordered_key_set_digest,
                self.custody_class,
                self.ml_dsa_87_custody.provider_id,
                self.ml_dsa_87_custody.custody_class,
                self.ml_dsa_87_custody.custody_reference,
                self.ed448_custody.provider_id,
                self.ed448_custody.custody_class,
                self.ed448_custody.custody_reference,
            )
            .to_uppercase();
            if ["TEST", "MOCK", "STUB", "FIXTURE", "PLACEHOLDER"]
                .iter()
                .any(|term| metadata.contains(term))
            {
                return Err(BoundaryError::SignerMismatch);
            }
        }
        if sha512_hex(self.public_key.ml_dsa_87_bytes()) != self.ml_dsa_87_key_id
            || sha512_hex(self.public_key.ed448_bytes()) != self.ed448_key_id
            || hex_lower(&self.public_key.ordered_key_set_digest()) != self.ordered_key_set_digest
        {
            return Err(BoundaryError::SignerMismatch);
        }
        Ok(())
    }
}

fn signed_payload(object: &Map<String, Value>) -> Result<Value, BoundaryError> {
    if RESERVED.iter().any(|field| !object.contains_key(*field)) {
        return Err(BoundaryError::Malformed("signature_envelope"));
    }
    let payload = object
        .iter()
        .filter(|(key, _)| !RESERVED.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(Value::Object(payload))
}

pub fn verify_signed_object(
    object: &Value,
    signer: Option<&SignerExpectation>,
    require_effect_authority: bool,
) -> Result<(), BoundaryError> {
    let signer = signer.ok_or(BoundaryError::SignerMissing)?;
    signer.validate()?;
    if require_effect_authority {
        #[cfg(not(test))]
        return Err(BoundaryError::Unsupported(
            Gap::HybridHardwareCustodyAndPinningUnavailable,
        ));

        #[cfg(test)]
        if !signer.provider_id.starts_with("TEST-ONLY-NONPRODUCTION:")
            || signer.custody_class != TEST_ONLY_CUSTODY_CLASS
        {
            return Err(BoundaryError::Unsupported(
                Gap::HybridHardwareCustodyAndPinningUnavailable,
            ));
        }
    }
    let object = object
        .as_object()
        .ok_or(BoundaryError::Malformed("signed_object"))?;
    if object.get("verified") != Some(&Value::Bool(false)) {
        return Err(BoundaryError::Malformed("verified"));
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or(BoundaryError::Malformed("signature_envelope"))?;
    let expected_fields = [
        "provider_id",
        "algorithm",
        "suite_version",
        "verification_rule",
        "security_profile",
        "transition_policy",
        "lane_independence_required",
        "ml_dsa_87_key_id",
        "ed448_key_id",
        "ordered_key_set_digest",
        "custody_class",
        "ml_dsa_87_custody_record_sha512",
        "ed448_custody_record_sha512",
        "dual_custody_admission_sha512",
        "effect_authority",
        "authority_epoch",
        "purpose",
        "context_sha512",
        "ml_dsa_87_signature_b64",
        "ed448_signature_b64",
    ];
    if signature.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !signature.contains_key(*field))
    {
        return Err(BoundaryError::Malformed("signature_envelope"));
    }
    let expected_context_digest = hex_lower(&sha512(&signer.application_context));
    let expected_ml_custody_digest = signer.ml_dsa_87_custody.record_sha512()?;
    let expected_ed_custody_digest = signer.ed448_custody.record_sha512()?;
    let exact = signature.get("provider_id").and_then(Value::as_str)
        == Some(signer.provider_id.as_str())
        && signature.get("algorithm").and_then(Value::as_str) == Some(SUITE_ID)
        && signature.get("suite_version").and_then(Value::as_u64) == Some(u64::from(SUITE_VERSION))
        && signature.get("verification_rule").and_then(Value::as_str) == Some(VERIFICATION_RULE)
        && signature.get("security_profile").and_then(Value::as_str) == Some(SECURITY_PROFILE)
        && signature.get("transition_policy").and_then(Value::as_str) == Some(TRANSITION_POLICY)
        && signature
            .get("lane_independence_required")
            .and_then(Value::as_bool)
            == Some(true)
        && signature.get("ml_dsa_87_key_id").and_then(Value::as_str)
            == Some(signer.ml_dsa_87_key_id.as_str())
        && signature.get("ed448_key_id").and_then(Value::as_str)
            == Some(signer.ed448_key_id.as_str())
        && signature
            .get("ordered_key_set_digest")
            .and_then(Value::as_str)
            == Some(signer.ordered_key_set_digest.as_str())
        && signature.get("custody_class").and_then(Value::as_str)
            == Some(signer.custody_class.as_str())
        && signature
            .get("ml_dsa_87_custody_record_sha512")
            .and_then(Value::as_str)
            == Some(expected_ml_custody_digest.as_str())
        && signature
            .get("ed448_custody_record_sha512")
            .and_then(Value::as_str)
            == Some(expected_ed_custody_digest.as_str())
        && signature
            .get("dual_custody_admission_sha512")
            .and_then(Value::as_str)
            == Some(signer.dual_custody_admission_sha512.as_str())
        && signature.get("effect_authority").and_then(Value::as_bool)
            == Some(signer.effect_authority)
        && signature.get("authority_epoch").and_then(Value::as_u64) == Some(signer.authority_epoch)
        && signature.get("purpose").and_then(Value::as_str) == Some(signer.purpose.as_str())
        && signature.get("context_sha512").and_then(Value::as_str)
            == Some(expected_context_digest.as_str());
    if !exact || (require_effect_authority && !signer.effect_authority) {
        return Err(BoundaryError::SignerMismatch);
    }
    let payload = signed_payload(object)?;
    let message = canonical_assurance_bytes(&payload)?;
    let observed_digest = object
        .get("digest")
        .and_then(Value::as_str)
        .ok_or(BoundaryError::Malformed("digest"))?;
    if !constant_time_hex_equal(observed_digest, &sha512_hex(&message)) {
        return Err(BoundaryError::DigestMismatch("signed_object"));
    }
    let ml_signature = decode_exact_signature_field(
        signature,
        "ml_dsa_87_signature_b64",
        ML_DSA_87_SIGNATURE_BYTES,
    )?;
    let ed_signature =
        decode_exact_signature_field(signature, "ed448_signature_b64", ED448_SIGNATURE_BYTES)?;
    let hybrid_signature = HybridSignature::from_slices(&ml_signature, &ed_signature)
        .map_err(|_| BoundaryError::SignatureInvalid)?;
    signer
        .public_key
        .verify(
            &signer.purpose,
            signer.authority_epoch,
            &signer.application_context,
            &message,
            &hybrid_signature,
        )
        .map_err(|_| BoundaryError::SignatureInvalid)
}

fn decode_exact_signature_field(
    signature: &Map<String, Value>,
    field: &'static str,
    expected_length: usize,
) -> Result<Vec<u8>, BoundaryError> {
    let encoded = signature
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BoundaryError::Malformed(field))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| BoundaryError::Malformed(field))?;
    if bytes.len() != expected_length || STANDARD.encode(&bytes) != encoded {
        return Err(BoundaryError::SignatureInvalid);
    }
    Ok(bytes)
}

pub fn public_key_id(public_key: &HybridPublicKey) -> String {
    hex_lower(&public_key.ordered_key_set_digest())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
