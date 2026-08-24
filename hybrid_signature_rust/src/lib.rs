#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]
//! Fixed-suite SBP-LEX V2 strict full-strength dual-signature boundary.
//!
//! Verification is always available. In-process software signing exists only
//! behind the `software-signing` feature for deterministic interoperability
//! evidence and tests. Production effect authority must use external custody.

use ed448_goldilocks_plus::{Signature as Ed448Signature, VerifyingKey as Ed448VerifyingKey};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature};
use sha2::{Digest as _, Sha512};

#[cfg(feature = "software-signing")]
use ed448_goldilocks_plus::SigningKey as Ed448SigningKey;
#[cfg(feature = "software-signing")]
use ml_dsa::{Seed, SigningKey as MlDsaSigningKey};
#[cfg(feature = "software-signing")]
use zeroize::{Zeroize, Zeroizing};

pub const SUITE_ID: &str = "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1";
pub const RETIRED_HYBRID_SUITE_ID: &str = "SBP_LEX_V2_HYBRID_ML_DSA_87_ED448_V2";
pub const SUITE_VERSION: u16 = 1;
pub const VERIFICATION_RULE: &str = "ALL_LANES_REQUIRED";
pub const SECURITY_PROFILE: &str = "FULL_STRENGTH_ML_DSA_87_AND_ED448";
pub const TRANSITION_POLICY: &str =
    "NEW_SUITE_ID_AND_EXPLICIT_ADMISSION_REQUIRED_NO_IMPLICIT_FALLBACK";
pub const REQUIRED_LANES: [&str; 2] = ["ML-DSA-87", "Ed448"];
pub const PREIMAGE_DOMAIN: &[u8] = b"SBP-LEX/V2/STRICT-DUAL-SIGNATURE/PREIMAGE/1\0";
pub const KEY_ID_DOMAIN: &[u8] = b"SBP-LEX/V2/STRICT-DUAL-SIGNATURE/KEY-ID/1\0";
// The algorithm-level contexts are deliberately empty because RFC 8032 Ed448
// APIs are not uniformly context-capable. Domain separation and all context
// binding live in the one byte-identical canonical preimage signed by both
// lanes.
pub const CRYPTO_CONTEXT: &[u8] = b"";

pub const SHA512_BYTES: usize = 64;
pub const ML_DSA_87_SEED_BYTES: usize = 32;
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2_592;
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4_627;
pub const ED448_SEED_BYTES: usize = 57;
pub const ED448_PUBLIC_KEY_BYTES: usize = 57;
pub const ED448_SIGNATURE_BYTES: usize = 114;
pub const HYBRID_SIGNATURE_BYTES: usize = ML_DSA_87_SIGNATURE_BYTES + ED448_SIGNATURE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridError {
    EmptyPurpose,
    PurposeTooLong,
    InvalidPublicKeyLength,
    InvalidPublicKey,
    InvalidSignatureLength,
    NonCanonicalSignature,
    MlDsaVerificationFailed,
    Ed448VerificationFailed,
    SigningFailed,
    InvalidSeedLength,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HybridPublicKey {
    ml_dsa_87: [u8; ML_DSA_87_PUBLIC_KEY_BYTES],
    ed448: [u8; ED448_PUBLIC_KEY_BYTES],
}

impl core::fmt::Debug for HybridPublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HybridPublicKey")
            .field(
                "ordered_key_set_digest",
                &hex_lower(&self.ordered_key_set_digest()),
            )
            .finish_non_exhaustive()
    }
}

impl HybridPublicKey {
    pub fn from_slices(ml_dsa_87: &[u8], ed448: &[u8]) -> Result<Self, HybridError> {
        let ml_dsa_87: [u8; ML_DSA_87_PUBLIC_KEY_BYTES] = ml_dsa_87
            .try_into()
            .map_err(|_| HybridError::InvalidPublicKeyLength)?;
        let ed448: [u8; ED448_PUBLIC_KEY_BYTES] = ed448
            .try_into()
            .map_err(|_| HybridError::InvalidPublicKeyLength)?;

        let mut encoded_ml = EncodedVerifyingKey::<MlDsa87>::default();
        encoded_ml.copy_from_slice(&ml_dsa_87);
        let decoded_ml = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded_ml);
        if decoded_ml.encode().as_slice() != ml_dsa_87 {
            return Err(HybridError::InvalidPublicKey);
        }
        let decoded_ed =
            Ed448VerifyingKey::from_bytes(&ed448).map_err(|_| HybridError::InvalidPublicKey)?;
        if decoded_ed.to_bytes() != ed448 {
            return Err(HybridError::InvalidPublicKey);
        }
        Ok(Self { ml_dsa_87, ed448 })
    }

    pub const fn ml_dsa_87_bytes(&self) -> &[u8; ML_DSA_87_PUBLIC_KEY_BYTES] {
        &self.ml_dsa_87
    }

    pub const fn ed448_bytes(&self) -> &[u8; ED448_PUBLIC_KEY_BYTES] {
        &self.ed448
    }

    pub fn ml_dsa_87_digest(&self) -> [u8; SHA512_BYTES] {
        sha512(&self.ml_dsa_87)
    }

    pub fn ed448_digest(&self) -> [u8; SHA512_BYTES] {
        sha512(&self.ed448)
    }

    pub fn ml_dsa_87_key_id(&self) -> [u8; SHA512_BYTES] {
        self.ml_dsa_87_digest()
    }

    pub fn ed448_key_id(&self) -> [u8; SHA512_BYTES] {
        self.ed448_digest()
    }

    pub fn ordered_key_set_digest(&self) -> [u8; SHA512_BYTES] {
        let mut hash = Sha512::new();
        hash.update(KEY_ID_DOMAIN);
        hash.update(SUITE_ID.as_bytes());
        hash.update([0]);
        hash.update(self.ml_dsa_87_key_id());
        hash.update(self.ed448_key_id());
        hash.finalize().into()
    }

    pub fn verify(
        &self,
        purpose: &str,
        authority_epoch: u64,
        application_context: &[u8],
        payload: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), HybridError> {
        let preimage =
            canonical_preimage(self, purpose, authority_epoch, application_context, payload)?;

        let mut encoded_ml = EncodedVerifyingKey::<MlDsa87>::default();
        encoded_ml.copy_from_slice(&self.ml_dsa_87);
        let ml_key = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded_ml);
        let mut encoded_ml_signature = EncodedSignature::<MlDsa87>::default();
        encoded_ml_signature.copy_from_slice(&signature.ml_dsa_87);
        let ml_signature = MlDsaSignature::<MlDsa87>::decode(&encoded_ml_signature)
            .ok_or(HybridError::NonCanonicalSignature)?;
        if ml_signature.encode().as_slice() != signature.ml_dsa_87 {
            return Err(HybridError::NonCanonicalSignature);
        }
        if !ml_key.verify_with_context(&preimage, CRYPTO_CONTEXT, &ml_signature) {
            return Err(HybridError::MlDsaVerificationFailed);
        }

        let ed_key = Ed448VerifyingKey::from_bytes(&self.ed448)
            .map_err(|_| HybridError::InvalidPublicKey)?;
        let ed_signature = Ed448Signature::from_bytes(&signature.ed448)
            .map_err(|_| HybridError::NonCanonicalSignature)?;
        if ed_signature.to_bytes() != signature.ed448 {
            return Err(HybridError::NonCanonicalSignature);
        }
        ed_key
            .verify_raw(&ed_signature, &preimage)
            .map_err(|_| HybridError::Ed448VerificationFailed)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HybridSignature {
    ml_dsa_87: [u8; ML_DSA_87_SIGNATURE_BYTES],
    ed448: [u8; ED448_SIGNATURE_BYTES],
}

impl core::fmt::Debug for HybridSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HybridSignature")
            .field("bytes", &HYBRID_SIGNATURE_BYTES)
            .finish()
    }
}

impl HybridSignature {
    pub fn from_slices(ml_dsa_87: &[u8], ed448: &[u8]) -> Result<Self, HybridError> {
        let ml_dsa_87: [u8; ML_DSA_87_SIGNATURE_BYTES] = ml_dsa_87
            .try_into()
            .map_err(|_| HybridError::InvalidSignatureLength)?;
        let ed448: [u8; ED448_SIGNATURE_BYTES] = ed448
            .try_into()
            .map_err(|_| HybridError::InvalidSignatureLength)?;

        let mut encoded_ml = EncodedSignature::<MlDsa87>::default();
        encoded_ml.copy_from_slice(&ml_dsa_87);
        let decoded_ml = MlDsaSignature::<MlDsa87>::decode(&encoded_ml)
            .ok_or(HybridError::NonCanonicalSignature)?;
        if decoded_ml.encode().as_slice() != ml_dsa_87 {
            return Err(HybridError::NonCanonicalSignature);
        }
        let decoded_ed =
            Ed448Signature::from_bytes(&ed448).map_err(|_| HybridError::NonCanonicalSignature)?;
        if decoded_ed.to_bytes() != ed448 {
            return Err(HybridError::NonCanonicalSignature);
        }
        Ok(Self { ml_dsa_87, ed448 })
    }

    pub fn from_combined(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != HYBRID_SIGNATURE_BYTES {
            return Err(HybridError::InvalidSignatureLength);
        }
        Self::from_slices(
            &bytes[..ML_DSA_87_SIGNATURE_BYTES],
            &bytes[ML_DSA_87_SIGNATURE_BYTES..],
        )
    }

    pub const fn ml_dsa_87_bytes(&self) -> &[u8; ML_DSA_87_SIGNATURE_BYTES] {
        &self.ml_dsa_87
    }

    pub const fn ed448_bytes(&self) -> &[u8; ED448_SIGNATURE_BYTES] {
        &self.ed448
    }

    pub fn to_combined(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIGNATURE_BYTES);
        out.extend_from_slice(&self.ml_dsa_87);
        out.extend_from_slice(&self.ed448);
        out
    }
}

pub fn sha512(bytes: &[u8]) -> [u8; SHA512_BYTES] {
    Sha512::digest(bytes).into()
}

pub fn canonical_preimage(
    public_key: &HybridPublicKey,
    purpose: &str,
    authority_epoch: u64,
    application_context: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, HybridError> {
    if purpose.is_empty() {
        return Err(HybridError::EmptyPurpose);
    }
    let purpose_length = u16::try_from(purpose.len()).map_err(|_| HybridError::PurposeTooLong)?;
    let payload_digest = sha512(payload);
    let context_digest = sha512(application_context);
    let ml_key_digest = public_key.ml_dsa_87_key_id();
    let ed_key_digest = public_key.ed448_key_id();
    let mut out = Vec::with_capacity(
        PREIMAGE_DOMAIN.len() + SUITE_ID.len() + 1 + 2 + purpose.len() + 8 + SHA512_BYTES * 4,
    );
    out.extend_from_slice(PREIMAGE_DOMAIN);
    out.extend_from_slice(SUITE_ID.as_bytes());
    out.push(0);
    out.extend_from_slice(&purpose_length.to_be_bytes());
    out.extend_from_slice(purpose.as_bytes());
    out.extend_from_slice(&authority_epoch.to_be_bytes());
    out.extend_from_slice(&ml_key_digest);
    out.extend_from_slice(&ed_key_digest);
    out.extend_from_slice(&payload_digest);
    out.extend_from_slice(&context_digest);
    Ok(out)
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

#[cfg(feature = "software-signing")]
pub struct SoftwareHybridSigningKey {
    ml_dsa_87: MlDsaSigningKey<MlDsa87>,
    ed448: Ed448SigningKey,
}

#[cfg(feature = "software-signing")]
impl core::fmt::Debug for SoftwareHybridSigningKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SoftwareHybridSigningKey")
            .field(
                "ordered_key_set_digest",
                &hex_lower(&self.public_key().ordered_key_set_digest()),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "software-signing")]
impl SoftwareHybridSigningKey {
    pub fn from_seed_slices(ml_dsa_seed: &[u8], ed448_seed: &[u8]) -> Result<Self, HybridError> {
        if ml_dsa_seed.len() != ML_DSA_87_SEED_BYTES || ed448_seed.len() != ED448_SEED_BYTES {
            return Err(HybridError::InvalidSeedLength);
        }
        let mut ml_seed = Zeroizing::new([0u8; ML_DSA_87_SEED_BYTES]);
        ml_seed.copy_from_slice(ml_dsa_seed);
        let mut ml_seed_value = Seed::from(*ml_seed);
        let ml_dsa_87 = MlDsaSigningKey::<MlDsa87>::from_seed(&ml_seed_value);
        ml_seed_value.zeroize();
        let mut ed_seed = Zeroizing::new([0u8; ED448_SEED_BYTES]);
        ed_seed.copy_from_slice(ed448_seed);
        let ed448 = Ed448SigningKey::try_from(ed_seed.as_slice())
            .map_err(|_| HybridError::SigningFailed)?;
        Ok(Self { ml_dsa_87, ed448 })
    }

    pub fn public_key(&self) -> HybridPublicKey {
        let ml_encoded = self.ml_dsa_87.as_ref().encode();
        let mut ml_dsa_87 = [0u8; ML_DSA_87_PUBLIC_KEY_BYTES];
        ml_dsa_87.copy_from_slice(ml_encoded.as_slice());
        let ed448 = self.ed448.verifying_key().to_bytes();
        HybridPublicKey { ml_dsa_87, ed448 }
    }

    pub fn sign(
        &self,
        purpose: &str,
        authority_epoch: u64,
        application_context: &[u8],
        payload: &[u8],
    ) -> Result<HybridSignature, HybridError> {
        let public_key = self.public_key();
        let mut preimage = Zeroizing::new(canonical_preimage(
            &public_key,
            purpose,
            authority_epoch,
            application_context,
            payload,
        )?);
        let ml_signature = self
            .ml_dsa_87
            .expanded_key()
            .sign_deterministic(&preimage, CRYPTO_CONTEXT)
            .map_err(|_| HybridError::SigningFailed)?;
        let ed_signature = self.ed448.sign_raw(&preimage);
        preimage.zeroize();
        let ml_encoded = ml_signature.encode();
        let mut ml_dsa_87 = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        ml_dsa_87.copy_from_slice(ml_encoded.as_slice());
        let ed448 = ed_signature.to_bytes();
        Ok(HybridSignature { ml_dsa_87, ed448 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_policy_is_closed_and_has_no_legacy_fallback() {
        assert_eq!(SUITE_ID, "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1");
        assert_eq!(SUITE_VERSION, 1);
        assert_eq!(VERIFICATION_RULE, "ALL_LANES_REQUIRED");
        assert_eq!(REQUIRED_LANES, ["ML-DSA-87", "Ed448"]);
        assert_ne!(SUITE_ID, RETIRED_HYBRID_SUITE_ID);
        assert_eq!(
            TRANSITION_POLICY,
            "NEW_SUITE_ID_AND_EXPLICIT_ADMISSION_REQUIRED_NO_IMPLICIT_FALLBACK"
        );
    }

    #[cfg(feature = "software-signing")]
    fn signer() -> SoftwareHybridSigningKey {
        SoftwareHybridSigningKey::from_seed_slices(&[0x11; 32], &[0x22; 57]).unwrap()
    }

    #[cfg(feature = "software-signing")]
    #[test]
    fn both_lanes_verify_the_same_bound_preimage() {
        let signer = signer();
        let key = signer.public_key();
        let signature = signer
            .sign("WIRE_EFFECT", 17, b"owner-pinned-context", b"payload")
            .unwrap();
        key.verify(
            "WIRE_EFFECT",
            17,
            b"owner-pinned-context",
            b"payload",
            &signature,
        )
        .unwrap();
    }

    #[cfg(feature = "software-signing")]
    #[test]
    fn every_binding_dimension_is_mandatory() {
        let signer = signer();
        let key = signer.public_key();
        let signature = signer
            .sign("WIRE_EFFECT", 17, b"owner-pinned-context", b"payload")
            .unwrap();
        assert!(
            key.verify("OTHER", 17, b"owner-pinned-context", b"payload", &signature)
                .is_err()
        );
        assert!(
            key.verify(
                "WIRE_EFFECT",
                18,
                b"owner-pinned-context",
                b"payload",
                &signature
            )
            .is_err()
        );
        assert!(
            key.verify("WIRE_EFFECT", 17, b"other-context", b"payload", &signature)
                .is_err()
        );
        assert!(
            key.verify(
                "WIRE_EFFECT",
                17,
                b"owner-pinned-context",
                b"other",
                &signature
            )
            .is_err()
        );
    }

    #[cfg(feature = "software-signing")]
    #[test]
    fn one_lane_corruption_cannot_fall_back() {
        let signer = signer();
        let key = signer.public_key();
        let signature = signer.sign("TEST", 1, b"ctx", b"payload").unwrap();
        let mut ml = *signature.ml_dsa_87_bytes();
        ml[0] ^= 1;
        if let Ok(corrupt) = HybridSignature::from_slices(&ml, signature.ed448_bytes()) {
            assert!(key.verify("TEST", 1, b"ctx", b"payload", &corrupt).is_err());
        }
        let mut ed = *signature.ed448_bytes();
        ed[0] ^= 1;
        if let Ok(corrupt) = HybridSignature::from_slices(signature.ml_dsa_87_bytes(), &ed) {
            assert!(key.verify("TEST", 1, b"ctx", b"payload", &corrupt).is_err());
        }
    }

    #[test]
    fn rejects_wrong_lengths_and_noncanonical_ed448() {
        assert_eq!(
            HybridPublicKey::from_slices(&[0; ML_DSA_87_PUBLIC_KEY_BYTES - 1], &[0; 57]),
            Err(HybridError::InvalidPublicKeyLength)
        );
        assert_eq!(
            HybridSignature::from_combined(&[0; HYBRID_SIGNATURE_BYTES - 1]),
            Err(HybridError::InvalidSignatureLength)
        );
        assert_eq!(
            HybridSignature::from_slices(
                &[0; ML_DSA_87_SIGNATURE_BYTES],
                &[0; ED448_SIGNATURE_BYTES]
            ),
            Err(HybridError::NonCanonicalSignature)
        );
    }
}
