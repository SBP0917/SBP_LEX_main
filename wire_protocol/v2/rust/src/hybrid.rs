//! Versioned hybrid-authenticated wrapper for exact legacy wire-v2 payloads.
//!
//! This is a distinct schema. It never reinterprets legacy signature fields.
//! A syntactically valid legacy frame is admitted only as non-effect
//! compatibility data; only a verified hybrid frame can carry effect authority.

use sbp_lex_v2_hybrid_signature::{
    sha512, HybridError, HybridPublicKey, HybridSignature, ED448_PUBLIC_KEY_BYTES,
    ED448_SIGNATURE_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, SHA512_BYTES,
    SUITE_ID,
};

use crate::{
    decode_frame as decode_legacy_frame, Message, Value, WireError, MAX_FRAME_BYTES,
    MAX_SAFE_INTEGER,
};

pub const HYBRID_PROTOCOL: &str = "SBP-LEX-AUTH-WIRE-HYBRID/2";
pub const HYBRID_MAGIC: &[u8] = b"SBP-LEX-AUTH-WIRE-HYBRID/2\0";
pub const MAX_HYBRID_FRAME_BYTES: usize = 49_152;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridEnvelope {
    purpose: String,
    authority_epoch: u64,
    context_sha512: [u8; SHA512_BYTES],
    payload_sha512: [u8; SHA512_BYTES],
    ml_dsa_87_key_id: [u8; SHA512_BYTES],
    ed448_key_id: [u8; SHA512_BYTES],
    ordered_key_set_digest: [u8; SHA512_BYTES],
    public_key: HybridPublicKey,
    signature: HybridSignature,
    payload: Vec<u8>,
}

impl HybridEnvelope {
    pub fn new(
        purpose: &str,
        authority_epoch: u64,
        application_context: &[u8],
        payload: Vec<u8>,
        public_key: HybridPublicKey,
        signature: HybridSignature,
    ) -> Result<Self, WireError> {
        validate_purpose(purpose)?;
        validate_authority_epoch(authority_epoch)?;
        if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
            return Err(fail("hybrid payload length"));
        }
        Ok(Self {
            purpose: purpose.to_owned(),
            authority_epoch,
            context_sha512: sha512(application_context),
            payload_sha512: sha512(&payload),
            ml_dsa_87_key_id: public_key.ml_dsa_87_key_id(),
            ed448_key_id: public_key.ed448_key_id(),
            ordered_key_set_digest: public_key.ordered_key_set_digest(),
            public_key,
            signature,
            payload,
        })
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn context_sha512(&self) -> &[u8; SHA512_BYTES] {
        &self.context_sha512
    }

    pub const fn payload_sha512(&self) -> &[u8; SHA512_BYTES] {
        &self.payload_sha512
    }

    pub const fn ml_dsa_87_key_id(&self) -> &[u8; SHA512_BYTES] {
        &self.ml_dsa_87_key_id
    }

    pub const fn ed448_key_id(&self) -> &[u8; SHA512_BYTES] {
        &self.ed448_key_id
    }

    pub const fn ordered_key_set_digest(&self) -> &[u8; SHA512_BYTES] {
        &self.ordered_key_set_digest
    }

    pub const fn public_key(&self) -> &HybridPublicKey {
        &self.public_key
    }

    pub const fn signature(&self) -> &HybridSignature {
        &self.signature
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn verify(&self, admission: &OwnerPinnedHybridAdmission) -> Result<(), WireError> {
        if self.purpose != admission.purpose
            || self.authority_epoch != admission.authority_epoch
            || self.context_sha512 != sha512(&admission.application_context)
            || self.payload_sha512 != sha512(&self.payload)
            || self.public_key != admission.public_key
            || self.ml_dsa_87_key_id != admission.public_key.ml_dsa_87_key_id()
            || self.ed448_key_id != admission.public_key.ed448_key_id()
            || self.ordered_key_set_digest != admission.ordered_key_set_digest
        {
            return Err(fail("hybrid binding mismatch"));
        }
        admission
            .public_key
            .verify(
                &self.purpose,
                self.authority_epoch,
                &admission.application_context,
                &self.payload,
                &self.signature,
            )
            .map_err(map_hybrid_error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridAdmissionClass {
    TestOnlyNonEffect,
    ProductionAuthenticatedNonEffect,
    ProductionEffect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerPinnedHybridAdmission {
    public_key: HybridPublicKey,
    ordered_key_set_digest: [u8; SHA512_BYTES],
    purpose: String,
    authority_epoch: u64,
    application_context: Vec<u8>,
    expected_payload_kind: String,
    admission_class: HybridAdmissionClass,
    external_custody_admitted: bool,
}

impl OwnerPinnedHybridAdmission {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_key: HybridPublicKey,
        ordered_key_set_digest: [u8; SHA512_BYTES],
        purpose: &str,
        authority_epoch: u64,
        application_context: &[u8],
        expected_payload_kind: &str,
        admission_class: HybridAdmissionClass,
        external_custody_admitted: bool,
    ) -> Result<Self, WireError> {
        validate_purpose(purpose)?;
        validate_authority_epoch(authority_epoch)?;
        validate_payload_kind(expected_payload_kind)?;
        if application_context.is_empty() {
            return Err(fail("hybrid application context"));
        }
        if ordered_key_set_digest != public_key.ordered_key_set_digest() {
            return Err(fail("hybrid owner-pinned key-set digest"));
        }
        match admission_class {
            HybridAdmissionClass::TestOnlyNonEffect if external_custody_admitted => {
                return Err(fail("test-only custody admission"));
            }
            HybridAdmissionClass::ProductionAuthenticatedNonEffect
            | HybridAdmissionClass::ProductionEffect
                if !external_custody_admitted =>
            {
                return Err(fail("production external custody not admitted"));
            }
            _ => {}
        }
        Ok(Self {
            public_key,
            ordered_key_set_digest,
            purpose: purpose.to_owned(),
            authority_epoch,
            application_context: application_context.to_vec(),
            expected_payload_kind: expected_payload_kind.to_owned(),
            admission_class,
            external_custody_admitted,
        })
    }

    pub const fn public_key(&self) -> &HybridPublicKey {
        &self.public_key
    }

    pub const fn ordered_key_set_digest(&self) -> &[u8; SHA512_BYTES] {
        &self.ordered_key_set_digest
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub fn application_context(&self) -> &[u8] {
        &self.application_context
    }

    pub fn expected_payload_kind(&self) -> &str {
        &self.expected_payload_kind
    }

    pub const fn admission_class(&self) -> HybridAdmissionClass {
        self.admission_class
    }

    pub const fn external_custody_admitted(&self) -> bool {
        self.external_custody_admitted
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireAdmission {
    HybridAuthenticatedNonEffect {
        envelope: Box<HybridEnvelope>,
        payload: Message,
        admission_class: HybridAdmissionClass,
    },
    HybridProductionEffect {
        envelope: Box<HybridEnvelope>,
        payload: Message,
    },
    LegacyV2NonEffect(Message),
}

impl WireAdmission {
    pub const fn carries_effect_authority(&self) -> bool {
        matches!(self, Self::HybridProductionEffect { .. })
    }
}

pub fn encode_hybrid_frame(envelope: &HybridEnvelope) -> Result<Vec<u8>, WireError> {
    validate_purpose(&envelope.purpose)?;
    if envelope.payload.is_empty() || envelope.payload.len() > MAX_FRAME_BYTES {
        return Err(fail("hybrid payload length"));
    }
    let suite_length = u16::try_from(SUITE_ID.len()).map_err(|_| fail("suite length"))?;
    let purpose_length =
        u16::try_from(envelope.purpose.len()).map_err(|_| fail("purpose length"))?;
    let payload_length =
        u32::try_from(envelope.payload.len()).map_err(|_| fail("payload length"))?;
    let mut body = Vec::with_capacity(
        HYBRID_MAGIC.len()
            + 2
            + SUITE_ID.len()
            + 2
            + envelope.purpose.len()
            + 8
            + SHA512_BYTES * 5
            + ML_DSA_87_PUBLIC_KEY_BYTES
            + ED448_PUBLIC_KEY_BYTES
            + ML_DSA_87_SIGNATURE_BYTES
            + ED448_SIGNATURE_BYTES
            + 4
            + envelope.payload.len(),
    );
    body.extend_from_slice(HYBRID_MAGIC);
    body.extend_from_slice(&suite_length.to_be_bytes());
    body.extend_from_slice(SUITE_ID.as_bytes());
    body.extend_from_slice(&purpose_length.to_be_bytes());
    body.extend_from_slice(envelope.purpose.as_bytes());
    body.extend_from_slice(&envelope.authority_epoch.to_be_bytes());
    body.extend_from_slice(&envelope.context_sha512);
    body.extend_from_slice(&envelope.payload_sha512);
    body.extend_from_slice(&envelope.ml_dsa_87_key_id);
    body.extend_from_slice(&envelope.ed448_key_id);
    body.extend_from_slice(&envelope.ordered_key_set_digest);
    body.extend_from_slice(envelope.public_key.ml_dsa_87_bytes());
    body.extend_from_slice(envelope.public_key.ed448_bytes());
    body.extend_from_slice(envelope.signature.ml_dsa_87_bytes());
    body.extend_from_slice(envelope.signature.ed448_bytes());
    body.extend_from_slice(&payload_length.to_be_bytes());
    body.extend_from_slice(&envelope.payload);
    if body.len() > MAX_HYBRID_FRAME_BYTES {
        return Err(fail("hybrid frame too large"));
    }
    let body_length = u32::try_from(body.len()).map_err(|_| fail("hybrid frame length"))?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&body_length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_hybrid_frame(frame: &[u8]) -> Result<HybridEnvelope, WireError> {
    if frame.len() < 4 || frame.len() > MAX_HYBRID_FRAME_BYTES + 4 {
        return Err(fail("hybrid frame length"));
    }
    let declared = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| fail("hybrid frame prefix"))?,
    ) as usize;
    if declared == 0 || declared > MAX_HYBRID_FRAME_BYTES || frame.len() != declared + 4 {
        return Err(fail("hybrid frame prefix"));
    }
    let mut cursor = Cursor::new(&frame[4..]);
    if cursor.take(HYBRID_MAGIC.len())? != HYBRID_MAGIC {
        return Err(fail("hybrid protocol"));
    }
    let suite_length = usize::from(cursor.u16()?);
    let suite = cursor.take(suite_length)?;
    if suite != SUITE_ID.as_bytes() {
        return Err(fail("hybrid suite downgrade"));
    }
    let purpose_length = usize::from(cursor.u16()?);
    let purpose = core::str::from_utf8(cursor.take(purpose_length)?)
        .map_err(|_| fail("hybrid purpose"))?
        .to_owned();
    validate_purpose(&purpose)?;
    let authority_epoch = cursor.u64()?;
    validate_authority_epoch(authority_epoch)?;
    let context_sha512 = cursor.array::<SHA512_BYTES>()?;
    let payload_sha512 = cursor.array::<SHA512_BYTES>()?;
    let ml_dsa_87_key_id = cursor.array::<SHA512_BYTES>()?;
    let ed448_key_id = cursor.array::<SHA512_BYTES>()?;
    let ordered_key_set_digest = cursor.array::<SHA512_BYTES>()?;
    let ml_public_key = cursor.array::<ML_DSA_87_PUBLIC_KEY_BYTES>()?;
    let ed_public_key = cursor.array::<ED448_PUBLIC_KEY_BYTES>()?;
    let ml_signature = cursor.array::<ML_DSA_87_SIGNATURE_BYTES>()?;
    let ed_signature = cursor.array::<ED448_SIGNATURE_BYTES>()?;
    let payload_length = cursor.u32()? as usize;
    if payload_length == 0 || payload_length > MAX_FRAME_BYTES {
        return Err(fail("hybrid payload length"));
    }
    let payload = cursor.take(payload_length)?.to_vec();
    if !cursor.is_finished() {
        return Err(fail("hybrid trailing bytes"));
    }
    let public_key =
        HybridPublicKey::from_slices(&ml_public_key, &ed_public_key).map_err(map_hybrid_error)?;
    let signature =
        HybridSignature::from_slices(&ml_signature, &ed_signature).map_err(map_hybrid_error)?;
    if ml_dsa_87_key_id != public_key.ml_dsa_87_key_id()
        || ed448_key_id != public_key.ed448_key_id()
        || ordered_key_set_digest != public_key.ordered_key_set_digest()
        || payload_sha512 != sha512(&payload)
    {
        return Err(fail("hybrid embedded digest"));
    }
    Ok(HybridEnvelope {
        purpose,
        authority_epoch,
        context_sha512,
        payload_sha512,
        ml_dsa_87_key_id,
        ed448_key_id,
        ordered_key_set_digest,
        public_key,
        signature,
        payload,
    })
}

pub fn decode_for_admission(
    frame: &[u8],
    owner_pins: Option<&OwnerPinnedHybridAdmission>,
) -> Result<WireAdmission, WireError> {
    if frame.get(4..4 + HYBRID_MAGIC.len()) == Some(HYBRID_MAGIC) {
        let admission = owner_pins.ok_or_else(|| fail("hybrid owner pins required"))?;
        let envelope = decode_hybrid_frame(frame)?;
        envelope.verify(admission)?;
        let payload = decode_legacy_frame(envelope.payload())?;
        if payload_kind(&payload)? != admission.expected_payload_kind {
            return Err(fail("hybrid payload kind mismatch"));
        }
        return match admission.admission_class {
            HybridAdmissionClass::ProductionEffect => Ok(WireAdmission::HybridProductionEffect {
                envelope: Box::new(envelope),
                payload,
            }),
            HybridAdmissionClass::TestOnlyNonEffect
            | HybridAdmissionClass::ProductionAuthenticatedNonEffect => {
                Ok(WireAdmission::HybridAuthenticatedNonEffect {
                    envelope: Box::new(envelope),
                    payload,
                    admission_class: admission.admission_class,
                })
            }
        };
    }
    Ok(WireAdmission::LegacyV2NonEffect(decode_legacy_frame(
        frame,
    )?))
}

fn validate_authority_epoch(authority_epoch: u64) -> Result<(), WireError> {
    if authority_epoch == 0 || authority_epoch > MAX_SAFE_INTEGER {
        return Err(fail("hybrid authority epoch"));
    }
    Ok(())
}

fn validate_purpose(purpose: &str) -> Result<(), WireError> {
    if purpose.is_empty()
        || purpose.len() > u16::MAX.into()
        || !purpose
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(fail("hybrid purpose"));
    }
    Ok(())
}

fn validate_payload_kind(kind: &str) -> Result<(), WireError> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(fail("hybrid payload kind"));
    }
    Ok(())
}

fn payload_kind(message: &Message) -> Result<&str, WireError> {
    match message.get("kind") {
        Some(Value::Text(kind)) => Ok(kind),
        _ => Err(fail("hybrid payload kind")),
    }
}

fn map_hybrid_error(error: HybridError) -> WireError {
    WireError(format!("hybrid cryptographic rejection: {error:?}"))
}

fn fail(text: &str) -> WireError {
    WireError(text.to_owned())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| fail("hybrid length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| fail("hybrid truncated"))?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| fail("hybrid fixed field"))
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbp_lex_v2_hybrid_signature::SoftwareHybridSigningKey;

    const PURPOSE: &str = "WIRE_EFFECT";
    const EPOCH: u64 = 41;
    const CONTEXT: &[u8] = b"owner-pinned:test-context";
    const ARBITRARY_PAYLOAD: &[u8] = b"signed bytes are not a typed effect payload";

    fn signer() -> SoftwareHybridSigningKey {
        SoftwareHybridSigningKey::from_seed_slices(&[0x31; 32], &[0x42; 57]).unwrap()
    }

    fn attacker_signer() -> SoftwareHybridSigningKey {
        SoftwareHybridSigningKey::from_seed_slices(&[0x51; 32], &[0x62; 57]).unwrap()
    }

    fn legacy_payload() -> (Vec<u8>, String) {
        let line = include_str!("../../vectors/mode1_golden.jsonl")
            .lines()
            .next()
            .unwrap();
        let message = crate::parse_message(line.as_bytes()).unwrap();
        let kind = payload_kind(&message).unwrap().to_owned();
        (crate::encode_frame(&message).unwrap(), kind)
    }

    fn frame_with(
        signer: &SoftwareHybridSigningKey,
        purpose: &str,
        epoch: u64,
        context: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let key = signer.public_key();
        let signature = signer.sign(purpose, epoch, context, payload).unwrap();
        let envelope =
            HybridEnvelope::new(purpose, epoch, context, payload.to_vec(), key, signature).unwrap();
        encode_hybrid_frame(&envelope).unwrap()
    }

    fn frame() -> Vec<u8> {
        let (payload, _) = legacy_payload();
        frame_with(&signer(), PURPOSE, EPOCH, CONTEXT, &payload)
    }

    fn policy_with(
        signer: &SoftwareHybridSigningKey,
        purpose: &str,
        epoch: u64,
        context: &[u8],
        admission_class: HybridAdmissionClass,
        external_custody_admitted: bool,
    ) -> OwnerPinnedHybridAdmission {
        let key = signer.public_key();
        let digest = key.ordered_key_set_digest();
        let (_, kind) = legacy_payload();
        OwnerPinnedHybridAdmission::new(
            key,
            digest,
            purpose,
            epoch,
            context,
            &kind,
            admission_class,
            external_custody_admitted,
        )
        .unwrap()
    }

    fn effect_policy(signer: &SoftwareHybridSigningKey) -> OwnerPinnedHybridAdmission {
        policy_with(
            signer,
            PURPOSE,
            EPOCH,
            CONTEXT,
            HybridAdmissionClass::ProductionEffect,
            true,
        )
    }

    #[test]
    fn round_trip_requires_owner_pins_and_both_real_signature_lanes() {
        let owner_signer = signer();
        let policy = effect_policy(&owner_signer);
        let encoded = frame();
        let decoded = decode_hybrid_frame(&encoded).unwrap();
        decoded.verify(&policy).unwrap();
        assert!(matches!(
            decode_for_admission(&encoded, Some(&policy)).unwrap(),
            WireAdmission::HybridProductionEffect { .. }
        ));
    }

    #[test]
    fn purpose_context_epoch_and_payload_are_not_substitutable() {
        let owner_signer = signer();
        let encoded = frame();
        let decoded = decode_hybrid_frame(&encoded).unwrap();
        let wrong_purpose = policy_with(
            &owner_signer,
            "OTHER",
            EPOCH,
            CONTEXT,
            HybridAdmissionClass::ProductionEffect,
            true,
        );
        let wrong_epoch = policy_with(
            &owner_signer,
            PURPOSE,
            EPOCH + 1,
            CONTEXT,
            HybridAdmissionClass::ProductionEffect,
            true,
        );
        let wrong_context = policy_with(
            &owner_signer,
            PURPOSE,
            EPOCH,
            b"other-owner-context",
            HybridAdmissionClass::ProductionEffect,
            true,
        );
        assert!(decoded.verify(&wrong_purpose).is_err());
        assert!(decoded.verify(&wrong_epoch).is_err());
        assert!(decoded.verify(&wrong_context).is_err());

        let mut payload_corrupt = encoded;
        *payload_corrupt.last_mut().unwrap() ^= 1;
        assert!(decode_hybrid_frame(&payload_corrupt).is_err());
    }

    #[test]
    fn suite_and_each_lane_fail_closed() {
        let owner_signer = signer();
        let policy = effect_policy(&owner_signer);
        let encoded = frame();
        let suite_start = 4 + HYBRID_MAGIC.len() + 2;
        let mut suite_corrupt = encoded.clone();
        suite_corrupt[suite_start] ^= 1;
        assert!(decode_hybrid_frame(&suite_corrupt).is_err());

        let fixed_prefix =
            4 + HYBRID_MAGIC.len() + 2 + SUITE_ID.len() + 2 + PURPOSE.len() + 8 + SHA512_BYTES * 5;
        let ml_signature_start = fixed_prefix + ML_DSA_87_PUBLIC_KEY_BYTES + ED448_PUBLIC_KEY_BYTES;
        let mut ml_corrupt = encoded.clone();
        ml_corrupt[ml_signature_start] ^= 1;
        assert!(decode_for_admission(&ml_corrupt, Some(&policy)).is_err());

        let ed_signature_start = ml_signature_start + ML_DSA_87_SIGNATURE_BYTES;
        let mut ed_corrupt = encoded;
        ed_corrupt[ed_signature_start] ^= 1;
        assert!(decode_for_admission(&ed_corrupt, Some(&policy)).is_err());
    }

    #[test]
    fn whole_attacker_bundle_and_key_substitution_reject() {
        let owner_signer = signer();
        let attacker = attacker_signer();
        let owner_policy = effect_policy(&owner_signer);
        let attacker_policy = effect_policy(&attacker);
        let (payload, _) = legacy_payload();

        let attacker_bundle = frame_with(&attacker, PURPOSE, EPOCH, CONTEXT, &payload);
        assert!(decode_for_admission(&attacker_bundle, Some(&owner_policy)).is_err());

        let owner_bundle = frame_with(&owner_signer, PURPOSE, EPOCH, CONTEXT, &payload);
        assert!(decode_for_admission(&owner_bundle, Some(&attacker_policy)).is_err());
    }

    #[test]
    fn arbitrary_signed_payload_is_never_promoted_to_effect() {
        let owner_signer = signer();
        let policy = effect_policy(&owner_signer);
        let encoded = frame_with(&owner_signer, PURPOSE, EPOCH, CONTEXT, ARBITRARY_PAYLOAD);
        assert!(decode_for_admission(&encoded, Some(&policy)).is_err());
    }

    #[test]
    fn test_only_admission_is_non_effect_and_production_requires_external_custody() {
        let owner_signer = signer();
        let test_policy = policy_with(
            &owner_signer,
            PURPOSE,
            EPOCH,
            CONTEXT,
            HybridAdmissionClass::TestOnlyNonEffect,
            false,
        );
        let encoded = frame();
        let admission = decode_for_admission(&encoded, Some(&test_policy)).unwrap();
        assert!(!admission.carries_effect_authority());
        assert!(matches!(
            admission,
            WireAdmission::HybridAuthenticatedNonEffect {
                admission_class: HybridAdmissionClass::TestOnlyNonEffect,
                ..
            }
        ));

        let key = owner_signer.public_key();
        let digest = key.ordered_key_set_digest();
        let (_, kind) = legacy_payload();
        assert!(OwnerPinnedHybridAdmission::new(
            key,
            digest,
            PURPOSE,
            EPOCH,
            CONTEXT,
            &kind,
            HybridAdmissionClass::ProductionEffect,
            false,
        )
        .is_err());

        let key = owner_signer.public_key();
        let digest = key.ordered_key_set_digest();
        assert!(OwnerPinnedHybridAdmission::new(
            key,
            digest,
            PURPOSE,
            EPOCH,
            CONTEXT,
            &kind,
            HybridAdmissionClass::TestOnlyNonEffect,
            true,
        )
        .is_err());
    }

    #[test]
    fn missing_owner_pins_reject_hybrid() {
        assert!(decode_for_admission(&frame(), None).is_err());
    }

    #[test]
    fn legacy_v2_is_explicitly_non_effect() {
        let line = include_str!("../../vectors/mode1_golden.jsonl")
            .lines()
            .next()
            .unwrap();
        let message = crate::parse_message(line.as_bytes()).unwrap();
        let legacy = crate::encode_frame(&message).unwrap();
        let admission = decode_for_admission(&legacy, None).unwrap();
        assert!(!admission.carries_effect_authority());
        assert!(matches!(admission, WireAdmission::LegacyV2NonEffect(_)));
    }

    #[test]
    fn truncation_extension_and_length_ambiguity_reject() {
        let encoded = frame();
        for cut in [0, 1, 3, 4, 100, encoded.len() - 1] {
            assert!(decode_hybrid_frame(&encoded[..cut]).is_err());
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(decode_hybrid_frame(&extended).is_err());
        let mut wrong_length = encoded;
        wrong_length[..4].copy_from_slice(&1u32.to_be_bytes());
        assert!(decode_hybrid_frame(&wrong_length).is_err());
    }
}
