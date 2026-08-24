use crate::{BoundaryError, Gap};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TpmProviderStatus {
    AvailableButHybridSuiteUnsupported,
    Unavailable,
    ProviderFailure(i32),
    UnsupportedPlatform,
}

/// Probe the actual Microsoft Platform Crypto Provider. This does not claim key
/// creation or signing: no provider mapping for the mandatory ML-DSA-87 plus
/// Ed448 hybrid suite exists in this repository.
#[cfg(windows)]
pub fn probe_platform_crypto_provider() -> TpmProviderStatus {
    use windows_sys::Win32::Foundation::NTE_DEVICE_NOT_READY;
    use windows_sys::Win32::Security::Cryptography::{
        NCryptFreeObject, NCryptOpenStorageProvider, MS_PLATFORM_CRYPTO_PROVIDER,
        NCRYPT_PROV_HANDLE,
    };

    let mut provider: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: NCrypt receives a valid out-pointer, a static NUL-terminated
    // provider name supplied by windows-sys, and flags=0. A successful handle
    // is released exactly once below.
    let status =
        unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    if status != 0 {
        return if status == NTE_DEVICE_NOT_READY {
            TpmProviderStatus::Unavailable
        } else {
            TpmProviderStatus::ProviderFailure(status)
        };
    }
    // SAFETY: provider is a successful NCrypt handle and is not used again.
    let free_status = unsafe { NCryptFreeObject(provider) };
    if free_status != 0 {
        return TpmProviderStatus::ProviderFailure(free_status);
    }
    TpmProviderStatus::AvailableButHybridSuiteUnsupported
}

#[cfg(not(windows))]
pub const fn probe_platform_crypto_provider() -> TpmProviderStatus {
    TpmProviderStatus::UnsupportedPlatform
}

pub fn create_nonexportable_signing_key(_key_name: &str) -> Result<(), BoundaryError> {
    Err(BoundaryError::Unsupported(
        Gap::HybridHardwareCustodyAndPinningUnavailable,
    ))
}

pub fn sign_with_tpm(_key_name: &str, _message: &[u8]) -> Result<Vec<u8>, BoundaryError> {
    Err(BoundaryError::Unsupported(
        Gap::HybridHardwareCustodyAndPinningUnavailable,
    ))
}

pub fn verify_with_tpm_public_key(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), BoundaryError> {
    Err(BoundaryError::Unsupported(
        Gap::HybridHardwareCustodyAndPinningUnavailable,
    ))
}
