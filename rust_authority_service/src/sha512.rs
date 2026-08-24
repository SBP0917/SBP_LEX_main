use sha2::{Digest as _, Sha512};

pub(crate) fn digest(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}
