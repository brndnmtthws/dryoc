use crate::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;
use crate::rng::copy_randombytes;
use crate::traits::Gen;
use crate::types::SecretStreamKeyBase;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, Clone, PartialEq))]
#[zeroize(drop)]
/// A wrapper for [`crate::dryocsecretbox::DryocSecretStream`] secret keys
pub struct SecretStreamKey(pub SecretStreamKeyBase);

impl SecretStreamKey {
    /// Returns an empty initialized secret key
    pub fn new() -> Self {
        Self([0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES])
    }
}

impl From<[u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES]> for SecretStreamKey {
    fn from(data: [u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES]) -> Self {
        Self(data)
    }
}

impl Gen for SecretStreamKey {
    /// Generates a random keypair
    fn gen() -> Self {
        let mut key = Self::new();
        copy_randombytes(&mut key.0);
        key
    }
}

impl Default for SecretStreamKey {
    fn default() -> Self {
        Self::new()
    }
}
