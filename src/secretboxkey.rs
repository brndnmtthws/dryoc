use crate::constants::CRYPTO_SECRETBOX_KEYBYTES;
use crate::rng::copy_randombytes;
use crate::traits::Gen;
use crate::types::SecretBoxKeyBase;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, Clone, PartialEq))]
#[zeroize(drop)]
pub struct SecretBoxKey(pub SecretBoxKeyBase);

impl SecretBoxKey {
    pub fn new() -> Self {
        Self([0u8; CRYPTO_SECRETBOX_KEYBYTES])
    }
}

impl From<[u8; CRYPTO_SECRETBOX_KEYBYTES]> for SecretBoxKey {
    fn from(data: [u8; CRYPTO_SECRETBOX_KEYBYTES]) -> Self {
        Self(data)
    }
}

impl Gen for SecretBoxKey {
    /// Generates a random keypair
    fn gen() -> Self {
        let mut key = Self::new();
        copy_randombytes(&mut key.0);
        key
    }
}

impl Default for SecretBoxKey {
    fn default() -> Self {
        Self::new()
    }
}
