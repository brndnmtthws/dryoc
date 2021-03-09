use crate::constants::*;
use crate::traits::*;
use crate::types::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, Clone, PartialEq))]
#[zeroize(drop)]
pub struct SecretKey(pub SecretBoxKeyBase);

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, Clone, PartialEq))]
#[zeroize(drop)]
pub struct PublicKey(pub PublicKeyBase);

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, Clone, PartialEq))]
#[zeroize(drop)]
/// Public/private keypair for use with [DryocBox], aka libsodium box
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl PublicKey {
    pub fn new() -> Self {
        Self([0u8; CRYPTO_BOX_SECRETKEYBYTES])
    }
}

impl From<[u8; CRYPTO_BOX_SECRETKEYBYTES]> for PublicKey {
    fn from(data: [u8; CRYPTO_BOX_SECRETKEYBYTES]) -> Self {
        Self(data)
    }
}

impl SecretKey {
    pub fn new() -> Self {
        Self([0u8; CRYPTO_BOX_SECRETKEYBYTES])
    }
}

impl From<[u8; CRYPTO_BOX_SECRETKEYBYTES]> for SecretKey {
    fn from(data: [u8; CRYPTO_BOX_SECRETKEYBYTES]) -> Self {
        Self(data)
    }
}

impl KeyPair {
    /// Creates a new, unititialized keypair
    pub fn new() -> Self {
        Self {
            public_key: PublicKey::new(),
            secret_key: SecretKey::new(),
        }
    }
    /// Derives a keypair from `secret_key`, and consume it
    pub fn from_secret_key(secret_key: SecretKeyBase) -> Self {
        use crate::crypto_core::crypto_scalarmult_base;
        let public_key = crypto_scalarmult_base(&secret_key);
        Self {
            public_key: public_key.into(),
            secret_key: secret_key.into(),
        }
    }

    /// Constructs a new keypair from key slices, consuming them. Does not check
    /// validity or authenticity of keypair.
    pub fn from_slices(public_key: PublicKeyBase, secret_key: SecretKeyBase) -> Self {
        Self {
            public_key: public_key.into(),
            secret_key: secret_key.into(),
        }
    }
}

impl Gen for KeyPair {
    /// Generates a random keypair
    fn gen() -> Self {
        use crate::crypto_box::crypto_box_keypair;
        crypto_box_keypair()
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a KeyPair> for &'a SecretKey {
    fn from(keypair: &'a KeyPair) -> Self {
        &keypair.secret_key
    }
}

impl<'a> From<&'a KeyPair> for &'a PublicKey {
    fn from(keypair: &'a KeyPair) -> Self {
        &keypair.public_key
    }
}

impl From<KeyPair> for SecretKey {
    fn from(keypair: KeyPair) -> Self {
        keypair.secret_key.clone()
    }
}

impl From<KeyPair> for PublicKey {
    fn from(keypair: KeyPair) -> Self {
        keypair.public_key.clone()
    }
}

mod tests {
    use super::*;

    fn all_eq<T>(t: &[T], v: T) -> bool
    where
        T: PartialEq,
    {
        t.iter().fold(true, |acc, x| acc && *x == v)
    }

    #[test]
    fn test_new() {
        let keypair = KeyPair::new();

        assert_eq!(all_eq(&keypair.public_key.0, 0), true);
        assert_eq!(all_eq(&keypair.secret_key.0, 0), true);
    }

    #[test]
    fn test_default() {
        let keypair = KeyPair::default();

        assert_eq!(all_eq(&keypair.public_key.0, 0), true);
        assert_eq!(all_eq(&keypair.secret_key.0, 0), true);
    }

    #[test]
    fn test_gen_keypair() {
        use crate::crypto_core::crypto_scalarmult_base;
        use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

        let keypair = KeyPair::gen();

        let public_key = crypto_scalarmult_base(&keypair.secret_key.0);

        assert_eq!(keypair.public_key.0, public_key);

        let ge = scalarmult_base(&Scalar::from_slice(&keypair.secret_key.0).unwrap());

        assert_eq!(ge.as_ref(), public_key);
    }

    #[test]
    fn test_from_secret_key() {
        let keypair_1 = KeyPair::gen();
        let keypair_2 = KeyPair::from_secret_key(keypair_1.secret_key.0);

        assert_eq!(keypair_1.public_key, keypair_2.public_key);
    }
}
