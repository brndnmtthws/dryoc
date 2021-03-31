use crate::constants::CRYPTO_BOX_SECRETKEYBYTES;
use crate::crypto_box::{PublicKey, SecretKey};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, Clone, PartialEq))]
#[zeroize(drop)]
/// Public/private keypair for use with [`crate::dryocbox::DryocBox`], aka libsodium box
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Creates a new, unititialized keypair
    pub fn new() -> Self {
        Self {
            public_key: PublicKey::new(),
            secret_key: SecretKey::new(),
        }
    }
    /// Generates a random keypair
    pub fn gen() -> Self {
        use crate::crypto_box::crypto_box_keypair;
        crypto_box_keypair()
    }
    /// Derives a keypair from `secret_key`, and consume it
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        use crate::crypto_core::crypto_scalarmult_base;
        let public_key = crypto_scalarmult_base(secret_key.as_ref());
        Self {
            public_key: public_key.into(),
            secret_key,
        }
    }

    /// Constructs a new keypair from key slices, consuming them. Does not check
    /// validity or authenticity of keypair.
    pub fn from_slices(
        public_key: [u8; CRYPTO_BOX_SECRETKEYBYTES],
        secret_key: [u8; CRYPTO_BOX_SECRETKEYBYTES],
    ) -> Self {
        Self {
            public_key: public_key.into(),
            secret_key: secret_key.into(),
        }
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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

        assert_eq!(all_eq(&keypair.public_key, 0), true);
        assert_eq!(all_eq(&keypair.secret_key, 0), true);
    }

    #[test]
    fn test_default() {
        let keypair = KeyPair::default();

        assert_eq!(all_eq(&keypair.public_key, 0), true);
        assert_eq!(all_eq(&keypair.secret_key, 0), true);
    }

    #[test]
    fn test_gen_keypair() {
        use crate::crypto_core::crypto_scalarmult_base;
        use crate::types::*;
        use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

        let keypair = KeyPair::gen();

        let public_key = crypto_scalarmult_base(keypair.secret_key.as_ref());

        assert_eq!(keypair.public_key.as_slice(), &public_key);

        let ge = scalarmult_base(&Scalar::from_slice(keypair.secret_key.as_slice()).unwrap());

        assert_eq!(ge.as_ref(), public_key);
    }

    #[test]
    fn test_from_secret_key() {
        let keypair_1 = KeyPair::gen();
        let keypair_2 = KeyPair::from_secret_key(keypair_1.secret_key.clone());

        assert_eq!(keypair_1.public_key, keypair_2.public_key);
    }
}
