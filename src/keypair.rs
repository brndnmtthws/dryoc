use crate::constants::*;
use crate::types::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "example", derive(Serialize, Deserialize))]
/// Public/private keypair for use with [DryocBox], aka libsodium box
pub struct KeyPair {
    /// Secret key
    pub secret_key: SecretKey,
    /// Public key
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Creates a new, unititialized keypair
    pub fn new() -> Self {
        Self {
            public_key: [0u8; CRYPTO_BOX_SECRETKEYBYTES],
            secret_key: [0u8; CRYPTO_BOX_SECRETKEYBYTES],
        }
    }
    /// Generates a random keypair
    pub fn gen() -> Self {
        use crate::crypto_box::crypto_box_keypair;
        crypto_box_keypair()
    }
    /// Derives a keypair from a secret key
    pub fn from_secret_key(from_secret_key: &SecretKey) -> Self {
        use crate::crypto_core::crypto_scalarmult_base;
        let public_key = crypto_scalarmult_base(from_secret_key);
        let mut secret_key: SecretKey = [0u8; CRYPTO_BOX_SECRETKEYBYTES];
        secret_key.copy_from_slice(from_secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}
impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_gen_keypair() {
        use crate::crypto_core::crypto_scalarmult_base;
        use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

        let keypair = KeyPair::gen();

        let public_key = crypto_scalarmult_base(&keypair.secret_key);

        assert_eq!(keypair.public_key, public_key);

        let ge = scalarmult_base(&Scalar::from_slice(&keypair.secret_key).unwrap());

        assert_eq!(ge.as_ref(), public_key);
    }

    #[test]
    fn test_from_secret_key() {
        let keypair_1 = KeyPair::gen();
        let keypair_2 = KeyPair::from_secret_key(&keypair_1.secret_key);

        assert_eq!(keypair_1.public_key, keypair_2.public_key);
    }
}
