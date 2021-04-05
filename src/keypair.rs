#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES};
use crate::error::Error;
use crate::types::*;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Debug, Clone, PartialEq))]
/// Public/private keypair for use with [`crate::dryocbox::DryocBox`], aka
/// libsodium box
pub struct KeyPair<
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
> {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl<
    PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
    SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
> KeyPair<PublicKey, SecretKey>
{
    /// Creates a new, unititialized keypair
    pub fn new() -> Self {
        Self {
            public_key: PublicKey::new_byte_array(),
            secret_key: SecretKey::new_byte_array(),
        }
    }
}

impl<
    'a,
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + From<[u8; CRYPTO_BOX_PUBLICKEYBYTES]>,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + From<[u8; CRYPTO_BOX_SECRETKEYBYTES]>,
> KeyPair<PublicKey, SecretKey>
{
    /// Generates a random keypair
    pub fn gen() -> Self {
        use crate::crypto_box::crypto_box_keypair;
        let (pk, sk) = crypto_box_keypair();
        Self {
            public_key: PublicKey::from(pk),
            secret_key: SecretKey::from(sk),
        }
    }
}

impl<
    'a,
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + std::convert::TryFrom<&'a [u8]>,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + std::convert::TryFrom<&'a [u8]>,
> KeyPair<PublicKey, SecretKey>
{
    /// Constructs a new keypair from key slices, consuming them. Does not check
    /// validity or authenticity of keypair.
    pub fn from_slices(public_key: &'a [u8], secret_key: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            public_key: PublicKey::try_from(public_key)
                .map_err(|e| dryoc_error!("invalid public key"))?,
            secret_key: SecretKey::try_from(secret_key)
                .map_err(|e| dryoc_error!("invalid secret key"))?,
        })
    }
}

impl<
    PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
    SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
> KeyPair<PublicKey, SecretKey>
{
    /// Derives a keypair from `secret_key`, and consume it
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        use crate::crypto_core::crypto_scalarmult_base;

        let mut public_key = PublicKey::new_byte_array();
        let secret_key = SecretKey::from(secret_key);
        crypto_scalarmult_base(public_key.as_mut_array(), secret_key.as_array());

        Self {
            public_key,
            secret_key,
        }
    }
}

impl<
    PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
    SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
> Default for KeyPair<PublicKey, SecretKey>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {

    use super::*;
    use crate::protected::t::*;
    use crate::protected::*;

    impl
        KeyPair<
            Locked<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
            Locked<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new locked byte array.
        pub fn new_locked_keypair() -> Result<Self, std::io::Error> {
            Ok(Self {
                public_key: HeapByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::new_locked()?,
                secret_key: HeapByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::new_locked()?,
            })
        }

        /// Returns a new locked byte array filled with random data.
        pub fn gen_locked_keypair() -> Result<Self, std::io::Error> {
            use crate::crypto_core::crypto_scalarmult_base;
            use crate::rng::copy_randombytes;

            let mut res = Self::new_locked_keypair()?;
            copy_randombytes(res.secret_key.as_mut_slice());

            crypto_scalarmult_base(res.public_key.as_mut_array(), res.secret_key.as_array());

            Ok(res)
        }
    }

    impl
        KeyPair<
            LockedRO<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
            LockedRO<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new locked byte array filled with random data.
        pub fn gen_readonly_locked_keypair() -> Result<Self, std::io::Error> {
            use crate::crypto_core::crypto_scalarmult_base;
            use crate::rng::copy_randombytes;

            let mut public_key = HeapByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::new_locked()?;
            let mut secret_key = HeapByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::new_locked()?;

            copy_randombytes(secret_key.as_mut_slice());
            crypto_scalarmult_base(public_key.as_mut_array(), secret_key.as_array());

            let public_key = public_key.mprotect_readonly()?;
            let secret_key = secret_key.mprotect_readonly()?;

            Ok(Self {
                public_key,
                secret_key,
            })
        }
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
        let keypair = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::new();

        assert_eq!(all_eq(&keypair.public_key, 0), true);
        assert_eq!(all_eq(&keypair.secret_key, 0), true);
    }

    #[test]
    fn test_default() {
        let keypair = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::default();

        assert_eq!(all_eq(&keypair.public_key, 0), true);
        assert_eq!(all_eq(&keypair.secret_key, 0), true);
    }

    #[test]
    fn test_gen_keypair() {
        use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

        use crate::crypto_core::crypto_scalarmult_base;

        let keypair = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::gen();

        let mut public_key = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        crypto_scalarmult_base(&mut public_key, keypair.secret_key.as_array());

        assert_eq!(keypair.public_key.as_array(), &public_key);

        let ge = scalarmult_base(&Scalar::from_slice(&keypair.secret_key).unwrap());

        assert_eq!(ge.as_ref(), public_key);
    }

    #[test]
    fn test_from_secret_key() {
        let keypair_1 = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::gen();
        let keypair_2 = KeyPair::from_secret_key(keypair_1.secret_key.clone());

        assert_eq!(keypair_1.public_key, keypair_2.public_key);
    }
}
