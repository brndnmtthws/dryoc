//! # Public/secret keypair tools
//!
//! Provides an implementation for handling public/private keypairs based on
//! libsodium's crypto_box, which uses X25519.
//!
//! Refer to the [protected] mod for details on usage with protected memory.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_box::crypto_box_seed_keypair_inplace;
use crate::constants::{
    CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_KX_SESSIONKEYBYTES,
};
use crate::error::Error;
use crate::kx;
use crate::types::*;

/// Stack-allocated public key type alias.
pub type PublicKey = StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
/// Stack-allocated secret key type alias.
pub type SecretKey = StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
/// Stack-allocated key pair type alias.
pub type StackKeyPair = KeyPair<PublicKey, SecretKey>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Debug, Clone)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, ZeroizeOnDrop, Debug, Clone))]
/// Public/private keypair for use with [`crate::dryocbox::DryocBox`], aka
/// libsodium box
pub struct KeyPair<
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl<
    PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> KeyPair<PublicKey, SecretKey>
{
    /// Creates a new, empty keypair.
    pub fn new() -> Self {
        Self {
            public_key: PublicKey::new_byte_array(),
            secret_key: SecretKey::new_byte_array(),
        }
    }

    /// Generates a random keypair.
    pub fn gen() -> Self {
        use crate::classic::crypto_box::crypto_box_keypair_inplace;

        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();
        crypto_box_keypair_inplace(public_key.as_mut_array(), secret_key.as_mut_array());

        Self {
            public_key,
            secret_key,
        }
    }

    /// Derives a keypair from `secret_key`, and consumes it, and returns a new
    /// keypair.
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        use crate::classic::crypto_core::crypto_scalarmult_base;

        let mut public_key = PublicKey::new_byte_array();
        crypto_scalarmult_base(public_key.as_mut_array(), secret_key.as_array());

        Self {
            public_key,
            secret_key,
        }
    }

    /// Derives a keypair from `seed`, returning
    /// a new keypair.
    pub fn from_seed<Seed: Bytes>(seed: &Seed) -> Self {
        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();

        crypto_box_seed_keypair_inplace(
            public_key.as_mut_array(),
            secret_key.as_mut_array(),
            seed.as_slice(),
        );

        Self {
            public_key,
            secret_key,
        }
    }
}

impl KeyPair<StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>, StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>> {
    /// Randomly generates a new keypair, using default types
    /// (stack-allocated byte arrays). Provided for convenience.
    pub fn gen_with_defaults() -> Self {
        Self::gen()
    }
}

impl<
    'a,
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
> KeyPair<PublicKey, SecretKey>
{
    /// Constructs a new keypair from key slices, consuming them. Does not check
    /// validity or authenticity of keypair.
    pub fn from_slices(public_key: &'a [u8], secret_key: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            public_key: PublicKey::try_from(public_key)
                .map_err(|_e| dryoc_error!("invalid public key"))?,
            secret_key: SecretKey::try_from(secret_key)
                .map_err(|_e| dryoc_error!("invalid secret key"))?,
        })
    }
}

impl<
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> KeyPair<PublicKey, SecretKey>
{
    /// Creates new client session keys using this keypair and
    /// `server_public_key`, assuming this keypair is for the client.
    pub fn kx_new_client_session<SessionKey: NewByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize>(
        &self,
        server_public_key: &PublicKey,
    ) -> Result<kx::Session<SessionKey>, Error> {
        kx::Session::new_client(self, server_public_key)
    }

    /// Creates new server session keys using this keypair and
    /// `client_public_key`, assuming this keypair is for the server.
    pub fn kx_new_server_session<SessionKey: NewByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize>(
        &self,
        client_public_key: &PublicKey,
    ) -> Result<kx::Session<SessionKey>, Error> {
        kx::Session::new_server(self, client_public_key)
    }
}

impl<
    PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> Default for KeyPair<PublicKey, SecretKey>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory for [`KeyPair`]
    use super::*;
    use crate::classic::crypto_box::crypto_box_keypair_inplace;
    pub use crate::protected::*;

    impl
        KeyPair<
            Locked<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
            Locked<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new locked keypair.
        pub fn new_locked_keypair() -> Result<Self, std::io::Error> {
            Ok(Self {
                public_key: HeapByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::new_locked()?,
                secret_key: HeapByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::new_locked()?,
            })
        }

        /// Returns a new randomly generated locked keypair.
        pub fn gen_locked_keypair() -> Result<Self, std::io::Error> {
            let mut res = Self::new_locked_keypair()?;

            crypto_box_keypair_inplace(
                res.public_key.as_mut_array(),
                res.secret_key.as_mut_array(),
            );

            Ok(res)
        }
    }

    impl
        KeyPair<
            LockedRO<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
            LockedRO<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new randomly generated locked, read-only keypair.
        pub fn gen_readonly_locked_keypair() -> Result<Self, std::io::Error> {
            let mut public_key = HeapByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::new_locked()?;
            let mut secret_key = HeapByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::new_locked()?;

            crypto_box_keypair_inplace(public_key.as_mut_array(), secret_key.as_mut_array());

            let public_key = public_key.mprotect_readonly()?;
            let secret_key = secret_key.mprotect_readonly()?;

            Ok(Self {
                public_key,
                secret_key,
            })
        }
    }
}

impl<
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> PartialEq<KeyPair<PublicKey, SecretKey>> for KeyPair<PublicKey, SecretKey>
{
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .as_slice()
            .ct_eq(other.public_key.as_slice())
            .unwrap_u8()
            == 1
            && self
                .secret_key
                .as_slice()
                .ct_eq(other.secret_key.as_slice())
                .unwrap_u8()
                == 1
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn all_eq<T>(t: &[T], v: T) -> bool
    where
        T: PartialEq,
    {
        t.iter().all(|x| *x == v)
    }

    #[test]
    fn test_new() {
        let keypair = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::new();

        assert!(all_eq(&keypair.public_key, 0));
        assert!(all_eq(&keypair.secret_key, 0));
    }

    #[test]
    fn test_default() {
        let keypair = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::default();

        assert!(all_eq(&keypair.public_key, 0));
        assert!(all_eq(&keypair.secret_key, 0));
    }

    #[test]
    fn test_gen_keypair() {
        use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

        use crate::classic::crypto_core::crypto_scalarmult_base;

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
