//! # Public/secret keypair tools
//!
//! Provides an implementation for handling public/private keypairs based on
//! libsodium's crypto_box, which uses X25519.
//!
//! Refer to the [protected] mod for details on usage with protected memory.

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_box::crypto_box_seed_keypair_inplace;
use crate::constants::{
    CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES,
    CRYPTO_BOX_SEEDBYTES, CRYPTO_KX_SESSIONKEYBYTES,
};
use crate::error::Error;
use crate::kx;
use crate::precalc::PrecalcSecretKey;
use crate::types::*;
use crate::utils::ct_eq_bytes;

/// Stack-allocated public key type alias.
pub type PublicKey = StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
/// Stack-allocated secret key type alias.
pub type SecretKey = StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
/// Stack-allocated key pair type alias.
pub type StackKeyPair = KeyPair<PublicKey, SecretKey>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, ZeroizeOnDrop, Clone))]
/// Public/secret keypair for use with [`crate::dryocbox::DryocBox`] and
/// libsodium-compatible public-key encryption.
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
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> fmt::Debug for KeyPair<PublicKey, SecretKey>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
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
    pub fn generate() -> Self {
        use crate::classic::crypto_box::crypto_box_keypair_inplace;

        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();
        crypto_box_keypair_inplace(public_key.as_mut_array(), secret_key.as_mut_array());

        Self {
            public_key,
            secret_key,
        }
    }

    /// Derives the public key for `secret_key` and returns the complete
    /// keypair, consuming the secret key.
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        use crate::classic::crypto_core::crypto_scalarmult_base;

        let mut public_key = PublicKey::new_byte_array();
        crypto_scalarmult_base(public_key.as_mut_array(), secret_key.as_array());

        Self {
            public_key,
            secret_key,
        }
    }

    /// Deterministically derives a keypair from `seed`.
    pub fn from_seed<Seed: ByteArray<CRYPTO_BOX_SEEDBYTES>>(seed: &Seed) -> Self {
        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();

        crypto_box_seed_keypair_inplace(
            public_key.as_mut_array(),
            secret_key.as_mut_array(),
            seed.as_array(),
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
    pub fn generate_with_defaults() -> Self {
        Self::generate()
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
    ///
    /// # Errors
    ///
    /// Returns an error if either slice does not have the required key length,
    /// or if the target key type rejects the key bytes.
    pub fn from_slices(public_key: &'a [u8], secret_key: &'a [u8]) -> Result<Self, Error> {
        validate_length!(
            exact CRYPTO_BOX_PUBLICKEYBYTES,
            public_key.len(),
            crate::ErrorContext::PublicKey
        );
        validate_length!(
            exact CRYPTO_BOX_SECRETKEYBYTES,
            secret_key.len(),
            crate::ErrorContext::SecretKey
        );

        Ok(Self {
            public_key: PublicKey::try_from(public_key)
                .map_err(|_| Error::invalid_key(crate::ErrorContext::PublicKey))?,
            secret_key: SecretKey::try_from(secret_key)
                .map_err(|_| Error::invalid_key(crate::ErrorContext::SecretKey))?,
        })
    }
}

impl<
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> KeyPair<PublicKey, SecretKey>
{
    /// Checks if the given public key is valid according to X25519 rules.
    ///
    /// For X25519 ([`crypto_box`](`crate::classic::crypto_box`),
    /// [`DryocBox`](`crate::dryocbox::DryocBox`)), this performs a trial scalar
    /// multiplication and rejects public keys that produce an all-zero shared
    /// secret, including low-order inputs rejected by libsodium. As required by
    /// RFC 7748, the high bit of the encoded public key is ignored.
    ///
    /// ## Validating Protected Keys
    ///
    /// You can validate keys stored in protected memory directly, as the
    /// validation functions operate on references.
    ///
    /// ```
    /// # #![cfg_attr(not(all(feature = "protected", any(unix, windows))), ignore)]
    /// # #[cfg(all(feature = "protected", any(unix, windows)))]
    /// # {
    /// use dryoc::constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES};
    /// use dryoc::keypair::protected::{HeapByteArray, LockedRO};
    /// use dryoc::keypair::{KeyPair, PublicKey, SecretKey};
    ///
    /// // Generate a keypair stored in locked, read-only memory
    /// let protected_kp: KeyPair<
    ///     LockedRO<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
    ///     LockedRO<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
    /// > = KeyPair::generate_readonly_locked_keypair().expect("Failed to generate locked keypair");
    ///
    /// // Validate the X25519 public key.
    /// let is_x25519_valid = KeyPair::<
    ///     LockedRO<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
    ///     LockedRO<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
    /// >::is_valid_public_key(&protected_kp.public_key);
    ///
    /// assert!(is_x25519_valid, "Protected X25519 key should be valid");
    /// # }
    /// ```
    pub fn is_valid_public_key<PK: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>(key: &PK) -> bool {
        let scalar = [0u8; CRYPTO_BOX_SECRETKEYBYTES];
        let mut shared_secret = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];

        crate::classic::crypto_core::crypto_scalarmult(&mut shared_secret, &scalar, key.as_array())
            .is_ok()
    }

    /// Checks if the given key is a valid prime-order Ed25519 public key.
    ///
    /// The canonical compressed encoding is required. The high bit, which
    /// encodes the sign of the x-coordinate, may legitimately be set.
    ///
    /// This is a strict prime-subgroup policy, not a generic Ed25519 signature
    /// validity predicate. Use it when an application or point-arithmetic
    /// protocol requires canonical, nonidentity, prime-order keys. Verify
    /// signatures with
    /// [`crypto_sign_verify_detached`](crate::classic::crypto_sign::crypto_sign_verify_detached)
    /// instead; some signature profiles intentionally define different
    /// point-acceptance rules.
    /// `is_valid_public_key` should be used for X25519 keys used in crypto_box.
    pub fn is_valid_ed25519_key<PK: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>(key: &PK) -> bool {
        crate::classic::crypto_core::crypto_core_ed25519_is_valid_point(key.as_array())
    }

    /// Creates new client session keys using this keypair and
    /// `server_public_key`, assuming this keypair is for the client.
    ///
    /// # Errors
    ///
    /// Returns an error if `server_public_key` is unacceptable, including a
    /// low-order point that would produce an all-zero shared secret.
    pub fn kx_new_client_session<
        SessionKey: NewByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize + ZeroizeOnDrop,
    >(
        &self,
        server_public_key: &PublicKey,
    ) -> Result<kx::Session<SessionKey>, Error> {
        kx::Session::new_client(self, server_public_key)
    }

    /// Creates new server session keys using this keypair and
    /// `client_public_key`, assuming this keypair is for the server.
    ///
    /// # Errors
    ///
    /// Returns an error if `client_public_key` is unacceptable, including a
    /// low-order point that would produce an all-zero shared secret.
    pub fn kx_new_server_session<
        SessionKey: NewByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize + ZeroizeOnDrop,
    >(
        &self,
        client_public_key: &PublicKey,
    ) -> Result<kx::Session<SessionKey>, Error> {
        kx::Session::new_server(self, client_public_key)
    }

    /// Computes a stack-allocated shared secret key using a secret key from
    /// this keypair and `third_party_public_key`.
    ///
    /// Compatible with libsodium's `crypto_box_beforenm`.
    ///
    /// # Errors
    ///
    /// Returns an error if `third_party_public_key` is an unacceptable
    /// low-order point.
    #[inline]
    pub fn precalculate(
        &self,
        third_party_public_key: &PublicKey,
    ) -> Result<PrecalcSecretKey<StackByteArray<CRYPTO_BOX_BEFORENMBYTES>>, Error> {
        PrecalcSecretKey::precalculate(third_party_public_key, &self.secret_key)
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

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory for [`KeyPair`]
    use super::*;
    use crate::classic::crypto_box::crypto_box_keypair_inplace;
    pub use crate::protected::*;

    impl
        KeyPair<
            Locked<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
            Locked<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new zero-filled locked keypair.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Io`] if either allocation cannot be locked,
        /// commonly because the process has reached its locked-memory limit.
        ///
        /// # Panics
        ///
        /// Panics if either page-aligned allocation cannot be created or its
        /// size cannot be represented with guard pages.
        pub fn new_locked_keypair() -> Result<Self, Error> {
            Ok(Self {
                public_key: HeapByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::new_locked()?,
                secret_key: HeapByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::new_locked()?,
            })
        }

        /// Returns a new randomly generated locked keypair.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Io`] if either allocation cannot be locked.
        ///
        /// # Panics
        ///
        /// Panics if either page-aligned allocation cannot be created, its
        /// size cannot be represented with guard pages, or the operating
        /// system's random number generator fails.
        pub fn generate_locked_keypair() -> Result<Self, Error> {
            let mut res = Self::new_locked_keypair()?;

            crypto_box_keypair_inplace(
                res.public_key.as_mut_array(),
                res.secret_key.as_mut_array(),
            );

            Ok(res)
        }

        /// Computes a heap-allocated, page-aligned, locked shared secret key
        /// using a secret key from this keypair and
        /// `third_party_public_key`.
        ///
        /// Compatible with libsodium's `crypto_box_beforenm`.
        ///
        /// # Errors
        ///
        /// Returns an error if `third_party_public_key` is an unacceptable
        /// low-order point or the shared-key allocation cannot be locked.
        ///
        /// # Panics
        ///
        /// Panics if the page-aligned shared-key allocation cannot be created
        /// or its size cannot be represented with guard pages.
        #[inline]
        pub fn precalculate_locked<OtherPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>(
            &self,
            third_party_public_key: &OtherPublicKey,
        ) -> Result<PrecalcSecretKey<Locked<HeapByteArray<CRYPTO_BOX_BEFORENMBYTES>>>, Error>
        {
            PrecalcSecretKey::precalculate_locked(third_party_public_key, &self.secret_key)
        }
    }

    impl
        KeyPair<
            LockedRO<HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>,
            LockedRO<HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new randomly generated locked, read-only keypair.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Io`] if either allocation cannot be locked or its
        /// page permissions cannot be changed to read-only.
        ///
        /// # Panics
        ///
        /// Panics if either page-aligned allocation cannot be created, its
        /// size cannot be represented with guard pages, or the operating
        /// system's random number generator fails.
        pub fn generate_readonly_locked_keypair() -> Result<Self, Error> {
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

        /// Computes a heap-allocated, page-aligned, locked, read-only shared
        /// secret key using a secret key from this keypair and
        /// `third_party_public_key`.
        ///
        /// Compatible with libsodium's `crypto_box_beforenm`.
        ///
        /// # Errors
        ///
        /// Returns an error if `third_party_public_key` is an unacceptable
        /// low-order point, the shared-key allocation cannot be locked, or its
        /// page permissions cannot be changed to read-only.
        ///
        /// # Panics
        ///
        /// Panics if the page-aligned shared-key allocation cannot be created
        /// or its size cannot be represented with guard pages.
        #[inline]
        pub fn precalculate_readonly_locked<
            OtherPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        >(
            &self,
            third_party_public_key: &OtherPublicKey,
        ) -> Result<PrecalcSecretKey<LockedRO<HeapByteArray<CRYPTO_BOX_BEFORENMBYTES>>>, Error>
        {
            PrecalcSecretKey::precalculate_readonly_locked(third_party_public_key, &self.secret_key)
        }
    }
}

impl<
    PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
> PartialEq<KeyPair<PublicKey, SecretKey>> for KeyPair<PublicKey, SecretKey>
{
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.public_key.as_slice(), other.public_key.as_slice())
            && ct_eq_bytes(self.secret_key.as_slice(), other.secret_key.as_slice())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::kx::Session;

    #[test]
    fn keypair_debug_redacts_keys() {
        let keypair = StackKeyPair::generate();
        let debug = format!("{keypair:?}");

        assert_eq!(
            debug,
            "KeyPair { public_key: \"[REDACTED]\", secret_key: \"[REDACTED]\" }"
        );
    }

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
    fn test_from_secret_key() {
        let keypair_1 = KeyPair::<
            StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >::generate();
        let keypair_2 = KeyPair::from_secret_key(keypair_1.secret_key.clone());

        assert_eq!(keypair_1.public_key, keypair_2.public_key);
    }

    /// `crypto_box_seed_keypair` outputs from libsodium for the all-`0x01` and
    /// all-`0x02` seeds, and the `crypto_kx_client_session_keys` they derive.
    const SEED_KEYPAIRS: [([u8; CRYPTO_BOX_SEEDBYTES], &str, &str); 2] = [
        (
            [1u8; CRYPTO_BOX_SEEDBYTES],
            "1b1b58dd50ea14b60da17b790cd02754d970c9bab864ebb3c0f3016fe51d3f57",
            "5ce86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef3ee",
        ),
        (
            [2u8; CRYPTO_BOX_SEEDBYTES],
            "60346e7c911a5f6ba154129174cafe75b294ac3bbd5549632f48cec6266f8410",
            "aa3c626bc9c38c8c201878ebb1d5b0b50ac40e8986c78793db1d4ef369fca1ce",
        ),
    ];
    const CLIENT_RX: &str = "4081524abf55a75021ebd5e98e08552fb2bd26315c40e563b74e64abff1be442";
    const CLIENT_TX: &str = "2f9c2f944f504caf772db17affc91e3ba8886a806ba53ab37881d15c042f3410";

    /// RFC 7748 section 6.1 / NaCl `tests/box.c` keys and their
    /// `crypto_box_beforenm` shared key.
    const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_SK: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_KEY: &str = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";

    fn keypair_from_hex(public_key: &str, secret_key: &str) -> StackKeyPair {
        KeyPair::from_slices(
            &hex::decode(public_key).expect("hex"),
            &hex::decode(secret_key).expect("hex"),
        )
        .expect("keypair")
    }

    #[test]
    fn from_seed_matches_libsodium_and_classic_seed_keypair() {
        for (seed, public_key, secret_key) in SEED_KEYPAIRS {
            let keypair: StackKeyPair = KeyPair::from_seed(&seed);
            assert_eq!(keypair, keypair_from_hex(public_key, secret_key));

            let (classic_pk, classic_sk) =
                crate::classic::crypto_box::crypto_box_seed_keypair(&seed);
            assert_eq!(keypair.public_key.as_array(), &classic_pk);
            assert_eq!(keypair.secret_key.as_array(), &classic_sk);

            assert_eq!(
                KeyPair::from_secret_key(keypair.secret_key.clone()),
                keypair
            );
            assert!(KeyPair::<PublicKey, SecretKey>::is_valid_public_key(
                &keypair.public_key
            ));
        }
        assert_ne!(
            StackKeyPair::from_seed(&SEED_KEYPAIRS[0].0),
            StackKeyPair::from_seed(&SEED_KEYPAIRS[1].0)
        );
    }

    #[test]
    fn generated_public_key_is_the_base_point_multiple_of_the_secret_key() {
        use crate::classic::crypto_core::crypto_scalarmult_base;

        let keypair = KeyPair::generate_with_defaults();
        let mut public_key = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        crypto_scalarmult_base(&mut public_key, keypair.secret_key.as_array());
        assert_eq!(keypair.public_key.as_array(), &public_key);
        assert_eq!(
            KeyPair::from_secret_key(keypair.secret_key.clone()),
            keypair
        );
    }

    #[test]
    fn from_slices_accepts_exact_lengths_and_reports_the_short_side() {
        let alice = keypair_from_hex(ALICE_PK, ALICE_SK);
        assert_eq!(
            alice.public_key.as_slice(),
            hex::decode(ALICE_PK).expect("hex")
        );
        assert_eq!(
            alice.secret_key.as_slice(),
            hex::decode(ALICE_SK).expect("hex")
        );
        assert_eq!(
            StackKeyPair::from_secret_key(alice.secret_key.clone()).public_key,
            alice.public_key
        );

        for len in [
            0,
            CRYPTO_BOX_PUBLICKEYBYTES - 1,
            CRYPTO_BOX_PUBLICKEYBYTES + 1,
        ] {
            assert!(matches!(
                StackKeyPair::from_slices(&vec![0u8; len], alice.secret_key.as_slice()),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::PublicKey,
                    actual,
                    ..
                }) if actual == len
            ));
        }
        for len in [
            0,
            CRYPTO_BOX_SECRETKEYBYTES - 1,
            CRYPTO_BOX_SECRETKEYBYTES + 1,
        ] {
            assert!(matches!(
                StackKeyPair::from_slices(alice.public_key.as_slice(), &vec![0u8; len]),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::SecretKey,
                    actual,
                    ..
                }) if actual == len
            ));
        }
    }

    #[test]
    fn precalculate_matches_nacl_shared_key() {
        let alice = keypair_from_hex(ALICE_PK, ALICE_SK);
        let bob = keypair_from_hex(BOB_PK, BOB_SK);
        let expected = hex::decode(SHARED_KEY).expect("hex");

        let from_alice = alice.precalculate(&bob.public_key).expect("precalc");
        let from_bob = bob.precalculate(&alice.public_key).expect("precalc");
        assert_eq!(from_alice.as_slice(), expected.as_slice());
        assert_eq!(from_alice, from_bob);
        assert!(alice.precalculate(&PublicKey::default()).is_err());
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_precalculate_matches_nacl_shared_key() {
        use crate::keypair::protected::*;

        let alice = keypair_from_hex(ALICE_PK, ALICE_SK);
        let bob = keypair_from_hex(BOB_PK, BOB_SK);
        let expected = hex::decode(SHARED_KEY).expect("hex");
        let locked_alice = KeyPair {
            public_key: HeapByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::from_slice_into_locked(
                alice.public_key.as_slice(),
            )
            .expect("lock pk"),
            secret_key: HeapByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::from_slice_into_locked(
                alice.secret_key.as_slice(),
            )
            .expect("lock sk"),
        };

        let locked = locked_alice
            .precalculate_locked(&bob.public_key)
            .expect("precalc locked");
        assert_eq!(locked.as_slice(), expected.as_slice());
        assert!(
            locked_alice
                .precalculate_locked(&PublicKey::default())
                .is_err()
        );
    }

    #[test]
    fn kx_sessions_equal_session_constructors_and_libsodium_known_answers() {
        let client: StackKeyPair = KeyPair::from_seed(&SEED_KEYPAIRS[0].0);
        let server: StackKeyPair = KeyPair::from_seed(&SEED_KEYPAIRS[1].0);
        let client_rx = hex::decode(CLIENT_RX).expect("hex");
        let client_tx = hex::decode(CLIENT_TX).expect("hex");

        let client_session: Session<StackByteArray<CRYPTO_KX_SESSIONKEYBYTES>> = client
            .kx_new_client_session(&server.public_key)
            .expect("client session");
        assert_eq!(client_session.rx_as_slice(), client_rx.as_slice());
        assert_eq!(client_session.tx_as_slice(), client_tx.as_slice());
        let expected =
            Session::new_client_with_defaults(&client, &server.public_key).expect("client");
        assert_eq!(client_session.rx_as_array(), expected.rx_as_array());
        assert_eq!(client_session.tx_as_array(), expected.tx_as_array());

        let server_session: Session<StackByteArray<CRYPTO_KX_SESSIONKEYBYTES>> = server
            .kx_new_server_session(&client.public_key)
            .expect("server session");
        assert_eq!(server_session.rx_as_slice(), client_tx.as_slice());
        assert_eq!(server_session.tx_as_slice(), client_rx.as_slice());
        let expected =
            Session::new_server_with_defaults(&server, &client.public_key).expect("server");
        assert_eq!(server_session.rx_as_array(), expected.rx_as_array());
        assert_eq!(server_session.tx_as_array(), expected.tx_as_array());

        let low_order: Result<Session<StackByteArray<CRYPTO_KX_SESSIONKEYBYTES>>, Error> =
            client.kx_new_client_session(&PublicKey::default());
        assert!(low_order.is_err());
        let low_order: Result<Session<StackByteArray<CRYPTO_KX_SESSIONKEYBYTES>>, Error> =
            server.kx_new_server_session(&PublicKey::default());
        assert!(low_order.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_keeps_the_keypair_usable_for_boxes() {
        use crate::dryocbox::{DryocBox, Nonce, VecBox};

        let alice = keypair_from_hex(ALICE_PK, ALICE_SK);
        let bob = keypair_from_hex(BOB_PK, BOB_SK);

        let json = serde_json::to_string(&bob).expect("serialize");
        let decoded: StackKeyPair = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, bob);

        let nonce = Nonce::from([3u8; crate::constants::CRYPTO_BOX_NONCEBYTES]);
        let dryocbox =
            DryocBox::encrypt_to_vecbox(b"for bob", &nonce, &decoded.public_key, &alice.secret_key)
                .expect("encrypt");
        assert_eq!(
            VecBox::from_bytes(&dryocbox.to_vec())
                .expect("parse")
                .decrypt_to_vec(&nonce, &alice.public_key, &decoded.secret_key)
                .expect("decrypt"),
            b"for bob"
        );

        // Swapping the encoded fields yields a keypair that cannot open the
        // box.
        let swapped = json
            .replacen("public_key", "tmp", 1)
            .replacen("secret_key", "public_key", 1)
            .replacen("tmp", "secret_key", 1);
        let swapped: StackKeyPair = serde_json::from_str(&swapped).expect("deserialize");
        assert_ne!(swapped, bob);
        assert!(
            dryocbox
                .decrypt_to_vec(&nonce, &alice.public_key, &swapped.secret_key)
                .is_err()
        );
    }

    #[test]
    fn test_is_valid_public_key() {
        // Known valid key (assuming it meets X25519 criteria)
        // This specific key is also a valid Ed25519 key.
        let valid_pk_bytes = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let valid_pk = PublicKey::from(valid_pk_bytes);
        assert!(
            KeyPair::<PublicKey, SecretKey>::is_valid_public_key(&valid_pk),
            "Known valid key failed validation"
        );

        // RFC 7748 requires the high bit to be ignored when decoding X25519
        // public keys.
        let mut high_bit_bytes = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        high_bit_bytes[0] = 9;
        high_bit_bytes[31] = 0x80;
        let high_bit = PublicKey::from(high_bit_bytes);
        assert!(
            KeyPair::<PublicKey, SecretKey>::is_valid_public_key(&high_bit),
            "RFC 7748 high-bit encoding should be accepted"
        );

        // Invalid: Zero point
        let zero_bytes = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        let zero_pk = PublicKey::from(zero_bytes);
        assert!(
            !KeyPair::<PublicKey, SecretKey>::is_valid_public_key(&zero_pk),
            "Zero key should be invalid"
        );

        let mut identity_bytes = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        identity_bytes[0] = 1;
        let identity = PublicKey::from(identity_bytes);
        assert!(
            !KeyPair::<PublicKey, SecretKey>::is_valid_public_key(&identity),
            "Low-order key should be invalid"
        );

        // Generated key should be valid
        let kp = KeyPair::generate_with_defaults();
        assert!(
            KeyPair::<PublicKey, SecretKey>::is_valid_public_key(&kp.public_key),
            "Generated key failed validation"
        );
    }

    #[test]
    fn test_is_valid_ed25519_key() {
        let (valid_pk, _) = crate::classic::crypto_sign::crypto_sign_keypair();
        assert!(
            KeyPair::<PublicKey, SecretKey>::is_valid_ed25519_key(&valid_pk),
            "Ed25519 key from crypto_sign_keypair should pass validation"
        );

        let mut negative_basepoint =
            curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        negative_basepoint[31] |= 0x80;
        assert!(
            KeyPair::<PublicKey, SecretKey>::is_valid_ed25519_key(&negative_basepoint),
            "the Ed25519 x-coordinate sign bit should be accepted"
        );

        let zero_bytes = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        let zero_pk = PublicKey::from(zero_bytes);
        assert!(
            !KeyPair::<PublicKey, SecretKey>::is_valid_ed25519_key(&zero_pk),
            "zero key should be invalid"
        );

        let identity_bytes = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let identity_pk = PublicKey::from(identity_bytes);
        assert!(
            !KeyPair::<PublicKey, SecretKey>::is_valid_ed25519_key(&identity_pk),
            "identity element should be invalid"
        );

        let mut noncanonical_identity = [0xff; CRYPTO_BOX_PUBLICKEYBYTES];
        noncanonical_identity[0] = 0xee;
        noncanonical_identity[31] = 0x7f;
        assert!(
            !KeyPair::<PublicKey, SecretKey>::is_valid_ed25519_key(&noncanonical_identity),
            "noncanonical identity encoding should be invalid"
        );

        let mut mixed_order = [0x99; CRYPTO_BOX_PUBLICKEYBYTES];
        mixed_order[0] = 0x95;
        assert!(
            !KeyPair::<PublicKey, SecretKey>::is_valid_ed25519_key(&mixed_order),
            "mixed-order Ed25519 key should fail the prime-subgroup policy"
        );
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;

        #[test]
        fn test_gen_keypair() {
            use sodiumoxide::crypto::scalarmult::curve25519::{Scalar, scalarmult_base};

            use crate::classic::crypto_core::crypto_scalarmult_base;

            let keypair = KeyPair::<
                StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
                StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
            >::generate();

            let mut public_key = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
            crypto_scalarmult_base(&mut public_key, keypair.secret_key.as_array());

            assert_eq!(keypair.public_key.as_array(), &public_key);

            let ge = scalarmult_base(&Scalar::from_slice(&keypair.secret_key).unwrap());

            assert_eq!(ge.as_ref(), public_key);
        }
    }
}
