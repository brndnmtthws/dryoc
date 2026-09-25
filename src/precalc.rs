//! Precalculated secret key for use with `precalc_*` functions in
//! [`crate::dryocbox::DryocBox`]
//!
//! Precalculation avoids repeating the public-key operation when encrypting or
//! decrypting multiple messages between the same sender and receiver.
use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES,
};
use crate::error::Error;
use crate::types::{ByteArray, Bytes, MutByteArray, MutBytes, StackByteArray};

type InnerKey = StackByteArray<CRYPTO_BOX_BEFORENMBYTES>;

/// Precalculated secret key for use with `precalc_*` functions in
/// [`crate::dryocbox::DryocBox`].
///
/// Use `precalc_*` functions to encrypt or decrypt multiple messages between
/// the same sender and receiver. They reuse this shared secret instead of
/// repeating the public-key operation for every message.
///
/// Using precalculated secret keys is compatible with libsodium's
/// `crypto_box_beforenm`.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct PrecalcSecretKey<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize>(InnerKey);

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> fmt::Debug
    for PrecalcSecretKey<InnerKey>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrecalcSecretKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> PartialEq
    for PrecalcSecretKey<InnerKey>
{
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> Eq for PrecalcSecretKey<InnerKey> {}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Bytes + Zeroize> Bytes
    for PrecalcSecretKey<InnerKey>
{
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> ByteArray<CRYPTO_BOX_BEFORENMBYTES>
    for PrecalcSecretKey<InnerKey>
{
    #[inline]
    fn as_array(&self) -> &[u8; CRYPTO_BOX_BEFORENMBYTES] {
        self.0.as_array()
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize + MutBytes> MutBytes
    for PrecalcSecretKey<InnerKey>
{
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    #[inline]
    fn copy_from_slice(&mut self, other: &[u8]) {
        self.0.copy_from_slice(other);
    }
}

impl<InnerKey: MutByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize>
    MutByteArray<CRYPTO_BOX_BEFORENMBYTES> for PrecalcSecretKey<InnerKey>
{
    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; CRYPTO_BOX_BEFORENMBYTES] {
        self.0.as_mut_array()
    }
}

impl PrecalcSecretKey<InnerKey> {
    /// Computes a stack-allocated shared secret key for the given
    /// `third_party_public_key` and `secret_key`.
    ///
    /// Compatible with libsodium's `crypto_box_beforenm`.
    ///
    /// # Errors
    ///
    /// Returns an error if `third_party_public_key` is an unacceptable
    /// low-order point.
    #[inline]
    pub fn precalculate<
        ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        third_party_public_key: &ThirdPartyPublicKey,
        secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::classic::crypto_box::crypto_box_beforenm;

        Ok(Self(
            crypto_box_beforenm(third_party_public_key.as_array(), secret_key.as_array())?.into(),
        ))
    }
}

#[cfg(any(
    all(feature = "protected", any(unix, windows)),
    all(doc, not(doctest), feature = "std")
))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory for [`PrecalcSecretKey`]
    use super::*;
    pub use crate::protected::*;

    type InnerKey = HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;

    /// Shared `crypto_box_beforenm` computation placed into a locked buffer.
    fn beforenm_into_locked<
        ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        third_party_public_key: &ThirdPartyPublicKey,
        secret_key: &SecretKey,
    ) -> Result<Locked<HeapByteArray<CRYPTO_BOX_BEFORENMBYTES>>, Error> {
        use crate::classic::crypto_box::crypto_box_beforenm;

        let mut precalc = HeapByteArray::<CRYPTO_BOX_BEFORENMBYTES>::new_locked()?;
        let mut key =
            crypto_box_beforenm(third_party_public_key.as_array(), secret_key.as_array())?;

        precalc.copy_from_slice(&key);
        key.zeroize();

        Ok(precalc)
    }

    impl PrecalcSecretKey<Locked<InnerKey>> {
        /// Computes a heap-allocated, page-aligned, locked shared secret key
        /// for the given `third_party_public_key` and `secret_key`.
        ///
        /// Compatible with libsodium's `crypto_box_beforenm`.
        ///
        /// # Errors
        ///
        /// Returns an error if `third_party_public_key` is an unacceptable
        /// low-order point or the protected allocation cannot be locked.
        ///
        /// # Panics
        ///
        /// Panics if the page-aligned allocation cannot be created or its size
        /// cannot be represented with guard pages.
        pub fn precalculate_locked<
            ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >(
            third_party_public_key: &ThirdPartyPublicKey,
            secret_key: &SecretKey,
        ) -> Result<Self, Error> {
            Ok(PrecalcSecretKey(beforenm_into_locked(
                third_party_public_key,
                secret_key,
            )?))
        }
    }

    impl PrecalcSecretKey<LockedRO<InnerKey>> {
        /// Computes a heap-allocated, page-aligned, locked, read-only shared
        /// secret key for the given `third_party_public_key` and
        /// `secret_key`.
        ///
        /// Compatible with libsodium's `crypto_box_beforenm`.
        ///
        /// # Errors
        ///
        /// Returns an error if `third_party_public_key` is an unacceptable
        /// low-order point, the protected allocation cannot be locked, or its
        /// page permissions cannot be changed to read-only.
        ///
        /// # Panics
        ///
        /// Panics if the page-aligned allocation cannot be created or its size
        /// cannot be represented with guard pages.
        pub fn precalculate_readonly_locked<
            ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >(
            third_party_public_key: &ThirdPartyPublicKey,
            secret_key: &SecretKey,
        ) -> Result<Self, Error> {
            Ok(PrecalcSecretKey(
                beforenm_into_locked(third_party_public_key, secret_key)?.mprotect_readonly()?,
            ))
        }
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> core::ops::Deref
    for PrecalcSecretKey<InnerKey>
{
    type Target = InnerKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> core::ops::DerefMut
    for PrecalcSecretKey<InnerKey>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precalculated_key_debug_redacts_contents_and_equality_is_value_based() {
        let key = PrecalcSecretKey(StackByteArray::from([0xabu8; CRYPTO_BOX_BEFORENMBYTES]));
        let same = key.clone();
        let different = PrecalcSecretKey(StackByteArray::from([0xcdu8; CRYPTO_BOX_BEFORENMBYTES]));

        assert_eq!(format!("{key:?}"), "PrecalcSecretKey(\"[REDACTED]\")");
        assert_eq!(key, same);
        assert_ne!(key, different);
    }
    use crate::constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES};

    /// NaCl `tests/box.c` / RFC 7748 section 6.1 keys: `beforenm(bobpk,
    /// alicesk)` is NaCl's secretbox `firstkey`.
    const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_SK: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_KEY: &str = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";

    fn array<const N: usize>(hex: &str) -> StackByteArray<N> {
        StackByteArray::try_from(hex::decode(hex).expect("hex").as_slice()).expect("length")
    }

    fn low_order_public_keys() -> [StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>; 2] {
        let mut identity = StackByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::default();
        identity[0] = 1;
        [StackByteArray::default(), identity]
    }

    #[test]
    fn precalculate_matches_nacl_shared_key_from_both_sides() {
        let alice_sk: StackByteArray<CRYPTO_BOX_SECRETKEYBYTES> = array(ALICE_SK);
        let alice_pk: StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES> = array(ALICE_PK);
        let bob_sk: StackByteArray<CRYPTO_BOX_SECRETKEYBYTES> = array(BOB_SK);
        let bob_pk: StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES> = array(BOB_PK);
        let expected: StackByteArray<CRYPTO_BOX_BEFORENMBYTES> = array(SHARED_KEY);

        let alice_side = PrecalcSecretKey::precalculate(&bob_pk, &alice_sk).expect("precalc");
        let bob_side = PrecalcSecretKey::precalculate(&alice_pk, &bob_sk).expect("precalc");
        assert_eq!(alice_side.as_array(), expected.as_array());
        assert_eq!(alice_side.as_slice(), expected.as_slice());
        assert_eq!(alice_side, bob_side);
        assert_eq!(alice_side.len(), CRYPTO_BOX_BEFORENMBYTES);

        // A different secret key must not reproduce the shared key.
        let stranger = PrecalcSecretKey::precalculate(&bob_pk, &bob_sk).expect("precalc");
        assert_ne!(stranger, alice_side);

        for low_order in low_order_public_keys() {
            assert!(PrecalcSecretKey::precalculate(&low_order, &alice_sk).is_err());
        }
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_precalculation_matches_stack_precalculation() {
        let alice_sk: StackByteArray<CRYPTO_BOX_SECRETKEYBYTES> = array(ALICE_SK);
        let bob_pk: StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES> = array(BOB_PK);
        let expected = hex::decode(SHARED_KEY).expect("hex");

        let mut locked =
            PrecalcSecretKey::precalculate_locked(&bob_pk, &alice_sk).expect("precalc locked");
        assert_eq!(locked.as_slice(), expected.as_slice());
        assert_eq!(locked.as_array(), &expected[..]);

        let readonly = PrecalcSecretKey::precalculate_readonly_locked(&bob_pk, &alice_sk)
            .expect("precalc readonly locked");
        assert_eq!(readonly.as_slice(), expected.as_slice());

        // The locked key is writable through both mutable accessors.
        locked.as_mut_slice()[0] ^= 0xff;
        locked.as_mut_array()[1] ^= 0xff;
        assert_eq!(locked.as_slice()[0], expected[0] ^ 0xff);
        assert_eq!(locked.as_slice()[1], expected[1] ^ 0xff);
        assert_eq!(&locked.as_slice()[2..], &expected[2..]);

        for low_order in low_order_public_keys() {
            assert!(PrecalcSecretKey::precalculate_locked(&low_order, &alice_sk).is_err());
            assert!(PrecalcSecretKey::precalculate_readonly_locked(&low_order, &alice_sk).is_err());
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn precalculate_matches_libsodium_beforenm() {
        use crate::utils::test_util::XorShift64;

        crate::native_test_util::init();

        let mut rng = XorShift64::new(0x7072_6563_616c_6321);
        for _ in 0..16 {
            let secret_key = StackByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::from(rng.next_bytes32());
            let other_secret_key =
                StackByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::from(rng.next_bytes32());
            let mut public_key = StackByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::default();
            crate::classic::crypto_core::crypto_scalarmult_base(
                public_key.as_mut_array(),
                other_secret_key.as_array(),
            );

            let precalc =
                PrecalcSecretKey::precalculate(&public_key, &secret_key).expect("precalc");

            let mut sodium_key = [0u8; CRYPTO_BOX_BEFORENMBYTES];
            let rc = unsafe {
                libsodium_sys::crypto_box_beforenm(
                    sodium_key.as_mut_ptr(),
                    public_key.as_ptr(),
                    secret_key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(precalc.as_array(), &sodium_key);
        }
    }
}
