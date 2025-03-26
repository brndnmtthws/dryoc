//! Precalculated secret key for use with `precalc_*` functions in
//! [`crate::dryocbox::DryocBox`]
//!
//! You may want to use `precalc_*` functions if you need to
//! encrypt/decrypt multiple messages between the same sender and receiver.
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES,
};
use crate::types::{ByteArray, Bytes, StackByteArray};

type InnerKey = StackByteArray<CRYPTO_BOX_BEFORENMBYTES>;

/// Precalculated secret key for use with `precalc_*` functions in
/// [`crate::dryocbox::DryocBox`].
///
/// You probably want to use `precalc_*` functions if you need to
/// encrypt/decrypt multiple messages between the same sender and receiver.
/// These functions save computation time by using [`PrecalcSecretKey`]
/// instead of computing the shared secret every time.
///
/// Using precalculated secret keys is compatible with libsodium's
/// `crypto_box_beforenm`.
#[derive(Zeroize, ZeroizeOnDrop, Debug, PartialEq, Eq, Clone)]
pub struct PrecalcSecretKey<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize>(InnerKey);

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
        &self.0.as_array()
    }
}

impl PrecalcSecretKey<InnerKey> {
    /// Computes a stack-allocated shared secret key for the given
    /// `third_party_public_key` and `secret_key`.
    ///
    /// Compatible with libsodium's `crypto_box_beforenm`.
    #[inline]
    pub fn precalculate<
        ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        third_party_public_key: &ThirdPartyPublicKey,
        secret_key: &SecretKey,
    ) -> Self {
        use crate::classic::crypto_box::crypto_box_beforenm;

        Self(crypto_box_beforenm(third_party_public_key.as_array(), secret_key.as_array()).into())
    }
}

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory for [`PrecalcSecretKey`]
    use super::*;
    pub use crate::protected::*;

    type InnerKey = HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;

    impl PrecalcSecretKey<Locked<InnerKey>> {
        /// Computes a heap-allocated, page-aligned, locked shared secret key
        /// for the given `third_party_public_key` and `secret_key`.
        ///
        /// Compatible with libsodium's `crypto_box_beforenm`.
        pub fn precalculate_locked<
            ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >(
            third_party_public_key: &ThirdPartyPublicKey,
            secret_key: &SecretKey,
        ) -> Result<Self, std::io::Error> {
            use crate::classic::crypto_box::crypto_box_beforenm;

            let mut precalc = HeapByteArray::<CRYPTO_BOX_BEFORENMBYTES>::new_locked()?;
            let mut key =
                crypto_box_beforenm(third_party_public_key.as_array(), secret_key.as_array());

            precalc.copy_from_slice(&key);
            key.zeroize();

            Ok(PrecalcSecretKey(precalc))
        }
    }

    impl PrecalcSecretKey<LockedRO<InnerKey>> {
        /// Computes a heap-allocated, page-aligned, locked, read-only shared
        /// secret key for the given `third_party_public_key` and
        /// `secret_key`.
        ///
        /// Compatible with libsodium's `crypto_box_beforenm`.
        pub fn precalculate_readonly_locked<
            ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
            SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        >(
            third_party_public_key: &ThirdPartyPublicKey,
            secret_key: &SecretKey,
        ) -> Result<Self, std::io::Error> {
            use crate::classic::crypto_box::crypto_box_beforenm;

            let mut precalc = HeapByteArray::<CRYPTO_BOX_BEFORENMBYTES>::new_locked()?;
            let mut key =
                crypto_box_beforenm(third_party_public_key.as_array(), secret_key.as_array());

            precalc.copy_from_slice(&key);
            key.zeroize();

            Ok(PrecalcSecretKey(precalc.mprotect_readonly()?))
        }
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> std::ops::Deref
    for PrecalcSecretKey<InnerKey>
{
    type Target = InnerKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<InnerKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize> std::ops::DerefMut
    for PrecalcSecretKey<InnerKey>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES};

    #[test]
    fn test_precalculate() {
        let public_key = StackByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::default();
        let secret_key = StackByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::default();
        let precalc_key = PrecalcSecretKey::precalculate(&public_key, &secret_key);
        assert_eq!(precalc_key.0.len(), CRYPTO_BOX_BEFORENMBYTES);
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_precalculate_locked() {
        let public_key = StackByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::default();
        let secret_key = StackByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::default();
        let precalc_key = PrecalcSecretKey::precalculate_locked(&public_key, &secret_key).unwrap();
        assert_eq!(precalc_key.0.len(), CRYPTO_BOX_BEFORENMBYTES);
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_precalculate_readonly_locked() {
        let public_key = StackByteArray::<CRYPTO_BOX_PUBLICKEYBYTES>::default();
        let secret_key = StackByteArray::<CRYPTO_BOX_SECRETKEYBYTES>::default();
        let precalc_key =
            PrecalcSecretKey::precalculate_readonly_locked(&public_key, &secret_key).unwrap();
        assert_eq!(precalc_key.0.len(), CRYPTO_BOX_BEFORENMBYTES);
    }
}
