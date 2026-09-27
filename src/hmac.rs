//! # HMAC authentication
//!
//! [`HmacSha256`], [`HmacSha512`], and [`HmacSha512256`] provide Rustaceous
//! wrappers for libsodium's direct HMAC authentication variants.
//!
//! HMAC computes a fixed-size authentication tag for a message using a shared
//! secret key. Anyone with the same key can recompute the tag and verify that
//! the message was produced by someone who knew the key and that the message
//! was not changed. HMAC does not encrypt the message.
//!
//! Use these types when:
//!
//! * you need one of libsodium's direct `crypto_auth_hmacsha*` variants
//! * two parties already share the same secret key
//! * the message can be public, but tampering must be detected
//!
//! [`HmacSha512256`] matches libsodium's default [`crypto_auth`](crate::auth)
//! construction. [`HmacSha256`] and [`HmacSha512`] are available for protocol
//! compatibility when those exact algorithms are required.
//!
//! # Rustaceous API example
//!
//! ```
//! use dryoc::hmac::{HmacSha256, HmacSha256Key, HmacSha256Mac};
//! use dryoc::types::*;
//!
//! let key = HmacSha256Key::generate();
//! let message = b"Uneasy lies the head that wears a crown.";
//!
//! let mac: HmacSha256Mac = HmacSha256::compute(&key, message);
//! HmacSha256::compute_and_verify(&mac, &key, message).expect("verify failed");
//! ```
//!
//! The concrete authenticators are type aliases over [`Hmac`] and can also be
//! used through [`HmacVariant`] in generic code.
//!
//! # Incremental interface
//!
//! ```
//! use dryoc::hmac::{HmacSha512256, HmacSha512256Key, HmacSha512256Mac};
//! use dryoc::types::*;
//!
//! let key = HmacSha512256Key::generate();
//! let mut auth = HmacSha512256::new(&key);
//! auth.update(b"Though she be but little, ");
//! auth.update(b"she is fierce.");
//! let mac: HmacSha512256Mac = auth.finalize();
//!
//! let mut verifier = HmacSha512256::new(&key);
//! verifier.update(b"Though she be but little, ");
//! verifier.update(b"she is fierce.");
//! verifier.verify(&mac).expect("verify failed");
//! ```
//!
//! # Generic HMAC variants
//!
//! ```
//! use dryoc::constants::{CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA256_KEYBYTES};
//! use dryoc::hmac::{Hmac, HmacSha256, HmacSha256Key, HmacSha256Variant, HmacVariant};
//! use dryoc::types::*;
//!
//! fn authenticate<Variant, const KEY_LENGTH: usize, const MAC_LENGTH: usize>(
//!     key: &StackByteArray<KEY_LENGTH>,
//!     input: &[u8],
//! ) -> Vec<u8>
//! where
//!     Variant: HmacVariant<KEY_LENGTH, MAC_LENGTH>,
//! {
//!     Hmac::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_to_vec(key, input)
//! }
//!
//! let key = HmacSha256Key::generate();
//! let message = b"The quality of mercy is not strained.";
//! let generic_mac = authenticate::<
//!     HmacSha256Variant,
//!     CRYPTO_AUTH_HMACSHA256_KEYBYTES,
//!     CRYPTO_AUTH_HMACSHA256_BYTES,
//! >(&key, message);
//! let concrete_mac = HmacSha256::compute_to_vec(&key, message);
//! assert_eq!(generic_mac, concrete_mac);
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::marker::PhantomData;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::classic::crypto_auth_hmacsha256::{
    HmacSha256State, crypto_auth_hmacsha256, crypto_auth_hmacsha256_final,
    crypto_auth_hmacsha256_init, crypto_auth_hmacsha256_update, crypto_auth_hmacsha256_verify,
};
use crate::classic::crypto_auth_hmacsha512::{
    HmacSha512State, crypto_auth_hmacsha512, crypto_auth_hmacsha512_final,
    crypto_auth_hmacsha512_init, crypto_auth_hmacsha512_update, crypto_auth_hmacsha512_verify,
};
use crate::classic::crypto_auth_hmacsha512256::{
    HmacSha512256State, crypto_auth_hmacsha512256, crypto_auth_hmacsha512256_final,
    crypto_auth_hmacsha512256_init, crypto_auth_hmacsha512256_update,
    crypto_auth_hmacsha512256_verify,
};
use crate::constants::{
    CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA256_KEYBYTES, CRYPTO_AUTH_HMACSHA512_BYTES,
    CRYPTO_AUTH_HMACSHA512_KEYBYTES, CRYPTO_AUTH_HMACSHA512256_BYTES,
    CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key for HMAC-SHA-256.
pub type HmacSha256Key = StackByteArray<CRYPTO_AUTH_HMACSHA256_KEYBYTES>;
/// Stack-allocated message authentication code for HMAC-SHA-256.
pub type HmacSha256Mac = StackByteArray<CRYPTO_AUTH_HMACSHA256_BYTES>;
/// Stack-allocated key for HMAC-SHA-512.
pub type HmacSha512Key = StackByteArray<CRYPTO_AUTH_HMACSHA512_KEYBYTES>;
/// Stack-allocated message authentication code for HMAC-SHA-512.
pub type HmacSha512Mac = StackByteArray<CRYPTO_AUTH_HMACSHA512_BYTES>;
/// Stack-allocated key for HMAC-SHA-512-256.
pub type HmacSha512256Key = StackByteArray<CRYPTO_AUTH_HMACSHA512256_KEYBYTES>;
/// Stack-allocated message authentication code for HMAC-SHA-512-256.
pub type HmacSha512256Mac = StackByteArray<CRYPTO_AUTH_HMACSHA512256_BYTES>;

#[cfg(any(
    all(feature = "protected", any(unix, windows)),
    all(doc, not(doctest), feature = "std")
))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for HMAC
    //!
    //! This mod provides protected-memory aliases for HMAC keys and MACs. Use
    //! these aliases when key material or authentication tags should live in
    //! locked memory.
    //!
    //! ```
    //! use dryoc::hmac::HmacSha256;
    //! use dryoc::hmac::protected::*;
    //!
    //! let key = HmacSha256Key::generate_readonly_locked().expect("key failed");
    //! let input = HeapBytes::from_slice_into_readonly_locked(b"More matter, with less art.")
    //!     .expect("input failed");
    //! let mac: Locked<HmacSha256Mac> = HmacSha256::compute(&key, &input);
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned key for HMAC-SHA-256.
    pub type HmacSha256Key = HeapByteArray<CRYPTO_AUTH_HMACSHA256_KEYBYTES>;
    /// Heap-allocated, page-aligned MAC for HMAC-SHA-256.
    pub type HmacSha256Mac = HeapByteArray<CRYPTO_AUTH_HMACSHA256_BYTES>;
    /// Heap-allocated, page-aligned key for HMAC-SHA-512.
    pub type HmacSha512Key = HeapByteArray<CRYPTO_AUTH_HMACSHA512_KEYBYTES>;
    /// Heap-allocated, page-aligned MAC for HMAC-SHA-512.
    pub type HmacSha512Mac = HeapByteArray<CRYPTO_AUTH_HMACSHA512_BYTES>;
    /// Heap-allocated, page-aligned key for HMAC-SHA-512-256.
    pub type HmacSha512256Key = HeapByteArray<CRYPTO_AUTH_HMACSHA512256_KEYBYTES>;
    /// Heap-allocated, page-aligned MAC for HMAC-SHA-512-256.
    pub type HmacSha512256Mac = HeapByteArray<CRYPTO_AUTH_HMACSHA512256_BYTES>;
}

/// HMAC algorithm variant used by [`Hmac`].
pub trait HmacVariant<const KEY_LENGTH: usize, const MAC_LENGTH: usize> {
    /// Incremental state for this HMAC variant.
    type State;
    /// Default stack-allocated MAC type used by verification.
    type Mac: NewByteArray<MAC_LENGTH> + Zeroize;

    /// Computes a MAC in one shot.
    fn compute(mac: &mut [u8; MAC_LENGTH], input: &[u8], key: &[u8; KEY_LENGTH]);
    /// Verifies a MAC in one shot.
    ///
    /// # Errors
    ///
    /// Returns an error if `mac` does not authenticate `input` under `key`.
    fn verify(mac: &[u8; MAC_LENGTH], input: &[u8], key: &[u8; KEY_LENGTH]) -> Result<(), Error>;
    /// Initializes incremental authentication.
    fn init(key: &[u8; KEY_LENGTH]) -> Self::State;
    /// Updates incremental authentication.
    fn update(state: &mut Self::State, input: &[u8]);
    /// Finalizes incremental authentication.
    fn finalize(state: Self::State, mac: &mut [u8; MAC_LENGTH]);
}

/// Rustaceous HMAC authenticator for a specific [`HmacVariant`].
pub struct Hmac<Variant, const KEY_LENGTH: usize, const MAC_LENGTH: usize>
where
    Variant: HmacVariant<KEY_LENGTH, MAC_LENGTH>,
{
    state: Variant::State,
    _variant: PhantomData<Variant>,
}

/// HMAC-SHA-256 algorithm marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacSha256Variant;
/// HMAC-SHA-512 algorithm marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacSha512Variant;
/// HMAC-SHA-512-256 algorithm marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacSha512256Variant;

/// Rustaceous HMAC-SHA-256 authenticator.
pub type HmacSha256 =
    Hmac<HmacSha256Variant, CRYPTO_AUTH_HMACSHA256_KEYBYTES, CRYPTO_AUTH_HMACSHA256_BYTES>;
/// Rustaceous HMAC-SHA-512 authenticator.
pub type HmacSha512 =
    Hmac<HmacSha512Variant, CRYPTO_AUTH_HMACSHA512_KEYBYTES, CRYPTO_AUTH_HMACSHA512_BYTES>;
/// Rustaceous HMAC-SHA-512-256 authenticator.
pub type HmacSha512256 =
    Hmac<HmacSha512256Variant, CRYPTO_AUTH_HMACSHA512256_KEYBYTES, CRYPTO_AUTH_HMACSHA512256_BYTES>;

macro_rules! impl_hmac_variant {
    (
        $variant:ty,
        $key_len:expr,
        $mac_len:expr,
        $state:ty,
        $mac:ty,
        $compute:path,
        $verify:path,
        $init:path,
        $update:path,
        $finalize:path
    ) => {
        impl HmacVariant<$key_len, $mac_len> for $variant {
            type Mac = $mac;
            type State = $state;

            fn compute(mac: &mut [u8; $mac_len], input: &[u8], key: &[u8; $key_len]) {
                $compute(mac, input, key);
            }

            fn verify(
                mac: &[u8; $mac_len],
                input: &[u8],
                key: &[u8; $key_len],
            ) -> Result<(), Error> {
                $verify(mac, input, key)
            }

            fn init(key: &[u8; $key_len]) -> Self::State {
                $init(key)
            }

            fn update(state: &mut Self::State, input: &[u8]) {
                $update(state, input);
            }

            fn finalize(state: Self::State, mac: &mut [u8; $mac_len]) {
                $finalize(state, mac);
            }
        }
    };
}

impl_hmac_variant!(
    HmacSha256Variant,
    CRYPTO_AUTH_HMACSHA256_KEYBYTES,
    CRYPTO_AUTH_HMACSHA256_BYTES,
    HmacSha256State,
    HmacSha256Mac,
    crypto_auth_hmacsha256,
    crypto_auth_hmacsha256_verify,
    crypto_auth_hmacsha256_init,
    crypto_auth_hmacsha256_update,
    crypto_auth_hmacsha256_final
);

impl_hmac_variant!(
    HmacSha512Variant,
    CRYPTO_AUTH_HMACSHA512_KEYBYTES,
    CRYPTO_AUTH_HMACSHA512_BYTES,
    HmacSha512State,
    HmacSha512Mac,
    crypto_auth_hmacsha512,
    crypto_auth_hmacsha512_verify,
    crypto_auth_hmacsha512_init,
    crypto_auth_hmacsha512_update,
    crypto_auth_hmacsha512_final
);

impl_hmac_variant!(
    HmacSha512256Variant,
    CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
    CRYPTO_AUTH_HMACSHA512256_BYTES,
    HmacSha512256State,
    HmacSha512256Mac,
    crypto_auth_hmacsha512256,
    crypto_auth_hmacsha512256_verify,
    crypto_auth_hmacsha512256_init,
    crypto_auth_hmacsha512256_update,
    crypto_auth_hmacsha512256_final
);

impl<Variant, const KEY_LENGTH: usize, const MAC_LENGTH: usize>
    Hmac<Variant, KEY_LENGTH, MAC_LENGTH>
where
    Variant: HmacVariant<KEY_LENGTH, MAC_LENGTH>,
{
    /// Computes and returns the message authentication code for `input` using
    /// `key`.
    #[must_use]
    pub fn compute<
        Key: ByteArray<KEY_LENGTH>,
        Input: Bytes + ?Sized,
        Output: NewByteArray<MAC_LENGTH>,
    >(
        key: &Key,
        input: &Input,
    ) -> Output {
        let mut output = Output::new_byte_array();
        Variant::compute(output.as_mut_array(), input.as_slice(), key.as_array());
        output
    }

    /// Convenience wrapper around [`Self::compute`] that returns a [`Vec`].
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn compute_to_vec<Key: ByteArray<KEY_LENGTH>, Input: Bytes + ?Sized>(
        key: &Key,
        input: &Input,
    ) -> Vec<u8> {
        Self::compute::<_, _, StackByteArray<MAC_LENGTH>>(key, input).to_vec()
    }

    /// Verifies `other_mac` against `input` using `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if `other_mac` does not authenticate `input` under
    /// `key`.
    pub fn compute_and_verify<
        OtherMac: ByteArray<MAC_LENGTH>,
        Key: ByteArray<KEY_LENGTH>,
        Input: Bytes + ?Sized,
    >(
        other_mac: &OtherMac,
        key: &Key,
        input: &Input,
    ) -> Result<(), Error> {
        Variant::verify(other_mac.as_array(), input.as_slice(), key.as_array())
    }

    /// Returns a new incremental authenticator for `key`.
    #[must_use]
    pub fn new<Key: ByteArray<KEY_LENGTH>>(key: &Key) -> Self {
        Self {
            state: Variant::init(key.as_array()),
            _variant: PhantomData,
        }
    }

    /// Updates the authenticator with `input`.
    pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
        Variant::update(&mut self.state, input.as_slice())
    }

    /// Finalizes this authenticator, returning the message authentication code.
    #[must_use]
    pub fn finalize<Output: NewByteArray<MAC_LENGTH>>(self) -> Output {
        let mut output = Output::new_byte_array();
        Variant::finalize(self.state, output.as_mut_array());
        output
    }

    /// Finalizes this authenticator, returning the message authentication code
    /// as a [`Vec`].
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize::<StackByteArray<MAC_LENGTH>>().to_vec()
    }

    /// Finalizes this authenticator and verifies that the computed code matches
    /// `other_mac` using a constant-time comparison.
    ///
    /// # Errors
    ///
    /// Returns an error if `other_mac` does not match the authentication code
    /// computed from the data passed to [`Hmac::update`].
    pub fn verify<OtherMac: ByteArray<MAC_LENGTH>>(
        self,
        other_mac: &OtherMac,
    ) -> Result<(), Error> {
        let mut computed_mac = Variant::Mac::new_byte_array();
        Variant::finalize(self.state, computed_mac.as_mut_array());
        let valid = other_mac
            .as_array()
            .ct_eq(computed_mac.as_array())
            .unwrap_u8();
        computed_mac.as_mut_slice().zeroize();

        if valid == 1 {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    // RFC 4231 test cases 1-4. libsodium's `crypto_auth_hmacsha*` take
    // fixed 32-byte keys, so the shorter RFC keys are zero-padded, which HMAC
    // defines to produce the same tag. HMAC-SHA-512-256 is the 32-byte
    // truncation of HMAC-SHA-512.
    use crate::classic::crypto_auth_hmac_impl::test_util::RFC4231_PADDABLE_KEYS as CASES;

    fn padded_key<const KEY_LENGTH: usize>(key: &[u8]) -> StackByteArray<KEY_LENGTH> {
        let mut padded = StackByteArray::<KEY_LENGTH>::default();
        padded[..key.len()].copy_from_slice(key);
        padded
    }

    /// Exercises every entry point of one variant against `expected`.
    fn assert_variant<Variant, const KEY_LENGTH: usize, const MAC_LENGTH: usize>(
        key: StackByteArray<KEY_LENGTH>,
        message: &[u8],
        expected: &[u8],
    ) where
        Variant: HmacVariant<KEY_LENGTH, MAC_LENGTH>,
    {
        type H<V, const K: usize, const M: usize> = Hmac<V, K, M>;

        assert_eq!(
            H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_to_vec(&key, message),
            expected
        );
        let fixed: StackByteArray<MAC_LENGTH> =
            H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute(&key, message);
        assert_eq!(fixed.as_slice(), expected);
        H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_and_verify(&fixed, &key, message)
            .expect("one-shot verify failed");

        let split = message.len() / 3;
        for parts in [
            vec![message],
            vec![&message[..split], &message[split..]],
            vec![
                &[][..],
                &message[..1],
                &message[1..split],
                &message[split..],
                &[][..],
            ],
        ] {
            let mut auth = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(&key);
            for part in &parts {
                auth.update(*part);
            }
            assert_eq!(auth.finalize_to_vec(), expected);

            let mut verifier = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(&key);
            for part in &parts {
                verifier.update(*part);
            }
            verifier.verify(&fixed).expect("incremental verify failed");
        }

        for index in [0, MAC_LENGTH / 2, MAC_LENGTH - 1] {
            let mut flipped = fixed.clone();
            flipped[index] ^= 1;
            assert!(matches!(
                H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_and_verify(&flipped, &key, message),
                Err(Error::AuthenticationFailed)
            ));
            let mut verifier = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(&key);
            verifier.update(message);
            assert!(matches!(
                verifier.verify(&flipped),
                Err(Error::AuthenticationFailed)
            ));
        }

        let mut wrong_key = key.clone();
        wrong_key[KEY_LENGTH - 1] ^= 1;
        assert!(matches!(
            H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_and_verify(&fixed, &wrong_key, message),
            Err(Error::AuthenticationFailed)
        ));
        let mut verifier = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(&key);
        verifier.update(&message[..message.len() - 1]);
        assert!(matches!(
            verifier.verify(&fixed),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn rfc4231_vectors_through_all_three_variants() {
        for case in CASES {
            let sha256 = case.sha256();
            let sha512 = case.sha512();
            assert_variant::<
                HmacSha256Variant,
                CRYPTO_AUTH_HMACSHA256_KEYBYTES,
                CRYPTO_AUTH_HMACSHA256_BYTES,
            >(padded_key(case.key), case.data, &sha256);
            assert_variant::<
                HmacSha512Variant,
                CRYPTO_AUTH_HMACSHA512_KEYBYTES,
                CRYPTO_AUTH_HMACSHA512_BYTES,
            >(padded_key(case.key), case.data, &sha512);
            assert_variant::<
                HmacSha512256Variant,
                CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
                CRYPTO_AUTH_HMACSHA512256_BYTES,
            >(
                padded_key(case.key),
                case.data,
                &sha512[..CRYPTO_AUTH_HMACSHA512256_BYTES],
            );
        }
    }

    #[test]
    fn rustaceous_and_classic_macs_verify_each_other() {
        for case in CASES {
            let key256: HmacSha256Key = padded_key(case.key);
            let mac = HmacSha256::compute_to_vec(&key256, case.data);
            crypto_auth_hmacsha256_verify(
                mac.as_slice().try_into().expect("MAC length"),
                case.data,
                key256.as_array(),
            )
            .expect("classic verify");
            let mut classic = [0u8; CRYPTO_AUTH_HMACSHA256_BYTES];
            crypto_auth_hmacsha256(&mut classic, case.data, key256.as_array());
            HmacSha256::compute_and_verify(&classic, &key256, case.data)
                .expect("rustaceous verify");
            let mut verifier = HmacSha256::new(&key256);
            verifier.update(case.data);
            verifier.verify(&classic).expect("incremental verify");

            let key512: HmacSha512Key = padded_key(case.key);
            let mac = HmacSha512::compute_to_vec(&key512, case.data);
            crypto_auth_hmacsha512_verify(
                mac.as_slice().try_into().expect("MAC length"),
                case.data,
                key512.as_array(),
            )
            .expect("classic verify");
            let mut classic = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
            crypto_auth_hmacsha512(&mut classic, case.data, key512.as_array());
            HmacSha512::compute_and_verify(&classic, &key512, case.data)
                .expect("rustaceous verify");
            let mut verifier = HmacSha512::new(&key512);
            verifier.update(case.data);
            verifier.verify(&classic).expect("incremental verify");

            let key512256: HmacSha512256Key = padded_key(case.key);
            let mac = HmacSha512256::compute_to_vec(&key512256, case.data);
            crypto_auth_hmacsha512256_verify(
                mac.as_slice().try_into().expect("MAC length"),
                case.data,
                key512256.as_array(),
            )
            .expect("classic verify");
            let mut classic = [0u8; CRYPTO_AUTH_HMACSHA512256_BYTES];
            crypto_auth_hmacsha512256(&mut classic, case.data, key512256.as_array());
            HmacSha512256::compute_and_verify(&classic, &key512256, case.data)
                .expect("rustaceous verify");
            let mut verifier = HmacSha512256::new(&key512256);
            verifier.update(case.data);
            verifier.verify(&classic).expect("incremental verify");
        }
    }

    #[test]
    fn variants_are_distinct_and_the_generic_api_matches_the_aliases() {
        fn compute_with_variant<Variant, const KEY_LENGTH: usize, const MAC_LENGTH: usize>(
            key: StackByteArray<KEY_LENGTH>,
            input: &[u8],
        ) -> Vec<u8>
        where
            Variant: HmacVariant<KEY_LENGTH, MAC_LENGTH>,
        {
            Hmac::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_to_vec(&key, input)
        }

        let case = CASES[0];
        let sha256 = case.sha256();
        let sha512 = case.sha512();
        assert_eq!(
            compute_with_variant::<
                HmacSha256Variant,
                CRYPTO_AUTH_HMACSHA256_KEYBYTES,
                CRYPTO_AUTH_HMACSHA256_BYTES,
            >(padded_key(case.key), case.data),
            sha256
        );
        assert_eq!(
            compute_with_variant::<
                HmacSha512Variant,
                CRYPTO_AUTH_HMACSHA512_KEYBYTES,
                CRYPTO_AUTH_HMACSHA512_BYTES,
            >(padded_key(case.key), case.data),
            sha512
        );
        let truncated = compute_with_variant::<
            HmacSha512256Variant,
            CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
            CRYPTO_AUTH_HMACSHA512256_BYTES,
        >(padded_key(case.key), case.data);
        assert_eq!(truncated, &sha512[..CRYPTO_AUTH_HMACSHA512256_BYTES]);
        // Same key length and MAC length, different hash: the aliases must not
        // collapse onto one another.
        assert_ne!(truncated, sha256);
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn rfc4231_keys_match_libsodium() {
        use crate::native_test_util::{auth_hmacsha256, auth_hmacsha512, auth_hmacsha512256};

        for case in CASES {
            let key: HmacSha256Key = padded_key(case.key);
            let so_tag = auth_hmacsha256(case.data, key.as_slice());
            assert_eq!(HmacSha256::compute_to_vec(&key, case.data), so_tag);

            let key: HmacSha512Key = padded_key(case.key);
            let so_tag = auth_hmacsha512(case.data, key.as_slice());
            assert_eq!(HmacSha512::compute_to_vec(&key, case.data), so_tag);

            let key: HmacSha512256Key = padded_key(case.key);
            let so_tag = auth_hmacsha512256(case.data, key.as_slice());
            assert_eq!(HmacSha512256::compute_to_vec(&key, case.data), so_tag);
        }
    }
}
