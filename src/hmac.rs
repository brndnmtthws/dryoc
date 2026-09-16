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
//! use dryoc::hmac::{HmacSha256, HmacSha256Key};
//! use dryoc::types::*;
//!
//! let key = HmacSha256Key::generate();
//! let message = b"Uneasy lies the head that wears a crown.";
//!
//! let mac = HmacSha256::compute_to_vec(key.clone(), message);
//! HmacSha256::compute_and_verify(&mac, key, message).expect("verify failed");
//! ```
//!
//! The concrete authenticators are type aliases over [`Hmac`] and can also be
//! used through [`HmacVariant`] in generic code.
//!
//! # Incremental interface
//!
//! ```
//! use dryoc::hmac::{HmacSha512256, HmacSha512256Key};
//! use dryoc::types::*;
//!
//! let key = HmacSha512256Key::generate();
//! let mut auth = HmacSha512256::new(key.clone());
//! auth.update(b"Though she be but little, ");
//! auth.update(b"she is fierce.");
//! let mac = auth.finalize_to_vec();
//!
//! let mut verifier = HmacSha512256::new(key);
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
//!     key: StackByteArray<KEY_LENGTH>,
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
//! >(key.clone(), message);
//! let concrete_mac = HmacSha256::compute_to_vec(key, message);
//! assert_eq!(generic_mac, concrete_mac);
//! ```

use std::marker::PhantomData;

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

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
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
    //! let mac: Locked<HmacSha256Mac> = HmacSha256::compute(key, &input);
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
    ///
    /// This function takes ownership of `key`, but HMAC keys may authenticate
    /// multiple messages. Clone the key first when it is needed again.
    pub fn compute<
        Key: ByteArray<KEY_LENGTH>,
        Input: Bytes + ?Sized,
        Output: NewByteArray<MAC_LENGTH>,
    >(
        key: Key,
        input: &Input,
    ) -> Output {
        let mut output = Output::new_byte_array();
        Variant::compute(output.as_mut_array(), input.as_slice(), key.as_array());
        output
    }

    /// Convenience wrapper around [`Self::compute`] that returns a [`Vec`].
    pub fn compute_to_vec<Key: ByteArray<KEY_LENGTH>, Input: Bytes + ?Sized>(
        key: Key,
        input: &Input,
    ) -> Vec<u8> {
        Self::compute(key, input)
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
        key: Key,
        input: &Input,
    ) -> Result<(), Error> {
        Variant::verify(other_mac.as_array(), input.as_slice(), key.as_array())
    }

    /// Returns a new incremental authenticator for `key`.
    ///
    /// This function takes ownership of `key`, but HMAC keys may authenticate
    /// multiple messages. Clone the key first when it is needed again.
    pub fn new<Key: ByteArray<KEY_LENGTH>>(key: Key) -> Self {
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
    pub fn finalize<Output: NewByteArray<MAC_LENGTH>>(self) -> Output {
        let mut output = Output::new_byte_array();
        Variant::finalize(self.state, output.as_mut_array());
        output
    }

    /// Finalizes this authenticator, returning the message authentication code
    /// as a [`Vec`].
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test cases 1-4. libsodium's `crypto_auth_hmacsha*` take
    /// fixed 32-byte keys, so the shorter RFC keys are zero-padded, which HMAC
    /// defines to produce the same tag. HMAC-SHA-512-256 is the 32-byte
    /// truncation of HMAC-SHA-512.
    struct Case {
        key: &'static [u8],
        message: &'static [u8],
        sha256: &'static str,
        sha512: &'static str,
    }

    const CASES: [Case; 4] = [
        Case {
            key: &[0x0b; 20],
            message: b"Hi There",
            sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            sha512: concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
        },
        Case {
            key: b"Jefe",
            message: b"what do ya want for nothing?",
            sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            sha512: concat!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
        },
        Case {
            key: &[0xaa; 20],
            message: &[0xdd; 50],
            sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            sha512: concat!(
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
                "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            ),
        },
        Case {
            key: &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            ],
            message: &[0xcd; 50],
            sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            sha512: concat!(
                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db",
                "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            ),
        },
    ];

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
            H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_to_vec(key.clone(), message),
            expected
        );
        let fixed: StackByteArray<MAC_LENGTH> =
            H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute(key.clone(), message);
        assert_eq!(fixed.as_slice(), expected);
        H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_and_verify(&fixed, key.clone(), message)
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
            let mut auth = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(key.clone());
            for part in &parts {
                auth.update(*part);
            }
            assert_eq!(auth.finalize_to_vec(), expected);

            let mut verifier = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(key.clone());
            for part in &parts {
                verifier.update(*part);
            }
            verifier.verify(&fixed).expect("incremental verify failed");
        }

        for index in [0, MAC_LENGTH / 2, MAC_LENGTH - 1] {
            let mut flipped = fixed.clone();
            flipped[index] ^= 1;
            assert!(matches!(
                H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_and_verify(
                    &flipped,
                    key.clone(),
                    message
                ),
                Err(Error::AuthenticationFailed)
            ));
            let mut verifier = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(key.clone());
            verifier.update(message);
            assert!(matches!(
                verifier.verify(&flipped),
                Err(Error::AuthenticationFailed)
            ));
        }

        let mut wrong_key = key.clone();
        wrong_key[KEY_LENGTH - 1] ^= 1;
        assert!(matches!(
            H::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_and_verify(&fixed, wrong_key, message),
            Err(Error::AuthenticationFailed)
        ));
        let mut verifier = H::<Variant, KEY_LENGTH, MAC_LENGTH>::new(key);
        verifier.update(&message[..message.len() - 1]);
        assert!(matches!(
            verifier.verify(&fixed),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn rfc4231_vectors_through_all_three_variants() {
        for case in &CASES {
            let sha256 = hex::decode(case.sha256).expect("hex");
            let sha512 = hex::decode(case.sha512).expect("hex");
            assert_variant::<
                HmacSha256Variant,
                CRYPTO_AUTH_HMACSHA256_KEYBYTES,
                CRYPTO_AUTH_HMACSHA256_BYTES,
            >(padded_key(case.key), case.message, &sha256);
            assert_variant::<
                HmacSha512Variant,
                CRYPTO_AUTH_HMACSHA512_KEYBYTES,
                CRYPTO_AUTH_HMACSHA512_BYTES,
            >(padded_key(case.key), case.message, &sha512);
            assert_variant::<
                HmacSha512256Variant,
                CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
                CRYPTO_AUTH_HMACSHA512256_BYTES,
            >(
                padded_key(case.key),
                case.message,
                &sha512[..CRYPTO_AUTH_HMACSHA512256_BYTES],
            );
        }
    }

    #[test]
    fn rustaceous_and_classic_macs_verify_each_other() {
        for case in &CASES {
            let key256: HmacSha256Key = padded_key(case.key);
            let mac = HmacSha256::compute_to_vec(key256.clone(), case.message);
            crypto_auth_hmacsha256_verify(mac.as_array(), case.message, key256.as_array())
                .expect("classic verify");
            let mut classic = [0u8; CRYPTO_AUTH_HMACSHA256_BYTES];
            crypto_auth_hmacsha256(&mut classic, case.message, key256.as_array());
            HmacSha256::compute_and_verify(&classic, key256.clone(), case.message)
                .expect("rustaceous verify");
            let mut verifier = HmacSha256::new(key256);
            verifier.update(case.message);
            verifier.verify(&classic).expect("incremental verify");

            let key512: HmacSha512Key = padded_key(case.key);
            let mac = HmacSha512::compute_to_vec(key512.clone(), case.message);
            crypto_auth_hmacsha512_verify(mac.as_array(), case.message, key512.as_array())
                .expect("classic verify");
            let mut classic = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
            crypto_auth_hmacsha512(&mut classic, case.message, key512.as_array());
            HmacSha512::compute_and_verify(&classic, key512.clone(), case.message)
                .expect("rustaceous verify");
            let mut verifier = HmacSha512::new(key512);
            verifier.update(case.message);
            verifier.verify(&classic).expect("incremental verify");

            let key512256: HmacSha512256Key = padded_key(case.key);
            let mac = HmacSha512256::compute_to_vec(key512256.clone(), case.message);
            crypto_auth_hmacsha512256_verify(mac.as_array(), case.message, key512256.as_array())
                .expect("classic verify");
            let mut classic = [0u8; CRYPTO_AUTH_HMACSHA512256_BYTES];
            crypto_auth_hmacsha512256(&mut classic, case.message, key512256.as_array());
            HmacSha512256::compute_and_verify(&classic, key512256.clone(), case.message)
                .expect("rustaceous verify");
            let mut verifier = HmacSha512256::new(key512256);
            verifier.update(case.message);
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
            Hmac::<Variant, KEY_LENGTH, MAC_LENGTH>::compute_to_vec(key, input)
        }

        let case = &CASES[0];
        let sha256 = hex::decode(case.sha256).expect("hex");
        let sha512 = hex::decode(case.sha512).expect("hex");
        assert_eq!(
            compute_with_variant::<
                HmacSha256Variant,
                CRYPTO_AUTH_HMACSHA256_KEYBYTES,
                CRYPTO_AUTH_HMACSHA256_BYTES,
            >(padded_key(case.key), case.message),
            sha256
        );
        assert_eq!(
            compute_with_variant::<
                HmacSha512Variant,
                CRYPTO_AUTH_HMACSHA512_KEYBYTES,
                CRYPTO_AUTH_HMACSHA512_BYTES,
            >(padded_key(case.key), case.message),
            sha512
        );
        let truncated = compute_with_variant::<
            HmacSha512256Variant,
            CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
            CRYPTO_AUTH_HMACSHA512256_BYTES,
        >(padded_key(case.key), case.message);
        assert_eq!(truncated, &sha512[..CRYPTO_AUTH_HMACSHA512256_BYTES]);
        // Same key length and MAC length, different hash: the aliases must not
        // collapse onto one another.
        assert_ne!(truncated, sha256);
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn rfc4231_keys_match_sodiumoxide() {
        use sodiumoxide::crypto::auth::{hmacsha256, hmacsha512, hmacsha512256};

        for case in &CASES {
            let key: HmacSha256Key = padded_key(case.key);
            let so_tag = hmacsha256::authenticate(
                case.message,
                &hmacsha256::Key::from_slice(key.as_slice()).unwrap(),
            );
            assert_eq!(
                HmacSha256::compute_to_vec(key, case.message),
                so_tag.as_ref()
            );

            let key: HmacSha512Key = padded_key(case.key);
            let so_tag = hmacsha512::authenticate(
                case.message,
                &hmacsha512::Key::from_slice(key.as_slice()).unwrap(),
            );
            assert_eq!(
                HmacSha512::compute_to_vec(key, case.message),
                so_tag.as_ref()
            );

            let key: HmacSha512256Key = padded_key(case.key);
            let so_tag = hmacsha512256::authenticate(
                case.message,
                &hmacsha512256::Key::from_slice(key.as_slice()).unwrap(),
            );
            assert_eq!(
                HmacSha512256::compute_to_vec(key, case.message),
                so_tag.as_ref()
            );
        }
    }
}
