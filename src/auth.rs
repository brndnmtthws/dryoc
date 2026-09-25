//! # Secret-key message authentication
//!
//! [`Auth`] implements libsodium's secret-key authentication, based on
//! HMAC-SHA512-256.
//!
//! Use [`Auth`] to authenticate messages when:
//!
//! * you want to authenticate arbitrary messages
//! * you have a pre-shared key between both parties
//! * (optionally) you want to share the authentication tag publicly
//!
//! The same HMAC key can authenticate multiple messages. Keep the key secret,
//! and use separate keys when protocols require domain separation.
//!
//! # Rustaceous API example, single-part interface
//!
//! ```
//! use dryoc::auth::*;
//! use dryoc::types::*;
//!
//! // Generate a random key
//! let key = Key::generate();
//!
//! // Compute the MAC in one shot. This API takes ownership of the key, so clone
//! // it when the same key is also needed for verification.
//! let mac: Mac = Auth::compute(key.clone(), b"Data to authenticate");
//!
//! // Verify the MAC
//! Auth::compute_and_verify(&mac, key, b"Data to authenticate").expect("verify failed");
//! ```
//!
//! # Rustaceous API example, incremental interface
//!
//! ```
//! use dryoc::auth::*;
//! use dryoc::types::*;
//!
//! // Generate a random key
//! let key = Key::generate();
//!
//! // Initialize the MAC
//! let mut mac = Auth::new(key.clone());
//! mac.update(b"Multi-part");
//! mac.update(b"data");
//! let mac: Mac = mac.finalize();
//!
//! // Verify the MAC
//! let mut verify_mac = Auth::new(key.clone());
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"data");
//! verify_mac.verify(&mac).expect("verify failed");
//!
//! // Check that invalid data fails
//! let mut verify_mac = Auth::new(key);
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"bad data");
//! verify_mac
//!     .verify(&mac)
//!     .expect_err("verify should have failed");
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::classic::crypto_auth::{
    AuthState, crypto_auth, crypto_auth_final, crypto_auth_init, crypto_auth_update,
    crypto_auth_verify,
};
use crate::constants::{CRYPTO_AUTH_BYTES, CRYPTO_AUTH_KEYBYTES};
use crate::error::Error;
use crate::types::*;
use crate::utils::verify_ct;

/// Stack-allocated key for secret-key authentication.
pub type Key = StackByteArray<CRYPTO_AUTH_KEYBYTES>;
/// Stack-allocated message authentication code for secret-key authentication.
pub type Mac = StackByteArray<CRYPTO_AUTH_BYTES>;

#[cfg(any(
    all(feature = "protected", any(unix, windows)),
    all(doc, not(doctest), feature = "std")
))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`Auth`]
    //!
    //! Protected-memory aliases for authentication keys and codes.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::auth::Auth;
    //! use dryoc::auth::protected::*;
    //!
    //! // Create a randomly generated key, lock it, protect it as read-only
    //! let key = Key::generate_readonly_locked().expect("generate failed");
    //! let input =
    //!     HeapBytes::from_slice_into_readonly_locked(b"super secret input").expect("input failed");
    //! // Compute the message authentication code. This takes ownership of the key.
    //! let mac: Locked<Mac> = Auth::compute(key, &input);
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned secret key for authentication with
    /// protected memory.
    pub type Key = HeapByteArray<CRYPTO_AUTH_KEYBYTES>;
    /// Heap-allocated, page-aligned authentication code for use with protected
    /// memory.
    pub type Mac = HeapByteArray<CRYPTO_AUTH_BYTES>;
}

/// Secret-key authentication implementation based on libsodium's
/// HMAC-SHA512-256 `crypto_auth_*` functions.
pub struct Auth {
    state: AuthState,
}

impl Auth {
    /// Computes the message authentication code for `input` using `key`.
    ///
    /// This function takes ownership of `key`, but HMAC keys may be reused for
    /// multiple messages. Clone the key first when it is needed again.
    pub fn compute<
        Key: ByteArray<CRYPTO_AUTH_KEYBYTES>,
        Input: Bytes,
        Output: NewByteArray<CRYPTO_AUTH_BYTES>,
    >(
        key: Key,
        input: &Input,
    ) -> Output {
        let mut output = Output::new_byte_array();
        crypto_auth(output.as_mut_array(), input.as_slice(), key.as_array());
        output
    }

    /// Computes the message authentication code and returns it as a [`Vec`].
    ///
    /// This is a convenience wrapper around [`Auth::compute`].
    #[cfg(feature = "alloc")]
    pub fn compute_to_vec<Key: ByteArray<CRYPTO_AUTH_KEYBYTES>, Input: Bytes>(
        key: Key,
        input: &Input,
    ) -> Vec<u8> {
        Self::compute::<_, _, Mac>(key, input).to_vec()
    }

    /// Verifies that `other_mac` authenticates `input` under `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if `other_mac` does not match the authentication code
    /// computed from `key` and `input`.
    pub fn compute_and_verify<
        OtherMac: ByteArray<CRYPTO_AUTH_BYTES>,
        Key: ByteArray<CRYPTO_AUTH_KEYBYTES>,
        Input: Bytes,
    >(
        other_mac: &OtherMac,
        key: Key,
        input: &Input,
    ) -> Result<(), Error> {
        crypto_auth_verify(other_mac.as_array(), input.as_slice(), key.as_array())
    }

    /// Returns a new incremental authenticator for `key`.
    ///
    /// This function takes ownership of `key`, but HMAC keys may be reused for
    /// multiple messages. Clone the key first when it is needed again.
    pub fn new<Key: ByteArray<CRYPTO_AUTH_KEYBYTES>>(key: Key) -> Self {
        Self {
            state: crypto_auth_init(key.as_array()),
        }
    }

    /// Updates the secret-key authenticator at `self` with `input`.
    pub fn update<Input: Bytes>(&mut self, input: &Input) {
        crypto_auth_update(&mut self.state, input.as_slice())
    }

    /// Finalizes this secret-key authenticator, returning the message
    /// authentication code.
    pub fn finalize<Output: NewByteArray<CRYPTO_AUTH_BYTES>>(self) -> Output {
        let mut output = Output::new_byte_array();
        crypto_auth_final(self.state, output.as_mut_array());
        output
    }

    /// Finalizes this secret-key authenticator, returning the message
    /// authentication code as a [`Vec`]. Convenience wrapper around
    /// [`Auth::finalize`].
    #[cfg(feature = "alloc")]
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize::<Mac>().to_vec()
    }

    /// Finalizes this authenticator, and verifies that the computed code
    /// matches `other_mac` using a constant-time comparison.
    ///
    /// # Errors
    ///
    /// Returns an error if `other_mac` does not match the authentication code
    /// computed from the data passed to [`Auth::update`].
    pub fn verify<OtherMac: ByteArray<CRYPTO_AUTH_BYTES>>(
        self,
        other_mac: &OtherMac,
    ) -> Result<(), Error> {
        let computed_mac: Mac = self.finalize();

        verify_ct(other_mac.as_array(), computed_mac.as_array())
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    /// RFC 4231 cases 1-3 for HMAC-SHA-512, truncated to the 32 bytes
    /// `crypto_auth` (HMAC-SHA-512-256) emits. Keys shorter than 32 bytes are
    /// zero-padded, which HMAC defines to yield the same tag.
    const CASES: [(&[u8], &[u8], &str); 3] = [
        (
            &[0x0b; 20],
            b"Hi There",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
        ),
    ];

    fn padded_key(key: &[u8]) -> Key {
        let mut padded = Key::default();
        padded[..key.len()].copy_from_slice(key);
        padded
    }

    #[test]
    fn rfc4231_vectors_through_single_and_multi_part_interfaces() {
        for (key, message, expected) in CASES {
            let key = padded_key(key);
            let expected = hex::decode(expected).expect("hex");

            assert_eq!(Auth::compute_to_vec(key.clone(), &message), expected);
            let fixed: Mac = Auth::compute(key.clone(), &message);
            assert_eq!(fixed.as_slice(), expected.as_slice());
            Auth::compute_and_verify(&fixed, key.clone(), &message).expect("verify failed");

            let split = message.len() / 2;
            let mut auth = Auth::new(key.clone());
            auth.update(&&message[..split]);
            auth.update(&&[][..]);
            auth.update(&&message[split..]);
            assert_eq!(auth.finalize_to_vec(), expected);

            let mut verifier = Auth::new(key.clone());
            verifier.update(&message);
            verifier.verify(&fixed).expect("incremental verify failed");

            for index in [0, CRYPTO_AUTH_BYTES - 1] {
                let mut flipped = fixed.clone();
                flipped[index] ^= 1;
                assert!(matches!(
                    Auth::compute_and_verify(&flipped, key.clone(), &message),
                    Err(Error::AuthenticationFailed)
                ));
                let mut verifier = Auth::new(key.clone());
                verifier.update(&message);
                assert!(matches!(
                    verifier.verify(&flipped),
                    Err(Error::AuthenticationFailed)
                ));
            }

            let mut wrong_key = key.clone();
            wrong_key[CRYPTO_AUTH_KEYBYTES - 1] ^= 1;
            assert!(matches!(
                Auth::compute_and_verify(&fixed, wrong_key, &message),
                Err(Error::AuthenticationFailed)
            ));
            let mut verifier = Auth::new(key);
            verifier.update(&&message[..message.len() - 1]);
            assert!(matches!(
                verifier.verify(&fixed),
                Err(Error::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn rustaceous_and_classic_macs_verify_each_other() {
        for (key, message, _) in CASES {
            let key = padded_key(key);
            let mac = Auth::compute_to_vec(key.clone(), &message);
            crypto_auth_verify(
                mac.as_slice().try_into().expect("MAC length"),
                message,
                key.as_array(),
            )
            .expect("classic verify");

            let mut classic = [0u8; CRYPTO_AUTH_BYTES];
            crypto_auth(&mut classic, message, key.as_array());
            Auth::compute_and_verify(&classic, key.clone(), &message).expect("rustaceous verify");
            let mut verifier = Auth::new(key);
            verifier.update(&message);
            verifier.verify(&classic).expect("incremental verify");
        }
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_key_and_input_produce_the_same_mac() {
        use crate::auth::protected::*;

        for (key, message, expected) in CASES {
            let expected = hex::decode(expected).expect("hex");
            let lock_key = || {
                protected::Key::from_slice_into_readonly_locked(padded_key(key).as_slice())
                    .expect("lock key")
            };
            let input = HeapBytes::from_slice_into_readonly_locked(message).expect("lock input");

            let mac: Locked<protected::Mac> = Auth::compute(lock_key(), &input);
            assert_eq!(mac.as_slice(), expected.as_slice());
            Auth::compute_and_verify(&mac, lock_key(), &input).expect("verify failed");
            let mut verifier = Auth::new(lock_key());
            verifier.update(&input);
            verifier.verify(&mac).expect("incremental verify failed");
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn rfc4231_keys_match_libsodium() {
        use crate::native_test_util::auth_hmacsha512256;

        for (key, message, _) in CASES {
            let key = padded_key(key);
            let so_tag = auth_hmacsha512256(message, key.as_slice());
            assert_eq!(Auth::compute_to_vec(key.clone(), &message), so_tag);
            Auth::compute_and_verify(&so_tag, key, &message).expect("verify sodium tag");
        }
    }
}
