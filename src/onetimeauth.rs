//! # One-time authentication
//!
//! [`OnetimeAuth`] implements libsodium's one-time authentication, based on the
//! Poly1305 message authentication code.
//!
//! Use [`OnetimeAuth`] to authenticate messages when:
//!
//! * you want to exchange many small messages, such as in an online protocol
//! * you can generate a unique key for each message you're authenticating,
//!   i.e., using a key and a nonce
//!
//! Do not reuse the same key for difference messages with [`OnetimeAuth`], as
//! it provides an opportunity for an attacker to discover the key.
//!
//!
//! # Rustaceous API example, one-time interface
//!
//! ```
//! use dryoc::onetimeauth::*;
//! use dryoc::types::*;
//!
//! // Generate a random key
//! let key = Key::gen();
//!
//! // Compute the mac in one shot. Here we clone the key for the purpose of this
//! // example, but normally you would not do this as you never want to re-use a
//! // key.
//! let mac = OnetimeAuth::compute_to_vec(key.clone(), b"Data to authenticate");
//!
//! // Verify the mac
//! OnetimeAuth::compute_and_verify(&mac, key, b"Data to authenticate").expect("verify failed");
//! ```
//!
//! # Rustaceous API example, incremental interface
//!
//! ```
//! use dryoc::onetimeauth::*;
//! use dryoc::types::*;
//!
//! // Generate a random key
//! let key = Key::gen();
//!
//! // Initialize the MAC, clone the key (don't do this)
//! let mut mac = OnetimeAuth::new(key.clone());
//! mac.update(b"Multi-part");
//! mac.update(b"data");
//! let mac = mac.finalize_to_vec();
//!
//! // Verify it's correct, clone the key (don't do this)
//! let mut verify_mac = OnetimeAuth::new(key.clone());
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"data");
//! verify_mac.verify(&mac).expect("verify failed");
//!
//! // Check that invalid data fails, consume the key
//! let mut verify_mac = OnetimeAuth::new(key);
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"bad data");
//! verify_mac
//!     .verify(&mac)
//!     .expect_err("verify should have failed");
//! ```

use subtle::ConstantTimeEq;

use crate::classic::crypto_onetimeauth::{
    crypto_onetimeauth, crypto_onetimeauth_final, crypto_onetimeauth_init,
    crypto_onetimeauth_update, crypto_onetimeauth_verify, OnetimeauthState,
};
use crate::constants::{CRYPTO_ONETIMEAUTH_BYTES, CRYPTO_ONETIMEAUTH_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key for one-time authentication.
pub type Key = StackByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>;
/// Stack-allocated message authentication code for one-time authentication.
pub type Mac = StackByteArray<CRYPTO_ONETIMEAUTH_BYTES>;

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`OnetimeAuth`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`OnetimeAuth`]. These type aliases are provided for
    //! convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::onetimeauth::protected::*;
    //! use dryoc::onetimeauth::OnetimeAuth;
    //!
    //! // Create a randomly generated key, lock it, protect it as read-only
    //! let key = Key::gen_readonly_locked().expect("gen failed");
    //! let input =
    //!     HeapBytes::from_slice_into_readonly_locked(b"super secret input").expect("input failed");
    //! // Compute the message authentication code, consuming the key.
    //! let mac: Locked<Mac> = OnetimeAuth::compute(key, &input);
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned secret key for the generic hash algorithm,
    /// for use with protected memory.
    pub type Key = HeapByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>;
    /// Heap-allocated, page-aligned hash output for the generic hash algorithm,
    /// for use with protected memory.
    pub type Mac = HeapByteArray<CRYPTO_ONETIMEAUTH_BYTES>;
}

/// One-time authentication implementation based on Poly1305, compatible with
/// libsodium's `crypto_onetimeauth_*` functions.
pub struct OnetimeAuth {
    state: OnetimeauthState,
}

impl OnetimeAuth {
    /// Single-part interface for [`OnetimeAuth`]. Computes (and returns) the
    /// message authentication code for `input` using `key`. The `key` is
    /// consumed to prevent accidental re-use of the same key.
    pub fn compute<
        Key: ByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>,
        Input: Bytes,
        Output: NewByteArray<CRYPTO_ONETIMEAUTH_BYTES>,
    >(
        key: Key,
        input: &Input,
    ) -> Output {
        let mut output = Output::new_byte_array();
        crypto_onetimeauth(output.as_mut_array(), input.as_slice(), key.as_array());
        output
    }

    /// Convience wrapper around [`OnetimeAuth::compute`]. Returns the message
    /// authentication code as a [`Vec`]. The `key` is
    /// consumed to prevent accidental re-use of the same key.
    pub fn compute_to_vec<Key: ByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>, Input: Bytes>(
        key: Key,
        input: &Input,
    ) -> Vec<u8> {
        Self::compute(key, input)
    }

    /// Verifies the message authentication code `other_mac` matches the
    /// expected code for `key` and `input`. The `key` is
    /// consumed to prevent accidental re-use of the same key.
    pub fn compute_and_verify<
        OtherMac: ByteArray<CRYPTO_ONETIMEAUTH_BYTES>,
        Key: ByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>,
        Input: Bytes,
    >(
        other_mac: &OtherMac,
        key: Key,
        input: &Input,
    ) -> Result<(), Error> {
        crypto_onetimeauth_verify(other_mac.as_array(), input.as_slice(), key.as_array())
    }

    /// Returns a new one-time authenticator for `key`. The `key` is
    /// consumed to prevent accidental re-use of the same key.
    pub fn new<Key: ByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>>(key: Key) -> Self {
        Self {
            state: crypto_onetimeauth_init(key.as_array()),
        }
    }

    /// Updates the one-time authenticator at `self` with `input`.
    pub fn update<Input: Bytes>(&mut self, input: &Input) {
        crypto_onetimeauth_update(&mut self.state, input.as_slice())
    }

    /// Finalizes this one-time authenticator, returning the message
    /// authentication code.
    pub fn finalize<Output: NewByteArray<CRYPTO_ONETIMEAUTH_BYTES>>(self) -> Output {
        let mut output = Output::new_byte_array();
        crypto_onetimeauth_final(self.state, output.as_mut_array());
        output
    }

    /// Finalizes this one-time authenticator, returning the message
    /// authentication code as a [`Vec`]. Convenience wrapper around
    /// [`OnetimeAuth::finalize`].
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize()
    }

    /// Finalizes this authenticator, and verifies that the computed code
    /// matches `other_mac` using a constant-time comparison.
    pub fn verify<OtherMac: ByteArray<CRYPTO_ONETIMEAUTH_BYTES>>(
        self,
        other_mac: &OtherMac,
    ) -> Result<(), Error> {
        let computed_mac: Mac = self.finalize();

        if other_mac
            .as_array()
            .ct_eq(computed_mac.as_array())
            .unwrap_u8()
            == 1
        {
            Ok(())
        } else {
            Err(dryoc_error!("authentication codes do not match"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_part() {
        let key = Key::gen();
        let mac = OnetimeAuth::compute_to_vec(key.clone(), b"Data to authenticate");

        OnetimeAuth::compute_and_verify(&mac, key, b"Data to authenticate").expect("verify failed");
    }

    #[test]
    fn test_multi_part() {
        let key = Key::gen();

        let mut mac = OnetimeAuth::new(key.clone());
        mac.update(b"Multi-part");
        mac.update(b"data");
        let mac = mac.finalize_to_vec();

        let mut verify_mac = OnetimeAuth::new(key.clone());
        verify_mac.update(b"Multi-part");
        verify_mac.update(b"data");
        verify_mac.verify(&mac).expect("verify failed");

        let mut verify_mac = OnetimeAuth::new(key);
        verify_mac.update(b"Multi-part");
        verify_mac.update(b"bad data");
        verify_mac
            .verify(&mac)
            .expect_err("verify should have failed");
    }
}
