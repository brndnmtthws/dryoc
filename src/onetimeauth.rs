//! # One-time authentication
//!
//! [`OnetimeAuth`] implements libsodium's one-time authentication, based on the
//! Poly1305 message authentication code.
//!
//! Use [`OnetimeAuth`] to authenticate messages when:
//!
//! * you need to authenticate a message with a one-time Poly1305 key
//! * your protocol derives a unique key for every distinct message
//!
//! Never use the same key to authenticate two different messages. Poly1305 key
//! reuse can let an attacker forge authentication codes. Reusing the key to
//! verify the authentication code for the same message is safe.
//!
//! # Rustaceous API example, single-part interface
//!
//! ```
//! use dryoc::onetimeauth::*;
//! use dryoc::types::*;
//!
//! // Generate a random key
//! let key = Key::generate();
//!
//! // Compute the MAC. Keep a copy only to verify this same message.
//! let mac = OnetimeAuth::compute_to_vec(key.clone(), b"Data to authenticate");
//!
//! // Verify the MAC
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
//! let key = Key::generate();
//!
//! // Initialize the MAC. Keep a copy only to verify this same message.
//! let mut mac = OnetimeAuth::new(key.clone());
//! mac.update(b"Multi-part");
//! mac.update(b"data");
//! let mac = mac.finalize_to_vec();
//!
//! // Verify the MAC for the same message
//! let mut verify_mac = OnetimeAuth::new(key.clone());
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"data");
//! verify_mac.verify(&mac).expect("verify failed");
//!
//! // Check that a modified MAC fails for the same message
//! let mut modified_mac = mac.clone();
//! modified_mac[0] ^= 1;
//! let mut verify_mac = OnetimeAuth::new(key);
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"data");
//! verify_mac
//!     .verify(&modified_mac)
//!     .expect_err("verify should have failed");
//! ```

use subtle::ConstantTimeEq;

use crate::classic::crypto_onetimeauth::{
    OnetimeauthState, crypto_onetimeauth, crypto_onetimeauth_final, crypto_onetimeauth_init,
    crypto_onetimeauth_update, crypto_onetimeauth_verify,
};
use crate::constants::{CRYPTO_ONETIMEAUTH_BYTES, CRYPTO_ONETIMEAUTH_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key for one-time authentication.
pub type Key = StackByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>;
/// Stack-allocated message authentication code for one-time authentication.
pub type Mac = StackByteArray<CRYPTO_ONETIMEAUTH_BYTES>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`OnetimeAuth`]
    //!
    //! Protected-memory aliases for one-time authentication keys and codes.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::onetimeauth::OnetimeAuth;
    //! use dryoc::onetimeauth::protected::*;
    //!
    //! // Create a randomly generated key, lock it, protect it as read-only
    //! let key = Key::generate_readonly_locked().expect("generate failed");
    //! let input =
    //!     HeapBytes::from_slice_into_readonly_locked(b"super secret input").expect("input failed");
    //! // Compute the message authentication code, consuming the key.
    //! let mac: Locked<Mac> = OnetimeAuth::compute(key, &input);
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned key for one-time authentication with
    /// protected memory.
    pub type Key = HeapByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>;
    /// Heap-allocated, page-aligned one-time authentication code for use with
    /// protected memory.
    pub type Mac = HeapByteArray<CRYPTO_ONETIMEAUTH_BYTES>;
}

/// One-time authentication implementation based on Poly1305, compatible with
/// libsodium's `crypto_onetimeauth_*` functions.
pub struct OnetimeAuth {
    state: OnetimeauthState,
}

impl OnetimeAuth {
    /// Computes the message authentication code for `input` using `key`.
    ///
    /// The key must not be used to authenticate any other message. It may be
    /// retained to verify the authentication code for this same message.
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

    /// Computes the message authentication code and returns it as a [`Vec`].
    ///
    /// This is a convenience wrapper around [`OnetimeAuth::compute`].
    pub fn compute_to_vec<Key: ByteArray<CRYPTO_ONETIMEAUTH_KEYBYTES>, Input: Bytes>(
        key: Key,
        input: &Input,
    ) -> Vec<u8> {
        Self::compute(key, input)
    }

    /// Verifies that `other_mac` authenticates `input` under `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if `other_mac` does not match the authentication code
    /// computed from `key` and `input`.
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

    /// Returns a new incremental one-time authenticator for `key`.
    ///
    /// The key must not be used to authenticate any other message. It may be
    /// retained to verify the authentication code for this same message.
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
    ///
    /// # Errors
    ///
    /// Returns an error if `other_mac` does not match the authentication code
    /// computed from the data passed to [`OnetimeAuth::update`].
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
        let key = Key::generate();
        let mac = OnetimeAuth::compute_to_vec(key.clone(), b"Data to authenticate");

        OnetimeAuth::compute_and_verify(&mac, key, b"Data to authenticate").expect("verify failed");
    }

    #[test]
    fn test_multi_part() {
        let key = Key::generate();

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
