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
//! # Rustaceous API example, one-time interface
//!
//! ```
//! use dryoc::auth::*;
//! use dryoc::types::*;
//!
//! // Generate a random key
//! let key = Key::gen();
//!
//! // Compute the mac in one shot. Here we clone the key for the purpose of this
//! // example, but normally you would not do this as you never want to re-use a
//! // key.
//! let mac = Auth::compute_to_vec(key.clone(), b"Data to authenticate");
//!
//! // Verify the mac
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
//! let key = Key::gen();
//!
//! // Initialize the MAC, clone the key (don't do this)
//! let mut mac = Auth::new(key.clone());
//! mac.update(b"Multi-part");
//! mac.update(b"data");
//! let mac = mac.finalize_to_vec();
//!
//! // Verify it's correct, clone the key (don't do this)
//! let mut verify_mac = Auth::new(key.clone());
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"data");
//! verify_mac.verify(&mac).expect("verify failed");
//!
//! // Check that invalid data fails, consume the key
//! let mut verify_mac = Auth::new(key);
//! verify_mac.update(b"Multi-part");
//! verify_mac.update(b"bad data");
//! verify_mac
//!     .verify(&mac)
//!     .expect_err("verify should have failed");
//! ```

use subtle::ConstantTimeEq;

use crate::classic::crypto_auth::{
    crypto_auth, crypto_auth_final, crypto_auth_init, crypto_auth_update, crypto_auth_verify,
    AuthState,
};
use crate::constants::{CRYPTO_AUTH_BYTES, CRYPTO_AUTH_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key for secret-key authentication.
pub type Key = StackByteArray<CRYPTO_AUTH_KEYBYTES>;
/// Stack-allocated message authentication code for secret-key authentication.
pub type Mac = StackByteArray<CRYPTO_AUTH_BYTES>;

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`Auth`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`Auth`]. These type aliases are provided for
    //! convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::auth::protected::*;
    //! use dryoc::auth::Auth;
    //!
    //! // Create a randomly generated key, lock it, protect it as read-only
    //! let key = Key::gen_readonly_locked().expect("gen failed");
    //! let input =
    //!     HeapBytes::from_slice_into_readonly_locked(b"super secret input").expect("input failed");
    //! // Compute the message authentication code, consuming the key.
    //! let mac: Locked<Mac> = Auth::compute(key, &input);
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned secret key for the generic hash algorithm,
    /// for use with protected memory.
    pub type Key = HeapByteArray<CRYPTO_AUTH_KEYBYTES>;
    /// Heap-allocated, page-aligned hash output for the generic hash algorithm,
    /// for use with protected memory.
    pub type Mac = HeapByteArray<CRYPTO_AUTH_BYTES>;
}

/// secret-key authentication implementation based on Poly1305, compatible with
/// libsodium's `crypto_Auth_*` functions.
pub struct Auth {
    state: AuthState,
}

impl Auth {
    /// Single-part interface for [`Auth`]. Computes (and returns) the
    /// message authentication code for `input` using `key`. The `key` is
    /// consumed to prevent accidental re-use of the same key.
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

    /// Convience wrapper around [`Auth::compute`]. Returns the message
    /// authentication code as a [`Vec`]. The `key` is
    /// consumed to prevent accidental re-use of the same key.
    pub fn compute_to_vec<Key: ByteArray<CRYPTO_AUTH_KEYBYTES>, Input: Bytes>(
        key: Key,
        input: &Input,
    ) -> Vec<u8> {
        Self::compute(key, input)
    }

    /// Verifies the message authentication code `other_mac` matches the
    /// expected code for `key` and `input`. The `key` is
    /// consumed to prevent accidental re-use of the same key.
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

    /// Returns a new secret-key authenticator for `key`. The `key` is
    /// consumed to prevent accidental re-use of the same key.
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
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize()
    }

    /// Finalizes this authenticator, and verifies that the computed code
    /// matches `other_mac` using a constant-time comparison.
    pub fn verify<OtherMac: ByteArray<CRYPTO_AUTH_BYTES>>(
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
        let mac = Auth::compute_to_vec(key.clone(), b"Data to authenticate");

        Auth::compute_and_verify(&mac, key, b"Data to authenticate").expect("verify failed");
    }

    #[test]
    fn test_multi_part() {
        let key = Key::gen();

        let mut mac = Auth::new(key.clone());
        mac.update(b"Multi-part");
        mac.update(b"data");
        let mac = mac.finalize_to_vec();

        let mut verify_mac = Auth::new(key.clone());
        verify_mac.update(b"Multi-part");
        verify_mac.update(b"data");
        verify_mac.verify(&mac).expect("verify failed");

        let mut verify_mac = Auth::new(key);
        verify_mac.update(b"Multi-part");
        verify_mac.update(b"bad data");
        verify_mac
            .verify(&mac)
            .expect_err("verify should have failed");
    }
}
