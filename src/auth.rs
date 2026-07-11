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
//! let mac = Auth::compute_to_vec(key.clone(), b"Data to authenticate");
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
//! let mac = mac.finalize_to_vec();
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

use subtle::ConstantTimeEq;

use crate::classic::crypto_auth::{
    AuthState, crypto_auth, crypto_auth_final, crypto_auth_init, crypto_auth_update,
    crypto_auth_verify,
};
use crate::constants::{CRYPTO_AUTH_BYTES, CRYPTO_AUTH_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key for secret-key authentication.
pub type Key = StackByteArray<CRYPTO_AUTH_KEYBYTES>;
/// Stack-allocated message authentication code for secret-key authentication.
pub type Mac = StackByteArray<CRYPTO_AUTH_BYTES>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
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
    pub fn compute_to_vec<Key: ByteArray<CRYPTO_AUTH_KEYBYTES>, Input: Bytes>(
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
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize()
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

        if other_mac
            .as_array()
            .ct_eq(computed_mac.as_array())
            .unwrap_u8()
            == 1
        {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_part() {
        let key = Key::generate();
        let mac = Auth::compute_to_vec(key.clone(), b"Data to authenticate");

        Auth::compute_and_verify(&mac, key, b"Data to authenticate").expect("verify failed");
    }

    #[test]
    fn test_multi_part() {
        let key = Key::generate();

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
