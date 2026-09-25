//! # Secret-key authentication
//!
//! Implements secret-key authentication using HMAC-SHA512-256, compatible
//! with libsodium's `crypto_auth_*` functions.
//!
//! # Classic API single-part example
//!
//! ```
//! use dryoc::classic::crypto_auth::{Mac, crypto_auth, crypto_auth_keygen, crypto_auth_verify};
//!
//! let key = crypto_auth_keygen();
//! let mut mac = Mac::default();
//!
//! crypto_auth(&mut mac, b"Data to authenticate", &key);
//!
//! // This should be valid
//! crypto_auth_verify(&mac, b"Data to authenticate", &key).expect("failed to authenticate");
//!
//! // This should not be valid
//! crypto_auth_verify(&mac, b"Invalid data", &key).expect_err("should not authenticate");
//! ```
//!
//! # Classic API multi-part example
//!
//! ```
//! use dryoc::classic::crypto_auth::{
//!     Mac, crypto_auth_final, crypto_auth_init, crypto_auth_keygen, crypto_auth_update,
//!     crypto_auth_verify,
//! };
//!
//! let key = crypto_auth_keygen();
//! let mut mac = Mac::default();
//!
//! let mut state = crypto_auth_init(&key);
//! crypto_auth_update(&mut state, b"Multi-part");
//! crypto_auth_update(&mut state, b"data");
//! crypto_auth_final(state, &mut mac);
//!
//! // This should be valid
//! crypto_auth_verify(&mac, b"Multi-partdata", &key).expect("failed to authenticate");
//!
//! // This should not be valid
//! crypto_auth_verify(&mac, b"Invalid data", &key).expect_err("should not authenticate");
//! ```
use super::crypto_auth_hmacsha512256::{
    HmacSha512256State, crypto_auth_hmacsha512256, crypto_auth_hmacsha512256_final,
    crypto_auth_hmacsha512256_init, crypto_auth_hmacsha512256_keygen,
    crypto_auth_hmacsha512256_update, crypto_auth_hmacsha512256_verify,
};
use crate::constants::{CRYPTO_AUTH_BYTES, CRYPTO_AUTH_KEYBYTES};
use crate::error::Error;

/// Key for secret-key message authentication.
pub type Key = [u8; CRYPTO_AUTH_KEYBYTES];
/// Message authentication code type for use with secret-key authentication.
pub type Mac = [u8; CRYPTO_AUTH_BYTES];

/// Authenticates `message` using `key`, and places the result into
/// `mac`.
///
/// Equivalent to libsodium's `crypto_auth`.
pub fn crypto_auth(mac: &mut Mac, message: &[u8], key: &Key) {
    crypto_auth_hmacsha512256(mac, message, key)
}

/// Verifies that `mac` is the correct authenticator for `message` using `key`.
/// Returns `Ok(())` if the message authentication code is valid.
///
/// Equivalent to libsodium's `crypto_auth_verify`.
///
/// # Errors
///
/// Returns an error if `mac` is not valid for `input` under `key`.
pub fn crypto_auth_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    crypto_auth_hmacsha512256_verify(mac, input, key)
}

/// Internal state for [`crypto_auth`].
pub struct AuthState {
    state: HmacSha512256State,
}

/// Generates a random key using
/// [`copy_randombytes`](crate::rng::copy_randombytes), suitable for use with
/// [`crypto_auth_init`] and [`crypto_auth`].
///
/// Equivalent to libsodium's `crypto_auth_keygen`.
pub fn crypto_auth_keygen() -> Key {
    crypto_auth_hmacsha512256_keygen()
}

/// Initialize the incremental interface for HMAC-SHA512-256 secret-key.
///
/// Initializes the incremental interface for HMAC-SHA512-256 secret-key
/// authentication, using `key`. Returns a state struct which is required for
/// subsequent calls to [`crypto_auth_update`] and
/// [`crypto_auth_final`].
pub fn crypto_auth_init(key: &Key) -> AuthState {
    AuthState {
        state: crypto_auth_hmacsha512256_init(key),
    }
}

/// Updates `state` for the secret-key authentication function, based on
/// `input`.
pub fn crypto_auth_update(state: &mut AuthState, input: &[u8]) {
    crypto_auth_hmacsha512256_update(&mut state.state, input)
}

/// Finalizes the message authentication code for `state`, and places the result
/// into `output`.
pub fn crypto_auth_final(state: AuthState, output: &mut [u8; CRYPTO_AUTH_BYTES]) {
    crypto_auth_hmacsha512256_final(state.state, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(dryoc_native_tests)]
    use crate::test_prelude::*;

    const KEY: Key = {
        let mut key = [0u8; CRYPTO_AUTH_KEYBYTES];
        let mut i = 0;
        while i < key.len() {
            key[i] = i as u8;
            i += 1;
        }
        key
    };
    const MESSAGE: &[u8] = b"classic crypto_auth boundary";
    /// HMAC-SHA-512 of `MESSAGE` under `KEY`, truncated to 32 bytes
    /// (computed independently with Python's `hmac`/`hashlib`).
    const TAG: &str = "2f850f393b25f3568a2e8686d2a19401aa2343ab2ea1474f450962cef5de2b58";

    /// `crypto_auth` is HMAC-SHA-512-256, one-shot and streamed, and the tag
    /// verifies only for the exact message.
    #[test]
    fn test_crypto_auth_known_answer() {
        let expected = hex::decode(TAG).expect("hex failed");
        let mut mac = Mac::default();
        crypto_auth(&mut mac, MESSAGE, &KEY);
        assert_eq!(mac.as_slice(), expected.as_slice());

        let mut state = crypto_auth_init(&KEY);
        crypto_auth_update(&mut state, b"");
        for chunk in MESSAGE.chunks(7) {
            crypto_auth_update(&mut state, chunk);
        }
        let mut streamed = Mac::default();
        crypto_auth_final(state, &mut streamed);
        assert_eq!(streamed, mac);

        crypto_auth_verify(&mac, MESSAGE, &KEY).expect("verify failed");
        crypto_auth_verify(&mac, &MESSAGE[..MESSAGE.len() - 1], &KEY)
            .expect_err("truncated message");
        let mut flipped = mac;
        flipped[0] ^= 1;
        crypto_auth_verify(&flipped, MESSAGE, &KEY).expect_err("flipped tag");
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_crypto_auth_matches_libsodium() {
        use crate::native_test_util::auth_hmacsha512256;

        for len in [0usize, 127, 128, 129] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 31 % 251) as u8).collect();
            let so_tag = auth_hmacsha512256(&message, &KEY);
            let mut mac = Mac::default();
            crypto_auth(&mut mac, &message, &KEY);
            assert_eq!(mac, so_tag, "len {len}");
        }
    }
}
