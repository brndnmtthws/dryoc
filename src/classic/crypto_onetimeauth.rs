//! # One-time authentication
//!
//! Implements one-time authentication using the Poly1305 algorithm, compatible
//! with libsodium's `crypto_onetimeauth_*` functions.
//!
//! # Classic API single-part example
//!
//! ```
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::classic::crypto_onetimeauth::{
//!     crypto_onetimeauth, crypto_onetimeauth_keygen, crypto_onetimeauth_verify, Mac,
//! };
//!
//! let key = crypto_onetimeauth_keygen();
//! let mut mac = Mac::default();
//!
//! crypto_onetimeauth(&mut mac, b"Data to authenticate", &key);
//!
//! // This should be valid
//! crypto_onetimeauth_verify(&mac, b"Data to authenticate", &key).expect("failed to authenticate");
//!
//! // This should not be valid
//! crypto_onetimeauth_verify(&mac, b"Invalid data", &key).expect_err("should not authenticate");
//! ```
//!
//! # Classic API multi-part example
//!
//! ```
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::classic::crypto_onetimeauth::{
//!     crypto_onetimeauth_final, crypto_onetimeauth_init, crypto_onetimeauth_keygen,
//!     crypto_onetimeauth_update, crypto_onetimeauth_verify, Mac,
//! };
//!
//! let key = crypto_onetimeauth_keygen();
//! let mut mac = Mac::default();
//!
//! let mut state = crypto_onetimeauth_init(&key);
//! crypto_onetimeauth_update(&mut state, b"Multi-part");
//! crypto_onetimeauth_update(&mut state, b"data");
//! crypto_onetimeauth_final(state, &mut mac);
//!
//! // This should be valid
//! crypto_onetimeauth_verify(&mac, b"Multi-partdata", &key).expect("failed to authenticate");
//!
//! // This should not be valid
//! crypto_onetimeauth_verify(&mac, b"Invalid data", &key).expect_err("should not authenticate");
//! ```
use subtle::ConstantTimeEq;

use crate::constants::{
    CRYPTO_ONETIMEAUTH_BYTES, CRYPTO_ONETIMEAUTH_KEYBYTES, CRYPTO_ONETIMEAUTH_POLY1305_BYTES,
    CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES,
};
use crate::error::Error;
use crate::poly1305::Poly1305;
use crate::types::*;
struct OnetimeauthPoly1305State {
    mac: Poly1305,
}

/// Key type for use with one-time authentication.
pub type Key = [u8; CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES];
/// Message authentication code type for use with one-time authentication.
pub type Mac = [u8; CRYPTO_ONETIMEAUTH_POLY1305_BYTES];

fn crypto_onetimeauth_poly1305(output: &mut Mac, message: &[u8], key: &Key) {
    let mut poly1305 = Poly1305::new(key);
    poly1305.update(message);
    poly1305.finalize(output)
}
fn crypto_onetimeauth_poly1305_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    let mut poly1305 = Poly1305::new(key);
    poly1305.update(input);
    let computed_mac = poly1305.finalize_to_array();

    if mac.ct_eq(&computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("authentication codes do not match"))
    }
}

fn crypto_onetimeauth_poly1305_init(key: &Key) -> OnetimeauthPoly1305State {
    OnetimeauthPoly1305State {
        mac: Poly1305::new(key),
    }
}

fn crypto_onetimeauth_poly1305_update(state: &mut OnetimeauthPoly1305State, input: &[u8]) {
    state.mac.update(input)
}
fn crypto_onetimeauth_poly1305_final(
    mut state: OnetimeauthPoly1305State,
    output: &mut [u8; CRYPTO_ONETIMEAUTH_POLY1305_BYTES],
) {
    state.mac.finalize(output)
}

/// Authenticates `message` using `key`, and places the result into
/// `mac`. `key` should only be used once.
///
/// Equivalent to libsodium's `crypto_onetimeauth`.
pub fn crypto_onetimeauth(mac: &mut Mac, message: &[u8], key: &Key) {
    crypto_onetimeauth_poly1305(mac, message, key)
}

/// Verifies that `mac` is the correct authenticator for `message` using `key`.
/// Returns `Ok(())` if the message authentication code is valid.
///
/// Equivalent to libsodium's `crypto_onetimeauth_verify`.
pub fn crypto_onetimeauth_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    crypto_onetimeauth_poly1305_verify(mac, input, key)
}

/// Internal state for [`crypto_onetimeauth`].
pub struct OnetimeauthState {
    state: OnetimeauthPoly1305State,
}

/// Generates a random key using
/// [`copy_randombytes`](crate::rng::copy_randombytes), suitable for use with
/// [`crypto_onetimeauth_init`] and [`crypto_onetimeauth`]. The key should only
/// be used once.
///
/// Equivalent to libsodium's `crypto_onetimeauth_keygen`.
pub fn crypto_onetimeauth_keygen() -> Key {
    Key::gen()
}

/// Initialize the incremental interface for Poly1305-based one-time
/// authentication, using `key`. Returns a state struct which is required for
/// subsequent calls to [`crypto_onetimeauth_update`] and
/// [`crypto_onetimeauth_final`]. The key should only be used once.
///
/// Equivalent to libsodium's `crypto_onetimeauth_init`.
pub fn crypto_onetimeauth_init(key: &[u8; CRYPTO_ONETIMEAUTH_KEYBYTES]) -> OnetimeauthState {
    OnetimeauthState {
        state: crypto_onetimeauth_poly1305_init(key),
    }
}

/// Updates `state` for the one-time authentication function, based on `input`.
///
/// Equivalent to libsodium's `crypto_onetimeauth_update`.
pub fn crypto_onetimeauth_update(state: &mut OnetimeauthState, input: &[u8]) {
    crypto_onetimeauth_poly1305_update(&mut state.state, input)
}

/// Finalizes the message authentication code for `state`, and places the result
/// into `output`.
///
/// Equivalent to libsodium's `crypto_onetimeauth_final`.
pub fn crypto_onetimeauth_final(
    state: OnetimeauthState,
    output: &mut [u8; CRYPTO_ONETIMEAUTH_BYTES],
) {
    crypto_onetimeauth_poly1305_final(state.state, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onetimeauth() {
        use sodiumoxide::crypto::onetimeauth;

        use crate::rng::copy_randombytes;

        for _ in 0..20 {
            let mut key = [0u8; 32];
            copy_randombytes(&mut key);
            let mut input = [0u8; 1024];
            copy_randombytes(&mut input);

            let so_mac = onetimeauth::authenticate(
                &input,
                &onetimeauth::poly1305::Key::from_slice(&key).expect("so key failed"),
            );

            let mut mac = [0u8; CRYPTO_ONETIMEAUTH_BYTES];
            crypto_onetimeauth(&mut mac, &input, &key);

            assert_eq!(so_mac.0, mac);

            crypto_onetimeauth_verify(&mac, &input, &key).expect("verify failed");
        }
    }

    #[test]
    fn test_onetimeauth_incremental() {
        use sodiumoxide::crypto::onetimeauth;

        use crate::rng::copy_randombytes;

        for _ in 0..20 {
            let mut key = [0u8; 32];
            copy_randombytes(&mut key);
            let mut input = [0u8; 1024];
            copy_randombytes(&mut input);

            let so_mac = onetimeauth::authenticate(
                &input,
                &onetimeauth::poly1305::Key::from_slice(&key).expect("so key failed"),
            );

            let mut mac = [0u8; CRYPTO_ONETIMEAUTH_BYTES];
            let mut state = crypto_onetimeauth_init(&key);
            crypto_onetimeauth_update(&mut state, &input);
            crypto_onetimeauth_final(state, &mut mac);

            assert_eq!(so_mac.0, mac);

            crypto_onetimeauth_verify(&mac, &input, &key).expect("verify failed");
        }
    }
}
