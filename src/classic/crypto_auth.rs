//! # Secret-key authentication
//!
//! Implements secret-key authentication using HMAC-SHA512-256, compatible
//! with libsodium's `crypto_auth_*` functions.
//!
//! # Classic API single-part example
//!
//! ```
//! use dryoc::classic::crypto_auth::{crypto_auth, crypto_auth_keygen, crypto_auth_verify, Mac};
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
//!     crypto_auth_final, crypto_auth_init, crypto_auth_keygen, crypto_auth_update,
//!     crypto_auth_verify, Mac,
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
use subtle::ConstantTimeEq;

use crate::constants::{CRYPTO_AUTH_BYTES, CRYPTO_AUTH_HMACSHA512256_BYTES, CRYPTO_AUTH_KEYBYTES};
use crate::error::Error;
use crate::sha512::Sha512;
use crate::types::*;

struct HmacSha512State {
    octx: Sha512,
    ictx: Sha512,
}

/// Key for secret-key message authentication.
pub type Key = [u8; CRYPTO_AUTH_KEYBYTES];
/// Message authentication code type for use with secret-key authentication.
pub type Mac = [u8; CRYPTO_AUTH_BYTES];

fn crypto_auth_hmacsha512256(output: &mut Mac, message: &[u8], key: &Key) {
    let mut state = crypto_auth_hmacsha512256_init(key);
    crypto_auth_hmacsha512256_update(&mut state, message);
    crypto_auth_hmacsha512256_final(state, output);
}

fn crypto_auth_hmacsha512256_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    let mut computed_mac = Mac::default();
    crypto_auth_hmacsha512256(&mut computed_mac, input, key);
    if mac.ct_eq(&computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("authentication codes do not match"))
    }
}

fn crypto_auth_hmacsha512256_init(key: &[u8]) -> HmacSha512State {
    let mut pad = [0x36u8; 128];
    let mut khash = [0u8; 64];
    let keylen = key.len();

    let key = if keylen > 128 {
        Sha512::compute_into_bytes(&mut khash, key);
        &khash
    } else {
        key
    };

    let mut ictx = Sha512::new();
    for i in 0..keylen {
        pad[i] ^= key[i]
    }
    ictx.update(&pad);

    let mut octx = Sha512::new();
    pad.fill(0x5c);
    for i in 0..keylen {
        pad[i] ^= key[i]
    }
    octx.update(&pad);

    HmacSha512State { octx, ictx }
}

fn crypto_auth_hmacsha512256_update(state: &mut HmacSha512State, input: &[u8]) {
    state.ictx.update(input)
}
fn crypto_auth_hmacsha512256_final(
    mut state: HmacSha512State,
    output: &mut [u8; CRYPTO_AUTH_HMACSHA512256_BYTES],
) {
    let mut ihash = [0u8; 64];
    state.ictx.finalize_into_bytes(&mut ihash);
    state.octx.update(&ihash);
    state.octx.finalize_into_bytes(&mut ihash);
    output.copy_from_slice(&ihash[..CRYPTO_AUTH_HMACSHA512256_BYTES])
}

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
pub fn crypto_auth_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    crypto_auth_hmacsha512256_verify(mac, input, key)
}

/// Internal state for [`crypto_auth`].
pub struct AuthState {
    state: HmacSha512State,
}

/// Generates a random key using
/// [`copy_randombytes`](crate::rng::copy_randombytes), suitable for use with
/// [`crypto_auth_init`] and [`crypto_auth`].
///
/// Equivalent to libsodium's `crypto_auth_keygen`.
pub fn crypto_auth_keygen() -> Key {
    Key::gen()
}

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

    #[test]
    fn test_crypto_auth() {
        use rand_core::{OsRng, RngCore};
        use sodiumoxide::crypto::auth;
        use sodiumoxide::crypto::auth::Key as SOKey;

        use crate::rng::copy_randombytes;

        for _ in 0..20 {
            let mlen = (OsRng.next_u32() % 5000) as usize;
            let mut message = vec![0u8; mlen];
            copy_randombytes(&mut message);
            let key = crypto_auth_keygen();

            let so_tag =
                auth::authenticate(&message, &SOKey::from_slice(&key).expect("key failed"));

            let mut mac = Mac::new_byte_array();
            crypto_auth(&mut mac, &message, &key);

            assert_eq!(mac, so_tag.0);

            crypto_auth_verify(&mac, &message, &key).expect("verify failed");
            crypto_auth_verify(&mac, b"invalid message", &key)
                .expect_err("verify should have failed");
        }
    }
}
