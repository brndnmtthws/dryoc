//! # HMAC-SHA-512 authentication
//!
//! Implements libsodium's `crypto_auth_hmacsha512_*` functions.
//!
//! HMAC-SHA-512 authenticates a message with a shared secret key and writes a
//! 64-byte tag. Use it when a protocol specifically requires HMAC-SHA-512.
//! Verification fails if either the message or the tag has been changed.
//!
//! ```
//! use dryoc::classic::crypto_auth_hmacsha512::*;
//!
//! let key = crypto_auth_hmacsha512_keygen();
//! let message = b"One touch of nature makes the whole world kin.";
//!
//! let mut mac: Mac = [0u8; 64];
//! crypto_auth_hmacsha512(&mut mac, message, &key);
//! crypto_auth_hmacsha512_verify(&mac, message, &key).expect("verify failed");
//! crypto_auth_hmacsha512_verify(&mac, b"invalid", &key).expect_err("verify should fail");
//! ```
//!
//! The incremental interface produces the same MAC as the one-shot interface:
//!
//! ```
//! use dryoc::classic::crypto_auth_hmacsha512::*;
//!
//! let key = crypto_auth_hmacsha512_keygen();
//! let mut one_shot: Mac = [0u8; 64];
//! crypto_auth_hmacsha512(
//!     &mut one_shot,
//!     b"How far that little candle throws his beams!",
//!     &key,
//! );
//!
//! let mut state = crypto_auth_hmacsha512_init(&key);
//! crypto_auth_hmacsha512_update(&mut state, b"How far that little candle ");
//! crypto_auth_hmacsha512_update(&mut state, b"throws his beams!");
//! let mut streaming: Mac = [0u8; 64];
//! crypto_auth_hmacsha512_final(state, &mut streaming);
//!
//! assert_eq!(one_shot, streaming);
//! ```

use crate::classic::crypto_auth_hmac_impl::{
    HmacState, hmac, hmac_final, hmac_init, hmac_keygen, hmac_update, hmac_verify,
};
use crate::constants::{CRYPTO_AUTH_HMACSHA512_BYTES, CRYPTO_AUTH_HMACSHA512_KEYBYTES};
use crate::error::Error;
use crate::sha512::Sha512;

/// Key for HMAC-SHA-512 message authentication.
pub type Key = [u8; CRYPTO_AUTH_HMACSHA512_KEYBYTES];
/// Message authentication code type for HMAC-SHA-512.
pub type Mac = [u8; CRYPTO_AUTH_HMACSHA512_BYTES];

/// Internal state for HMAC-SHA-512.
pub struct HmacSha512State(HmacState<Sha512, 128, CRYPTO_AUTH_HMACSHA512_BYTES>);

/// Authenticates `message` using `key`, and places the result into `mac`.
pub fn crypto_auth_hmacsha512(mac: &mut Mac, message: &[u8], key: &Key) {
    hmac::<Sha512, CRYPTO_AUTH_HMACSHA512_KEYBYTES, 128, CRYPTO_AUTH_HMACSHA512_BYTES>(
        mac, message, key,
    );
}

/// Verifies that `mac` is the correct authenticator for `message` using `key`.
///
/// # Errors
///
/// Returns an error if `mac` is not valid for `input` under `key`.
pub fn crypto_auth_hmacsha512_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    hmac_verify::<Sha512, CRYPTO_AUTH_HMACSHA512_KEYBYTES, 128, CRYPTO_AUTH_HMACSHA512_BYTES>(
        mac, input, key,
    )
}

/// Generates a random key for HMAC-SHA-512.
pub fn crypto_auth_hmacsha512_keygen() -> Key {
    hmac_keygen()
}

/// Initializes the incremental interface for HMAC-SHA-512.
pub fn crypto_auth_hmacsha512_init(key: &[u8]) -> HmacSha512State {
    HmacSha512State(hmac_init::<Sha512, 128, CRYPTO_AUTH_HMACSHA512_BYTES>(key))
}

/// Updates `state` for HMAC-SHA-512 with `input`.
pub fn crypto_auth_hmacsha512_update(state: &mut HmacSha512State, input: &[u8]) {
    hmac_update(&mut state.0, input);
}

/// Finalizes HMAC-SHA-512 and places the result into `output`.
pub fn crypto_auth_hmacsha512_final(state: HmacSha512State, output: &mut Mac) {
    hmac_final(state.0, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classic::crypto_auth_hmac_impl::test_util::hmac_classic_tests;

    hmac_classic_tests! {
        hash: sha2::Sha512,
        block: 128,
        bytes: CRYPTO_AUTH_HMACSHA512_BYTES,
        keybytes: CRYPTO_AUTH_HMACSHA512_KEYBYTES,
        tag: sha512,
        chunk: 31,
        one_shot: crypto_auth_hmacsha512,
        verify: crypto_auth_hmacsha512_verify,
        keygen: crypto_auth_hmacsha512_keygen,
        init: crypto_auth_hmacsha512_init,
        update: crypto_auth_hmacsha512_update,
        finalize: crypto_auth_hmacsha512_final,
        sodium_one_shot: auth_hmacsha512,
        sodium_state: AuthHmacSha512State,
        keybytes_test: test_rfc4231_case_1_matches_one_shot_for_keybytes_key(b"Hi There"),
        rfc4231: {
            test_rfc4231_case_1 => RFC4231_CASE_1,
            test_rfc4231_short_key_case_2 => RFC4231_CASE_2,
            test_rfc4231_long_message_case_3 => RFC4231_CASE_3,
            test_rfc4231_case_4 => RFC4231_CASE_4,
            test_rfc4231_long_key_case_6 => RFC4231_CASE_6,
            test_rfc4231_long_key_and_message_case_7 => RFC4231_CASE_7,
        },
    }
}
