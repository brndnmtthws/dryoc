//! # HMAC-SHA-256 authentication
//!
//! Implements libsodium's `crypto_auth_hmacsha256_*` functions.
//!
//! HMAC-SHA-256 authenticates a message with a shared secret key and writes a
//! 32-byte tag. Verification recomputes the tag and compares it in constant
//! time. The message is not encrypted, and the same key must be available to
//! both the sender and verifier.
//!
//! ```
//! use dryoc::classic::crypto_auth_hmacsha256::*;
//!
//! let key = crypto_auth_hmacsha256_keygen();
//! let message = b"What's past is prologue.";
//!
//! let mut mac = Mac::default();
//! crypto_auth_hmacsha256(&mut mac, message, &key);
//! crypto_auth_hmacsha256_verify(&mac, message, &key).expect("verify failed");
//! crypto_auth_hmacsha256_verify(&mac, b"invalid", &key).expect_err("verify should fail");
//! ```
//!
//! The incremental interface produces the same MAC as the one-shot interface:
//!
//! ```
//! use dryoc::classic::crypto_auth_hmacsha256::*;
//!
//! let key = crypto_auth_hmacsha256_keygen();
//! let mut one_shot = Mac::default();
//! crypto_auth_hmacsha256(&mut one_shot, b"Parting is such sweet sorrow.", &key);
//!
//! let mut state = crypto_auth_hmacsha256_init(&key);
//! crypto_auth_hmacsha256_update(&mut state, b"Parting is such ");
//! crypto_auth_hmacsha256_update(&mut state, b"sweet sorrow.");
//! let mut streaming = Mac::default();
//! crypto_auth_hmacsha256_final(state, &mut streaming);
//!
//! assert_eq!(one_shot, streaming);
//! ```

use crate::classic::crypto_auth_hmac_impl::{
    HmacState, hmac, hmac_final, hmac_init, hmac_keygen, hmac_update, hmac_verify,
};
use crate::constants::{CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA256_KEYBYTES};
use crate::error::Error;
use crate::sha256::Sha256;

/// Key for HMAC-SHA-256 message authentication.
pub type Key = [u8; CRYPTO_AUTH_HMACSHA256_KEYBYTES];
/// Message authentication code type for HMAC-SHA-256.
pub type Mac = [u8; CRYPTO_AUTH_HMACSHA256_BYTES];

/// Internal state for HMAC-SHA-256.
pub struct HmacSha256State(HmacState<Sha256, 64, CRYPTO_AUTH_HMACSHA256_BYTES>);

/// Authenticates `message` using `key`, and places the result into `mac`.
pub fn crypto_auth_hmacsha256(mac: &mut Mac, message: &[u8], key: &Key) {
    hmac::<Sha256, CRYPTO_AUTH_HMACSHA256_KEYBYTES, 64, CRYPTO_AUTH_HMACSHA256_BYTES>(
        mac, message, key,
    );
}

/// Verifies that `mac` is the correct authenticator for `message` using `key`.
///
/// # Errors
///
/// Returns an error if `mac` is not valid for `input` under `key`.
pub fn crypto_auth_hmacsha256_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    hmac_verify::<Sha256, CRYPTO_AUTH_HMACSHA256_KEYBYTES, 64, CRYPTO_AUTH_HMACSHA256_BYTES>(
        mac, input, key,
    )
}

/// Generates a random key for HMAC-SHA-256.
#[must_use]
pub fn crypto_auth_hmacsha256_keygen() -> Key {
    hmac_keygen()
}

/// Initializes the incremental interface for HMAC-SHA-256.
#[must_use]
pub fn crypto_auth_hmacsha256_init(key: &[u8]) -> HmacSha256State {
    HmacSha256State(hmac_init::<Sha256, 64, CRYPTO_AUTH_HMACSHA256_BYTES>(key))
}

/// Updates `state` for HMAC-SHA-256 with `input`.
pub fn crypto_auth_hmacsha256_update(state: &mut HmacSha256State, input: &[u8]) {
    hmac_update(&mut state.0, input);
}

/// Finalizes HMAC-SHA-256 and places the result into `output`.
pub fn crypto_auth_hmacsha256_final(state: HmacSha256State, output: &mut Mac) {
    hmac_final(state.0, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classic::crypto_auth_hmac_impl::test_util::hmac_classic_tests;

    hmac_classic_tests! {
        hash: sha2::Sha256,
        block: 64,
        bytes: CRYPTO_AUTH_HMACSHA256_BYTES,
        keybytes: CRYPTO_AUTH_HMACSHA256_KEYBYTES,
        tag: sha256,
        chunk: 17,
        one_shot: crypto_auth_hmacsha256,
        verify: crypto_auth_hmacsha256_verify,
        keygen: crypto_auth_hmacsha256_keygen,
        init: crypto_auth_hmacsha256_init,
        update: crypto_auth_hmacsha256_update,
        finalize: crypto_auth_hmacsha256_final,
        sodium_one_shot: auth_hmacsha256,
        sodium_state: AuthHmacSha256State,
        keybytes_test: test_one_shot_matches_incremental_for_keybytes_key(b"message"),
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
