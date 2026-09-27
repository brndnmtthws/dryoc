//! # HMAC-SHA-512-256 authentication
//!
//! Implements libsodium's `crypto_auth_hmacsha512256_*` functions.
//!
//! HMAC-SHA-512-256 is HMAC-SHA-512 with a 32-byte truncated output. This is
//! libsodium's default `crypto_auth` construction. It authenticates a public
//! message with a shared secret key; it does not hide the message contents.
//!
//! ```
//! use dryoc::classic::crypto_auth_hmacsha512256::*;
//!
//! let key = crypto_auth_hmacsha512256_keygen();
//! let message = b"No legacy is so rich as honesty.";
//!
//! let mut mac = Mac::default();
//! crypto_auth_hmacsha512256(&mut mac, message, &key);
//! crypto_auth_hmacsha512256_verify(&mac, message, &key).expect("verify failed");
//! crypto_auth_hmacsha512256_verify(&mac, b"invalid", &key).expect_err("verify should fail");
//! ```
//!
//! The incremental interface produces the same truncated HMAC-SHA-512 MAC as
//! the one-shot interface:
//!
//! ```
//! use dryoc::classic::crypto_auth_hmacsha512256::*;
//!
//! let key = crypto_auth_hmacsha512256_keygen();
//! let mut one_shot = Mac::default();
//! crypto_auth_hmacsha512256(
//!     &mut one_shot,
//!     b"Small cheer and great welcome makes a merry feast.",
//!     &key,
//! );
//!
//! let mut state = crypto_auth_hmacsha512256_init(&key);
//! crypto_auth_hmacsha512256_update(&mut state, b"Small cheer and great welcome ");
//! crypto_auth_hmacsha512256_update(&mut state, b"makes a merry feast.");
//! let mut streaming = Mac::default();
//! crypto_auth_hmacsha512256_final(state, &mut streaming);
//!
//! assert_eq!(one_shot, streaming);
//! ```

use crate::classic::crypto_auth_hmac_impl::hmac_keygen;
use crate::classic::crypto_auth_hmacsha512::{
    HmacSha512State, crypto_auth_hmacsha512_final, crypto_auth_hmacsha512_init,
    crypto_auth_hmacsha512_update,
};
use crate::constants::{
    CRYPTO_AUTH_HMACSHA512_BYTES, CRYPTO_AUTH_HMACSHA512256_BYTES,
    CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
};
use crate::error::Error;
use crate::utils::{verify_ct, zeroize_bytes};

/// Key for HMAC-SHA-512-256 message authentication.
pub type Key = [u8; CRYPTO_AUTH_HMACSHA512256_KEYBYTES];
/// Message authentication code type for HMAC-SHA-512-256.
pub type Mac = [u8; CRYPTO_AUTH_HMACSHA512256_BYTES];
/// Internal state for HMAC-SHA-512-256.
pub type HmacSha512256State = HmacSha512State;

/// Authenticates `message` using `key`, and places the result into `mac`.
pub fn crypto_auth_hmacsha512256(mac: &mut Mac, message: &[u8], key: &Key) {
    let mut state = crypto_auth_hmacsha512256_init(key);
    crypto_auth_hmacsha512256_update(&mut state, message);
    crypto_auth_hmacsha512256_final(state, mac);
}

/// Verifies that `mac` is the correct authenticator for `message` using `key`.
///
/// # Errors
///
/// Returns an error if `mac` is not valid for `input` under `key`.
pub fn crypto_auth_hmacsha512256_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    let mut computed_mac = Mac::default();
    crypto_auth_hmacsha512256(&mut computed_mac, input, key);
    let result = verify_ct(mac, &computed_mac);
    zeroize_bytes(&mut computed_mac);
    result
}

/// Generates a random key for HMAC-SHA-512-256.
#[must_use]
pub fn crypto_auth_hmacsha512256_keygen() -> Key {
    hmac_keygen()
}

/// Initializes the incremental interface for HMAC-SHA-512-256.
#[must_use]
pub fn crypto_auth_hmacsha512256_init(key: &[u8]) -> HmacSha512256State {
    crypto_auth_hmacsha512_init(key)
}

/// Updates `state` for HMAC-SHA-512-256 with `input`.
pub fn crypto_auth_hmacsha512256_update(state: &mut HmacSha512256State, input: &[u8]) {
    crypto_auth_hmacsha512_update(state, input);
}

/// Finalizes HMAC-SHA-512-256 and places the truncated result into `output`.
pub fn crypto_auth_hmacsha512256_final(state: HmacSha512256State, output: &mut Mac) {
    let mut full_output = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
    crypto_auth_hmacsha512_final(state, &mut full_output);
    output.copy_from_slice(&full_output[..CRYPTO_AUTH_HMACSHA512256_BYTES]);
    zeroize_bytes(&mut full_output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classic::crypto_auth_hmac_impl::test_util::hmac_classic_tests;

    hmac_classic_tests! {
        hash: sha2::Sha512,
        block: 128,
        bytes: CRYPTO_AUTH_HMACSHA512256_BYTES,
        keybytes: CRYPTO_AUTH_HMACSHA512256_KEYBYTES,
        tag: sha512256,
        chunk: 31,
        one_shot: crypto_auth_hmacsha512256,
        verify: crypto_auth_hmacsha512256_verify,
        keygen: crypto_auth_hmacsha512256_keygen,
        init: crypto_auth_hmacsha512256_init,
        update: crypto_auth_hmacsha512256_update,
        finalize: crypto_auth_hmacsha512256_final,
        sodium_one_shot: auth_hmacsha512256,
        sodium_state: AuthHmacSha512256State,
        keybytes_test: test_one_shot_matches_incremental_for_keybytes_key(b"message"),
        rfc4231: {
            test_rfc4231_case_1_truncated => RFC4231_CASE_1,
            test_rfc4231_short_key_case_2_truncated => RFC4231_CASE_2,
            test_rfc4231_long_key_case_6_truncated => RFC4231_CASE_6,
            test_rfc4231_long_key_and_message_case_7_truncated => RFC4231_CASE_7,
        },
    }
}
