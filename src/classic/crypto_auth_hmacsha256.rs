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
pub fn crypto_auth_hmacsha256_verify(mac: &Mac, input: &[u8], key: &Key) -> Result<(), Error> {
    hmac_verify::<Sha256, CRYPTO_AUTH_HMACSHA256_KEYBYTES, 64, CRYPTO_AUTH_HMACSHA256_BYTES>(
        mac, input, key,
    )
}

/// Generates a random key for HMAC-SHA-256.
pub fn crypto_auth_hmacsha256_keygen() -> Key {
    hmac_keygen()
}

/// Initializes the incremental interface for HMAC-SHA-256.
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

    fn compute_hmac(key: &[u8], message: &[u8]) -> Mac {
        let mut mac = Mac::default();
        let mut state = crypto_auth_hmacsha256_init(key);
        crypto_auth_hmacsha256_update(&mut state, message);
        crypto_auth_hmacsha256_final(state, &mut mac);
        mac
    }

    fn assert_hmac(key: &[u8], message: &[u8], expected_hex: &str) {
        let mac = compute_hmac(key, message);
        let expected = hex::decode(expected_hex).expect("hex failed");
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        assert_hmac(
            &key,
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
    }

    #[test]
    fn test_rfc4231_short_key_case_2() {
        assert_hmac(
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
    }

    #[test]
    fn test_rfc4231_long_message_case_3() {
        let key = [0xaau8; 20];
        let message = [0xddu8; 50];
        assert_hmac(
            &key,
            &message,
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        );
    }

    #[test]
    fn test_rfc4231_case_4() {
        let key =
            hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").expect("hex failed");
        let message = [0xcdu8; 50];
        assert_hmac(
            &key,
            &message,
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        );
    }

    #[test]
    fn test_rfc4231_long_key_case_6() {
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        );
    }

    #[test]
    fn test_rfc4231_long_key_and_message_case_7() {
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"This is a test using a larger than block-size key and a larger than block-size data. \
              The key needs to be hashed before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        );
    }

    #[test]
    fn test_one_shot_matches_incremental_for_keybytes_key() {
        let key = [0x0bu8; CRYPTO_AUTH_HMACSHA256_KEYBYTES];
        let message = b"message";
        let mut one_shot = Mac::default();
        crypto_auth_hmacsha256(&mut one_shot, message, &key);
        assert_eq!(one_shot, compute_hmac(&key, message));
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_libsodium_compatibility() {
        use sodiumoxide::crypto::auth::hmacsha256;

        let key = crypto_auth_hmacsha256_keygen();
        let message = b"message to authenticate";
        let so_key = hmacsha256::Key::from_slice(&key).expect("key failed");
        let so_mac = hmacsha256::authenticate(message, &so_key);

        let mut mac = Mac::default();
        crypto_auth_hmacsha256(&mut mac, message, &key);
        assert_eq!(mac.as_slice(), so_mac.as_ref());
        crypto_auth_hmacsha256_verify(&mac, message, &key).expect("verify failed");

        let mut state = crypto_auth_hmacsha256_init(&key);
        crypto_auth_hmacsha256_update(&mut state, b"message ");
        crypto_auth_hmacsha256_update(&mut state, b"to authenticate");
        let mut state_mac = Mac::default();
        crypto_auth_hmacsha256_final(state, &mut state_mac);
        assert_eq!(state_mac.as_slice(), so_mac.as_ref());
    }
}
