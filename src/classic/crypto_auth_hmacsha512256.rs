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
pub fn crypto_auth_hmacsha512256_keygen() -> Key {
    hmac_keygen()
}

/// Initializes the incremental interface for HMAC-SHA-512-256.
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
    use crate::test_prelude::*;

    fn compute_hmac(key: &[u8], message: &[u8]) -> Mac {
        let mut mac = Mac::default();
        let mut state = crypto_auth_hmacsha512256_init(key);
        crypto_auth_hmacsha512256_update(&mut state, message);
        crypto_auth_hmacsha512256_final(state, &mut mac);
        mac
    }

    fn assert_hmac(key: &[u8], message: &[u8], expected_hex: &str) {
        let mac = compute_hmac(key, message);
        let expected = hex::decode(expected_hex).expect("hex failed");
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_rfc4231_case_1_truncated() {
        let key = [0x0bu8; 20];
        assert_hmac(
            &key,
            b"Hi There",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
        );
    }

    #[test]
    fn test_rfc4231_short_key_case_2_truncated() {
        assert_hmac(
            b"Jefe",
            b"what do ya want for nothing?",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
        );
    }

    #[test]
    fn test_rfc4231_long_key_case_6_truncated() {
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
        );
    }

    #[test]
    fn test_rfc4231_long_key_and_message_case_7_truncated() {
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"This is a test using a larger than block-size key and a larger than block-size data. \
              The key needs to be hashed before being used by the HMAC algorithm.",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944",
        );
    }

    #[test]
    fn test_one_shot_matches_incremental_for_keybytes_key() {
        let key = [0x0bu8; CRYPTO_AUTH_HMACSHA512256_KEYBYTES];
        let message = b"message";
        let mut one_shot = Mac::default();
        crypto_auth_hmacsha512256(&mut one_shot, message, &key);
        assert_eq!(one_shot, compute_hmac(&key, message));
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_libsodium_compatibility() {
        use crate::native_test_util::auth_hmacsha512256;

        let key = crypto_auth_hmacsha512256_keygen();
        let message = b"message to authenticate";
        let so_mac = auth_hmacsha512256(message, &key);

        let mut mac = Mac::default();
        crypto_auth_hmacsha512256(&mut mac, message, &key);
        assert_eq!(mac.as_slice(), so_mac.as_slice());
        crypto_auth_hmacsha512256_verify(&mac, message, &key).expect("verify failed");

        let mut state = crypto_auth_hmacsha512256_init(&key);
        crypto_auth_hmacsha512256_update(&mut state, b"message ");
        crypto_auth_hmacsha512256_update(&mut state, b"to authenticate");
        let mut state_mac = Mac::default();
        crypto_auth_hmacsha512256_final(state, &mut state_mac);
        assert_eq!(state_mac.as_slice(), so_mac.as_slice());
    }

    fn manual_hmac(key: &[u8], message: &[u8]) -> Mac {
        crate::classic::crypto_auth_hmac_impl::test_util::reference_hmac::<
            sha2::Sha512,
            128,
            CRYPTO_AUTH_HMACSHA512256_BYTES,
        >(key, message)
    }

    #[cfg(dryoc_native_tests)]
    fn sodium_hmac(key: &[u8], message: &[u8]) -> Mac {
        crate::native_test_util::init();
        let mut state = unsafe { core::mem::zeroed() };
        assert_eq!(
            unsafe {
                libsodium_sys::crypto_auth_hmacsha512256_init(&mut state, key.as_ptr(), key.len())
            },
            0
        );
        assert_eq!(
            unsafe {
                libsodium_sys::crypto_auth_hmacsha512256_update(&mut state, core::ptr::null(), 0)
            },
            0
        );
        for chunk in message.chunks(31) {
            assert_eq!(
                unsafe {
                    libsodium_sys::crypto_auth_hmacsha512256_update(
                        &mut state,
                        chunk.as_ptr(),
                        chunk.len() as u64,
                    )
                },
                0
            );
        }
        let mut mac = Mac::default();
        assert_eq!(
            unsafe { libsodium_sys::crypto_auth_hmacsha512256_final(&mut state, mac.as_mut_ptr()) },
            0
        );
        mac
    }

    /// Empty and block-boundary keys/messages, including the key-hashing
    /// transition at B+1, against the independent `sha2` construction and,
    /// natively, libsodium's variable-key incremental API.
    #[test]
    fn test_key_and_message_block_boundaries() {
        for key_len in [0usize, 127, 128, 129] {
            let key: Vec<u8> = (0..key_len as u32).map(|i| (i * 37 % 251) as u8).collect();
            for message_len in [0usize, 127, 128, 129] {
                let message: Vec<u8> = (0..message_len as u32)
                    .map(|i| (i * 31 % 251) as u8)
                    .collect();
                let expected = manual_hmac(&key, &message);
                let mut state = crypto_auth_hmacsha512256_init(&key);
                crypto_auth_hmacsha512256_update(&mut state, b"");
                for chunk in message.chunks(31) {
                    crypto_auth_hmacsha512256_update(&mut state, chunk);
                    crypto_auth_hmacsha512256_update(&mut state, b"");
                }
                let mut actual = Mac::default();
                crypto_auth_hmacsha512256_final(state, &mut actual);
                assert_eq!(actual, expected, "key {key_len}, message {message_len}");
                #[cfg(dryoc_native_tests)]
                assert_eq!(actual, sodium_hmac(&key, &message));
            }
        }
    }
}
