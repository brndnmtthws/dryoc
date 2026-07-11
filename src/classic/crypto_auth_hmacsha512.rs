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

    fn compute_hmac(key: &[u8], message: &[u8]) -> Mac {
        let mut mac = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
        let mut state = crypto_auth_hmacsha512_init(key);
        crypto_auth_hmacsha512_update(&mut state, message);
        crypto_auth_hmacsha512_final(state, &mut mac);
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
            concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb0",
                "2379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4",
                "be9d914eeb61f1702e696c203a126854",
            ),
        );
    }

    #[test]
    fn test_rfc4231_short_key_case_2() {
        assert_hmac(
            b"Jefe",
            b"what do ya want for nothing?",
            concat!(
                "164b7a7bfcf819e2e395fbe73b56e0a3",
                "87bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fd",
                "caeab1a34d4a6b4b636e070a38bce737",
            ),
        );
    }

    #[test]
    fn test_rfc4231_long_message_case_3() {
        let key = [0xaau8; 20];
        let message = [0xddu8; 50];
        assert_hmac(
            &key,
            &message,
            concat!(
                "fa73b0089d56a284efb0f0756c890be9",
                "b1b5dbdd8ee81a3655f83e33b2279d39",
                "bf3e848279a722c806b485a47e67c807",
                "b946a337bee8942674278859e13292fb",
            ),
        );
    }

    #[test]
    fn test_rfc4231_long_key_case_6() {
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            concat!(
                "80b24263c7c1a3ebb71493c1dd7be8b4",
                "9b46d1f41b4aeec1121b013783f8f352",
                "6b56d037e05f2598bd0fd2215d6a1e52",
                "95e64f73f63f0aec8b915a985d786598",
            ),
        );
    }

    #[test]
    fn test_rfc4231_long_key_and_message_case_7() {
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"This is a test using a larger than block-size key and a larger than block-size data. \
              The key needs to be hashed before being used by the HMAC algorithm.",
            concat!(
                "e37b6a775dc87dbaa4dfa9f96e5e3ffd",
                "debd71f8867289865df5a32d20cdc944",
                "b6022cac3c4982b10d5eeb55c3e4de15",
                "134676fb6de0446065c97440fa8c6a58",
            ),
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
            concat!(
                "b0ba465637458c6990e5a8c5f61d4af7",
                "e576d97ff94b872de76f8050361ee3db",
                "a91ca5c11aa25eb4d679275cc5788063",
                "a5f19741120c4f2de2adebeb10a298dd",
            ),
        );
    }

    #[test]
    fn test_rfc4231_case_1_matches_one_shot_for_keybytes_key() {
        let key = [0x0bu8; CRYPTO_AUTH_HMACSHA512_KEYBYTES];
        let message = b"Hi There";
        let mut one_shot = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
        crypto_auth_hmacsha512(&mut one_shot, message, &key);
        assert_eq!(one_shot, compute_hmac(&key, message));
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_libsodium_compatibility() {
        use sodiumoxide::crypto::auth::hmacsha512;

        let key = crypto_auth_hmacsha512_keygen();
        let message = b"message to authenticate";
        let so_key = hmacsha512::Key::from_slice(&key).expect("key failed");
        let so_mac = hmacsha512::authenticate(message, &so_key);

        let mut mac = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
        crypto_auth_hmacsha512(&mut mac, message, &key);
        assert_eq!(mac.as_slice(), so_mac.as_ref());
        crypto_auth_hmacsha512_verify(&mac, message, &key).expect("verify failed");

        let mut state = crypto_auth_hmacsha512_init(&key);
        crypto_auth_hmacsha512_update(&mut state, b"message ");
        crypto_auth_hmacsha512_update(&mut state, b"to authenticate");
        let mut state_mac = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
        crypto_auth_hmacsha512_final(state, &mut state_mac);
        assert_eq!(state_mac.as_slice(), so_mac.as_ref());
    }
}
