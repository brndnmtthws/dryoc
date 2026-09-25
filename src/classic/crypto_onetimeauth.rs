//! # One-time authentication
//!
//! Implements one-time authentication using the Poly1305 algorithm, compatible
//! with libsodium's `crypto_onetimeauth_*` functions.
//!
//! A Poly1305 key must be used for only one message. Reusing a key for
//! different messages can allow forgeries. This primitive authenticates data
//! but does not encrypt it.
//!
//! # Classic API single-part example
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::classic::crypto_onetimeauth::{
//!     Mac, crypto_onetimeauth, crypto_onetimeauth_keygen, crypto_onetimeauth_verify,
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
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::classic::crypto_onetimeauth::{
//!     Mac, crypto_onetimeauth_final, crypto_onetimeauth_init, crypto_onetimeauth_keygen,
//!     crypto_onetimeauth_update, crypto_onetimeauth_verify,
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
use crate::constants::{
    CRYPTO_ONETIMEAUTH_BYTES, CRYPTO_ONETIMEAUTH_KEYBYTES, CRYPTO_ONETIMEAUTH_POLY1305_BYTES,
    CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES,
};
use crate::error::Error;
use crate::poly1305::Poly1305;
use crate::types::*;
use crate::utils::verify_ct;
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

    verify_ct(mac, &computed_mac)
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
///
/// # Errors
///
/// Returns an error if `mac` is not valid for `input` under `key`.
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
    Key::generate()
}

/// Initializes the incremental Poly1305-based one-time authentication.
///
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
    use crate::test_prelude::*;

    /// RFC 8439 section 2.5.2: key, message and tag.
    const RFC_KEY: Key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    const RFC_MESSAGE: &[u8] = b"Cryptographic Forum Research Group";
    const RFC_TAG: Mac = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];

    /// Update boundaries inside, at and just past the first and second
    /// Poly1305 block of the 34-byte RFC message.
    const SPLITS: [usize; 8] = [0, 1, 15, 16, 17, 31, 32, 33];

    fn incremental(key: &Key, chunks: &[&[u8]]) -> Mac {
        let mut state = crypto_onetimeauth_init(key);
        for chunk in chunks {
            crypto_onetimeauth_update(&mut state, chunk);
        }
        let mut mac = Mac::default();
        crypto_onetimeauth_final(state, &mut mac);
        mac
    }

    /// The RFC 8439 vector one-shot, verified, and incrementally split at
    /// every boundary in [`SPLITS`] (two updates), and at all of them at
    /// once (nine updates, one of them empty).
    #[test]
    fn test_rfc8439_vector_one_shot_and_incremental() {
        let mut mac = Mac::default();
        crypto_onetimeauth(&mut mac, RFC_MESSAGE, &RFC_KEY);
        assert_eq!(mac, RFC_TAG);
        crypto_onetimeauth_verify(&RFC_TAG, RFC_MESSAGE, &RFC_KEY).expect("verify");

        for split in SPLITS {
            let (head, rest) = RFC_MESSAGE.split_at(split);
            assert_eq!(
                incremental(&RFC_KEY, &[head, rest]),
                RFC_TAG,
                "split {split}"
            );
        }

        let mut chunks = Vec::new();
        let mut cuts = SPLITS.to_vec();
        cuts.push(RFC_MESSAGE.len());
        for window in cuts.windows(2) {
            chunks.push(&RFC_MESSAGE[window[0]..window[1]]);
        }
        assert_eq!(incremental(&RFC_KEY, &[&[][..], RFC_MESSAGE]), RFC_TAG);
        assert_eq!(incremental(&RFC_KEY, &chunks), RFC_TAG);
    }

    /// Verification rejects a tag with any single byte altered, a message
    /// with its last byte altered or truncated, and the wrong key.
    #[test]
    fn test_verify_rejects_mutations() {
        for index in 0..CRYPTO_ONETIMEAUTH_BYTES {
            let mut mac = RFC_TAG;
            mac[index] ^= 1;
            assert!(
                matches!(
                    crypto_onetimeauth_verify(&mac, RFC_MESSAGE, &RFC_KEY),
                    Err(Error::AuthenticationFailed)
                ),
                "tag byte {index}"
            );
        }

        let mut message = RFC_MESSAGE.to_vec();
        *message.last_mut().unwrap() ^= 1;
        assert!(matches!(
            crypto_onetimeauth_verify(&RFC_TAG, &message, &RFC_KEY),
            Err(Error::AuthenticationFailed)
        ));
        assert!(matches!(
            crypto_onetimeauth_verify(&RFC_TAG, &RFC_MESSAGE[..RFC_MESSAGE.len() - 1], &RFC_KEY),
            Err(Error::AuthenticationFailed)
        ));

        let mut key = RFC_KEY;
        key[31] ^= 1;
        assert!(matches!(
            crypto_onetimeauth_verify(&RFC_TAG, RFC_MESSAGE, &key),
            Err(Error::AuthenticationFailed)
        ));
    }

    /// One-shot, verify and incremental (split at every boundary in
    /// [`SPLITS`]) against libsodium for deterministic keys and messages of
    /// every length around the Poly1305 block and past a kilobyte.
    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_matches_libsodium_at_block_boundaries() {
        use crate::utils::test_util::XorShift64;

        crate::native_test_util::init();

        let mut rng = XorShift64::new(0x0a3e_71c9_5b2d_f804);
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 1023, 1024, 1025] {
            let key: Key = rng.next_bytes32();
            let message: Vec<u8> = (0..len.div_ceil(8))
                .flat_map(|_| rng.next_u64().to_le_bytes())
                .take(len)
                .collect();
            let mut expected = Mac::default();
            // SAFETY: `expected` is `crypto_onetimeauth_BYTES` long, `message`
            // is valid for its length and `key` is
            // `crypto_onetimeauth_KEYBYTES`.
            let rc = unsafe {
                libsodium_sys::crypto_onetimeauth(
                    expected.as_mut_ptr(),
                    message.as_ptr(),
                    len as libc::c_ulonglong,
                    key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);

            let mut mac = Mac::default();
            crypto_onetimeauth(&mut mac, &message, &key);
            assert_eq!(mac, expected, "len {len}");
            crypto_onetimeauth_verify(&expected, &message, &key).expect("verify");
            for split in SPLITS.into_iter().filter(|&split| split <= len) {
                let (head, rest) = message.split_at(split);
                assert_eq!(
                    incremental(&key, &[head, rest]),
                    expected,
                    "len {len}, split {split}"
                );
            }
        }
    }
}
