//! # Public-key signatures
//!
//! This module implements libsodium's public-key signatures, based on Ed25519.
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_sign::*;
//! use dryoc::constants::CRYPTO_SIGN_BYTES;
//!
//! // Generate a random signing keypair
//! let (public_key, secret_key) = crypto_sign_keypair();
//! let message = b"These violent delights have violent ends...";
//!
//! // Signed message buffer needs to be correct length
//! let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_BYTES];
//!
//! // Sign the message, placing the result into `signed_message`
//! crypto_sign(&mut signed_message, message, &secret_key).expect("sign failed");
//!
//! // Allocate a new buffer for opening the message
//! let mut opened_message = vec![0u8; message.len()];
//!
//! // Open the signed message, verifying the signature
//! crypto_sign_open(&mut opened_message, &signed_message, &public_key).expect("verify failed");
//!
//! assert_eq!(&opened_message, message);
//!
//! // Create an invalid message
//! let mut invalid_signed_message = signed_message.clone();
//! invalid_signed_message[5] = !invalid_signed_message[5];
//!
//! // An invalid message can't be verified
//! crypto_sign_open(&mut opened_message, &invalid_signed_message, &public_key)
//!     .expect_err("open should not succeed");
//! ```
//!
//! ## Classic API example, detached mode
//!
//! ```
//! use dryoc::classic::crypto_sign::*;
//! use dryoc::constants::CRYPTO_SIGN_BYTES;
//!
//! // Generate a random signing keypair
//! let (public_key, secret_key) = crypto_sign_keypair();
//! let message = b"Brevity is the soul of wit.";
//! let mut signature = [0u8; CRYPTO_SIGN_BYTES];
//!
//! // Sign our message
//! crypto_sign_detached(&mut signature, message, &secret_key).expect("sign failed");
//!
//! // Verify the signature
//! crypto_sign_verify_detached(&signature, message, &public_key).expect("verify failed");
//! ```

use super::crypto_sign_ed25519::*;
pub use super::crypto_sign_ed25519::{
    PublicKey, SecretKey, crypto_sign_ed25519_sk_to_pk, crypto_sign_ed25519_sk_to_seed,
};
use crate::error::Error;

/// In-place variant of [`crypto_sign_keypair`].
pub fn crypto_sign_keypair_inplace(public_key: &mut PublicKey, secret_key: &mut SecretKey) {
    crypto_sign_ed25519_keypair_inplace(public_key, secret_key)
}

/// In-place variant of [`crypto_sign_seed_keypair`].
pub fn crypto_sign_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &[u8; 32],
) {
    crypto_sign_ed25519_seed_keypair_inplace(public_key, secret_key, seed)
}

/// Randomly generates a new Ed25519 `(PublicKey, SecretKey)` keypair that can
/// be used for message signing.
pub fn crypto_sign_keypair() -> (PublicKey, SecretKey) {
    crypto_sign_ed25519_keypair()
}

/// Returns a keypair derived from `seed`, which can be used for message
/// signing.
pub fn crypto_sign_seed_keypair(seed: &[u8; 32]) -> (PublicKey, SecretKey) {
    crypto_sign_ed25519_seed_keypair(seed)
}

/// Signs `message`, placing the result into `signed_message`. The length of
/// `signed_message` should be the length of the message plus
/// [`CRYPTO_SIGN_BYTES`](crate::constants::CRYPTO_SIGN_BYTES).
///
/// This function is compatible with libsodium's `crypto_sign`; the
/// `ED25519_NONDETERMINISTIC` feature is not supported.
///
/// # Errors
///
/// Returns an error if `signed_message` is not exactly one signature longer
/// than `message`, or signing fails.
pub fn crypto_sign(
    signed_message: &mut [u8],
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    crypto_sign_ed25519(signed_message, message, secret_key)
}

/// Verifies the signature of `signed_message`, placing the result into
/// `message`. The length of `message` should be the length of the signed
/// message minus [`CRYPTO_SIGN_BYTES`](crate::constants::CRYPTO_SIGN_BYTES).
///
/// This function is compatible with libsodium's `crypto_sign_open`; the
/// `ED25519_NONDETERMINISTIC` feature is not supported.
///
/// # Errors
///
/// Returns an error if `signed_message` is too short, `message` has the wrong
/// length, or the signature or public key is invalid.
pub fn crypto_sign_open(
    message: &mut [u8],
    signed_message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_open(message, signed_message, public_key)
}

/// Signs `message`, placing the signature into `signature` upon success.
/// Detached variant of [`crypto_sign_open`].
///
/// This function is compatible with libsodium's `crypto_sign_detached`; the
/// `ED25519_NONDETERMINISTIC` feature is not supported.
///
/// # Errors
///
/// The fixed-size signature and secret-key types satisfy the current
/// implementation's requirements, so this function does not return an error
/// in normal use. The [`Result`] is retained for API compatibility.
pub fn crypto_sign_detached(
    signature: &mut Signature,
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_detached(signature, message, secret_key)
}

/// Verifies that `signature` is a valid signature for `message` using the given
/// `public_key`.
///
/// This function is compatible with libsodium's `crypto_sign_verify_detached`;
/// the `ED25519_NONDETERMINISTIC` feature is not supported.
///
/// # Errors
///
/// Returns an error if `signature` or `public_key` is malformed, or if the
/// signature does not authenticate `message`.
pub fn crypto_sign_verify_detached(
    signature: &Signature,
    message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_verify_detached(signature, message, public_key)
}

/// State for incremental signing interface.
pub struct SignerState {
    state: Ed25519SignerState,
}

/// Initializes the incremental signing interface.
pub fn crypto_sign_init() -> SignerState {
    SignerState {
        state: crypto_sign_ed25519ph_init(),
    }
}

/// Updates the signature for `state` with `message`.
pub fn crypto_sign_update(state: &mut SignerState, message: &[u8]) {
    crypto_sign_ed25519ph_update(&mut state.state, message)
}

/// Finalizes the incremental signature for `state`, using `secret_key`, copying
/// the result into `signature` upon success, and consuming the state.
///
/// # Errors
///
/// The fixed-size signature and secret-key types satisfy the current
/// implementation's requirements, so this function does not return an error
/// in normal use. The [`Result`] is retained for API compatibility.
pub fn crypto_sign_final_create(
    state: SignerState,
    signature: &mut Signature,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    crypto_sign_ed25519ph_final_create(state.state, signature, secret_key)
}

/// Verifies the computed signature for `state` and `public_key` matches
/// `signature`, consuming the state.
///
/// # Errors
///
/// Returns an error if `signature` or `public_key` is malformed, or if the
/// signature does not match the accumulated message.
pub fn crypto_sign_final_verify(
    state: SignerState,
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), Error> {
    crypto_sign_ed25519ph_final_verify(state.state, signature, public_key)
}

#[cfg(test)]
mod consistency_tests {
    use super::*;
    use crate::constants::CRYPTO_SIGN_BYTES;
    use crate::test_prelude::*;
    use crate::utils::test_util::XorShift64;

    /// A combined signed message is the detached signature followed by the
    /// message, for the empty, one-byte and 1023-byte messages (the RFC 8032
    /// vector lengths); the signature verifies detached and the message opens.
    #[test]
    fn combined_signature_prefix_matches_detached() {
        let mut rng = XorShift64::new(0x1f83_d9ab_fb41_bd6b);
        let (public_key, secret_key) = crypto_sign_seed_keypair(&[21u8; 32]);
        let mut random = Vec::with_capacity(1023);
        while random.len() < 1023 {
            random.extend_from_slice(&rng.next_bytes32());
        }
        random.truncate(1023);

        for message in [&[][..], &[0x72], &random] {
            let mut signature = [0u8; CRYPTO_SIGN_BYTES];
            crypto_sign_detached(&mut signature, message, &secret_key).unwrap();

            let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_BYTES];
            crypto_sign(&mut signed_message, message, &secret_key).unwrap();
            assert_eq!(
                signed_message[..CRYPTO_SIGN_BYTES],
                signature,
                "{}",
                message.len()
            );
            assert_eq!(
                signed_message[CRYPTO_SIGN_BYTES..],
                *message,
                "{}",
                message.len()
            );

            crypto_sign_verify_detached(&signature, message, &public_key).unwrap();
            let mut opened = vec![0xa5; message.len()];
            crypto_sign_open(&mut opened, &signed_message, &public_key).unwrap();
            assert_eq!(opened, message);
        }
    }

    /// The incremental interface (Ed25519ph) gives one signature for a
    /// message however it is split across updates, verifiable by a state fed
    /// with any other split, and never the plain detached signature.
    #[test]
    fn incremental_signature_is_independent_of_split_points() {
        let mut rng = XorShift64::new(0x5be0_cd19_137e_2179);
        let (public_key, secret_key) = crypto_sign_seed_keypair(&[22u8; 32]);
        let message: Vec<u8> = (0..3).flat_map(|_| rng.next_bytes32()).take(75).collect();

        let mut whole = crypto_sign_init();
        crypto_sign_update(&mut whole, &message);
        let mut reference = [0u8; CRYPTO_SIGN_BYTES];
        crypto_sign_final_create(whole, &mut reference, &secret_key).unwrap();

        let mut byte_at_a_time = crypto_sign_init();
        for byte in &message {
            crypto_sign_update(&mut byte_at_a_time, core::slice::from_ref(byte));
        }
        crypto_sign_final_verify(byte_at_a_time, &reference, &public_key).unwrap();

        for split in [0, 1, 63, 64, 65, 74, 75] {
            let mut signer = crypto_sign_init();
            crypto_sign_update(&mut signer, &message[..split]);
            crypto_sign_update(&mut signer, &message[split..]);
            let mut signature = [0u8; CRYPTO_SIGN_BYTES];
            crypto_sign_final_create(signer, &mut signature, &secret_key).unwrap();
            assert_eq!(signature, reference, "split {split}");
        }

        let mut detached = [0u8; CRYPTO_SIGN_BYTES];
        crypto_sign_detached(&mut detached, &message, &secret_key).unwrap();
        assert_ne!(reference, detached);
        let mut verifier = crypto_sign_init();
        crypto_sign_update(&mut verifier, &message);
        assert!(matches!(
            crypto_sign_final_verify(verifier, &detached, &public_key),
            Err(Error::AuthenticationFailed)
        ));
        assert!(matches!(
            crypto_sign_verify_detached(&reference, &message, &public_key),
            Err(Error::AuthenticationFailed)
        ));
    }
}

#[cfg(all(test, dryoc_native_tests))]
mod tests {
    use super::*;
    use crate::constants::{CRYPTO_SIGN_BYTES, CRYPTO_SIGN_PUBLICKEYBYTES};
    use crate::test_prelude::*;

    #[test]
    fn combined_signing_rejects_invalid_buffer_lengths() {
        let (public_key, secret_key) = crypto_sign_keypair();

        let mut short_signed_message = [0u8; CRYPTO_SIGN_BYTES];
        let error = crypto_sign(&mut short_signed_message, b"x", &secret_key)
            .expect_err("the signed-message buffer should include the message");
        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::SignedMessage,
                ..
            }
        ));

        let mut message = [];
        let short_input = [0u8; CRYPTO_SIGN_BYTES - 1];
        let error = crypto_sign_open(&mut message, &short_input, &public_key)
            .expect_err("a signed message must contain a full signature");
        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::SignedMessage,
                ..
            }
        ));

        let mut oversized_message = [0u8; 1];
        let signature_only = [0u8; CRYPTO_SIGN_BYTES];
        let error = crypto_sign_open(&mut oversized_message, &signature_only, &public_key)
            .expect_err("the output length should match the embedded message");
        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::Message,
                ..
            }
        ));
    }

    #[test]
    fn verification_classifies_invalid_signatures_and_public_keys() {
        let (public_key, secret_key) = crypto_sign_keypair();
        let message = b"important message";
        let mut signature = [0u8; CRYPTO_SIGN_BYTES];
        crypto_sign_detached(&mut signature, message, &secret_key).expect("signing should succeed");

        let mut tampered_signature = signature;
        tampered_signature[CRYPTO_SIGN_BYTES - 1] ^= 1;
        assert!(matches!(
            crypto_sign_verify_detached(&tampered_signature, message, &public_key),
            Err(Error::AuthenticationFailed)
        ));
        // The top byte of S is rejected by the scalar decoding before any
        // curve arithmetic; a low bit of S (still below the group order) is a
        // forgery that only the double-scalar multiplication can catch.
        let mut tampered_s_low = signature;
        tampered_s_low[32] ^= 1;
        assert!(matches!(
            crypto_sign_verify_detached(&tampered_s_low, message, &public_key),
            Err(Error::AuthenticationFailed)
        ));
        // A flipped bit in R (still a valid curve point or not) and a changed
        // message must both fail, not just a changed S.
        for byte in [0, 15, 31] {
            let mut tampered_r = signature;
            tampered_r[byte] ^= 0x10;
            assert!(matches!(
                crypto_sign_verify_detached(&tampered_r, message, &public_key),
                Err(Error::AuthenticationFailed)
            ));
        }
        assert!(matches!(
            crypto_sign_verify_detached(&signature, b"important massage", &public_key),
            Err(Error::AuthenticationFailed)
        ));
        let (other_public_key, _) = crypto_sign_keypair();
        assert!(matches!(
            crypto_sign_verify_detached(&signature, message, &other_public_key),
            Err(Error::AuthenticationFailed)
        ));

        assert!(matches!(
            crypto_sign_verify_detached(&[0u8; CRYPTO_SIGN_BYTES], message, &public_key),
            Err(Error::AuthenticationFailed)
        ));

        assert!(matches!(
            crypto_sign_verify_detached(&signature, message, &[0u8; CRYPTO_SIGN_PUBLICKEYBYTES],),
            Err(Error::InvalidKey {
                context: crate::ErrorContext::Ed25519PublicKey,
            })
        ));
    }

    #[test]
    fn test_crypto_sign() {
        use base64::Engine as _;
        use base64::engine::general_purpose;

        use crate::native_test_util::{sign_ed25519, sign_ed25519_open};

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let message = b"important message";
            let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_BYTES];
            crypto_sign(&mut signed_message, message, &secret_key).expect("sign failed");

            let so_signed_message = sign_ed25519(message, &secret_key);

            assert_eq!(
                general_purpose::STANDARD.encode(&signed_message),
                general_purpose::STANDARD.encode(&so_signed_message)
            );

            let so_m = sign_ed25519_open(&signed_message, &public_key).expect("verify failed");

            assert_eq!(so_m, message);
        }
    }

    #[test]
    fn test_crypto_sign_open() {
        use base64::Engine as _;
        use base64::engine::general_purpose;

        use crate::native_test_util::{sign_ed25519, sign_ed25519_open};

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let message = b"important message";
            let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_BYTES];
            crypto_sign(&mut signed_message, message, &secret_key).expect("sign failed");

            let so_signed_message = sign_ed25519(message, &secret_key);

            assert_eq!(
                general_purpose::STANDARD.encode(&signed_message),
                general_purpose::STANDARD.encode(&so_signed_message)
            );

            let so_m = sign_ed25519_open(&signed_message, &public_key).expect("verify failed");

            assert_eq!(so_m, message);

            let mut opened_message = vec![0u8; message.len()];

            crypto_sign_open(&mut opened_message, &signed_message, &public_key)
                .expect("verify failed");

            assert_eq!(opened_message, message);
        }
    }

    #[test]
    fn test_crypto_sign_detached() {
        use crate::native_test_util::sign_ed25519_verify_detached;

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let message = b"important message";
            let mut signature = [0u8; CRYPTO_SIGN_BYTES];
            crypto_sign_detached(&mut signature, message, &secret_key).expect("sign failed");

            assert!(sign_ed25519_verify_detached(
                &signature,
                message,
                &public_key
            ));

            crypto_sign_verify_detached(&signature, message, &public_key).expect("verify failed");
        }
    }

    #[test]
    fn test_crypto_sign_incremental() {
        use crate::native_test_util::{sign_ed25519ph, sign_ed25519ph_verify};
        use crate::rng::copy_randombytes;

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let mut signer = crypto_sign_init();
            let mut verifier = crypto_sign_init();

            // libsodium's side absorbs the same three parts.
            let mut so_parts = Vec::new();

            for _ in 0..3 {
                let mut randos = vec![0u8; 100];
                copy_randombytes(&mut randos);

                crypto_sign_update(&mut signer, &randos);
                crypto_sign_update(&mut verifier, &randos);

                so_parts.push(randos);
            }
            let so_parts: Vec<&[u8]> = so_parts.iter().map(Vec::as_slice).collect();

            let mut signature = [0u8; CRYPTO_SIGN_BYTES];
            crypto_sign_final_create(signer, &mut signature, &secret_key)
                .expect("final create failed");

            let so_signature = sign_ed25519ph(&so_parts, &secret_key);

            assert_eq!(signature, so_signature);

            crypto_sign_final_verify(verifier, &so_signature, &public_key).expect("verify failed");

            assert!(sign_ed25519ph_verify(&so_parts, &signature, &public_key));
        }
    }
}
