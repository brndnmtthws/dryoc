//! # Key encapsulation
//!
//! Implements libsodium's `crypto_kem_*` functions, which use X-Wing: the
//! hybrid of ML-KEM-768 and X25519 in [`crate::classic::crypto_kem_xwing`].
//! X-Wing stays secure if either component does, so it protects against
//! quantum computers without giving up the security of elliptic-curve
//! cryptography.
//!
//! A key encapsulation mechanism (KEM) lets a sender create a fresh shared
//! secret for the holder of a public key. [`crypto_kem_enc`] returns the
//! shared secret and a ciphertext; the recipient recovers the same secret
//! with [`crypto_kem_dec`] and its secret key. Only the recipient needs a key
//! pair. Feed the shared secret to a key-derivation function such as
//! [`crate::classic::crypto_kdf`]'s HKDF before using it as an encryption
//! key. A KEM does not authenticate the sender; combine it with signatures
//! or an authenticated key exchange when that matters.
//!
//! ```
//! use dryoc::classic::crypto_kem::*;
//!
//! let (public_key, secret_key) = crypto_kem_keypair();
//!
//! let mut ciphertext = [0u8; dryoc::constants::CRYPTO_KEM_CIPHERTEXTBYTES];
//! let mut sender_secret = SharedSecret::default();
//! crypto_kem_enc(&mut ciphertext, &mut sender_secret, &public_key).expect("encapsulation failed");
//!
//! let mut recipient_secret = SharedSecret::default();
//! crypto_kem_dec(&mut recipient_secret, &ciphertext, &secret_key).expect("decapsulation failed");
//! assert_eq!(sender_secret, recipient_secret);
//! ```

pub use crate::classic::crypto_kem_xwing::{Ciphertext, PublicKey, SecretKey, Seed, SharedSecret};
use crate::classic::crypto_kem_xwing::{
    crypto_kem_xwing_dec, crypto_kem_xwing_enc, crypto_kem_xwing_keypair,
    crypto_kem_xwing_keypair_inplace, crypto_kem_xwing_seed_keypair,
    crypto_kem_xwing_seed_keypair_inplace,
};
use crate::error::Error;

/// In-place variant of [`crypto_kem_seed_keypair`].
pub fn crypto_kem_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &Seed,
) {
    crypto_kem_xwing_seed_keypair_inplace(public_key, secret_key, seed)
}

/// Deterministically derives a key pair from `seed`.
///
/// Compatible with libsodium's `crypto_kem_seed_keypair`.
pub fn crypto_kem_seed_keypair(seed: &Seed) -> (PublicKey, SecretKey) {
    crypto_kem_xwing_seed_keypair(seed)
}

/// In-place variant of [`crypto_kem_keypair`].
pub fn crypto_kem_keypair_inplace(public_key: &mut PublicKey, secret_key: &mut SecretKey) {
    crypto_kem_xwing_keypair_inplace(public_key, secret_key)
}

/// Returns a randomly generated key pair.
///
/// Compatible with libsodium's `crypto_kem_keypair`.
pub fn crypto_kem_keypair() -> (PublicKey, SecretKey) {
    crypto_kem_xwing_keypair()
}

/// Creates a random shared secret for `public_key`, writing it to
/// `shared_secret` and its encapsulation to `ciphertext`.
///
/// Compatible with libsodium's `crypto_kem_enc`.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `public_key` is not a valid X-Wing
/// public key; see [`crypto_kem_xwing_enc`].
pub fn crypto_kem_enc(
    ciphertext: &mut Ciphertext,
    shared_secret: &mut SharedSecret,
    public_key: &PublicKey,
) -> Result<(), Error> {
    crypto_kem_xwing_enc(ciphertext, shared_secret, public_key)
}

/// Recovers the shared secret encapsulated in `ciphertext` with
/// `secret_key`, writing it to `shared_secret`.
///
/// Compatible with libsodium's `crypto_kem_dec`.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `ciphertext` carries a low-order X25519
/// point; see [`crypto_kem_xwing_dec`].
pub fn crypto_kem_dec(
    shared_secret: &mut SharedSecret,
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    crypto_kem_xwing_dec(shared_secret, ciphertext, secret_key)
}

/// Cross-checks against libsodium 1.0.22's generic `crypto_kem_*`.
#[cfg(all(test, dryoc_native_tests))]
mod native_tests {
    use super::*;
    use crate::classic::crypto_kem_mlkem768::native_tests::seeds;
    use crate::constants::{CRYPTO_KEM_CIPHERTEXTBYTES, CRYPTO_KEM_SHAREDSECRETBYTES};
    use crate::native_test_util as sodium;

    /// The generic functions derive X-Wing key pairs in both libraries, and
    /// encapsulations made by either decapsulate in the other through both
    /// the generic and the X-Wing functions.
    #[test]
    fn test_generic_kem_is_xwing_like_libsodium() {
        for seed in seeds::<32>() {
            let keypair = crypto_kem_seed_keypair(&seed);
            assert_eq!(
                keypair,
                sodium::crypto_kem_seed_keypair(&seed),
                "seed {seed:02x?}"
            );
            assert_eq!(
                keypair,
                sodium::crypto_kem_xwing_seed_keypair(&seed),
                "seed {seed:02x?}"
            );
            let (public_key, secret_key) = keypair;

            let (so_ciphertext, so_sent) =
                sodium::crypto_kem_enc(&public_key).expect("libsodium enc");
            let mut received = [0u8; CRYPTO_KEM_SHAREDSECRETBYTES];
            crypto_kem_dec(&mut received, &so_ciphertext, &secret_key).expect("dec");
            assert_eq!(received, so_sent);
            assert_eq!(
                sodium::crypto_kem_xwing_dec(&so_ciphertext, &secret_key).expect("libsodium dec"),
                so_sent
            );

            let mut ciphertext = [0u8; CRYPTO_KEM_CIPHERTEXTBYTES];
            let mut sent = [0u8; CRYPTO_KEM_SHAREDSECRETBYTES];
            crypto_kem_enc(&mut ciphertext, &mut sent, &public_key).expect("enc");
            assert_eq!(
                sodium::crypto_kem_dec(&ciphertext, &secret_key).expect("libsodium dec"),
                sent
            );
            assert_eq!(
                sodium::crypto_kem_xwing_dec(&ciphertext, &secret_key).expect("libsodium dec"),
                sent
            );
        }
    }
}
