//! # ML-KEM-768 key encapsulation
//!
//! Implements libsodium's `crypto_kem_mlkem768_*` functions: ML-KEM-768 from
//! FIPS 203, a lattice-based key encapsulation mechanism (KEM) believed to
//! resist attacks by quantum computers.
//!
//! A KEM lets a sender create a fresh shared secret for the holder of a
//! public key. [`crypto_kem_mlkem768_enc`] returns the shared secret and a
//! ciphertext; the recipient recovers the same secret with
//! [`crypto_kem_mlkem768_dec`] and its secret key. Feed the shared secret to
//! a key-derivation function before using it as an encryption key. A KEM
//! does not authenticate the sender.
//!
//! Prefer [`crate::classic::crypto_kem`], which uses X-Wing: ML-KEM-768
//! combined with X25519, so it stays secure if either one is broken. Use
//! ML-KEM-768 directly when a protocol requires it.
//!
//! Encapsulation rejects a public key that is not a valid FIPS 203
//! encapsulation key. Decapsulation always succeeds: a ciphertext that was
//! not created for the key yields an unrelated pseudorandom secret
//! ("implicit rejection"), so the caller learns nothing from the result.
//!
//! ```
//! use dryoc::classic::crypto_kem_mlkem768::*;
//!
//! let (public_key, secret_key) = crypto_kem_mlkem768_keypair();
//!
//! let mut ciphertext = [0u8; dryoc::constants::CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
//! let mut sender_secret = SharedSecret::default();
//! crypto_kem_mlkem768_enc(&mut ciphertext, &mut sender_secret, &public_key)
//!     .expect("encapsulation failed");
//!
//! let mut recipient_secret = SharedSecret::default();
//! crypto_kem_mlkem768_dec(&mut recipient_secret, &ciphertext, &secret_key);
//! assert_eq!(sender_secret, recipient_secret);
//! ```

use zeroize::Zeroizing;

use crate::constants::{
    CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_ENCSEEDBYTES,
    CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES, CRYPTO_KEM_MLKEM768_SECRETKEYBYTES,
    CRYPTO_KEM_MLKEM768_SEEDBYTES, CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
};
use crate::error::Error;
use crate::mlkem::{self, Arith};
use crate::rng::copy_randombytes;

/// ML-KEM-768 public (encapsulation) key.
pub type PublicKey = [u8; CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES];
/// ML-KEM-768 secret (decapsulation) key, in FIPS 203's expanded form.
pub type SecretKey = [u8; CRYPTO_KEM_MLKEM768_SECRETKEYBYTES];
/// ML-KEM-768 ciphertext.
pub type Ciphertext = [u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
/// Shared secret produced by encapsulation and decapsulation.
pub type SharedSecret = [u8; CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES];
/// Key-generation seed: FIPS 203's `d || z`.
pub type Seed = [u8; CRYPTO_KEM_MLKEM768_SEEDBYTES];
/// Encapsulation seed: FIPS 203's message `m`.
pub type EncSeed = [u8; CRYPTO_KEM_MLKEM768_ENCSEEDBYTES];

/// In-place variant of [`crypto_kem_mlkem768_seed_keypair`].
pub fn crypto_kem_mlkem768_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &Seed,
) {
    mlkem::keypair(Arith::detect(), public_key, secret_key, seed);
}

/// Deterministically derives a key pair from `seed`.
///
/// Compatible with libsodium's `crypto_kem_mlkem768_seed_keypair`.
pub fn crypto_kem_mlkem768_seed_keypair(seed: &Seed) -> (PublicKey, SecretKey) {
    let mut public_key = [0u8; CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES];
    let mut secret_key = [0u8; CRYPTO_KEM_MLKEM768_SECRETKEYBYTES];
    crypto_kem_mlkem768_seed_keypair_inplace(&mut public_key, &mut secret_key, seed);
    (public_key, secret_key)
}

/// In-place variant of [`crypto_kem_mlkem768_keypair`].
pub fn crypto_kem_mlkem768_keypair_inplace(public_key: &mut PublicKey, secret_key: &mut SecretKey) {
    let mut seed = Zeroizing::new([0u8; CRYPTO_KEM_MLKEM768_SEEDBYTES]);
    copy_randombytes(seed.as_mut_slice());
    crypto_kem_mlkem768_seed_keypair_inplace(public_key, secret_key, &seed);
}

/// Returns a randomly generated key pair.
///
/// Compatible with libsodium's `crypto_kem_mlkem768_keypair`.
pub fn crypto_kem_mlkem768_keypair() -> (PublicKey, SecretKey) {
    let mut public_key = [0u8; CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES];
    let mut secret_key = [0u8; CRYPTO_KEM_MLKEM768_SECRETKEYBYTES];
    crypto_kem_mlkem768_keypair_inplace(&mut public_key, &mut secret_key);
    (public_key, secret_key)
}

/// Creates a random shared secret for `public_key`, writing it to
/// `shared_secret` and its encapsulation to `ciphertext`.
///
/// Compatible with libsodium's `crypto_kem_mlkem768_enc`.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `public_key` is not a valid ML-KEM-768
/// encapsulation key (a coefficient is not reduced modulo `q`).
pub fn crypto_kem_mlkem768_enc(
    ciphertext: &mut Ciphertext,
    shared_secret: &mut SharedSecret,
    public_key: &PublicKey,
) -> Result<(), Error> {
    let mut seed = Zeroizing::new([0u8; CRYPTO_KEM_MLKEM768_ENCSEEDBYTES]);
    copy_randombytes(seed.as_mut_slice());
    crypto_kem_mlkem768_enc_deterministic(ciphertext, shared_secret, public_key, &seed)
}

/// Deterministic variant of [`crypto_kem_mlkem768_enc`] with the
/// encapsulation randomness taken from `seed`. For known-answer tests; a
/// repeated seed repeats the shared secret.
///
/// Compatible with libsodium's `crypto_kem_mlkem768_enc_deterministic`.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `public_key` is not a valid ML-KEM-768
/// encapsulation key.
pub fn crypto_kem_mlkem768_enc_deterministic(
    ciphertext: &mut Ciphertext,
    shared_secret: &mut SharedSecret,
    public_key: &PublicKey,
    seed: &EncSeed,
) -> Result<(), Error> {
    mlkem::encapsulate(Arith::detect(), ciphertext, shared_secret, public_key, seed)
}

/// Recovers the shared secret encapsulated in `ciphertext` with
/// `secret_key`, writing it to `shared_secret`. A ciphertext not created for
/// this key yields an unrelated pseudorandom secret instead of an error.
///
/// Compatible with libsodium's `crypto_kem_mlkem768_dec`.
pub fn crypto_kem_mlkem768_dec(
    shared_secret: &mut SharedSecret,
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
) {
    mlkem::decapsulate(Arith::detect(), shared_secret, ciphertext, secret_key);
}

#[cfg(all(test, feature = "nightly"))]
mod benches {
    extern crate test;

    use super::*;

    #[bench]
    fn mlkem768_keypair_bench(b: &mut test::Bencher) {
        let seed = [7u8; CRYPTO_KEM_MLKEM768_SEEDBYTES];
        b.iter(|| crypto_kem_mlkem768_seed_keypair(test::black_box(&seed)));
    }

    #[bench]
    fn mlkem768_enc_bench(b: &mut test::Bencher) {
        let (public_key, _) =
            crypto_kem_mlkem768_seed_keypair(&[7u8; CRYPTO_KEM_MLKEM768_SEEDBYTES]);
        let (mut ciphertext, mut shared_secret) =
            ([0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES], [0u8; 32]);
        b.iter(|| {
            crypto_kem_mlkem768_enc_deterministic(
                &mut ciphertext,
                &mut shared_secret,
                test::black_box(&public_key),
                test::black_box(&[9u8; 32]),
            )
            .expect("enc")
        });
    }

    #[bench]
    fn mlkem768_dec_bench(b: &mut test::Bencher) {
        let (public_key, secret_key) =
            crypto_kem_mlkem768_seed_keypair(&[7u8; CRYPTO_KEM_MLKEM768_SEEDBYTES]);
        let mut ciphertext = [0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; 32];
        crypto_kem_mlkem768_enc(&mut ciphertext, &mut shared_secret, &public_key).expect("enc");
        b.iter(|| {
            crypto_kem_mlkem768_dec(
                &mut shared_secret,
                test::black_box(&ciphertext),
                test::black_box(&secret_key),
            )
        });
    }
}
