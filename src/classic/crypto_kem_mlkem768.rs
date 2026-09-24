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

/// Cross-checks against libsodium 1.0.22's ML-KEM-768.
#[cfg(all(test, dryoc_native_tests))]
pub(crate) mod native_tests {
    use super::*;
    use crate::native_test_util as sodium;
    use crate::utils::test_util::XorShift64;

    /// Seeds for key generation or encapsulation: all-zero, all-ones, four
    /// fixed pseudorandom ones and two fresh random ones.
    pub(crate) fn seeds<const N: usize>() -> Vec<[u8; N]> {
        let mut rng = XorShift64::new(0x6d6c_6b65_6d37_3638);
        let mut seeds = vec![[0u8; N], [0xff; N]];
        for _ in 0..4 {
            seeds.push(std::array::from_fn(|_| rng.next_u64() as u8));
        }
        for _ in 0..2 {
            let mut seed = [0u8; N];
            copy_randombytes(&mut seed);
            seeds.push(seed);
        }
        seeds
    }

    /// Copies of `key`, whose first 1152 bytes are an ML-KEM-768 encoded
    /// polynomial vector, with its first or its last 12-bit coefficient set
    /// to 4095: not reduced modulo q, so FIPS 203's modulus check rejects it.
    pub(crate) fn with_unreduced_coefficient<const N: usize>(key: &[u8; N]) -> [[u8; N]; 2] {
        let (mut first, mut last) = (*key, *key);
        first[0] = 0xff;
        first[1] |= 0x0f;
        last[1150] |= 0xf0;
        last[1151] = 0xff;
        [first, last]
    }

    /// Copies of `ciphertext` with one bit flipped at the start, middle and
    /// end.
    pub(crate) fn tampered<const N: usize>(ciphertext: &[u8; N]) -> [[u8; N]; 3] {
        [0, N / 2, N - 1].map(|index| {
            let mut copy = *ciphertext;
            copy[index] ^= 0x01;
            copy
        })
    }

    /// For every key seed and encapsulation seed, both libraries derive the
    /// same key pair, encapsulate to the same ciphertext and shared secret,
    /// decapsulate it to that secret, and agree on the implicit-rejection
    /// secret of each tampered ciphertext.
    #[test]
    fn test_mlkem768_matches_libsodium() {
        for seed in seeds::<CRYPTO_KEM_MLKEM768_SEEDBYTES>() {
            let (public_key, secret_key) = crypto_kem_mlkem768_seed_keypair(&seed);
            let (so_public_key, so_secret_key) = sodium::crypto_kem_mlkem768_seed_keypair(&seed);
            assert_eq!(public_key, so_public_key, "seed {seed:02x?}");
            assert_eq!(secret_key, so_secret_key, "seed {seed:02x?}");

            for enc_seed in seeds::<CRYPTO_KEM_MLKEM768_ENCSEEDBYTES>() {
                let mut ciphertext = [0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
                let mut sent = [0u8; CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES];
                crypto_kem_mlkem768_enc_deterministic(
                    &mut ciphertext,
                    &mut sent,
                    &public_key,
                    &enc_seed,
                )
                .expect("enc");
                let (so_ciphertext, so_sent) =
                    sodium::crypto_kem_mlkem768_enc_deterministic(&public_key, &enc_seed)
                        .expect("libsodium enc");
                assert_eq!(ciphertext, so_ciphertext, "enc seed {enc_seed:02x?}");
                assert_eq!(sent, so_sent, "enc seed {enc_seed:02x?}");

                for ciphertext in std::iter::once(ciphertext).chain(tampered(&ciphertext)) {
                    let mut received = [0u8; CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES];
                    crypto_kem_mlkem768_dec(&mut received, &ciphertext, &secret_key);
                    let so_received = sodium::crypto_kem_mlkem768_dec(&ciphertext, &secret_key)
                        .expect("libsodium dec");
                    assert_eq!(received, so_received, "enc seed {enc_seed:02x?}");
                    assert_eq!(received == sent, ciphertext == so_ciphertext);
                }
            }
        }
    }

    /// Both libraries refuse to encapsulate to a key with an unreduced
    /// coefficient, deterministically or not.
    #[test]
    fn test_mlkem768_unreduced_keys_rejected_like_libsodium() {
        for seed in seeds::<CRYPTO_KEM_MLKEM768_SEEDBYTES>() {
            let (public_key, _) = crypto_kem_mlkem768_seed_keypair(&seed);
            for invalid in with_unreduced_coefficient(&public_key) {
                let mut ciphertext = [0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
                let mut shared_secret = [0u8; CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES];
                assert!(
                    crypto_kem_mlkem768_enc_deterministic(
                        &mut ciphertext,
                        &mut shared_secret,
                        &invalid,
                        &[9u8; CRYPTO_KEM_MLKEM768_ENCSEEDBYTES],
                    )
                    .is_err()
                );
                assert!(
                    crypto_kem_mlkem768_enc(&mut ciphertext, &mut shared_secret, &invalid).is_err()
                );
                assert!(
                    sodium::crypto_kem_mlkem768_enc_deterministic(
                        &invalid,
                        &[9u8; CRYPTO_KEM_MLKEM768_ENCSEEDBYTES]
                    )
                    .is_err()
                );
                assert!(sodium::crypto_kem_mlkem768_enc(&invalid).is_err());
            }
        }
    }

    /// Randomized encapsulations made by either library decapsulate to the
    /// same shared secret in the other.
    #[test]
    fn test_mlkem768_randomized_interop_with_libsodium() {
        for _ in 0..8 {
            let (public_key, secret_key) = crypto_kem_mlkem768_keypair();

            let mut ciphertext = [0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
            let mut sent = [0u8; CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES];
            crypto_kem_mlkem768_enc(&mut ciphertext, &mut sent, &public_key).expect("enc");
            assert_eq!(
                sodium::crypto_kem_mlkem768_dec(&ciphertext, &secret_key).expect("libsodium dec"),
                sent
            );

            let (so_ciphertext, so_sent) =
                sodium::crypto_kem_mlkem768_enc(&public_key).expect("libsodium enc");
            let mut received = [0u8; CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES];
            crypto_kem_mlkem768_dec(&mut received, &so_ciphertext, &secret_key);
            assert_eq!(received, so_sent);
        }
    }
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

    /// libsodium's `crypto_kem_mlkem768_seed_keypair` on the same seed as
    /// `mlkem768_keypair_bench`.
    #[cfg(dryoc_native_tests)]
    #[bench]
    fn libsodium_mlkem768_keypair_bench(b: &mut test::Bencher) {
        crate::native_test_util::init();
        let seed = [7u8; CRYPTO_KEM_MLKEM768_SEEDBYTES];
        let mut public_key = [0u8; CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES];
        let mut secret_key = [0u8; CRYPTO_KEM_MLKEM768_SECRETKEYBYTES];
        b.iter(|| {
            // SAFETY: the key buffers and `seed` are arrays of libsodium's
            // sizes.
            let rc = unsafe {
                libsodium_sys::crypto_kem_mlkem768_seed_keypair(
                    public_key.as_mut_ptr(),
                    secret_key.as_mut_ptr(),
                    test::black_box(seed.as_ptr()),
                )
            };
            assert_eq!(rc, 0);
            test::black_box((&public_key, &secret_key));
        });
    }

    /// libsodium's `crypto_kem_mlkem768_enc_deterministic` on the same key
    /// and seed as `mlkem768_enc_bench`.
    #[cfg(dryoc_native_tests)]
    #[bench]
    fn libsodium_mlkem768_enc_bench(b: &mut test::Bencher) {
        crate::native_test_util::init();
        let (public_key, _) =
            crypto_kem_mlkem768_seed_keypair(&[7u8; CRYPTO_KEM_MLKEM768_SEEDBYTES]);
        let (mut ciphertext, mut shared_secret) =
            ([0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES], [0u8; 32]);
        let seed = [9u8; 32];
        b.iter(|| {
            // SAFETY: the output buffers, `public_key` and `seed` are arrays
            // of libsodium's sizes.
            let rc = unsafe {
                libsodium_sys::crypto_kem_mlkem768_enc_deterministic(
                    ciphertext.as_mut_ptr(),
                    shared_secret.as_mut_ptr(),
                    test::black_box(public_key.as_ptr()),
                    test::black_box(seed.as_ptr()),
                )
            };
            assert_eq!(rc, 0);
            test::black_box((&ciphertext, &shared_secret));
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

    /// libsodium's `crypto_kem_mlkem768_dec` with the same key and
    /// ciphertext setup as `mlkem768_dec_bench`.
    #[cfg(dryoc_native_tests)]
    #[bench]
    fn libsodium_mlkem768_dec_bench(b: &mut test::Bencher) {
        crate::native_test_util::init();
        let (public_key, secret_key) =
            crypto_kem_mlkem768_seed_keypair(&[7u8; CRYPTO_KEM_MLKEM768_SEEDBYTES]);
        let mut ciphertext = [0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; 32];
        crypto_kem_mlkem768_enc(&mut ciphertext, &mut shared_secret, &public_key).expect("enc");
        b.iter(|| {
            // SAFETY: `shared_secret`, `ciphertext` and `secret_key` are
            // arrays of libsodium's sizes.
            let rc = unsafe {
                libsodium_sys::crypto_kem_mlkem768_dec(
                    shared_secret.as_mut_ptr(),
                    test::black_box(ciphertext.as_ptr()),
                    test::black_box(secret_key.as_ptr()),
                )
            };
            assert_eq!(rc, 0);
            test::black_box(&shared_secret);
        });
    }
}
