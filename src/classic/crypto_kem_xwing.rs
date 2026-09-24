//! # X-Wing hybrid key encapsulation
//!
//! Implements libsodium's `crypto_kem_xwing_*` functions: X-Wing
//! (draft-connolly-cfrg-xwing-kem), which combines ML-KEM-768 with X25519.
//! Its shared secret stays secure as long as either ML-KEM-768 or X25519
//! does, so it protects against quantum computers without giving up the
//! security of elliptic-curve cryptography. [`crate::classic::crypto_kem`]
//! uses X-Wing.
//!
//! The 32-byte secret key is a seed; the ML-KEM-768 and X25519 keys are
//! derived from it with SHAKE256 whenever they are needed. The public key is
//! the ML-KEM-768 public key followed by the X25519 public key, and the
//! ciphertext is the ML-KEM-768 ciphertext followed by an ephemeral X25519
//! public key. The shared secret is SHA3-256 of both component secrets, the
//! X25519 ciphertext and public key, and a fixed label.
//!
//! A KEM does not authenticate the sender. Feed the shared secret to a
//! key-derivation function before using it as an encryption key.
//!
//! ```
//! use dryoc::classic::crypto_kem_xwing::*;
//!
//! let (public_key, secret_key) = crypto_kem_xwing_keypair();
//!
//! let mut ciphertext = [0u8; dryoc::constants::CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
//! let mut sender_secret = SharedSecret::default();
//! crypto_kem_xwing_enc(&mut ciphertext, &mut sender_secret, &public_key)
//!     .expect("encapsulation failed");
//!
//! let mut recipient_secret = SharedSecret::default();
//! crypto_kem_xwing_dec(&mut recipient_secret, &ciphertext, &secret_key)
//!     .expect("decapsulation failed");
//! assert_eq!(sender_secret, recipient_secret);
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::classic::crypto_core::{crypto_scalarmult, crypto_scalarmult_base};
use crate::constants::{
    CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES,
    CRYPTO_KEM_MLKEM768_SECRETKEYBYTES, CRYPTO_KEM_XWING_CIPHERTEXTBYTES,
    CRYPTO_KEM_XWING_ENCSEEDBYTES, CRYPTO_KEM_XWING_PUBLICKEYBYTES,
    CRYPTO_KEM_XWING_SECRETKEYBYTES, CRYPTO_KEM_XWING_SEEDBYTES,
    CRYPTO_KEM_XWING_SHAREDSECRETBYTES, CRYPTO_SCALARMULT_BYTES,
};
use crate::error::Error;
use crate::keccak::{DOMAIN_SHA3, DOMAIN_SHAKE, RATE_256, ROUNDS_FULL, Sponge, hash};
use crate::mlkem::{self, Arith};
use crate::rng::copy_randombytes;

/// X-Wing public key: the ML-KEM-768 public key, then the X25519 public key.
pub type PublicKey = [u8; CRYPTO_KEM_XWING_PUBLICKEYBYTES];
/// X-Wing secret key: the 32-byte seed both component keys derive from.
pub type SecretKey = [u8; CRYPTO_KEM_XWING_SECRETKEYBYTES];
/// X-Wing ciphertext: the ML-KEM-768 ciphertext, then an ephemeral X25519
/// public key.
pub type Ciphertext = [u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
/// Shared secret produced by encapsulation and decapsulation.
pub type SharedSecret = [u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
/// Key-generation seed; the secret key is the seed itself.
pub type Seed = [u8; CRYPTO_KEM_XWING_SEEDBYTES];
/// Encapsulation seed: the ML-KEM-768 message, then the ephemeral X25519
/// secret key.
pub type EncSeed = [u8; CRYPTO_KEM_XWING_ENCSEEDBYTES];

/// The combiner's domain-separation label, `\.//^\`.
const LABEL: &[u8; 6] = b"\\.//^\\";

/// The expanded secret key: the ML-KEM-768 key pair, and the X25519 secret
/// and public keys. Wiped on drop; [`Expanded::derive`] fills it in place so
/// no secret is copied out of it.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Expanded {
    mlkem_public_key: [u8; CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES],
    mlkem_secret_key: [u8; CRYPTO_KEM_MLKEM768_SECRETKEYBYTES],
    x25519_secret_key: [u8; CRYPTO_SCALARMULT_BYTES],
    x25519_public_key: [u8; CRYPTO_SCALARMULT_BYTES],
}

impl Expanded {
    fn zeroed() -> Self {
        Self {
            mlkem_public_key: [0u8; CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES],
            mlkem_secret_key: [0u8; CRYPTO_KEM_MLKEM768_SECRETKEYBYTES],
            x25519_secret_key: [0u8; CRYPTO_SCALARMULT_BYTES],
            x25519_public_key: [0u8; CRYPTO_SCALARMULT_BYTES],
        }
    }

    /// Expands `seed` with SHAKE256 into the ML-KEM-768 seed `d || z` and the
    /// X25519 secret key, then derives both key pairs into `self`, with
    /// ML-KEM arithmetic from `arith`.
    fn derive(&mut self, arith: Arith, seed: &SecretKey) {
        let keys = self;
        let mut mlkem_seed = Zeroizing::new([0u8; 64]);
        let mut sponge = Sponge::<RATE_256, ROUNDS_FULL>::new();
        sponge.absorb(seed);
        sponge.pad(DOMAIN_SHAKE);
        sponge.squeeze(&mut *mlkem_seed);
        sponge.squeeze(&mut keys.x25519_secret_key);
        mlkem::keypair(
            arith,
            &mut keys.mlkem_public_key,
            &mut keys.mlkem_secret_key,
            &mlkem_seed,
        );
        crypto_scalarmult_base(&mut keys.x25519_public_key, &keys.x25519_secret_key);
    }
}

/// The X-Wing combiner.
fn combine(
    shared_secret: &mut SharedSecret,
    mlkem_secret: &[u8],
    x25519_secret: &[u8],
    x25519_ciphertext: &[u8],
    x25519_public_key: &[u8],
) {
    hash::<RATE_256>(
        shared_secret,
        DOMAIN_SHA3,
        &[
            mlkem_secret,
            x25519_secret,
            x25519_ciphertext,
            x25519_public_key,
            LABEL,
        ],
    );
}

/// In-place variant of [`crypto_kem_xwing_seed_keypair`].
pub fn crypto_kem_xwing_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &Seed,
) {
    let mut keys = Expanded::zeroed();
    keys.derive(Arith::detect(), seed);
    let (mlkem_public_key, x25519_public_key) =
        public_key.split_at_mut(CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES);
    mlkem_public_key.copy_from_slice(&keys.mlkem_public_key);
    x25519_public_key.copy_from_slice(&keys.x25519_public_key);
    secret_key.copy_from_slice(seed);
}

/// Deterministically derives a key pair from `seed`. The secret key is the
/// seed itself.
///
/// Compatible with libsodium's `crypto_kem_xwing_seed_keypair`.
pub fn crypto_kem_xwing_seed_keypair(seed: &Seed) -> (PublicKey, SecretKey) {
    let mut public_key = [0u8; CRYPTO_KEM_XWING_PUBLICKEYBYTES];
    let mut secret_key = [0u8; CRYPTO_KEM_XWING_SECRETKEYBYTES];
    crypto_kem_xwing_seed_keypair_inplace(&mut public_key, &mut secret_key, seed);
    (public_key, secret_key)
}

/// In-place variant of [`crypto_kem_xwing_keypair`].
pub fn crypto_kem_xwing_keypair_inplace(public_key: &mut PublicKey, secret_key: &mut SecretKey) {
    let mut seed = Zeroizing::new([0u8; CRYPTO_KEM_XWING_SEEDBYTES]);
    copy_randombytes(seed.as_mut_slice());
    crypto_kem_xwing_seed_keypair_inplace(public_key, secret_key, &seed);
}

/// Returns a randomly generated key pair.
///
/// Compatible with libsodium's `crypto_kem_xwing_keypair`.
pub fn crypto_kem_xwing_keypair() -> (PublicKey, SecretKey) {
    let mut public_key = [0u8; CRYPTO_KEM_XWING_PUBLICKEYBYTES];
    let mut secret_key = [0u8; CRYPTO_KEM_XWING_SECRETKEYBYTES];
    crypto_kem_xwing_keypair_inplace(&mut public_key, &mut secret_key);
    (public_key, secret_key)
}

/// Creates a random shared secret for `public_key`, writing it to
/// `shared_secret` and its encapsulation to `ciphertext`.
///
/// Compatible with libsodium's `crypto_kem_xwing_enc`.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if the ML-KEM-768 part of `public_key` is
/// not a valid encapsulation key, or if its X25519 part is a low-order point
/// that gives an all-zero X25519 shared secret. `ciphertext` and
/// `shared_secret` are then left unchanged.
pub fn crypto_kem_xwing_enc(
    ciphertext: &mut Ciphertext,
    shared_secret: &mut SharedSecret,
    public_key: &PublicKey,
) -> Result<(), Error> {
    let mut seed = Zeroizing::new([0u8; CRYPTO_KEM_XWING_ENCSEEDBYTES]);
    copy_randombytes(seed.as_mut_slice());
    crypto_kem_xwing_enc_deterministic(ciphertext, shared_secret, public_key, &seed)
}

/// Deterministic variant of [`crypto_kem_xwing_enc`] with the encapsulation
/// randomness taken from `seed`. For known-answer tests; a repeated seed
/// repeats the shared secret.
///
/// Compatible with libsodium's `crypto_kem_xwing_enc_deterministic`.
///
/// # Errors
///
/// Returns the same errors as [`crypto_kem_xwing_enc`].
pub fn crypto_kem_xwing_enc_deterministic(
    ciphertext: &mut Ciphertext,
    shared_secret: &mut SharedSecret,
    public_key: &PublicKey,
    seed: &EncSeed,
) -> Result<(), Error> {
    enc_deterministic(Arith::detect(), ciphertext, shared_secret, public_key, seed)
}

/// [`crypto_kem_xwing_enc_deterministic`] with ML-KEM arithmetic from
/// `arith`, so tests can run each backend through this driver.
pub(crate) fn enc_deterministic(
    arith: Arith,
    ciphertext: &mut Ciphertext,
    shared_secret: &mut SharedSecret,
    public_key: &PublicKey,
    seed: &EncSeed,
) -> Result<(), Error> {
    let (mlkem_public_key, x25519_public_key) =
        public_key.split_at(CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES);
    let (mlkem_seed, x25519_ephemeral) = seed.split_at(32);
    let x25519_public_key: &[u8; CRYPTO_SCALARMULT_BYTES] =
        x25519_public_key.try_into().expect("32-byte X25519 key");
    let x25519_ephemeral: &[u8; CRYPTO_SCALARMULT_BYTES] =
        x25519_ephemeral.try_into().expect("32-byte X25519 key");
    let (mlkem_ciphertext, x25519_ciphertext) =
        ciphertext.split_at_mut(CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES);

    // Both fallible steps run before `ciphertext` is written, so a rejected
    // key leaves it unchanged, as in libsodium: the X25519 exchange first,
    // then ML-KEM, which checks the key before encrypting.
    let mut x25519_secret = Zeroizing::new([0u8; CRYPTO_SCALARMULT_BYTES]);
    crypto_scalarmult(&mut x25519_secret, x25519_ephemeral, x25519_public_key)?;
    let mut mlkem_secret = Zeroizing::new([0u8; 32]);
    mlkem::encapsulate(
        arith,
        mlkem_ciphertext.try_into().expect("sized ciphertext"),
        &mut mlkem_secret,
        mlkem_public_key.try_into().expect("sized public key"),
        mlkem_seed.try_into().expect("32-byte seed"),
    )?;
    let x25519_ciphertext: &mut [u8; CRYPTO_SCALARMULT_BYTES] =
        x25519_ciphertext.try_into().expect("32-byte X25519 key");
    crypto_scalarmult_base(x25519_ciphertext, x25519_ephemeral);

    combine(
        shared_secret,
        &*mlkem_secret,
        &*x25519_secret,
        x25519_ciphertext,
        x25519_public_key,
    );
    Ok(())
}

/// Recovers the shared secret encapsulated in `ciphertext` with
/// `secret_key`, writing it to `shared_secret`. A ciphertext not created for
/// this key yields an unrelated pseudorandom secret, not an error.
///
/// Compatible with libsodium's `crypto_kem_xwing_dec`.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if the X25519 part of `ciphertext` is a
/// low-order point that gives an all-zero X25519 shared secret.
pub fn crypto_kem_xwing_dec(
    shared_secret: &mut SharedSecret,
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    dec(Arith::detect(), shared_secret, ciphertext, secret_key)
}

/// [`crypto_kem_xwing_dec`] with ML-KEM arithmetic from `arith`, so tests
/// can run each backend through this driver.
pub(crate) fn dec(
    arith: Arith,
    shared_secret: &mut SharedSecret,
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut keys = Expanded::zeroed();
    keys.derive(arith, secret_key);
    let (mlkem_ciphertext, x25519_ciphertext) =
        ciphertext.split_at(CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES);
    let x25519_ciphertext: &[u8; CRYPTO_SCALARMULT_BYTES] =
        x25519_ciphertext.try_into().expect("32-byte X25519 key");

    let mut x25519_secret = Zeroizing::new([0u8; CRYPTO_SCALARMULT_BYTES]);
    crypto_scalarmult(
        &mut x25519_secret,
        &keys.x25519_secret_key,
        x25519_ciphertext,
    )?;
    let mut mlkem_secret = Zeroizing::new([0u8; 32]);
    mlkem::decapsulate(
        arith,
        &mut mlkem_secret,
        mlkem_ciphertext.try_into().expect("sized ciphertext"),
        &keys.mlkem_secret_key,
    );

    combine(
        shared_secret,
        &*mlkem_secret,
        &*x25519_secret,
        x25519_ciphertext,
        &keys.x25519_public_key,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::tests::{field, records};

    /// The draft's Appendix C vectors, which libsodium reproduces: seed to
    /// key pair, deterministic encapsulation and decapsulation.
    #[test]
    fn test_draft_vectors() {
        for record in records(include_str!("../mlkem/test-vectors/xwing_draft.txt")) {
            let index = record["index"];
            let (public_key, secret_key) = crypto_kem_xwing_seed_keypair(&field(&record, "seed"));
            assert_eq!(public_key, field(&record, "pk"), "index {index}");
            assert_eq!(secret_key, field::<32>(&record, "seed"), "index {index}");

            let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
            let mut sent = [0u8; 32];
            crypto_kem_xwing_enc_deterministic(
                &mut ciphertext,
                &mut sent,
                &public_key,
                &field(&record, "eseed"),
            )
            .expect("enc");
            assert_eq!(ciphertext, field(&record, "ct"), "index {index}");
            assert_eq!(sent, field::<32>(&record, "ss"), "index {index}");

            let mut received = [0u8; 32];
            crypto_kem_xwing_dec(&mut received, &ciphertext, &secret_key).expect("dec");
            assert_eq!(received, sent, "index {index}");
        }
    }

    /// libsodium's return codes for low-order X25519 inputs and an invalid
    /// ML-KEM key, and its shared secret for an X25519 ciphertext with the
    /// top bit set (hashed as given, not masked). Like libsodium, a failed
    /// call leaves its output buffers unchanged.
    #[test]
    fn test_libsodium_edge_cases() {
        for record in records(include_str!(
            "../mlkem/test-vectors/xwing_libsodium_edge.txt"
        )) {
            let name = record["name"];
            let success = record["rc"] == "0";
            let mut ciphertext = [0xa5u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
            let mut shared_secret = [0xa5u8; 32];
            let result = match record["op"] {
                "enc_deterministic" => crypto_kem_xwing_enc_deterministic(
                    &mut ciphertext,
                    &mut shared_secret,
                    &field(&record, "pk"),
                    &field(&record, "eseed"),
                ),
                "dec" => crypto_kem_xwing_dec(
                    &mut shared_secret,
                    &field(&record, "ct"),
                    &field(&record, "sk"),
                ),
                op => panic!("unknown op {op}"),
            };
            assert_eq!(result.is_ok(), success, "{name}");
            if !success {
                assert_eq!(
                    ciphertext, [0xa5; CRYPTO_KEM_XWING_CIPHERTEXTBYTES],
                    "{name}"
                );
                assert_eq!(shared_secret, [0xa5; 32], "{name}");
            }
            if let Some(ss) = record.get("ss") {
                assert_eq!(hex::encode(shared_secret), *ss, "{name}");
            }
        }
    }
}

/// Cross-checks against libsodium 1.0.22's X-Wing.
#[cfg(all(test, dryoc_native_tests))]
mod native_tests {
    use super::*;
    use crate::classic::crypto_kem_mlkem768::native_tests::{
        seeds, tampered, with_unreduced_coefficient,
    };
    use crate::native_test_util as sodium;

    /// Copies of `key` with its trailing X25519 part replaced by the
    /// low-order points `u = 0` and `u = 1`.
    fn with_low_order_x25519<const N: usize>(key: &[u8; N]) -> [[u8; N]; 2] {
        [0u8, 1].map(|u| {
            let mut copy = *key;
            copy[N - CRYPTO_SCALARMULT_BYTES..].fill(0);
            copy[N - CRYPTO_SCALARMULT_BYTES] = u;
            copy
        })
    }

    /// For every key seed and encapsulation seed, both libraries derive the
    /// same key pair, encapsulate to the same ciphertext and shared secret,
    /// decapsulate it to that secret, and agree on the secret of each
    /// tampered ciphertext (ML-KEM implicit rejection, or a changed X25519
    /// share).
    #[test]
    fn test_xwing_matches_libsodium() {
        for seed in seeds::<CRYPTO_KEM_XWING_SEEDBYTES>() {
            let (public_key, secret_key) = crypto_kem_xwing_seed_keypair(&seed);
            let (so_public_key, so_secret_key) = sodium::crypto_kem_xwing_seed_keypair(&seed);
            assert_eq!(public_key, so_public_key, "seed {seed:02x?}");
            assert_eq!(secret_key, so_secret_key, "seed {seed:02x?}");

            for enc_seed in seeds::<CRYPTO_KEM_XWING_ENCSEEDBYTES>() {
                let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
                let mut sent = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
                crypto_kem_xwing_enc_deterministic(
                    &mut ciphertext,
                    &mut sent,
                    &public_key,
                    &enc_seed,
                )
                .expect("enc");
                let (so_ciphertext, so_sent) =
                    sodium::crypto_kem_xwing_enc_deterministic(&public_key, &enc_seed)
                        .expect("libsodium enc");
                assert_eq!(ciphertext, so_ciphertext, "enc seed {enc_seed:02x?}");
                assert_eq!(sent, so_sent, "enc seed {enc_seed:02x?}");

                for ciphertext in std::iter::once(ciphertext).chain(tampered(&ciphertext)) {
                    let mut received = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
                    crypto_kem_xwing_dec(&mut received, &ciphertext, &secret_key).expect("dec");
                    let so_received = sodium::crypto_kem_xwing_dec(&ciphertext, &secret_key)
                        .expect("libsodium dec");
                    assert_eq!(received, so_received, "enc seed {enc_seed:02x?}");
                    assert_eq!(received == sent, ciphertext == so_ciphertext);
                }
            }
        }
    }

    /// Both libraries refuse to encapsulate to a key whose X25519 part is a
    /// low-order point or whose ML-KEM part has an unreduced coefficient,
    /// and refuse to decapsulate a ciphertext whose X25519 part is zero.
    #[test]
    fn test_xwing_invalid_inputs_rejected_like_libsodium() {
        for seed in seeds::<CRYPTO_KEM_XWING_SEEDBYTES>() {
            let (public_key, secret_key) = crypto_kem_xwing_seed_keypair(&seed);
            let enc_seed = [9u8; CRYPTO_KEM_XWING_ENCSEEDBYTES];
            let invalid_keys = with_low_order_x25519(&public_key)
                .into_iter()
                .chain(with_unreduced_coefficient(&public_key));
            for invalid in invalid_keys {
                let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
                let mut shared_secret = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
                assert!(
                    crypto_kem_xwing_enc_deterministic(
                        &mut ciphertext,
                        &mut shared_secret,
                        &invalid,
                        &enc_seed,
                    )
                    .is_err()
                );
                assert!(
                    crypto_kem_xwing_enc(&mut ciphertext, &mut shared_secret, &invalid).is_err()
                );
                assert!(sodium::crypto_kem_xwing_enc_deterministic(&invalid, &enc_seed).is_err());
                assert!(sodium::crypto_kem_xwing_enc(&invalid).is_err());
            }

            let (mut ciphertext, _) =
                sodium::crypto_kem_xwing_enc_deterministic(&public_key, &enc_seed).expect("enc");
            ciphertext[CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES..].fill(0);
            let mut shared_secret = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
            assert!(crypto_kem_xwing_dec(&mut shared_secret, &ciphertext, &secret_key).is_err());
            assert!(sodium::crypto_kem_xwing_dec(&ciphertext, &secret_key).is_err());
        }
    }

    /// Randomized encapsulations made by either library decapsulate to the
    /// same shared secret in the other.
    #[test]
    fn test_xwing_randomized_interop_with_libsodium() {
        for _ in 0..8 {
            let (public_key, secret_key) = crypto_kem_xwing_keypair();

            let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
            let mut sent = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
            crypto_kem_xwing_enc(&mut ciphertext, &mut sent, &public_key).expect("enc");
            assert_eq!(
                sodium::crypto_kem_xwing_dec(&ciphertext, &secret_key).expect("libsodium dec"),
                sent
            );

            let (so_ciphertext, so_sent) =
                sodium::crypto_kem_xwing_enc(&public_key).expect("libsodium enc");
            let mut received = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
            crypto_kem_xwing_dec(&mut received, &so_ciphertext, &secret_key).expect("dec");
            assert_eq!(received, so_sent);
        }
    }
}

#[cfg(all(test, feature = "nightly"))]
mod benches {
    extern crate test;

    use super::*;

    #[bench]
    fn xwing_keypair_bench(b: &mut test::Bencher) {
        b.iter(|| crypto_kem_xwing_seed_keypair(test::black_box(&[7u8; 32])));
    }

    #[bench]
    fn xwing_enc_bench(b: &mut test::Bencher) {
        let (public_key, _) = crypto_kem_xwing_seed_keypair(&[7u8; 32]);
        let (mut ciphertext, mut shared_secret) =
            ([0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES], [0u8; 32]);
        b.iter(|| {
            crypto_kem_xwing_enc_deterministic(
                &mut ciphertext,
                &mut shared_secret,
                test::black_box(&public_key),
                test::black_box(&[9u8; 64]),
            )
            .expect("enc")
        });
    }

    /// libsodium's `crypto_kem_xwing_seed_keypair` on the same seed as
    /// `xwing_keypair_bench`.
    #[cfg(dryoc_native_tests)]
    #[bench]
    fn libsodium_xwing_keypair_bench(b: &mut test::Bencher) {
        crate::native_test_util::init();
        let seed = [7u8; 32];
        let mut public_key = [0u8; CRYPTO_KEM_XWING_PUBLICKEYBYTES];
        let mut secret_key = [0u8; CRYPTO_KEM_XWING_SECRETKEYBYTES];
        b.iter(|| {
            // SAFETY: the key buffers and `seed` are arrays of libsodium's
            // sizes.
            let rc = unsafe {
                libsodium_sys::crypto_kem_xwing_seed_keypair(
                    public_key.as_mut_ptr(),
                    secret_key.as_mut_ptr(),
                    test::black_box(seed.as_ptr()),
                )
            };
            assert_eq!(rc, 0);
            test::black_box((&public_key, &secret_key));
        });
    }

    /// libsodium's `crypto_kem_xwing_enc_deterministic` on the same key and
    /// seed as `xwing_enc_bench`.
    #[cfg(dryoc_native_tests)]
    #[bench]
    fn libsodium_xwing_enc_bench(b: &mut test::Bencher) {
        crate::native_test_util::init();
        let (public_key, _) = crypto_kem_xwing_seed_keypair(&[7u8; 32]);
        let (mut ciphertext, mut shared_secret) =
            ([0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES], [0u8; 32]);
        let seed = [9u8; 64];
        b.iter(|| {
            // SAFETY: the output buffers, `public_key` and `seed` are arrays
            // of the sizes libsodium reads and writes.
            let rc = unsafe {
                libsodium_sys::crypto_kem_xwing_enc_deterministic(
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
    fn xwing_dec_bench(b: &mut test::Bencher) {
        let (public_key, secret_key) = crypto_kem_xwing_seed_keypair(&[7u8; 32]);
        let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; 32];
        crypto_kem_xwing_enc(&mut ciphertext, &mut shared_secret, &public_key).expect("enc");
        b.iter(|| {
            crypto_kem_xwing_dec(
                &mut shared_secret,
                test::black_box(&ciphertext),
                test::black_box(&secret_key),
            )
            .expect("dec")
        });
    }

    /// libsodium's `crypto_kem_xwing_dec` with the same key and ciphertext
    /// setup as `xwing_dec_bench`.
    #[cfg(dryoc_native_tests)]
    #[bench]
    fn libsodium_xwing_dec_bench(b: &mut test::Bencher) {
        crate::native_test_util::init();
        let (public_key, secret_key) = crypto_kem_xwing_seed_keypair(&[7u8; 32]);
        let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; 32];
        crypto_kem_xwing_enc(&mut ciphertext, &mut shared_secret, &public_key).expect("enc");
        b.iter(|| {
            // SAFETY: `shared_secret`, `ciphertext` and `secret_key` are
            // arrays of libsodium's sizes.
            let rc = unsafe {
                libsodium_sys::crypto_kem_xwing_dec(
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
