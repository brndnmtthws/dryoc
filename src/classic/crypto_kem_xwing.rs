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
    /// X25519 secret key, then derives both key pairs into `self`.
    fn derive(&mut self, seed: &SecretKey) {
        let keys = self;
        let mut mlkem_seed = Zeroizing::new([0u8; 64]);
        let mut sponge = Sponge::<RATE_256, ROUNDS_FULL>::new();
        sponge.absorb(seed);
        sponge.pad(DOMAIN_SHAKE);
        sponge.squeeze(&mut *mlkem_seed);
        sponge.squeeze(&mut keys.x25519_secret_key);
        mlkem::keypair(
            Arith::detect(),
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
    keys.derive(seed);
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
        Arith::detect(),
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
    let mut keys = Expanded::zeroed();
    keys.derive(secret_key);
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
        Arith::detect(),
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
}
