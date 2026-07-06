//! # SHA-2 and SHA-3 hashing
//!
//! Implements libsodium's `crypto_hash_sha256_*`, `crypto_hash_sha512_*`,
//! `crypto_hash_sha3256_*`, and `crypto_hash_sha3512_*` functions.
//!
//! SHA-2 and SHA-3 are unkeyed hash functions. They produce fixed-size digests
//! that identify input bytes, but they do not prove who created the input. Use
//! [`crate::classic::crypto_auth`] or the direct HMAC modules when a shared
//! secret key is required.
//!
//! ```
//! use dryoc::classic::crypto_hash::*;
//!
//! let message = b"The empty vessel makes the loudest sound.";
//!
//! let mut sha256 = Sha256Digest::default();
//! crypto_hash_sha256(&mut sha256, message);
//! assert_eq!(sha256.len(), 32);
//!
//! let mut sha512: Sha512Digest = [0u8; 64];
//! crypto_hash_sha512(&mut sha512, message);
//! assert_eq!(sha512.len(), 64);
//!
//! let mut sha3256 = Sha3256Digest::default();
//! crypto_hash_sha3256(&mut sha3256, message);
//! assert_eq!(sha3256.len(), 32);
//!
//! let mut sha3512: Sha3512Digest = [0u8; 64];
//! crypto_hash_sha3512(&mut sha3512, message);
//! assert_eq!(sha3512.len(), 64);
//! ```

use crate::constants::{
    CRYPTO_HASH_SHA256_BYTES, CRYPTO_HASH_SHA512_BYTES, CRYPTO_HASH_SHA3256_BYTES,
    CRYPTO_HASH_SHA3512_BYTES,
};
use crate::sha3::{Sha3256, Sha3512};
use crate::sha256::Sha256;
use crate::sha512::*;

/// Type alias for SHA512 digest output.
pub type Digest = Sha512Digest;
/// Type alias for SHA256 digest output.
pub type Sha256Digest = [u8; CRYPTO_HASH_SHA256_BYTES];
/// Type alias for SHA512 digest output.
pub type Sha512Digest = [u8; CRYPTO_HASH_SHA512_BYTES];
/// Type alias for SHA3-256 digest output.
pub type Sha3256Digest = [u8; CRYPTO_HASH_SHA3256_BYTES];
/// Type alias for SHA3-512 digest output.
pub type Sha3512Digest = [u8; CRYPTO_HASH_SHA3512_BYTES];

/// Computes a SHA-256 hash from `input`.
pub fn crypto_hash_sha256(output: &mut Sha256Digest, input: &[u8]) {
    let mut state = crypto_hash_sha256_init();
    crypto_hash_sha256_update(&mut state, input);
    crypto_hash_sha256_final(state, output);
}

/// Internal state for SHA-256 functions.
#[derive(Default)]
pub struct Sha256State {
    pub(super) hasher: Sha256,
}

/// Initializes a SHA-256 hasher.
pub fn crypto_hash_sha256_init() -> Sha256State {
    Sha256State::default()
}

/// Updates `state` of SHA-256 hasher with `input`.
pub fn crypto_hash_sha256_update(state: &mut Sha256State, input: &[u8]) {
    state.hasher.update(input);
}

/// Finalizes `state` of SHA-256, and writes the digest to `output` consuming
/// `state`.
pub fn crypto_hash_sha256_final(state: Sha256State, output: &mut Sha256Digest) {
    state.hasher.finalize_into_bytes(output)
}

/// Computes a SHA-512 hash from `input`.
pub fn crypto_hash_sha512(output: &mut Digest, input: &[u8]) {
    let mut state = crypto_hash_sha512_init();
    crypto_hash_sha512_update(&mut state, input);
    crypto_hash_sha512_final(state, output);
}

/// Internal state for SHA-512 functions.
#[derive(Default)]
pub struct Sha512State {
    pub(super) hasher: Sha512,
}

/// Initializes a SHA-512 hasher.
pub fn crypto_hash_sha512_init() -> Sha512State {
    Sha512State::default()
}

/// Updates `state` of SHA-512 hasher with `input`.
pub fn crypto_hash_sha512_update(state: &mut Sha512State, input: &[u8]) {
    state.hasher.update(input);
}

/// Finalizes `state` of SHA-512, and writes the digest to `output` consuming
/// `state`.
pub fn crypto_hash_sha512_final(state: Sha512State, output: &mut Digest) {
    state.hasher.finalize_into_bytes(output)
}

/// Computes a SHA3-256 hash from `input`.
pub fn crypto_hash_sha3256(output: &mut Sha3256Digest, input: &[u8]) {
    let mut state = crypto_hash_sha3256_init();
    crypto_hash_sha3256_update(&mut state, input);
    crypto_hash_sha3256_final(state, output);
}

/// Internal state for SHA3-256 functions.
#[derive(Default)]
pub struct Sha3256State {
    pub(super) hasher: Sha3256,
}

/// Initializes a SHA3-256 hasher.
pub fn crypto_hash_sha3256_init() -> Sha3256State {
    Sha3256State::default()
}

/// Updates `state` of SHA3-256 hasher with `input`.
pub fn crypto_hash_sha3256_update(state: &mut Sha3256State, input: &[u8]) {
    state.hasher.update(input);
}

/// Finalizes `state` of SHA3-256, and writes the digest to `output` consuming
/// `state`.
pub fn crypto_hash_sha3256_final(state: Sha3256State, output: &mut Sha3256Digest) {
    state.hasher.finalize_into_bytes(output)
}

/// Computes a SHA3-512 hash from `input`.
pub fn crypto_hash_sha3512(output: &mut Sha3512Digest, input: &[u8]) {
    let mut state = crypto_hash_sha3512_init();
    crypto_hash_sha3512_update(&mut state, input);
    crypto_hash_sha3512_final(state, output);
}

/// Internal state for SHA3-512 functions.
#[derive(Default)]
pub struct Sha3512State {
    pub(super) hasher: Sha3512,
}

/// Initializes a SHA3-512 hasher.
pub fn crypto_hash_sha3512_init() -> Sha3512State {
    Sha3512State::default()
}

/// Updates `state` of SHA3-512 hasher with `input`.
pub fn crypto_hash_sha3512_update(state: &mut Sha3512State, input: &[u8]) {
    state.hasher.update(input);
}

/// Finalizes `state` of SHA3-512, and writes the digest to `output` consuming
/// `state`.
pub fn crypto_hash_sha3512_final(state: Sha3512State, output: &mut Sha3512Digest) {
    state.hasher.finalize_into_bytes(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_hash_sha256() {
        let mut our_digest = [0u8; CRYPTO_HASH_SHA256_BYTES];
        crypto_hash_sha256(&mut our_digest, b"abc");

        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("hex failed");
        assert_eq!(our_digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_crypto_hash_sha3256() {
        let mut our_digest = [0u8; CRYPTO_HASH_SHA3256_BYTES];
        crypto_hash_sha3256(&mut our_digest, b"abc");

        let expected =
            hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
                .expect("hex failed");
        assert_eq!(our_digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_crypto_hash_sha3256_update() {
        let mut state = crypto_hash_sha3256_init();
        crypto_hash_sha3256_update(&mut state, b"a");
        crypto_hash_sha3256_update(&mut state, b"b");
        crypto_hash_sha3256_update(&mut state, b"c");

        let mut our_digest = [0u8; CRYPTO_HASH_SHA3256_BYTES];
        crypto_hash_sha3256_final(state, &mut our_digest);

        let expected =
            hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
                .expect("hex failed");
        assert_eq!(our_digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_crypto_hash_sha3512() {
        let mut our_digest = [0u8; CRYPTO_HASH_SHA3512_BYTES];
        crypto_hash_sha3512(&mut our_digest, b"abc");

        let expected = hex::decode(concat!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        ))
        .expect("hex failed");
        assert_eq!(our_digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_crypto_hash_sha3512_update() {
        let mut state = crypto_hash_sha3512_init();
        crypto_hash_sha3512_update(&mut state, b"a");
        crypto_hash_sha3512_update(&mut state, b"b");
        crypto_hash_sha3512_update(&mut state, b"c");

        let mut our_digest = [0u8; CRYPTO_HASH_SHA3512_BYTES];
        crypto_hash_sha3512_final(state, &mut our_digest);

        let expected = hex::decode(concat!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        ))
        .expect("hex failed");
        assert_eq!(our_digest.as_slice(), expected.as_slice());
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_crypto_hash_sha512() {
        use sodiumoxide::crypto::hash;

        use crate::rng::randombytes_buf;

        let r = randombytes_buf(64);

        let their_digest = hash::hash(&r);
        let mut our_digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
        crypto_hash_sha512(&mut our_digest, &r);

        assert_eq!(their_digest.as_ref(), our_digest);
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_crypto_hash_sha512_update() {
        use sodiumoxide::crypto::hash;

        use crate::rng::randombytes_buf;

        let mut their_state = hash::State::new();
        let mut our_state = crypto_hash_sha512_init();

        for _ in 0..10 {
            let r = randombytes_buf(64);
            their_state.update(&r);
            crypto_hash_sha512_update(&mut our_state, &r);
        }

        let their_digest = their_state.finalize();
        let mut our_digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
        crypto_hash_sha512_final(our_state, &mut our_digest);

        assert_eq!(their_digest.as_ref(), our_digest);
    }
}
