use crate::constants::{CRYPTO_HASH_SHA256_BYTES, CRYPTO_HASH_SHA512_BYTES};
use crate::sha256::Sha256;
use crate::sha512::*;

/// Type alias for SHA512 digest output.
pub type Digest = Sha512Digest;
/// Type alias for SHA256 digest output.
pub type Sha256Digest = [u8; CRYPTO_HASH_SHA256_BYTES];
/// Type alias for SHA512 digest output.
pub type Sha512Digest = [u8; CRYPTO_HASH_SHA512_BYTES];

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

#[cfg(all(test, dryoc_native_tests))]
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
    fn test_crypto_hash_sha512() {
        use sodiumoxide::crypto::hash;

        use crate::rng::randombytes_buf;

        let r = randombytes_buf(64);

        let their_digest = hash::hash(&r);
        let mut our_digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
        crypto_hash_sha512(&mut our_digest, &r);

        assert_eq!(their_digest.as_ref(), our_digest);
    }

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
