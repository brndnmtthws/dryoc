use crate::constants::CRYPTO_HASH_SHA512_BYTES;
use crate::sha512::*;

/// Type alias for SHA512 digest output.
pub type Digest = [u8; CRYPTO_HASH_SHA512_BYTES];

/// Computes a SHA-512 hash from `input`.
pub fn crypto_hash_sha512(output: &mut Digest, input: &[u8]) {
    let mut state = crypto_hash_sha512_init();
    crypto_hash_sha512_update(&mut state, input);
    crypto_hash_sha512_final(state, output);
}

/// Internal state for `crypto_hash_*` functions.
pub struct Sha512State {
    pub(super) hasher: Sha512,
}

impl Default for Sha512State {
    fn default() -> Self {
        Self {
            hasher: Sha512::new(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
