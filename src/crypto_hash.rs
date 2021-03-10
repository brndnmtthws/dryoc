use sha2::{Digest, Sha512};

/// Computes a SHA512 hash from `input'
pub fn crypto_hash_sha512(input: &[u8]) -> Vec<u8> {
    let mut state = crypto_hash_sha512_init();
    state.update(input);
    state.finalize().to_vec()
}

/// SHA512 wrapper
pub struct HashSha512 {
    hasher: Sha512,
}

impl HashSha512 {
    /// Returns a new SHA-512 hasher instance
    pub fn new() -> Self {
        Self {
            hasher: crypto_hash_sha512_init(),
        }
    }

    /// Updates SHA-512 hash state with `input`
    pub fn update(&mut self, input: &[u8]) {
        crypto_hash_sha512_update(&mut self.hasher, input);
    }

    /// Consumes hasher and return final computed hash
    pub fn finalize(self) -> Vec<u8> {
        crypto_hash_sha512_final(self.hasher)
    }
}

/// Initializes SHA512 hasher
pub fn crypto_hash_sha512_init() -> Sha512 {
    Sha512::new()
}

/// Updates `state` of SHA512 hasher with `input`
pub fn crypto_hash_sha512_update(state: &mut Sha512, input: &[u8]) {
    state.update(input);
}

/// Finalizes `state` of SHA512 and return hash result, consuming `state`
pub fn crypto_hash_sha512_final(state: Sha512) -> Vec<u8> {
    state.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_hash_sha512() {
        use crate::rng::randombytes_buf;
        use sodiumoxide::crypto::hash;

        let r = randombytes_buf(64);

        let their_digest = hash::hash(&r);
        let our_digest = crypto_hash_sha512(&r);

        assert_eq!(their_digest.as_ref(), our_digest);
    }

    #[test]
    fn test_sha512() {
        use crate::rng::randombytes_buf;
        use sodiumoxide::crypto::hash;

        let mut their_state = hash::State::new();
        let mut our_state = HashSha512::new();

        for _ in 0..10 {
            let r = randombytes_buf(64);
            their_state.update(&r);
            our_state.update(&r);
        }

        let their_digest = their_state.finalize();
        let our_digest = our_state.finalize();

        assert_eq!(their_digest.as_ref(), our_digest);
    }

    #[test]
    fn test_crypto_hash_sha512_update() {
        use crate::rng::randombytes_buf;
        use sodiumoxide::crypto::hash;

        let mut their_state = hash::State::new();
        let mut our_state = crypto_hash_sha512_init();

        for _ in 0..10 {
            let r = randombytes_buf(64);
            their_state.update(&r);
            crypto_hash_sha512_update(&mut our_state, &r);
        }

        let their_digest = their_state.finalize();
        let our_digest = crypto_hash_sha512_final(our_state);

        assert_eq!(their_digest.as_ref(), our_digest);
    }
}
