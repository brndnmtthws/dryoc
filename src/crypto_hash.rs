use sha2::{Digest, Sha512};

pub fn crypto_hash_sha512(input: &[u8]) -> Vec<u8> {
    let mut state = crypto_hash_sha512_init();
    state.update(input);
    state.finalize()
}

pub struct HashSha512 {
    hasher: Sha512,
}

impl HashSha512 {
    fn new() -> Self {
        Self {
            hasher: Sha512::new(),
        }
    }

    fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    fn finalize(self) -> Vec<u8> {
        let result = self.hasher.finalize();

        result.to_vec()
    }
}

pub fn crypto_hash_sha512_init() -> HashSha512 {
    HashSha512::new()
}

pub fn crypto_hash_sha512_update(state: &mut HashSha512, input: &[u8]) {
    state.update(input);
}

pub fn crypto_hash_sha512_final(state: HashSha512) -> Vec<u8> {
    state.finalize()
}

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
    fn test_crypto_hash_sha512_update() {
        use crate::rng::randombytes_buf;
        use sodiumoxide::crypto::hash;

        let mut their_state = hash::State::new();
        let mut our_state = crypto_hash_sha512_init();

        for _ in 0..10 {
            let r = randombytes_buf(64);
            their_state.update(&r);
            our_state.update(&r);
        }

        let their_digest = their_state.finalize();
        let our_digest = our_state.finalize();

        assert_eq!(their_digest.as_ref(), our_digest);
    }
}
