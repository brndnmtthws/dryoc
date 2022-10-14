//! # SHA-512 hash algorithm
//!
//! Provides an implementation of the SHA-512 hash algorithm.
//!
//! ## Example
//!
//! ```
//! use dryoc::sha512::Sha512;
//!
//! let mut state = Sha512::new();
//! state.update(b"bytes");
//! let hash = state.finalize_to_vec();
//! ```
use generic_array::typenum::U64;
use generic_array::GenericArray;
use sha2::{Digest as DigestImpl, Sha512 as Sha512Impl};

use crate::constants::CRYPTO_HASH_SHA512_BYTES;
use crate::types::*;

/// Type alias for SHA512 digest, provided for convience.
pub type Digest = StackByteArray<CRYPTO_HASH_SHA512_BYTES>;

/// SHA-512 wrapper, provided for convience.
pub struct Sha512 {
    hasher: Sha512Impl,
}

impl Sha512 {
    /// Returns a new SHA-512 hasher instance.
    pub fn new() -> Self {
        Self {
            hasher: Sha512Impl::new(),
        }
    }

    /// One-time interface to compute SHA-512 digest for `input`, copying result
    /// into `output`.
    pub fn compute_into_bytes<
        Input: Bytes + ?Sized,
        Output: MutByteArray<CRYPTO_HASH_SHA512_BYTES>,
    >(
        output: &mut Output,
        input: &Input,
    ) {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize_into_bytes(output)
    }

    /// One-time interface to compute SHA-512 digest for `input`.
    pub fn compute<Input: Bytes + ?Sized, Output: NewByteArray<CRYPTO_HASH_SHA512_BYTES>>(
        input: &Input,
    ) -> Output {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    /// Wrapper around [`Sha512::compute`], returning a [`Vec`]. Provided for
    /// convenience.
    pub fn compute_to_vec<Input: Bytes + ?Sized>(input: &Input) -> Vec<u8> {
        Self::compute(input)
    }

    /// Updates SHA-512 hash state with `input`.
    pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
        self.hasher.update(input.as_slice())
    }

    /// Consumes hasher and return final computed hash.
    pub fn finalize<Output: NewByteArray<CRYPTO_HASH_SHA512_BYTES>>(self) -> Output {
        let mut hash = Output::new_byte_array();
        self.finalize_into_bytes(&mut hash);
        hash
    }

    /// Consumes hasher and writes final computed hash into `output`.
    pub fn finalize_into_bytes<Output: MutByteArray<CRYPTO_HASH_SHA512_BYTES>>(
        mut self,
        output: &mut Output,
    ) {
        let arr = GenericArray::<_, U64>::from_mut_slice(output.as_mut_slice());
        self.hasher.finalize_into_reset(arr);
    }

    /// Consumes hasher and returns final computed hash as a [`Vec`].
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512() {
        use sodiumoxide::crypto::hash;

        use crate::rng::randombytes_buf;

        let mut their_state = hash::State::new();
        let mut our_state = Sha512::new();

        for _ in 0..10 {
            let r = randombytes_buf(64);
            their_state.update(&r);
            our_state.update(&r);
        }

        let their_digest = their_state.finalize();
        let our_digest = our_state.finalize_to_vec();

        assert_eq!(their_digest.as_ref(), our_digest);
    }
}
