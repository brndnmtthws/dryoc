//! # SHA-256 hash algorithm
//!
//! Provides an implementation of the SHA-256 hash algorithm.
//!
//! ## Example
//!
//! ```
//! use dryoc::sha256::Sha256;
//!
//! let mut state = Sha256::new();
//! state.update(b"bytes");
//! let hash = state.finalize_to_vec();
//! ```
use sha2::{Digest as DigestImpl, Sha256 as Sha256Impl};

use crate::constants::CRYPTO_HASH_SHA256_BYTES;
use crate::types::*;

/// Type alias for SHA256 digest, provided for convenience.
pub type Digest = StackByteArray<CRYPTO_HASH_SHA256_BYTES>;

/// SHA-256 wrapper, provided for convenience.
pub struct Sha256 {
    hasher: Sha256Impl,
}

impl Sha256 {
    /// Returns a new SHA-256 hasher instance.
    pub fn new() -> Self {
        Self {
            hasher: Sha256Impl::new(),
        }
    }

    /// One-time interface to compute SHA-256 digest for `input`, copying result
    /// into `output`.
    pub fn compute_into_bytes<
        Input: Bytes + ?Sized,
        Output: MutByteArray<CRYPTO_HASH_SHA256_BYTES>,
    >(
        output: &mut Output,
        input: &Input,
    ) {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize_into_bytes(output)
    }

    /// One-time interface to compute SHA-256 digest for `input`.
    pub fn compute<Input: Bytes + ?Sized, Output: NewByteArray<CRYPTO_HASH_SHA256_BYTES>>(
        input: &Input,
    ) -> Output {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    /// Wrapper around [`Sha256::compute`], returning a [`Vec`]. Provided for
    /// convenience.
    pub fn compute_to_vec<Input: Bytes + ?Sized>(input: &Input) -> Vec<u8> {
        Self::compute(input)
    }

    /// Updates SHA-256 hash state with `input`.
    pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
        self.hasher.update(input.as_slice())
    }

    /// Consumes hasher and return final computed hash.
    pub fn finalize<Output: NewByteArray<CRYPTO_HASH_SHA256_BYTES>>(self) -> Output {
        let mut hash = Output::new_byte_array();
        self.finalize_into_bytes(&mut hash);
        hash
    }

    /// Consumes hasher and writes final computed hash into `output`.
    pub fn finalize_into_bytes<Output: MutByteArray<CRYPTO_HASH_SHA256_BYTES>>(
        self,
        output: &mut Output,
    ) {
        let digest = self.hasher.finalize();
        output.as_mut_slice().copy_from_slice(&digest);
    }

    /// Consumes hasher and returns final computed hash as a [`Vec`].
    pub fn finalize_to_vec(self) -> Vec<u8> {
        self.finalize()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_answer() {
        let digest = Sha256::compute_to_vec(b"abc");
        assert_eq!(
            digest,
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("hex failed")
        );
    }
}
