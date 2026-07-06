//! # SHA-3 hash algorithms
//!
//! Provides implementations of the SHA3-256 and SHA3-512 hash algorithms.
//!
//! SHA-3 hashes are unkeyed cryptographic hash functions. They turn arbitrary
//! input bytes into fixed-size digests. Hashes are useful for fingerprints and
//! compatibility with protocols that require SHA-3, but they do not
//! authenticate messages by themselves. Use [`crate::auth`] or [`crate::hmac`]
//! when a secret key must be involved.
//!
//! ## Example
//!
//! ```
//! use dryoc::sha3::Sha3256;
//!
//! let mut state = Sha3256::new();
//! state.update(b"The web of our life is of a mingled yarn.");
//! let hash = state.finalize_to_vec();
//! assert_eq!(hash.len(), 32);
//! ```
use sha3_impl::{Digest as DigestImpl, Sha3_256 as Sha3256Impl, Sha3_512 as Sha3512Impl};

use crate::constants::{CRYPTO_HASH_SHA3256_BYTES, CRYPTO_HASH_SHA3512_BYTES};
use crate::types::*;

/// Type alias for SHA3-256 digest, provided for convenience.
pub type Sha3256Digest = StackByteArray<CRYPTO_HASH_SHA3256_BYTES>;
/// Type alias for SHA3-512 digest, provided for convenience.
pub type Sha3512Digest = StackByteArray<CRYPTO_HASH_SHA3512_BYTES>;

/// SHA3-256 wrapper, provided for convenience.
pub struct Sha3256 {
    hasher: Sha3256Impl,
}

impl Sha3256 {
    /// Returns a new SHA3-256 hasher instance.
    pub fn new() -> Self {
        Self {
            hasher: Sha3256Impl::new(),
        }
    }

    /// One-time interface to compute SHA3-256 digest for `input`, copying
    /// result into `output`.
    pub fn compute_into_bytes<
        Input: Bytes + ?Sized,
        Output: MutByteArray<CRYPTO_HASH_SHA3256_BYTES>,
    >(
        output: &mut Output,
        input: &Input,
    ) {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize_into_bytes(output)
    }

    /// One-time interface to compute SHA3-256 digest for `input`.
    pub fn compute<Input: Bytes + ?Sized, Output: NewByteArray<CRYPTO_HASH_SHA3256_BYTES>>(
        input: &Input,
    ) -> Output {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    /// Wrapper around [`Sha3256::compute`], returning a [`Vec`]. Provided for
    /// convenience.
    pub fn compute_to_vec<Input: Bytes + ?Sized>(input: &Input) -> Vec<u8> {
        Self::compute(input)
    }

    /// Updates SHA3-256 hash state with `input`.
    pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
        self.hasher.update(input.as_slice())
    }

    /// Consumes hasher and return final computed hash.
    pub fn finalize<Output: NewByteArray<CRYPTO_HASH_SHA3256_BYTES>>(self) -> Output {
        let mut hash = Output::new_byte_array();
        self.finalize_into_bytes(&mut hash);
        hash
    }

    /// Consumes hasher and writes final computed hash into `output`.
    pub fn finalize_into_bytes<Output: MutByteArray<CRYPTO_HASH_SHA3256_BYTES>>(
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

impl Default for Sha3256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA3-512 wrapper, provided for convenience.
pub struct Sha3512 {
    hasher: Sha3512Impl,
}

impl Sha3512 {
    /// Returns a new SHA3-512 hasher instance.
    pub fn new() -> Self {
        Self {
            hasher: Sha3512Impl::new(),
        }
    }

    /// One-time interface to compute SHA3-512 digest for `input`, copying
    /// result into `output`.
    pub fn compute_into_bytes<
        Input: Bytes + ?Sized,
        Output: MutByteArray<CRYPTO_HASH_SHA3512_BYTES>,
    >(
        output: &mut Output,
        input: &Input,
    ) {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize_into_bytes(output)
    }

    /// One-time interface to compute SHA3-512 digest for `input`.
    pub fn compute<Input: Bytes + ?Sized, Output: NewByteArray<CRYPTO_HASH_SHA3512_BYTES>>(
        input: &Input,
    ) -> Output {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    /// Wrapper around [`Sha3512::compute`], returning a [`Vec`]. Provided for
    /// convenience.
    pub fn compute_to_vec<Input: Bytes + ?Sized>(input: &Input) -> Vec<u8> {
        Self::compute(input)
    }

    /// Updates SHA3-512 hash state with `input`.
    pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
        self.hasher.update(input.as_slice())
    }

    /// Consumes hasher and return final computed hash.
    pub fn finalize<Output: NewByteArray<CRYPTO_HASH_SHA3512_BYTES>>(self) -> Output {
        let mut hash = Output::new_byte_array();
        self.finalize_into_bytes(&mut hash);
        hash
    }

    /// Consumes hasher and writes final computed hash into `output`.
    pub fn finalize_into_bytes<Output: MutByteArray<CRYPTO_HASH_SHA3512_BYTES>>(
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

impl Default for Sha3512 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_sha3256(input: &[u8], expected_hex: &str) {
        let expected = hex::decode(expected_hex).expect("hex failed");
        assert_eq!(Sha3256::compute_to_vec(input), expected);

        let mut state = Sha3256::new();
        for chunk in input.chunks(1) {
            state.update(chunk);
        }
        assert_eq!(state.finalize_to_vec(), expected);
    }

    fn assert_sha3512(input: &[u8], expected_hex: &str) {
        let expected = hex::decode(expected_hex).expect("hex failed");
        assert_eq!(Sha3512::compute_to_vec(input), expected);

        let mut state = Sha3512::new();
        for chunk in input.chunks(1) {
            state.update(chunk);
        }
        assert_eq!(state.finalize_to_vec(), expected);
    }

    #[test]
    fn test_sha3256_known_answers() {
        assert_sha3256(
            b"",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        );
        assert_sha3256(
            b"abc",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        );
    }

    #[test]
    fn test_sha3512_known_answers() {
        assert_sha3512(
            b"",
            concat!(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a",
                "615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            ),
        );
        assert_sha3512(
            b"abc",
            concat!(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            ),
        );
    }
}
