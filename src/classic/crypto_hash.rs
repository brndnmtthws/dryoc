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
//! let mut default_digest: Digest = [0u8; 64];
//! crypto_hash(&mut default_digest, message);
//! assert_eq!(default_digest.len(), 64);
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

/// Computes a SHA-512 hash from `input` using libsodium's default
/// `crypto_hash` primitive.
pub fn crypto_hash(output: &mut Digest, input: &[u8]) {
    crypto_hash_sha512(output, input);
}

/// Generates the `*State` struct and `init`/`update`/`final` triple for one
/// hash function. Attributes on an entry, including doc comments, are applied
/// to the generated item.
macro_rules! crypto_hash_state {
    (
        $(#[$state_meta:meta])*
        state: $state:ident($hasher:ty),
        $(#[$init_meta:meta])*
        init: $init:ident,
        $(#[$update_meta:meta])*
        update: $update:ident,
        $(#[$final_meta:meta])*
        final: $final:ident($digest:ty)
    ) => {
        $(#[$state_meta])*
        #[derive(Default)]
        pub struct $state {
            pub(super) hasher: $hasher,
        }

        $(#[$init_meta])*
        pub fn $init() -> $state {
            <$state>::default()
        }

        $(#[$update_meta])*
        pub fn $update(state: &mut $state, input: &[u8]) {
            state.hasher.update(input);
        }

        $(#[$final_meta])*
        pub fn $final(state: $state, output: &mut $digest) {
            state.hasher.finalize_into_bytes(output)
        }
    };
}

/// Computes a SHA-256 hash from `input`.
pub fn crypto_hash_sha256(output: &mut Sha256Digest, input: &[u8]) {
    Sha256::compute_into_bytes(output, input);
}

crypto_hash_state! {
    /// Internal state for SHA-256 functions.
    state: Sha256State(Sha256),
    /// Initializes a SHA-256 hasher.
    init: crypto_hash_sha256_init,
    /// Updates `state` of SHA-256 hasher with `input`.
    update: crypto_hash_sha256_update,
    /// Finalizes `state` of SHA-256, and writes the digest to `output`
    /// consuming `state`.
    final: crypto_hash_sha256_final(Sha256Digest)
}

/// Computes a SHA-512 hash from `input`.
pub fn crypto_hash_sha512(output: &mut Digest, input: &[u8]) {
    Sha512::compute_into_bytes(output, input);
}

crypto_hash_state! {
    /// Internal state for SHA-512 functions.
    state: Sha512State(Sha512),
    /// Initializes a SHA-512 hasher.
    init: crypto_hash_sha512_init,
    /// Updates `state` of SHA-512 hasher with `input`.
    update: crypto_hash_sha512_update,
    /// Finalizes `state` of SHA-512, and writes the digest to `output`
    /// consuming `state`.
    final: crypto_hash_sha512_final(Digest)
}

/// Computes a SHA3-256 hash from `input`.
pub fn crypto_hash_sha3256(output: &mut Sha3256Digest, input: &[u8]) {
    let mut state = crypto_hash_sha3256_init();
    crypto_hash_sha3256_update(&mut state, input);
    crypto_hash_sha3256_final(state, output);
}

crypto_hash_state! {
    /// Internal state for SHA3-256 functions.
    state: Sha3256State(Sha3256),
    /// Initializes a SHA3-256 hasher.
    init: crypto_hash_sha3256_init,
    /// Updates `state` of SHA3-256 hasher with `input`.
    update: crypto_hash_sha3256_update,
    /// Finalizes `state` of SHA3-256, and writes the digest to `output`
    /// consuming `state`.
    final: crypto_hash_sha3256_final(Sha3256Digest)
}

/// Computes a SHA3-512 hash from `input`.
pub fn crypto_hash_sha3512(output: &mut Sha3512Digest, input: &[u8]) {
    let mut state = crypto_hash_sha3512_init();
    crypto_hash_sha3512_update(&mut state, input);
    crypto_hash_sha3512_final(state, output);
}

crypto_hash_state! {
    /// Internal state for SHA3-512 functions.
    state: Sha3512State(Sha3512),
    /// Initializes a SHA3-512 hasher.
    init: crypto_hash_sha3512_init,
    /// Updates `state` of SHA3-512 hasher with `input`.
    update: crypto_hash_sha3512_update,
    /// Finalizes `state` of SHA3-512, and writes the digest to `output`
    /// consuming `state`.
    final: crypto_hash_sha3512_final(Sha3512Digest)
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;
    use crate::sha3::test_vectors::{SHA3_256_RATE, SHA3_512_RATE, sha3_256, sha3_512};

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex failed")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// Lengths around the padding boundary (the last message length whose
    /// `0x80` and bit-length field still fit the same block), the block
    /// boundary and two blocks, for a hash with `block`-byte blocks and a
    /// `length_field`-byte bit-length field.
    fn sha2_lengths(block: usize, length_field: usize) -> impl Iterator<Item = usize> {
        let pad = block - length_field;
        [
            0,
            1,
            pad - 1,
            pad,
            pad + 1,
            block - 1,
            block,
            block + 1,
            2 * block - 1,
            2 * block,
        ]
        .into_iter()
    }

    /// Drives a classic `init`/`update`/`final` triple over `message` with
    /// each chunking: one update, exact `block`-sized updates, and one byte
    /// per update with an empty update around every byte.
    fn streamed<S>(
        message: &[u8],
        block: usize,
        init: impl Fn() -> S,
        update: impl Fn(&mut S, &[u8]),
        finalize: impl Fn(S) -> Vec<u8>,
    ) -> [Vec<u8>; 3] {
        let mut one = init();
        update(&mut one, message);

        let mut blocks = init();
        for chunk in message.chunks(block) {
            update(&mut blocks, chunk);
        }

        let mut bytes = init();
        update(&mut bytes, b"");
        for byte in message {
            update(&mut bytes, std::slice::from_ref(byte));
            update(&mut bytes, b"");
        }

        [finalize(one), finalize(blocks), finalize(bytes)]
    }

    /// FIPS 180-4 SHA-256 known answers through the one-shot function.
    #[test]
    fn test_crypto_hash_sha256() {
        for (message, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut digest = [0u8; CRYPTO_HASH_SHA256_BYTES];
            crypto_hash_sha256(&mut digest, message);
            assert_eq!(digest.to_vec(), hex(expected));
        }
    }

    /// `crypto_hash` is FIPS 180-4 SHA-512: the `abc` and two-block example
    /// digests, one-shot and streamed.
    #[test]
    fn test_crypto_hash_is_sha512() {
        for (message, expected) in [
            (
                &b"abc"[..],
                concat!(
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                ),
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                concat!(
                    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018",
                    "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
                ),
            ),
        ] {
            let expected = hex(expected);
            let mut digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
            crypto_hash(&mut digest, message);
            assert_eq!(digest.to_vec(), expected);

            for actual in streamed(
                message,
                128,
                crypto_hash_sha512_init,
                crypto_hash_sha512_update,
                |state| {
                    let mut digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
                    crypto_hash_sha512_final(state, &mut digest);
                    digest.to_vec()
                },
            ) {
                assert_eq!(actual, expected);
            }
        }
    }

    /// The SHA-256 classic API at every padding and block boundary, for each
    /// chunking, against the `sha2` crate.
    #[test]
    fn test_crypto_hash_sha256_boundaries_match_sha2() {
        for len in sha2_lengths(64, 8) {
            let message = pattern(len);
            let expected = sha2::Sha256::digest(&message).to_vec();
            let mut digest = [0u8; CRYPTO_HASH_SHA256_BYTES];
            crypto_hash_sha256(&mut digest, &message);
            assert_eq!(digest.to_vec(), expected, "one-shot len {len}");
            for actual in streamed(
                &message,
                64,
                crypto_hash_sha256_init,
                crypto_hash_sha256_update,
                |state| {
                    let mut digest = [0u8; CRYPTO_HASH_SHA256_BYTES];
                    crypto_hash_sha256_final(state, &mut digest);
                    digest.to_vec()
                },
            ) {
                assert_eq!(actual, expected, "streamed len {len}");
            }
        }
    }

    /// The SHA-512 classic API at every padding and block boundary, for each
    /// chunking, against the `sha2` crate.
    #[test]
    fn test_crypto_hash_sha512_boundaries_match_sha2() {
        for len in sha2_lengths(128, 16) {
            let message = pattern(len);
            let expected = sha2::Sha512::digest(&message).to_vec();
            let mut digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
            crypto_hash_sha512(&mut digest, &message);
            assert_eq!(digest.to_vec(), expected, "one-shot len {len}");
            for actual in streamed(
                &message,
                128,
                crypto_hash_sha512_init,
                crypto_hash_sha512_update,
                |state| {
                    let mut digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
                    crypto_hash_sha512_final(state, &mut digest);
                    digest.to_vec()
                },
            ) {
                assert_eq!(actual, expected, "streamed len {len}");
            }
        }
    }

    /// FIPS 202 SHA3-256 answers at the rate boundaries through the one-shot
    /// function and every `init`/`update`/`final` chunking (rate-sized
    /// updates end exactly on a permutation).
    #[test]
    fn test_crypto_hash_sha3256_known_answers() {
        for (message, expected) in sha3_256() {
            let len = message.len();
            let mut digest = [0u8; CRYPTO_HASH_SHA3256_BYTES];
            crypto_hash_sha3256(&mut digest, &message);
            assert_eq!(digest.to_vec(), expected, "one-shot len {len}");
            if len > 2 * SHA3_256_RATE {
                // The million-byte message only needs the one-shot check.
                continue;
            }
            for actual in streamed(
                &message,
                SHA3_256_RATE,
                crypto_hash_sha3256_init,
                crypto_hash_sha3256_update,
                |state| {
                    let mut digest = [0u8; CRYPTO_HASH_SHA3256_BYTES];
                    crypto_hash_sha3256_final(state, &mut digest);
                    digest.to_vec()
                },
            ) {
                assert_eq!(actual, expected, "streamed len {len}");
            }
        }
    }

    #[test]
    fn test_crypto_hash_sha3512_known_answers() {
        for (message, expected) in sha3_512() {
            let len = message.len();
            let mut digest = [0u8; CRYPTO_HASH_SHA3512_BYTES];
            crypto_hash_sha3512(&mut digest, &message);
            assert_eq!(digest.to_vec(), expected, "one-shot len {len}");
            if len > 2 * SHA3_512_RATE {
                continue;
            }
            for actual in streamed(
                &message,
                SHA3_512_RATE,
                crypto_hash_sha3512_init,
                crypto_hash_sha3512_update,
                |state| {
                    let mut digest = [0u8; CRYPTO_HASH_SHA3512_BYTES];
                    crypto_hash_sha3512_final(state, &mut digest);
                    digest.to_vec()
                },
            ) {
                assert_eq!(actual, expected, "streamed len {len}");
            }
        }
    }

    /// libsodium's `crypto_hash` (SHA-512) at the same boundaries, one-shot
    /// and streamed with the same cuts on both sides.
    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_crypto_hash_sha512_matches_libsodium() {
        use sodiumoxide::crypto::hash;

        for len in sha2_lengths(128, 16) {
            let message = pattern(len);
            let expected = hash::hash(&message);
            let mut digest = [0u8; CRYPTO_HASH_SHA512_BYTES];
            crypto_hash(&mut digest, &message);
            assert_eq!(digest, expected.0, "one-shot len {len}");

            let mut theirs = hash::State::new();
            let mut ours = crypto_hash_sha512_init();
            for chunk in message.chunks(127) {
                theirs.update(chunk);
                crypto_hash_sha512_update(&mut ours, chunk);
                theirs.update(b"");
                crypto_hash_sha512_update(&mut ours, b"");
            }
            crypto_hash_sha512_final(ours, &mut digest);
            assert_eq!(digest, theirs.finalize().0, "streamed len {len}");
        }
    }
}
