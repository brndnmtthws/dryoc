//! # SHA-256 hash algorithm
//!
//! Provides an implementation of the SHA-256 hash algorithm.
//!
//! SHA-256 is an unkeyed cryptographic hash function. It turns arbitrary input
//! bytes into a 32-byte digest. Hashes are useful for fingerprints and
//! compatibility with protocols that require SHA-256, but they do not
//! authenticate messages by themselves. Use [`crate::auth`] or [`crate::hmac`]
//! when a secret key must be involved.
//!
//! ## Example
//!
//! ```
//! use dryoc::sha256::Sha256;
//!
//! let mut state = Sha256::new();
//! state.update(b"All the world's a stage, ");
//! state.update(b"and all the men and women merely players.");
//! let hash = state.finalize_to_vec();
//! assert_eq!(hash.len(), 32);
//! ```
use crate::constants::CRYPTO_HASH_SHA256_BYTES;
use crate::sha2_impl::sha2_hasher;
use crate::types::*;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod sha256_aarch64;

/// Type alias for SHA256 digest, provided for convenience.
pub type Digest = StackByteArray<CRYPTO_HASH_SHA256_BYTES>;

const BLOCK_BYTES: usize = 64;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Compresses whole blocks into `state`, using the hardware `sha2` extension
/// when the running CPU has it.
///
/// Out of line at opt-level `z` (with the kernels it calls at `z`, `s` and
/// `2`), which adds no copy: they only get `&mut` to the hasher's own state
/// or to `compute_into_bytes`' wiped local, and `&` to the blocks.
#[inline]
fn compress(state: &mut [u32; 8], blocks: &[[u8; BLOCK_BYTES]]) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if has_aarch64_feature!("sha2") {
        // SAFETY: the feature check above confirmed the `sha2` extension.
        unsafe { sha256_aarch64::compress(state, blocks) };
        return;
    }
    sha2::block_api::compress256(state, blocks);
}

sha2_hasher! {
    /// SHA-256 hasher.
    ///
    /// Buffers input into 64-byte blocks and drives the hardware `sha2` compression
    /// (runtime-detected on AArch64) or the `sha2` crate's
    /// compression function, which selects hardware SHA-256 instructions at
    /// runtime where available. The state and any buffered input are wiped when
    /// the hasher is dropped.
    pub struct Sha256;
    algorithm: "SHA-256",
    word: u32,
    word_bytes: 4,
    length: u64,
    length_bytes: 8,
    block_bytes: BLOCK_BYTES,
    digest_bytes: CRYPTO_HASH_SHA256_BYTES,
    iv: IV,
    compress: compress,
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use sha2::Digest as _;

    use super::*;
    use crate::test_prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex failed")
    }

    /// FIPS 180-2 test vectors, including the 56-byte message whose padding
    /// needs a second block.
    #[test]
    fn test_sha256_known_answers() {
        assert_eq!(
            Sha256::compute_to_vec(b""),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            Sha256::compute_to_vec(b"abc"),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            Sha256::compute_to_vec(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    /// Every buffer fill level and padding boundary, absorbed in one call and
    /// in irregular chunks, matches the `sha2` crate.
    #[test]
    fn test_sha256_matches_sha2_for_all_lengths_and_chunkings() {
        let message: Vec<u8> = (0..600u32).map(|i| (i * 31 % 251) as u8).collect();
        for len in (0..200).chain([255, 256, 257, 511, 512, 513, 599, 600]) {
            let expected = sha2::Sha256::digest(&message[..len]).to_vec();
            assert_eq!(
                Sha256::compute_to_vec(&message[..len]),
                expected,
                "len {len}"
            );

            let mut hasher = Sha256::new();
            let mut offset = 0;
            for chunk in [1usize, 7, 63, 64, 65, 100, 3].iter().cycle() {
                if offset >= len {
                    break;
                }
                let end = (offset + chunk).min(len);
                hasher.update(&message[offset..end]);
                offset = end;
            }
            assert_eq!(hasher.finalize_to_vec(), expected, "chunked len {len}");
        }
    }

    /// Empty updates at every buffer state and updates that end exactly on
    /// a block boundary from a partially filled buffer (1 + 63, 63 + 1), a
    /// whole block from an empty buffer, and finalization from both an empty
    /// and an almost-full buffer, against the `sha2` crate.
    #[test]
    fn test_empty_and_exact_fill_updates_match_sha2() {
        const B: usize = BLOCK_BYTES;
        let message: Vec<u8> = (0..3 * B as u32).map(|i| (i * 31 % 251) as u8).collect();
        for len in [B, B + 1, 2 * B, 2 * B + 1, 3 * B - 1, 3 * B] {
            let message = &message[..len];
            let mut cuts: Vec<usize> = [0, 1, B, 2 * B, 3 * B - 1, len]
                .into_iter()
                .filter(|&cut| cut <= len)
                .collect();
            cuts.dedup();
            let mut hasher = Sha256::new();
            hasher.update(b"");
            for window in cuts.windows(2) {
                hasher.update(&message[window[0]..window[1]]);
                hasher.update(b"");
            }
            assert_eq!(
                hasher.finalize_to_vec(),
                sha2::Sha256::digest(message).to_vec(),
                "len {len}"
            );
        }
    }

    /// The hardware loop agrees with the portable compression for every block
    /// count around its loop boundaries, including the empty run.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    #[test]
    fn test_hw_compress_matches_portable() {
        if !has_aarch64_feature!("sha2") {
            return;
        }
        let blocks: Vec<[u8; 64]> = (0..40u32)
            .map(|b| {
                core::array::from_fn(|i| (b * 64 + i as u32).wrapping_mul(2654435761) as u8 >> 1)
            })
            .collect();
        for n in 0..=blocks.len() {
            let mut expected = IV;
            let mut actual = IV;
            sha2::block_api::compress256(&mut expected, &blocks[..n]);
            unsafe { sha256_aarch64::compress(&mut actual, &blocks[..n]) };
            assert_eq!(actual, expected, "{n} blocks");
        }
    }
}
