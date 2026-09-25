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
use crate::constants::CRYPTO_HASH_SHA512_BYTES;
use crate::sha2_impl::sha2_hasher;
use crate::types::*;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod sha512_aarch64;

/// Type alias for a SHA-512 digest.
pub type Digest = StackByteArray<CRYPTO_HASH_SHA512_BYTES>;

const BLOCK_BYTES: usize = 128;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Compresses whole blocks into `state`, using the hardware SHA-512
/// instructions when the running CPU has them.
#[inline]
fn compress(state: &mut [u64; 8], blocks: &[[u8; BLOCK_BYTES]]) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if let Some(sha3) = crate::aarch64::Sha3::new() {
        sha512_aarch64::compress(sha3, state, blocks);
        return;
    }
    sha2::block_api::compress512(state, blocks);
}

sha2_hasher! {
    /// SHA-512 hasher.
    ///
    /// Buffers input into 128-byte blocks and drives the hardware SHA-512
    /// compression (runtime-detected on AArch64) or the `sha2` crate's portable
    /// compression function. The state and any buffered input are wiped when
    /// the hasher is dropped.
    pub struct Sha512;
    algorithm: "SHA-512",
    word: u64,
    word_bytes: 8,
    length: u128,
    length_bytes: 16,
    block_bytes: BLOCK_BYTES,
    digest_bytes: CRYPTO_HASH_SHA512_BYTES,
    iv: IV,
    compress: compress,
}

impl Sha512 {
    /// [`Self::absorb_key_block`] of `a` into the fresh hasher `self` and of
    /// `b` into the fresh hasher `other` (the HMAC inner and outer key
    /// blocks), compressed together where the hardware path can interleave
    /// them (see `sha512_aarch64::compress2`). Both chaining states are
    /// compressed in place.
    #[inline]
    pub(crate) fn absorb_key_blocks(
        &mut self,
        a: &[u8; BLOCK_BYTES],
        other: &mut Self,
        b: &[u8; BLOCK_BYTES],
    ) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if let Some(sha3) = crate::aarch64::Sha3::new() {
            debug_assert!(self.len == 0 && self.buflen == 0);
            debug_assert!(other.len == 0 && other.buflen == 0);
            sha512_aarch64::compress2(sha3, &mut self.state, a, &mut other.state, b);
            self.len = BLOCK_BYTES as u128;
            other.len = BLOCK_BYTES as u128;
            return;
        }
        self.absorb_key_block(a);
        other.absorb_key_block(b);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use sha2::Digest as _;

    use super::*;
    use crate::test_prelude::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex failed")
    }

    /// FIPS 180-2 test vectors, including the 112-byte message whose padding
    /// needs a second block.
    #[test]
    fn test_sha512_known_answers() {
        assert_eq!(
            Sha512::compute_to_vec(b""),
            hex(concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ))
        );
        assert_eq!(
            Sha512::compute_to_vec(b"abc"),
            hex(concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            ))
        );
        assert_eq!(
            Sha512::compute_to_vec(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            hex(concat!(
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018",
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            ))
        );
    }

    /// The interleaved two-state compression gives the same states as two
    /// single compressions, on random block pairs and edge patterns.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    #[test]
    fn test_compress2_matches_compress() {
        let Some(sha3) = crate::aarch64::Sha3::new() else {
            return;
        };
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..500 {
            let mut a = [0u8; BLOCK_BYTES];
            let mut b = [0u8; BLOCK_BYTES];
            match i {
                0 => {}
                1 => b = [0xff; BLOCK_BYTES],
                _ => {
                    for chunk in a.chunks_mut(8).chain(b.chunks_mut(8)) {
                        chunk.copy_from_slice(&next().to_le_bytes());
                    }
                }
            }
            let mut sa = IV;
            let mut sb = IV;
            if i % 3 == 0 {
                // Non-IV starting states too.
                for w in sa.iter_mut().chain(sb.iter_mut()) {
                    *w = next();
                }
            }
            let (mut ea, mut eb) = (sa, sb);
            compress(&mut ea, core::slice::from_ref(&a));
            compress(&mut eb, core::slice::from_ref(&b));
            sha512_aarch64::compress2(sha3, &mut sa, &a, &mut sb, &b);
            assert_eq!(sa, ea, "state a {i}");
            assert_eq!(sb, eb, "state b {i}");
        }
        let (mut x, mut y) = (Sha512::new(), Sha512::new());
        x.absorb_key_blocks(&[0x36; BLOCK_BYTES], &mut y, &[0x5c; BLOCK_BYTES]);
        let (mut ex, mut ey) = (Sha512::new(), Sha512::new());
        ex.absorb_key_block(&[0x36; BLOCK_BYTES]);
        ey.absorb_key_block(&[0x5c; BLOCK_BYTES]);
        assert_eq!(x.state, ex.state);
        assert_eq!(y.state, ey.state);
    }

    /// Every buffer fill level and padding boundary, absorbed in one call and
    /// in irregular chunks, matches the `sha2` crate.
    #[test]
    fn test_sha512_matches_sha2_for_all_lengths_and_chunkings() {
        let message: Vec<u8> = (0..1200u32).map(|i| (i * 31 % 251) as u8).collect();
        for len in (0..400).chain([511, 512, 513, 1023, 1024, 1025, 1199, 1200]) {
            let expected = sha2::Sha512::digest(&message[..len]).to_vec();
            assert_eq!(
                Sha512::compute_to_vec(&message[..len]),
                expected,
                "len {len}"
            );

            let mut hasher = Sha512::new();
            let mut offset = 0;
            for chunk in [1usize, 7, 127, 128, 129, 200, 3].iter().cycle() {
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
    /// a block boundary from a partially filled buffer (1 + 127, 127 + 1), a
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
            let mut hasher = Sha512::new();
            hasher.update(b"");
            for window in cuts.windows(2) {
                hasher.update(&message[window[0]..window[1]]);
                hasher.update(b"");
            }
            assert_eq!(
                hasher.finalize_to_vec(),
                sha2::Sha512::digest(message).to_vec(),
                "len {len}"
            );
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_sha512_matches_libsodium() {
        use crate::native_test_util::HashSha512State;
        use crate::rng::randombytes_buf;

        let mut their_state = HashSha512State::new();
        let mut our_state = Sha512::new();

        for _ in 0..10 {
            let r = randombytes_buf(64);
            their_state.update(&r);
            our_state.update(&r);
        }

        let their_digest = their_state.finalize();
        let our_digest = our_state.finalize_to_vec();

        assert_eq!(their_digest.as_slice(), our_digest);
    }

    /// The hardware loop agrees with the portable compression for every block
    /// count around its loop boundaries, including the empty run.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    #[test]
    fn test_hw_compress_matches_portable() {
        let Some(sha3) = crate::aarch64::Sha3::new() else {
            return;
        };
        let blocks: Vec<[u8; 128]> = (0..40u32)
            .map(|b| {
                core::array::from_fn(|i| (b * 128 + i as u32).wrapping_mul(2654435761) as u8 >> 1)
            })
            .collect();
        for n in 0..=blocks.len() {
            let mut expected = IV;
            let mut actual = IV;
            sha2::block_api::compress512(&mut expected, &blocks[..n]);
            sha512_aarch64::compress(sha3, &mut actual, &blocks[..n]);
            assert_eq!(actual, expected, "{n} blocks");
        }
    }
}
