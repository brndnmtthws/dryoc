use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BLOCK_SIZE, pad_partial_block};
use crate::types::*;
use crate::utils::load_u64_le;

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
    /// Pending partial block as little-endian bytes; only the low `buflen`
    /// bytes are meaningful. A `u128` zeroizes in one store, where a byte
    /// array costs one volatile store per byte on every finalize and drop.
    buffer: u128,
    buflen: usize,
}

/// Minimum run of full blocks worth handing to the NEON path; below this the
/// key-power precomputation and limb conversions cost more than they save.
/// Must be at least one `poly1305_neon::CHUNK`.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
const NEON_MIN_BYTES: usize = 480;

#[inline]
fn mul(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

#[inline]
fn shr(in_: u128, shift: u64) -> u64 {
    (in_ >> shift) as u64
}

#[inline]
fn lo(in_: u128) -> u64 {
    in_ as u64
}

pub type Key = StackByteArray<32>;

impl Poly1305 {
    pub fn new<K>(key: &K) -> Self
    where
        K: ByteArray<32>,
    {
        let mut state = Poly1305::default();

        let (t0, t1) = (
            load_u64_le(&key.as_array()[0..8]),
            load_u64_le(&key.as_array()[8..16]),
        );

        // wiped after finalization
        state.r[0] = t0 & 0xffc0fffffff;
        state.r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
        state.r[2] = (t1 >> 24) & 0x00ffffffc0f;

        // h = 0
        state.h.fill(0);

        // save pad for later
        state.pad[0] = load_u64_le(&key.as_array()[16..24]);
        state.pad[1] = load_u64_le(&key.as_array()[24..32]);

        state
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut m = input;
        if self.buflen > 0 {
            let input_block_end = std::cmp::min(BLOCK_SIZE - self.buflen, input.len());
            // copy start of incoming block into previous block
            let mut block = self.buffer.to_le_bytes();
            block[self.buflen..self.buflen + input_block_end]
                .copy_from_slice(&m[..input_block_end]);
            self.buflen += input_block_end;

            if self.buflen < BLOCK_SIZE {
                // don't have enough data yet, do nothing
                self.buffer = u128::from_le_bytes(block);
                return;
            }

            self.buffer = 0;
            self.buflen = 0;
            self.blocks(&block, false);

            m = &m[input_block_end..];
        }

        // process all full blocks
        let full_blocks_end = m.len() - (m.len() % BLOCK_SIZE);
        self.full_blocks(&m[..full_blocks_end]);

        if full_blocks_end < m.len() {
            // copy leftover into buffer
            let rest = &m[full_blocks_end..];
            let mut block = [0u8; BLOCK_SIZE];
            block[..rest.len()].copy_from_slice(rest);
            self.buffer = u128::from_le_bytes(block);
            self.buflen = rest.len();
        }
    }

    /// Processes a whole number of full blocks, using the NEON or x86-64
    /// bulk paths for long runs when available.
    fn full_blocks(&mut self, input: &[u8]) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if input.len() >= NEON_MIN_BYTES && std::arch::is_aarch64_feature_detected!("neon") {
            let bulk = input.len() - input.len() % super::poly1305_neon::CHUNK;
            // SAFETY: `poly1305_neon::blocks` requires the `neon` target
            // feature, which the runtime check above confirmed is present.
            unsafe { super::poly1305_neon::blocks(&mut self.h, &self.r, &input[..bulk]) };
            self.blocks(&input[bulk..], false);
            return;
        }
        #[cfg(target_arch = "x86_64")]
        let input = &input[super::poly1305_x86_64::full_blocks(&mut self.h, &self.r, input)..];
        self.blocks(input, false);
    }

    /// Scalar block loop over `self.h` with `self.r`. Its working values
    /// live only in registers and compiler spill slots, which are out of
    /// Rust's reach and are not wiped; the state itself is wiped by
    /// `finalize` and on drop.
    fn blocks(&mut self, input: &[u8], partial: bool) {
        let hibit = if partial {
            0u64
        } else {
            // 1 << 128
            1u64 << 40
        };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        let s1 = r1 * (5 << 2);
        let s2 = r2 * (5 << 2);

        debug_assert_eq!(input.len() % BLOCK_SIZE, 0);

        for m in input.as_chunks::<BLOCK_SIZE>().0 {
            // h += m[i]
            let t0 = load_u64_le(&m[0..8]);
            let t1 = load_u64_le(&m[8..]);

            h0 = h0.wrapping_add(t0 & 0xfffffffffff);
            h1 = h1.wrapping_add(((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
            h2 = h2.wrapping_add(((t1 >> 24) & 0x3ffffffffff) | hibit);

            // h *= r
            let d0 = mul(h0, r0) + mul(h1, s2) + mul(h2, s1);
            let mut d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s2);
            let mut d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0);

            // (partial) h %= p
            let mut c = shr(d0, 44);
            h0 = lo(d0) & 0xfffffffffff;
            d1 += c as u128;
            c = shr(d1, 44);
            h1 = lo(d1) & 0xfffffffffff;
            d2 += c as u128;
            c = shr(d2, 42);
            h2 = lo(d2) & 0x3ffffffffff;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= 0xfffffffffff;
            h1 += c;
        }

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
    }

    pub fn finalize_to_array(&mut self) -> [u8; BLOCK_SIZE] {
        let mut mac = [0u8; 16];

        self.finalize(&mut mac);

        mac
    }

    pub fn finalize(&mut self, output: &mut [u8]) {
        // process any remaining block
        if self.buflen > 0 {
            let block = self.buffer.to_le_bytes();
            self.blocks(&pad_partial_block(&block[..self.buflen]), true);
        }

        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        let mut c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 44;
        g0 &= 0xfffffffffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 44;
        g1 &= 0xfffffffffff;
        let mut g2 = (h2.wrapping_add(c)).wrapping_sub(1u64 << 42);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g2 >> ((8 * 8) - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        // h = (h + pad)
        let t0 = self.pad[0];
        let t1 = self.pad[1];

        h0 = h0.wrapping_add(t0 & 0xfffffffffff);
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 = h1.wrapping_add((((t0 >> 44) | (t1 << 20)) & 0xfffffffffff).wrapping_add(c));
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 = h2.wrapping_add(((t1 >> 24) & 0x3ffffffffff).wrapping_add(c));
        h2 &= 0x3ffffffffff;

        // mac = h % (2^128)
        h0 |= h1 << 44;
        h1 = (h1 >> 20) | (h2 << 24);

        output[0..8].copy_from_slice(&h0.to_le_bytes());
        output[8..16].copy_from_slice(&h1.to_le_bytes());

        // zero out the state
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    extern crate test;

    #[test]
    fn incremental_state_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Poly1305>();
        assert!(std::mem::needs_drop::<Poly1305>());
    }

    #[test]
    fn test_example_vector() {
        // from https://tools.ietf.org/html/rfc7539#section-2.5.2
        let key = Key::from(&[
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ]);
        let text = b"Cryptographic Forum Research Group";

        let mut mac = Poly1305::new(&key);
        mac.update(text);
        let mac = mac.finalize_to_array();

        assert_eq!(
            mac,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9,
            ]
        );
    }

    #[test]
    fn test_vector_1() {
        // from https://tools.ietf.org/html/rfc7539#appendix-A.3
        let key = Key::new();
        let text = [0u8; 64];

        let mut mac = Poly1305::new(&key);
        mac.update(&text);
        let mac = mac.finalize_to_array();

        assert_eq!(mac, [0u8; 16]);
    }

    #[test]
    fn test_vector_2() {
        // from https://tools.ietf.org/html/rfc7539#appendix-A.3
        let key = Key::from(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96,
            0x22, 0x7a, 0x86, 0x3e,
        ]);
        let text = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";

        let mut mac = Poly1305::new(&key);
        mac.update(text);
        let mac = mac.finalize_to_array();

        assert_eq!(
            mac,
            [
                0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
                0x86, 0x3e,
            ]
        );
    }

    #[test]
    fn test_vector_3() {
        // from https://tools.ietf.org/html/rfc7539#appendix-A.3
        let key = Key::from(&[
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        let text = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";

        let mut mac = Poly1305::new(&key);
        mac.update(text);
        let mac = mac.finalize_to_array();

        assert_eq!(
            mac,
            [
                0xf3, 0x47, 0x7e, 0x7c, 0xd9, 0x54, 0x17, 0xaf, 0x89, 0xa6, 0xb8, 0x79, 0x4c, 0x31,
                0x0c, 0xf0,
            ]
        );
    }

    #[test]
    fn test_vector_4() {
        // from https://tools.ietf.org/html/rfc7539#appendix-A.3
        let key = Key::from(&[
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
            0x20, 0x70, 0x75, 0xc0,
        ]);
        let text = [
            0x27u8, 0x54u8, 0x77u8, 0x61u8, 0x73u8, 0x20u8, 0x62u8, 0x72u8, 0x69u8, 0x6cu8, 0x6cu8,
            0x69u8, 0x67u8, 0x2cu8, 0x20u8, 0x61u8, 0x6eu8, 0x64u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8,
            0x20u8, 0x73u8, 0x6cu8, 0x69u8, 0x74u8, 0x68u8, 0x79u8, 0x20u8, 0x74u8, 0x6fu8, 0x76u8,
            0x65u8, 0x73u8, 0x0au8, 0x44u8, 0x69u8, 0x64u8, 0x20u8, 0x67u8, 0x79u8, 0x72u8, 0x65u8,
            0x20u8, 0x61u8, 0x6eu8, 0x64u8, 0x20u8, 0x67u8, 0x69u8, 0x6du8, 0x62u8, 0x6cu8, 0x65u8,
            0x20u8, 0x69u8, 0x6eu8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x77u8, 0x61u8, 0x62u8,
            0x65u8, 0x3au8, 0x0au8, 0x41u8, 0x6cu8, 0x6cu8, 0x20u8, 0x6du8, 0x69u8, 0x6du8, 0x73u8,
            0x79u8, 0x20u8, 0x77u8, 0x65u8, 0x72u8, 0x65u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8,
            0x62u8, 0x6fu8, 0x72u8, 0x6fu8, 0x67u8, 0x6fu8, 0x76u8, 0x65u8, 0x73u8, 0x2cu8, 0x0au8,
            0x41u8, 0x6eu8, 0x64u8, 0x20u8, 0x74u8, 0x68u8, 0x65u8, 0x20u8, 0x6du8, 0x6fu8, 0x6du8,
            0x65u8, 0x20u8, 0x72u8, 0x61u8, 0x74u8, 0x68u8, 0x73u8, 0x20u8, 0x6fu8, 0x75u8, 0x74u8,
            0x67u8, 0x72u8, 0x61u8, 0x62u8, 0x65u8, 0x2eu8,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(&text);
        let mac = mac.finalize_to_array();

        assert_eq!(
            mac,
            [
                0x45, 0x41, 0x66, 0x9a, 0x7e, 0xaa, 0xee, 0x61, 0xe7, 0x08, 0xdc, 0x7c, 0xbc, 0xc5,
                0xeb, 0x62,
            ]
        );
    }

    /// Deterministic keys stressing the limb carries: all clamped bits set,
    /// a tiny `r`, and a patterned one.
    fn carry_keys() -> [Key; 3] {
        let mut tiny = [0u8; 32];
        tiny[0] = 1;
        tiny[3] = 0x40;
        let patterned: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
        [
            Key::from(&[0xffu8; 32]),
            Key::from(&tiny),
            Key::from(&patterned),
        ]
    }

    /// `len` patterned bytes with a run of all-ones bytes in the second
    /// 160-byte chunk.
    fn carry_message(len: usize) -> Vec<u8> {
        let mut data: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add((i >> 8) as u8))
            .collect();
        if data.len() >= 320 {
            data[160..320].fill(0xff);
        }
        data
    }

    /// The authenticator of `message` computed with the scalar block loop
    /// only: whole blocks, then the padded partial block.
    fn scalar_mac(key: &Key, message: &[u8]) -> [u8; 16] {
        let mut mac = Poly1305::new(key);
        let (blocks, rest) = message.split_at(message.len() - message.len() % BLOCK_SIZE);
        mac.blocks(blocks, false);
        if !rest.is_empty() {
            mac.blocks(&pad_partial_block(rest), true);
        }
        mac.finalize_to_array()
    }

    /// A bulk kernel with `chunk`-byte chunks must leave the same state as
    /// the scalar block loop, starting from a non-zero state and followed by
    /// more scalar blocks, for every whole number of chunks in
    /// `chunk_counts`.
    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little", not(miri)),
        target_arch = "x86_64"
    ))]
    fn check_bulk_matches_scalar(
        name: &str,
        chunk: usize,
        chunk_counts: &[usize],
        bulk: impl Fn(&mut [u64; 3], &[u64; 3], &[u8]),
    ) {
        let data = carry_message(chunk_counts.iter().max().unwrap() * chunk + 64);
        for key in &carry_keys() {
            for len in chunk_counts.iter().map(|chunks| chunks * chunk) {
                let mut scalar = Poly1305::new(key);
                let mut vector = Poly1305::new(key);
                scalar.blocks(&data[..16], false);
                vector.blocks(&data[..16], false);

                scalar.blocks(&data[16..16 + len], false);
                bulk(&mut vector.h, &vector.r, &data[16..16 + len]);
                scalar.blocks(&data[16 + len..16 + len + 48], false);
                vector.blocks(&data[16 + len..16 + len + 48], false);
                assert_eq!(
                    scalar.finalize_to_array(),
                    vector.finalize_to_array(),
                    "{name} len={len}"
                );
            }
        }
    }

    /// The NEON bulk kernel, for 1 to 4 of its 160-byte chunks and for 8,
    /// 16 and 25 chunks (up to 4 KiB).
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    #[test]
    fn neon_blocks_match_scalar() {
        use super::super::poly1305_neon::{CHUNK, blocks};

        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        check_bulk_matches_scalar("neon", CHUNK, &[1, 2, 3, 4, 8, 16, 25], |h, r, input| {
            // SAFETY: `neon` was detected above.
            unsafe { blocks(h, r, input) }
        });
    }

    /// The AVX2 bulk kernel, for 1 to 4 of its 128-byte chunks and for 8,
    /// 16, 25 and 32 chunks (up to 4 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK, blocks};

        if !std::arch::is_x86_feature_detected!("avx2") {
            return;
        }
        check_bulk_matches_scalar(
            "avx2",
            CHUNK,
            &[1, 2, 3, 4, 8, 16, 25, 32],
            |h, r, input| {
                // SAFETY: `avx2` was detected above.
                unsafe { blocks(h, r, input) }
            },
        );
    }

    /// The AVX-512 bulk kernel, for 1 to 4 of its 256-byte chunks and for
    /// 8, 16, 25 and 32 chunks (up to 8 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK512, blocks_avx512};

        if !std::arch::is_x86_feature_detected!("avx512f") {
            return;
        }
        check_bulk_matches_scalar(
            "avx512",
            CHUNK512,
            &[1, 2, 3, 4, 8, 16, 25, 32],
            |h, r, input| {
                // SAFETY: `avx512f` was detected above.
                unsafe { blocks_avx512(h, r, input) }
            },
        );
    }

    /// The AVX-512 IFMA bulk kernel, for 1 to 4 of its 128-byte chunks and
    /// for 8, 16, 25, 32, 63 and 64 chunks (up to 8 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK_IFMA, blocks_ifma};

        if !std::arch::is_x86_feature_detected!("avx512f")
            || !std::arch::is_x86_feature_detected!("avx512ifma")
        {
            return;
        }
        check_bulk_matches_scalar(
            "ifma",
            CHUNK_IFMA,
            &[1, 2, 3, 4, 8, 16, 25, 32, 63, 64],
            |h, r, input| {
                // SAFETY: `avx512f` and `avx512ifma` were detected above.
                unsafe { blocks_ifma(h, r, input) }
            },
        );
    }

    /// The two-chain AVX-512 IFMA bulk kernel, for 1 to 4 of its 256-byte
    /// chunks and for 8, 16, 25 and 32 chunks (up to 8 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma2_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK_IFMA2, blocks_ifma2};

        if !std::arch::is_x86_feature_detected!("avx512f")
            || !std::arch::is_x86_feature_detected!("avx512ifma")
        {
            return;
        }
        check_bulk_matches_scalar(
            "ifma2",
            CHUNK_IFMA2,
            &[1, 2, 3, 4, 8, 16, 25, 32],
            |h, r, input| {
                // SAFETY: `avx512f` and `avx512ifma` were detected above.
                unsafe { blocks_ifma2(h, r, input) }
            },
        );
    }

    /// The production driver must match the scalar block loop at every
    /// length around the bulk-path thresholds (480 bytes on AArch64; 256,
    /// 512, 1024 and 2048 on x86-64) and their 160-, 128- and 256-byte chunk
    /// residues (including a 128-byte chunk left over from the two-chain
    /// run), one-shot and split so a partial block is pending before and
    /// after the bulk run.
    #[test]
    fn update_matches_scalar_blocks_at_bulk_boundaries() {
        let data = carry_message(4608 + 200);
        let lens = (240..=272)
            .chain(368..=400)
            .chain(464..=529)
            .chain([
                639, 640, 641, 767, 768, 769, 799, 800, 801, 959, 960, 961, 1023, 1024, 1025, 1151,
                1152, 1153, 1279, 1280, 1281, 1407, 1408, 1409, 2047, 2048, 2049, 2063, 2064, 2065,
                2175, 2176, 2177, 2303, 2304, 2305, 2559, 2560, 2561,
            ])
            .chain([4095, 4096, 4097, 4096 + 200])
            .chain(4336..=4368)
            .chain([4479, 4480, 4481, 4607, 4608, 4609, 4608 + 200]);
        for key in &carry_keys() {
            for len in lens.clone() {
                let message = &data[..len];
                let expected = scalar_mac(key, message);

                let mut mac = Poly1305::new(key);
                mac.update(message);
                assert_eq!(mac.finalize_to_array(), expected, "one-shot len={len}");

                for split in [
                    1usize, 15, 16, 17, 127, 128, 129, 159, 160, 161, 479, 480, 481, 512,
                ] {
                    if split >= len {
                        continue;
                    }
                    let mut mac = Poly1305::new(key);
                    mac.update(&message[..split]);
                    mac.update(&message[split..]);
                    assert_eq!(mac.finalize_to_array(), expected, "split={split} len={len}");
                }
            }
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    mod property_tests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(crate::utils::test_util::proptest_config(128))]

            /// The production driver (buffering, and the NEON bulk path for
            /// long full-block runs on AArch64) must match the scalar block
            /// loop for any key, message and chunking.
            #[test]
            fn proptest_update_matches_scalar_blocks(
                key in any::<[u8; 32]>(),
                message in prop::collection::vec(any::<u8>(), 0..4096),
                cuts in prop::collection::vec(0usize..4096, 0..6),
            ) {
                let key = Key::from(&key);
                let expected = scalar_mac(&key, &message);

                let mut mac = Poly1305::new(&key);
                mac.update(&message);
                prop_assert_eq!(mac.finalize_to_array(), expected);

                let mut cuts: Vec<usize> = cuts.into_iter().map(|cut| cut.min(message.len())).collect();
                cuts.push(0);
                cuts.push(message.len());
                cuts.sort_unstable();
                cuts.dedup();
                let mut mac = Poly1305::new(&key);
                for window in cuts.windows(2) {
                    mac.update(&message[window[0]..window[1]]);
                }
                prop_assert_eq!(mac.finalize_to_array(), expected);
            }
        }
    }

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    fn bench_poly1305(b: &mut test::Bencher, len: usize) {
        use crate::rng::copy_randombytes;

        let key = Key::generate();
        let mut input = vec![0u8; len];
        copy_randombytes(&mut input);
        b.bytes = len as u64;

        b.iter(|| {
            let mut mac = Poly1305::new(test::black_box(&key));
            mac.update(test::black_box(&input));
            test::black_box(mac.finalize_to_array());
        });
    }

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    #[bench]
    fn poly1305_64b_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::BYTES_64);
    }

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    #[bench]
    fn poly1305_1k_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::KIB_1);
    }

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    #[bench]
    fn poly1305_16k_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::KIB_16);
    }

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    #[bench]
    fn poly1305_1m_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::MIB_1);
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;

        #[test]
        fn test_libsodium() {
            use crate::native_test_util::onetimeauth_poly1305;
            use crate::rng::copy_randombytes;

            let random_u32 = || {
                let mut bytes = [0u8; 4];
                copy_randombytes(&mut bytes);
                u32::from_le_bytes(bytes)
            };

            let key = Key::generate();

            for _ in 0..20 {
                let rand_usize = (random_u32() % 1000) as usize;
                let mut data = vec![0u8; rand_usize];
                copy_randombytes(&mut data);

                let mut mac = Poly1305::new(&key);
                mac.update(&data);
                let mac = mac.finalize_to_array();

                let so_mac = onetimeauth_poly1305(&data, &key);

                assert_eq!(mac, so_mac);
            }
        }

        /// Exercises the NEON bulk path (runs of >= `NEON_MIN_BYTES` full-block
        /// bytes) with every residue of the 160-byte chunking, mixed chunk
        /// boundaries, and worst-case key/message limbs, against libsodium.
        #[test]
        fn test_libsodium_long_and_chunked() {
            use crate::native_test_util::onetimeauth_poly1305;
            use crate::rng::copy_randombytes;

            let mut keys = vec![Key::generate(), Key::generate()];
            // All-ones key (maximal clamped r and pad) and all-ones message
            // stress every carry in the 5x26 representation.
            keys.push(Key::from(&[0xffu8; 32]));

            for key in &keys {
                for len in (464..=1300).chain([4096, 4097, 65536 + 17]) {
                    let mut data = vec![0u8; len];
                    copy_randombytes(&mut data);
                    if len % 3 == 0 {
                        data.fill(0xff);
                    }
                    let so_mac = onetimeauth_poly1305(&data, key);

                    let mut mac = Poly1305::new(key);
                    mac.update(&data);
                    assert_eq!(mac.finalize_to_array(), so_mac, "one-shot len={len}");

                    // Split so the NEON path runs in the middle of a stream
                    // with a pending partial block before and after it, and
                    // so that the split lands inside the first, second or
                    // third chunk (chunks are 160 bytes, threshold 480).
                    for split in [
                        1usize, 15, 16, 17, 63, 64, 65, 127, 128, 129, 159, 160, 161, 319, 320,
                        321, 479, 480, 481,
                    ] {
                        if split >= len {
                            continue;
                        }
                        let mut mac = Poly1305::new(key);
                        mac.update(&data[..split]);
                        mac.update(&data[split..]);
                        assert_eq!(mac.finalize_to_array(), so_mac, "split={split} len={len}");
                    }
                }
            }
        }

        #[cfg(all(feature = "nightly", not(tarpaulin)))]
        fn bench_libsodium_poly1305(b: &mut test::Bencher, len: usize) {
            use crate::rng::copy_randombytes;

            crate::native_test_util::init();

            let key = Key::generate();
            let mut input = vec![0u8; len];
            copy_randombytes(&mut input);
            let mut mac = [0u8; 16];
            b.bytes = len as u64;

            b.iter(|| {
                // SAFETY: `mac` is a writable 16-byte array, `input` is live
                // for its length and `key` is 32 bytes.
                let rc = unsafe {
                    libsodium_sys::crypto_onetimeauth_poly1305(
                        mac.as_mut_ptr(),
                        test::black_box(input.as_ptr()),
                        input.len() as u64,
                        test::black_box(key.as_ptr()),
                    )
                };
                assert_eq!(rc, 0);
                test::black_box(&mac);
            });
        }

        #[cfg(all(feature = "nightly", not(tarpaulin)))]
        #[bench]
        fn libsodium_poly1305_64b_bench(b: &mut test::Bencher) {
            bench_libsodium_poly1305(b, crate::poly1305::bench_inputs::BYTES_64);
        }

        #[cfg(all(feature = "nightly", not(tarpaulin)))]
        #[bench]
        fn libsodium_poly1305_1k_bench(b: &mut test::Bencher) {
            bench_libsodium_poly1305(b, crate::poly1305::bench_inputs::KIB_1);
        }

        #[cfg(all(feature = "nightly", not(tarpaulin)))]
        #[bench]
        fn libsodium_poly1305_16k_bench(b: &mut test::Bencher) {
            bench_libsodium_poly1305(b, crate::poly1305::bench_inputs::KIB_16);
        }

        #[cfg(all(feature = "nightly", not(tarpaulin)))]
        #[bench]
        fn libsodium_poly1305_1m_bench(b: &mut test::Bencher) {
            bench_libsodium_poly1305(b, crate::poly1305::bench_inputs::MIB_1);
        }
    }
}
