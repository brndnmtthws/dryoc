use std::simd::Simd;

use zeroize::Zeroize;

use super::{BLOCK_SIZE, pad_partial_block};
use crate::types::*;
use crate::utils::{load_u32_le, load_u64_le};

const LANES: usize = 4;
const MASK26: u64 = (1 << 26) - 1;
const HIBIT: u64 = 1 << 24;

type Fe = [u64; 5];
type Fe4 = [Simd<u64, LANES>; 5];

#[derive(Default, Zeroize)]
pub struct Poly1305 {
    r: Fe,
    r2: Fe,
    r3: Fe,
    r4: Fe,
    h: Fe,
    pad: [u64; 2],
    buffer: Vec<u8>,
}

pub type Key = StackByteArray<32>;

#[inline(always)]
fn block_to_fe(block: &[u8], hibit: u64) -> Fe {
    let t0 = load_u32_le(&block[0..4]) as u64;
    let t1 = load_u32_le(&block[4..8]) as u64;
    let t2 = load_u32_le(&block[8..12]) as u64;
    let t3 = load_u32_le(&block[12..16]) as u64;

    [
        t0 & MASK26,
        ((t0 >> 26) | (t1 << 6)) & MASK26,
        ((t1 >> 20) | (t2 << 12)) & MASK26,
        ((t2 >> 14) | (t3 << 18)) & MASK26,
        ((t3 >> 8) & MASK26) | hibit,
    ]
}

#[inline]
fn key_to_r(key: &[u8]) -> Fe {
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
    block_to_fe(&r, 0)
}

#[inline(always)]
fn fe_add(lhs: Fe, rhs: Fe) -> Fe {
    core::array::from_fn(|i| lhs[i].wrapping_add(rhs[i]))
}

#[inline]
fn fe_carry(mut h: Fe) -> Fe {
    let mut c = h[0] >> 26;
    h[0] &= MASK26;
    h[1] += c;
    c = h[1] >> 26;
    h[1] &= MASK26;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= MASK26;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= MASK26;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= MASK26;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= MASK26;
    h[1] += c;
    h
}

#[inline(always)]
fn fe_mul(lhs: Fe, rhs: Fe) -> Fe {
    let rhs1_5 = rhs[1] * 5;
    let rhs2_5 = rhs[2] * 5;
    let rhs3_5 = rhs[3] * 5;
    let rhs4_5 = rhs[4] * 5;

    let d0 =
        lhs[0] * rhs[0] + lhs[1] * rhs4_5 + lhs[2] * rhs3_5 + lhs[3] * rhs2_5 + lhs[4] * rhs1_5;
    let mut d1 =
        lhs[0] * rhs[1] + lhs[1] * rhs[0] + lhs[2] * rhs4_5 + lhs[3] * rhs3_5 + lhs[4] * rhs2_5;
    let mut d2 =
        lhs[0] * rhs[2] + lhs[1] * rhs[1] + lhs[2] * rhs[0] + lhs[3] * rhs4_5 + lhs[4] * rhs3_5;
    let mut d3 =
        lhs[0] * rhs[3] + lhs[1] * rhs[2] + lhs[2] * rhs[1] + lhs[3] * rhs[0] + lhs[4] * rhs4_5;
    let mut d4 =
        lhs[0] * rhs[4] + lhs[1] * rhs[3] + lhs[2] * rhs[2] + lhs[3] * rhs[1] + lhs[4] * rhs[0];

    let mut h = [0u64; 5];
    let mut c = d0 >> 26;
    h[0] = d0 & MASK26;
    d1 += c;
    c = d1 >> 26;
    h[1] = d1 & MASK26;
    d2 += c;
    c = d2 >> 26;
    h[2] = d2 & MASK26;
    d3 += c;
    c = d3 >> 26;
    h[3] = d3 & MASK26;
    d4 += c;
    c = d4 >> 26;
    h[4] = d4 & MASK26;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= MASK26;
    h[1] += c;
    h
}

#[inline(always)]
fn fe4_splat(x: Fe) -> Fe4 {
    core::array::from_fn(|i| Simd::splat(x[i]))
}

#[inline(always)]
fn fe4_add(lhs: Fe4, rhs: Fe4) -> Fe4 {
    core::array::from_fn(|i| lhs[i] + rhs[i])
}

#[inline(always)]
fn fe4_mul(lhs: Fe4, rhs: Fe4) -> Fe4 {
    let five = Simd::splat(5);
    let rhs1_5 = rhs[1] * five;
    let rhs2_5 = rhs[2] * five;
    let rhs3_5 = rhs[3] * five;
    let rhs4_5 = rhs[4] * five;

    let d0 =
        lhs[0] * rhs[0] + lhs[1] * rhs4_5 + lhs[2] * rhs3_5 + lhs[3] * rhs2_5 + lhs[4] * rhs1_5;
    let mut d1 =
        lhs[0] * rhs[1] + lhs[1] * rhs[0] + lhs[2] * rhs4_5 + lhs[3] * rhs3_5 + lhs[4] * rhs2_5;
    let mut d2 =
        lhs[0] * rhs[2] + lhs[1] * rhs[1] + lhs[2] * rhs[0] + lhs[3] * rhs4_5 + lhs[4] * rhs3_5;
    let mut d3 =
        lhs[0] * rhs[3] + lhs[1] * rhs[2] + lhs[2] * rhs[1] + lhs[3] * rhs[0] + lhs[4] * rhs4_5;
    let mut d4 =
        lhs[0] * rhs[4] + lhs[1] * rhs[3] + lhs[2] * rhs[2] + lhs[3] * rhs[1] + lhs[4] * rhs[0];

    let mask = Simd::splat(MASK26);
    let shift = Simd::splat(26);
    let mut h = [Simd::splat(0); 5];
    let mut c = d0 >> shift;
    h[0] = d0 & mask;
    d1 += c;
    c = d1 >> shift;
    h[1] = d1 & mask;
    d2 += c;
    c = d2 >> shift;
    h[2] = d2 & mask;
    d3 += c;
    c = d3 >> shift;
    h[3] = d3 & mask;
    d4 += c;
    c = d4 >> shift;
    h[4] = d4 & mask;
    h[0] += c * five;
    c = h[0] >> shift;
    h[0] &= mask;
    h[1] += c;
    h
}

#[inline(always)]
fn blocks_to_fe4(input: &[u8], group: usize, h: Fe) -> Fe4 {
    let mut limbs = [[0u64; LANES]; 5];

    for (lane, block) in input[group * LANES * BLOCK_SIZE..][..LANES * BLOCK_SIZE]
        .chunks_exact(BLOCK_SIZE)
        .enumerate()
    {
        let mut fe = block_to_fe(block, HIBIT);
        if group == 0 && lane == 0 {
            fe = fe_add(fe, h);
        }

        for i in 0..5 {
            limbs[i][lane] = fe[i];
        }
    }

    core::array::from_fn(|i| Simd::from(limbs[i]))
}

#[inline]
fn sum_lanes(v: Fe4) -> Fe {
    fe_carry(core::array::from_fn(|i| {
        let lanes = v[i].to_array();
        lanes[0] + lanes[1] + lanes[2] + lanes[3]
    }))
}

impl Poly1305 {
    pub fn new<K>(key: &K) -> Self
    where
        K: ByteArray<32>,
    {
        let key = key.as_array();
        let r = key_to_r(&key[..16]);
        let r2 = fe_mul(r, r);
        let r3 = fe_mul(r2, r);
        let r4 = fe_mul(r2, r2);

        Poly1305 {
            r,
            r2,
            r3,
            r4,
            h: [0; 5],
            pad: [load_u64_le(&key[16..24]), load_u64_le(&key[24..32])],
            buffer: Vec::new(),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut m = input;
        if !self.buffer.is_empty() {
            let input_block_end = std::cmp::min(BLOCK_SIZE - self.buffer.len(), input.len());
            self.buffer.extend_from_slice(&m[..input_block_end]);

            if self.buffer.len() < BLOCK_SIZE {
                return;
            }

            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&self.buffer);
            self.buffer.clear();
            self.blocks(&block, false);

            m = &m[input_block_end..];
        }

        let full_blocks_end = m.len() - (m.len() % BLOCK_SIZE);
        self.blocks(&m[..full_blocks_end], false);

        if full_blocks_end < m.len() {
            self.buffer.extend_from_slice(&m[full_blocks_end..]);
        }
    }

    fn blocks_scalar(&mut self, input: &[u8], hibit: u64) {
        debug_assert_eq!(input.len() % BLOCK_SIZE, 0);

        for m in input.chunks_exact(BLOCK_SIZE) {
            self.h = fe_mul(fe_add(self.h, block_to_fe(m, hibit)), self.r);
        }
    }

    fn blocks(&mut self, input: &[u8], partial: bool) {
        if input.is_empty() {
            return;
        }

        if partial {
            debug_assert_eq!(input.len(), BLOCK_SIZE);
            self.blocks_scalar(input, 0);
            return;
        }

        let prefix_len = (input.len() / BLOCK_SIZE % LANES) * BLOCK_SIZE;
        if prefix_len != 0 {
            self.blocks_scalar(&input[..prefix_len], HIBIT);
        }

        let input = &input[prefix_len..];
        if input.is_empty() {
            return;
        }

        let group_count = input.len() / (LANES * BLOCK_SIZE);
        let r4 = fe4_splat(self.r4);
        let mut t = blocks_to_fe4(input, 0, self.h);

        for group in 1..group_count {
            t = fe4_add(fe4_mul(t, r4), blocks_to_fe4(input, group, [0; 5]));
        }

        let powers =
            core::array::from_fn(|i| Simd::from([self.r4[i], self.r3[i], self.r2[i], self.r[i]]));

        self.h = sum_lanes(fe4_mul(t, powers));
    }

    pub fn finalize_to_array(&mut self) -> [u8; BLOCK_SIZE] {
        let mut mac = [0u8; 16];
        self.finalize(&mut mac);
        mac
    }

    pub fn finalize(&mut self, output: &mut [u8]) {
        if !self.buffer.is_empty() {
            self.blocks(&pad_partial_block(&self.buffer), true);
        }

        let mut h = fe_carry(self.h);
        h = fe_carry(h);

        let mut g = [0u64; 5];
        g[0] = h[0] + 5;
        let mut c = g[0] >> 26;
        g[0] &= MASK26;
        for i in 1..4 {
            g[i] = h[i] + c;
            c = g[i] >> 26;
            g[i] &= MASK26;
        }
        g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g[4] >> 63).wrapping_sub(1);
        g[4] &= MASK26;
        for i in 0..5 {
            h[i] = (h[i] & !mask) | (g[i] & mask);
        }

        let f0 = h[0] | (h[1] << 26) | (h[2] << 52);
        let f1 = (h[2] >> 12) | (h[3] << 14) | (h[4] << 40);

        let f0 = f0 as u128 + self.pad[0] as u128;
        let f1 = f1 as u128 + self.pad[1] as u128 + (f0 >> 64);

        output[0..8].copy_from_slice(&(f0 as u64).to_le_bytes());
        output[8..16].copy_from_slice(&(f1 as u64).to_le_bytes());

        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::TryRng;

    use super::*;
    use crate::poly1305::poly1305_soft;

    #[cfg(feature = "nightly")]
    extern crate test;

    fn simd_mac(key: &[u8; 32], chunks: &[&[u8]]) -> [u8; BLOCK_SIZE] {
        let key = Key::from(key);
        let mut mac = Poly1305::new(&key);
        for chunk in chunks {
            mac.update(chunk);
        }
        mac.finalize_to_array()
    }

    fn soft_mac(key: &[u8; 32], chunks: &[&[u8]]) -> [u8; BLOCK_SIZE] {
        let key = poly1305_soft::Key::from(key);
        let mut mac = poly1305_soft::Poly1305::new(&key);
        for chunk in chunks {
            mac.update(chunk);
        }
        mac.finalize_to_array()
    }

    fn chunk_message_with_pattern<'a>(message: &'a [u8], pattern: &[usize]) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        let mut pattern_index = 0;

        while offset < message.len() {
            let chunk_len = pattern[pattern_index % pattern.len()].min(message.len() - offset);
            chunks.push(&message[offset..offset + chunk_len]);
            offset += chunk_len;
            pattern_index += 1;
        }

        if chunks.is_empty() {
            chunks.push(message);
        }

        chunks
    }

    fn chunk_message_with_splits<'a>(message: &'a [u8], splits: &[usize]) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        let mut offset = 0;

        for split in splits {
            if offset == message.len() {
                break;
            }

            let chunk_len = (*split).min(message.len() - offset);
            chunks.push(&message[offset..offset + chunk_len]);
            offset += chunk_len;
        }

        if offset < message.len() {
            chunks.push(&message[offset..]);
        }

        if chunks.is_empty() {
            chunks.push(message);
        }

        chunks
    }

    fn assert_matches_soft(key: &[u8; 32], chunks: &[&[u8]]) {
        assert_eq!(simd_mac(key, chunks), soft_mac(key, chunks));
    }

    #[test]
    fn test_example_vector() {
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
    fn test_libsodium_varied_lengths_and_chunking() {
        use rand::rngs::SysRng;
        use sodiumoxide::crypto::onetimeauth::poly1305::{Key as SOKey, authenticate};

        use crate::rng::copy_randombytes;

        let key = Key::r#gen();
        let so_key = SOKey::from_slice(&key).unwrap();

        for len in 0..260 {
            let mut data = vec![0u8; len];
            copy_randombytes(&mut data);

            let mut mac = Poly1305::new(&key);
            for chunk in data.chunks(7) {
                mac.update(chunk);
            }
            let mac = mac.finalize_to_array();

            let so_mac = authenticate(&data, &so_key);
            assert_eq!(mac, so_mac.as_ref(), "len={}", len);
        }

        for _ in 0..20 {
            let rand_usize = (SysRng.try_next_u32().unwrap() % 4096) as usize;
            let mut data = vec![0u8; rand_usize];
            copy_randombytes(&mut data);

            let mut mac = Poly1305::new(&key);
            mac.update(&data);
            let mac = mac.finalize_to_array();

            let so_mac = authenticate(&data, &so_key);
            assert_eq!(mac, so_mac.as_ref(), "len={}", rand_usize);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn proptest_simd_matches_soft_one_shot(
            key in any::<[u8; 32]>(),
            message in prop::collection::vec(any::<u8>(), 0..8192),
        ) {
            assert_matches_soft(&key, &[&message]);
        }

        #[test]
        fn proptest_simd_matches_soft_fixed_chunk_patterns(
            key in any::<[u8; 32]>(),
            message in prop::collection::vec(any::<u8>(), 0..8192),
        ) {
            for pattern in [
                &[1][..],
                &[7],
                &[15],
                &[16],
                &[17],
                &[31],
                &[3, 5, 8, 13, 21],
                &[64, 1, 32, 7],
            ] {
                let chunks = chunk_message_with_pattern(&message, pattern);
                assert_matches_soft(&key, &chunks);
            }
        }

        #[test]
        fn proptest_simd_matches_soft_random_chunking(
            key in any::<[u8; 32]>(),
            message in prop::collection::vec(any::<u8>(), 0..8192),
            splits in prop::collection::vec(1usize..128, 0..256),
        ) {
            let chunks = chunk_message_with_splits(&message, &splits);
            assert_matches_soft(&key, &chunks);
        }
    }

    #[cfg(feature = "nightly")]
    fn bench_poly1305(b: &mut test::Bencher, len: usize) {
        use crate::rng::copy_randombytes;

        let key = Key::r#gen();
        let mut input = vec![0u8; len];
        copy_randombytes(&mut input);
        b.bytes = len as u64;

        b.iter(|| {
            let mut mac = Poly1305::new(test::black_box(&key));
            mac.update(test::black_box(&input));
            test::black_box(mac.finalize_to_array());
        });
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn poly1305_64b_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::BYTES_64);
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn poly1305_1k_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::KIB_1);
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn poly1305_16k_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::KIB_16);
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn poly1305_1m_bench(b: &mut test::Bencher) {
        bench_poly1305(b, crate::poly1305::bench_inputs::MIB_1);
    }
}
