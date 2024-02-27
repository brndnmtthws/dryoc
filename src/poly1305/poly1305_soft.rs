use zeroize::Zeroize;

use crate::types::*;
use crate::utils::load_u64_le;

const BLOCK_SIZE: usize = 16;

#[derive(Default, Zeroize)]
pub struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
    buffer: Vec<u8>,
}

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
        if !self.buffer.is_empty() {
            let input_block_end = std::cmp::min(BLOCK_SIZE - self.buffer.len(), input.len());
            // copy start of incoming block into previous block
            self.buffer.extend_from_slice(&m[..input_block_end]);

            if self.buffer.len() < BLOCK_SIZE {
                // don't have enough data yet, do nothing
                return;
            }

            // process block
            let b = self.buffer.clone();
            self.blocks(&b, false);
            self.buffer.clear();

            m = &m[input_block_end..]
        }

        // process all full blocks
        let full_blocks_end = m.len() - (m.len() % BLOCK_SIZE);
        self.blocks(&m[..full_blocks_end], false);

        if full_blocks_end < m.len() {
            // copy leftover into buffer
            self.buffer.extend_from_slice(&m[full_blocks_end..]);
        }
    }

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

        for m in input.chunks(BLOCK_SIZE) {
            // h += m[i]
            let t0 = load_u64_le(&m[0..8]);
            let t1 = load_u64_le(&m[8..]);

            h0 = h0.wrapping_add(t0 & 0xfffffffffff);
            h1 = h1.wrapping_add(((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
            h2 = h2.wrapping_add(((t1 >> 24) & 0x3ffffffffff) | hibit);

            self.h[0] = h0;
            self.h[1] = h1;
            self.h[2] = h2;

            // h *= r
            let d0 = mul(h0, r0) + mul(h1, s2) + mul(h2, s1);
            let mut d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s2);
            let mut d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0);

            self.h[0] = h0;
            self.h[1] = h1;
            self.h[2] = h2;

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

            self.h[0] = h0;
            self.h[1] = h1;
            self.h[2] = h2;
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
        if !self.buffer.is_empty() {
            self.buffer.push(1);
            if self.buffer.len() % BLOCK_SIZE != 0 {
                self.buffer.resize(
                    self.buffer.len() + (BLOCK_SIZE - self.buffer.len() % BLOCK_SIZE),
                    0,
                );
            }

            self.blocks(&self.buffer.clone(), true);
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

        use sodiumoxide::crypto::onetimeauth::poly1305::{authenticate, Key as SOKey};
        let so_key = SOKey::from_slice(&key).expect("key");
        let so_mac = authenticate(text, &so_key);
        assert_eq!(mac, so_mac.as_ref());
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

    #[test]
    fn test_libsodium() {
        use rand_core::{OsRng, RngCore};
        use sodiumoxide::crypto::onetimeauth::poly1305::{authenticate, Key as SOKey};

        use crate::rng::copy_randombytes;

        let key = Key::gen();

        let so_key = SOKey::from_slice(&key).unwrap();

        for _ in 0..20 {
            let rand_usize = (OsRng.next_u32() % 1000) as usize;
            let mut data = vec![0u8; rand_usize];
            copy_randombytes(&mut data);

            let mut mac = Poly1305::new(&key);
            mac.update(&data);
            let mac = mac.finalize_to_array();

            let so_mac = authenticate(&data, &so_key);

            assert_eq!(mac, so_mac.as_ref());
        }
    }
}
