use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BLOCK_SIZE, pad_partial_block};
use crate::types::*;
use crate::utils::load_u64_le;

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    r: [u64; 3],
    /// The accumulator: on AArch64 (whose block loops run in radix 2^64) in
    /// radix 2^64 with `h[2]` below 8, elsewhere partially reduced 3x44-bit
    /// limbs.
    h: [u64; 3],
    pad: [u64; 2],
    /// Pending partial block as little-endian bytes; only the low `buflen`
    /// bytes are meaningful. A `u128` zeroizes in one store, where a byte
    /// array costs one volatile store per byte on every finalize and drop.
    buffer: u128,
    buflen: usize,
}

/// Minimum run of full blocks worth handing to the four-lane AArch64 path;
/// below this the lane join costs more than the overlap saves over the
/// single-lane loop (measured crossover about 320 bytes on Neoverse V3).
/// Must be at least one `poly1305_aarch64::CHUNK`.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
pub(super) const LANES_MIN_BYTES: usize = 384;

/// Minimum run of full blocks worth handing to the `simd128` path; below
/// this the key-power setup and limb conversions cost more than they save.
/// Must be at least one `poly1305_wasm32::CHUNK`.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
const WASM_MIN_BYTES: usize = 128;

#[cfg_attr(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    cfg(test)
)]
#[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
#[inline]
fn mul(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

/// `x * y` from four 32x32-bit products. WebAssembly has no 64x64 -> 128-bit
/// multiply, so the plain `u128` product is a call to compiler-rt's
/// `__multi3`; in `simd128` builds those calls made the scalar blocks (every
/// message under `WASM_MIN_BYTES`, and every tail) measurably slower in V8
/// than in builds without `simd128`, and the inline form is faster than the
/// call in both engines.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline(always)]
fn mul(x: u64, y: u64) -> u128 {
    let (xl, xh) = (x & 0xffff_ffff, x >> 32);
    let (yl, yh) = (y & 0xffff_ffff, y >> 32);
    let ll = xl * yl;
    let lh = xl * yh;
    let hl = xh * yl;
    let hh = xh * yh;
    // At most `3 * (2^32 - 1)`, so no overflow.
    let mid = (ll >> 32) + (lh & 0xffff_ffff) + (hl & 0xffff_ffff);
    let lo = (ll & 0xffff_ffff) | (mid << 32);
    let hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    (u128::from(hi) << 64) | u128::from(lo)
}

#[cfg_attr(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    cfg(test)
)]
#[inline]
fn shr(in_: u128, shift: u64) -> u64 {
    (in_ >> shift) as u64
}

#[cfg_attr(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    cfg(test)
)]
#[inline]
fn lo(in_: u128) -> u64 {
    in_ as u64
}

pub type Key = StackByteArray<32>;

/// The key of the two Poly1305 lanes that the stitched ChaCha20 kernel runs
/// over whole 512-byte chunks (`chacha20_neon::Kernel::xor_chunk_poly`):
/// `r` in radix 2^64 with the folded `s1 = r1 + r1 / 4`, and `r^16`, which
/// joins the first lane's 16 blocks to the second's. Wiped on drop.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
pub(crate) struct StitchKey {
    pub(crate) r: [u64; 3],
    r16: [u64; 3],
    /// `[r^8, r^16, r^24]` in 3x44-bit limbs: the four-lane join powers for
    /// one chunk ([`Poly1305::stitch_finish`]).
    powers: [[u64; 3]; 3],
}

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
impl Drop for StitchKey {
    fn drop(&mut self) {
        self.r.zeroize();
        self.r16.zeroize();
        self.powers.zeroize();
    }
}

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

    /// The key of a stitched lane: `r` in radix 2^64, with `s1 = r1 + r1 /
    /// 4`. The caller wipes it.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_r(&self) -> [u64; 3] {
        let [l0, l1, l2] = self.r;
        // `r` is clamped below 2^124, with the low two bits of `r1` clear.
        let r0 = l0 | (l1 << 44);
        let r1 = (l1 >> 20) | (l2 << 24);
        [r0, r1, r1 + (r1 >> 2)]
    }

    /// The stitched lanes' key (see [`StitchKey`]).
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_key(&self) -> StitchKey {
        let mut r2 = super::sq_mod_p(&self.r);
        let mut r4 = super::sq_mod_p(&r2);
        let r8 = super::sq_mod_p(&r4);
        let r16 = super::sq_mod_p(&r8);
        let r24 = super::mul_mod_p(&r16, &r8);
        r2.zeroize();
        r4.zeroize();
        StitchKey {
            r: self.stitch_r(),
            r16: super::limbs64(&r16),
            powers: [r8, r16, r24],
        }
    }

    /// Absorbs one whole stitched chunk (512 bytes) at a block boundary with
    /// the four-lane path, taking its join powers from `key` instead of
    /// forming them.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_finish(&mut self, key: &StitchKey, chunk: &[u8; 512]) {
        debug_assert_eq!(self.buflen, 0);
        super::poly1305_aarch64::blocks_with_powers(&mut self.h, &self.r, chunk, &key.powers);
    }

    /// The state as a single stitched lane (radix 2^64); the state must be
    /// at a block boundary (nothing buffered).
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_lane(&self) -> [u64; 3] {
        debug_assert_eq!(self.buflen, 0);
        self.h
    }

    /// Takes a single stitched lane back as the state.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_set(&mut self, lane: &[u64; 3]) {
        self.h = *lane;
    }

    /// The stitched lanes' start: the state for the first, zero for the
    /// second. The state must be at a block boundary (nothing buffered).
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_lanes(&self) -> [[u64; 3]; 2] {
        [self.stitch_lane(), [0; 3]]
    }

    /// Takes the lanes after one stitched chunk: the state becomes `a r^16 +
    /// b`, the Horner value of the chunk's 32 blocks.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    pub(crate) fn stitch_join(&mut self, lanes: &[[u64; 3]; 2], key: &StitchKey) {
        self.h = super::mul_add_64(&lanes[0], &key.r16, &lanes[1]);
    }

    pub fn update(&mut self, input: &[u8]) {
        // At opt-level `z` and `s` the slice index and `copy_from_slice`
        // helpers here are out of line, which adds no key-derived copy: they
        // only see message bytes and the partial-block buffer.
        let mut m = input;
        if self.buflen > 0 {
            let input_block_end = core::cmp::min(BLOCK_SIZE - self.buflen, input.len());
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

    /// Processes a whole number of full blocks, using the four-lane AArch64,
    /// x86-64 or `simd128` bulk paths for long runs when available.
    fn full_blocks(&mut self, input: &[u8]) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if input.len() >= LANES_MIN_BYTES {
            let bulk = input.len() - input.len() % super::poly1305_aarch64::CHUNK;
            super::poly1305_aarch64::blocks(&mut self.h, &self.r, &input[..bulk]);
            self.blocks(&input[bulk..], false);
            return;
        }
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        if input.len() >= WASM_MIN_BYTES {
            let bulk = input.len() - input.len() % super::poly1305_wasm32::CHUNK;
            super::poly1305_wasm32::blocks(&mut self.h, &self.r, &input[..bulk]);
            self.blocks(&input[bulk..], false);
            return;
        }
        #[cfg(target_arch = "x86_64")]
        let input = &input[super::poly1305_x86_64::full_blocks(&mut self.h, &self.r, input)..];
        self.blocks(input, false);
    }

    /// Scalar block loop over `self.h` with `self.r`: on AArch64 the
    /// radix-2^64 `asm!` loop of [`super::poly1305_aarch64::blocks1`],
    /// elsewhere [`Self::blocks_portable`].
    #[inline]
    fn blocks(&mut self, input: &[u8], partial: bool) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        super::poly1305_aarch64::blocks1(&mut self.h, &self.r, input, u64::from(!partial));
        #[cfg(not(all(target_arch = "aarch64", target_endian = "little", not(miri))))]
        self.blocks_portable(input, partial);
    }

    /// The portable 3x44-bit block loop. Its working values live only in
    /// registers and compiler spill slots, which are out of Rust's reach and
    /// are not wiped; the state itself is wiped on drop.
    #[cfg_attr(
        all(target_arch = "aarch64", target_endian = "little", not(miri)),
        cfg(test)
    )]
    fn blocks_portable(&mut self, input: &[u8], partial: bool) {
        let hibit = if partial {
            0u64
        } else {
            // 1 << 128
            1u64 << 40
        };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];

        // On AArch64 the state is in radix 2^64 (this loop is only the tests'
        // reference there).
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        let h = super::carry44(super::limbs44(&self.h));
        #[cfg(not(all(target_arch = "aarch64", target_endian = "little", not(miri))))]
        let h = self.h;
        let [mut h0, mut h1, mut h2] = h;

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

        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        {
            self.h = super::limbs64(&[h0, h1, h2]);
        }
        #[cfg(not(all(target_arch = "aarch64", target_endian = "little", not(miri))))]
        {
            self.h = [h0, h1, h2];
        }
    }

    pub fn finalize_to_array(&mut self) -> [u8; BLOCK_SIZE] {
        let mut mac = [0u8; 16];

        self.finalize(&mut mac);

        mac
    }

    pub fn finalize(&mut self, output: &mut [u8]) {
        // The tag words go straight into `output` as array stores: at
        // opt-level `z` and `s` `copy_from_slice` stays out of line and took
        // them by reference from a stack temporary that was never wiped (the
        // computed tag is secret when verification fails). The state is left
        // to its drop to wipe (a wipe here as well measured 5% of a 64-byte
        // `crypto_onetimeauth`): callers that do more work afterwards, such as
        // decrypting after verification, drop or wipe it first.
        // process any remaining block
        if self.buflen > 0 {
            let block = self.buffer.to_le_bytes();
            self.blocks(&pad_partial_block(&block[..self.buflen]), true);
        }

        // In radix 2^64 (`h2` small, see `limbs64`): fold the bits from 2^130
        // up once (`2^130 = 5` mod p), leaving `h < 2^130 + 5`, then take
        // `h - p = h + 5 - 2^130` when `h + 5` reaches 2^130, by masks; the
        // tag is the low 128 bits of `h + pad`, so `h`'s top limb only
        // decides the selection.
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        let [h0, h1, h2] = self.h;
        #[cfg(not(all(target_arch = "aarch64", target_endian = "little", not(miri))))]
        let [h0, h1, h2] = super::limbs64(&self.h);
        let (h, carry) =
            (u128::from(h0) | (u128::from(h1) << 64)).overflowing_add(u128::from((h2 >> 2) * 5));
        let h2 = (h2 & 3) + u64::from(carry);
        let (g, carry) = h.overflowing_add(5);
        let mask = 0u128.wrapping_sub(u128::from((h2 + u64::from(carry)) >> 2));
        let h = (h & !mask) | (g & mask);
        let pad = u128::from(self.pad[0]) | (u128::from(self.pad[1]) << 64);
        let tag = h.wrapping_add(pad);
        let (h0, h1) = (tag as u64, (tag >> 64) as u64);

        // One bounds check per word (not `output[..16]`) keeps two 8-byte
        // stores at opt-level 3; a merged 16-byte store measured +2% on
        // 64-byte `crypto_onetimeauth_verify`, which reads the tag bytewise.
        let (words, _) = output.as_chunks_mut::<8>();
        words[0] = h0.to_le_bytes();
        words[1] = h1.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::test_prelude::*;

    #[cfg(all(feature = "nightly", not(tarpaulin)))]
    extern crate test;

    #[test]
    fn incremental_state_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Poly1305>();
        assert!(core::mem::needs_drop::<Poly1305>());
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

    /// `finalize` gives `((h mod p) + pad) mod 2^128` for states at the
    /// reduction boundaries (`p - 1`, `p`, `p + 4`, `2^130 - 1`, `2^130`,
    /// `2^130 + 4`, `2p - 1`) and at the partially reduced limb bounds, in
    /// every limb split the block loops leave.
    #[test]
    fn finalize_reduces_boundary_states() {
        use num_bigint::BigUint;

        let p = (BigUint::from(1u8) << 130u32) - 5u32;
        let two130 = BigUint::from(1u8) << 130u32;
        let values = [
            BigUint::from(0u8),
            &p - 1u32,
            p.clone(),
            &p + 4u32,
            &two130 - 1u32,
            two130.clone(),
            &two130 + 4u32,
            &p * 2u32 - 1u32,
        ];
        let m44 = BigUint::from((1u64 << 44) - 1);
        let mut states: Vec<[u64; 3]> = values
            .iter()
            .map(|v| {
                let limb = |shift: u32, mask: &BigUint| {
                    ((v >> shift) & mask)
                        .to_u64_digits()
                        .first()
                        .copied()
                        .unwrap_or(0)
                };
                [
                    limb(0, &m44),
                    limb(44, &m44),
                    limb(88, &((BigUint::from(1u8) << 64u32) - 1u32)),
                ]
            })
            .collect();
        // Limbs above their widths, as a block loop's carry can leave them.
        states.push([(1 << 44) - 1, (1 << 44) + 1023, (1 << 42) + 1023]);
        states.push([(1 << 44) - 1, (1 << 44) - 1, (1 << 42) - 1]);
        for key in carry_keys() {
            for h in &states {
                let mut mac = Poly1305::new(&key);
                mac.h = *h;
                // The AArch64 state is in radix 2^64.
                #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
                {
                    mac.h = super::super::limbs64(h);
                }
                let pad = BigUint::from(mac.pad[0]) | (BigUint::from(mac.pad[1]) << 64u32);
                let value = BigUint::from(h[0])
                    + (BigUint::from(h[1]) << 44u32)
                    + (BigUint::from(h[2]) << 88u32);
                let expected = ((value % &p) + pad) % (BigUint::from(1u8) << 128u32);
                let mut expected_bytes = expected.to_bytes_le();
                expected_bytes.resize(16, 0);
                assert_eq!(mac.finalize_to_array().to_vec(), expected_bytes, "h={h:x?}");
            }
        }
    }

    /// Deterministic keys stressing the limb carries: all clamped bits set,
    /// a tiny `r`, and a patterned one.
    fn carry_keys() -> [Key; 3] {
        let mut tiny = [0u8; 32];
        tiny[0] = 1;
        tiny[3] = 0x40;
        let patterned: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
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
    /// `chunk_counts`, on the patterned carry message and on all-ones blocks
    /// (every message limb at its maximum).
    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little", not(miri)),
        target_arch = "x86_64",
        all(target_arch = "wasm32", target_feature = "simd128")
    ))]
    fn check_bulk_matches_scalar(
        name: &str,
        chunk: usize,
        chunk_counts: &[usize],
        bulk: impl Fn(&mut [u64; 3], &[u64; 3], &[u8]),
    ) {
        let size = chunk_counts.iter().max().unwrap() * chunk + 64;
        let messages = [carry_message(size), vec![0xff; size]];
        for (key, data) in carry_keys()
            .iter()
            .flat_map(|key| messages.iter().map(move |data| (key, data)))
        {
            for len in chunk_counts.iter().map(|chunks| chunks * chunk) {
                let mut scalar = Poly1305::new(key);
                let mut vector = Poly1305::new(key);
                scalar.blocks_portable(&data[..16], false);
                vector.blocks(&data[..16], false);

                scalar.blocks_portable(&data[16..16 + len], false);
                bulk(&mut vector.h, &vector.r, &data[16..16 + len]);
                scalar.blocks_portable(&data[16 + len..16 + len + 48], false);
                vector.blocks(&data[16 + len..16 + len + 48], false);
                assert_eq!(
                    scalar.finalize_to_array(),
                    vector.finalize_to_array(),
                    "{name} len={len}"
                );
            }
        }
    }

    /// The single-lane AArch64 loop leaves the portable loop's state for
    /// every block count up to 20, full blocks and a padded final block,
    /// from a nonzero state, with the carry keys and messages.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    #[test]
    fn aarch64_single_lane_matches_portable() {
        let messages = [carry_message(20 * 16 + 16), vec![0xff; 20 * 16 + 16]];
        for key in carry_keys() {
            for data in &messages {
                for blocks in 0..=20 {
                    for partial in [false, true] {
                        let mut portable = Poly1305::new(&key);
                        let mut asm = Poly1305::new(&key);
                        portable.blocks_portable(&data[..16], false);
                        asm.blocks_portable(&data[..16], false);
                        let input = &data[16..16 + 16 * blocks];
                        portable.blocks_portable(input, partial);
                        super::super::poly1305_aarch64::blocks1(
                            &mut asm.h,
                            &asm.r,
                            input,
                            u64::from(!partial),
                        );
                        assert_eq!(
                            portable.finalize_to_array(),
                            asm.finalize_to_array(),
                            "blocks={blocks} partial={partial}"
                        );
                    }
                }
            }
        }
    }

    /// The four-lane AArch64 kernel, for 1 to 5 of its 64-byte chunks (one
    /// block per lane, so the joins use `r^1` to `r^5`) and for 8, 16, 25
    /// and 64 chunks (up to 4 KiB), from a nonzero state that lane 0 carries.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    #[test]
    fn aarch64_blocks_match_scalar() {
        use super::super::poly1305_aarch64::{CHUNK, blocks};

        check_bulk_matches_scalar("aarch64", CHUNK, &[1, 2, 3, 4, 5, 8, 16, 25, 64], blocks);
    }

    /// The AVX2 bulk kernel, for 1 to 4 of its 128-byte chunks and for 8,
    /// 16, 25 and 32 chunks (up to 4 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK, blocks};

        let Some(token) = crate::x86_64::Avx2::new() else {
            return;
        };
        check_bulk_matches_scalar(
            "avx2",
            CHUNK,
            &[1, 2, 3, 4, 8, 16, 25, 32],
            |h, r, input| blocks(token, h, r, input),
        );
    }

    /// The AVX-512 bulk kernel, for 1 to 4 of its 256-byte chunks and for
    /// 8, 16, 25 and 32 chunks (up to 8 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK512, blocks_avx512};

        let Some(token) = crate::x86_64::Avx512::new() else {
            return;
        };
        check_bulk_matches_scalar(
            "avx512",
            CHUNK512,
            &[1, 2, 3, 4, 8, 16, 25, 32],
            |h, r, input| blocks_avx512(token, h, r, input),
        );
    }

    /// The AVX-512 IFMA bulk kernel, for 1 to 4 of its 128-byte chunks and
    /// for 8, 16, 25, 32, 63 and 64 chunks (up to 8 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK_IFMA, blocks_ifma};

        let Some(token) = crate::x86_64::Avx512Ifma::new() else {
            return;
        };
        check_bulk_matches_scalar(
            "ifma",
            CHUNK_IFMA,
            &[1, 2, 3, 4, 8, 16, 25, 32, 63, 64],
            |h, r, input| blocks_ifma(token, h, r, input),
        );
    }

    /// The two-chain AVX-512 IFMA bulk kernel, for 1 to 4 of its 256-byte
    /// chunks and for 8, 16, 25 and 32 chunks (up to 8 KiB).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma2_blocks_match_scalar() {
        use super::super::poly1305_x86_64::{CHUNK_IFMA2, blocks_ifma2};

        let Some(token) = crate::x86_64::Avx512Ifma::new() else {
            return;
        };
        check_bulk_matches_scalar(
            "ifma2",
            CHUNK_IFMA2,
            &[1, 2, 3, 4, 8, 16, 25, 32],
            |h, r, input| blocks_ifma2(token, h, r, input),
        );
    }

    /// The `simd128` bulk kernel, for 1 to 4 of its 128-byte chunks and for
    /// 8, 16, 25 and 32 chunks (up to 4 KiB).
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn simd128_blocks_match_scalar() {
        use super::super::poly1305_wasm32::{CHUNK, blocks};

        check_bulk_matches_scalar("simd128", CHUNK, &[1, 2, 3, 4, 8, 16, 25, 32], blocks);
    }

    /// The four-product `mul` of `simd128` builds equals the full 128-bit
    /// product, at the limb and carry boundaries and on pseudo-random words.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn simd128_mul_matches_u128_product() {
        let edges = [
            0,
            1,
            u64::from(u32::MAX),
            1 << 32,
            (1 << 44) - 1,
            (1 << 49) - 1,
            u64::MAX - 1,
            u64::MAX,
        ];
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        let random = core::iter::repeat_with(|| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        });
        let words: Vec<u64> = edges.into_iter().chain(random.take(64)).collect();
        for &x in &words {
            for &y in &words {
                assert_eq!(mul(x, y), u128::from(x) * u128::from(y), "{x:#x} * {y:#x}");
            }
        }
    }

    /// The production driver must match the scalar block loop at every
    /// length around the bulk-path thresholds (384 bytes on AArch64; 256,
    /// 512, 1024 and 2048 on x86-64; 128 with `simd128`) and their 64-, 128-
    /// and 256-byte chunk residues (including a 128-byte chunk left over from
    /// the two-chain run), one-shot and split so a partial block is pending
    /// before and after the bulk run.
    #[test]
    fn update_matches_scalar_blocks_at_bulk_boundaries() {
        let data = carry_message(4608 + 200);
        let lens = (112..=144)
            .chain(240..=272)
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

        /// Exercises the bulk paths (on AArch64 runs of >= `LANES_MIN_BYTES`
        /// full-block bytes in 64-byte chunks) with every residue of the
        /// chunking, mixed chunk boundaries, and worst-case key/message limbs,
        /// against libsodium.
        #[test]
        fn test_libsodium_long_and_chunked() {
            use crate::native_test_util::onetimeauth_poly1305;
            use crate::rng::copy_randombytes;

            let mut keys = vec![Key::generate(), Key::generate()];
            // All-ones key (maximal clamped r and pad) and all-ones message
            // stress every carry in the 5x26 representation.
            keys.push(Key::from(&[0xffu8; 32]));

            for key in &keys {
                for len in (96..=1300).chain([4096, 4097, 65536 + 17]) {
                    let mut data = vec![0u8; len];
                    copy_randombytes(&mut data);
                    if len % 3 == 0 {
                        data.fill(0xff);
                    }
                    let so_mac = onetimeauth_poly1305(&data, key);

                    let mut mac = Poly1305::new(key);
                    mac.update(&data);
                    assert_eq!(mac.finalize_to_array(), so_mac, "one-shot len={len}");

                    // Split so the bulk path runs in the middle of a stream
                    // with a pending partial block before and after it, and
                    // so that the split lands inside the first, second or
                    // third chunk of each backend's chunking.
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
