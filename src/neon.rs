//! NEON helpers shared by the AArch64 stream-cipher kernels (`chacha20`,
//! `salsa20`): 16-byte loads and stores, word-vector construction, the
//! per-lane counter input, the lane-set transpose and the keystream XOR into
//! a [`Dest`].

use core::arch::aarch64::{
    uint8x16_t, uint32x4_t, vaddq_u32, vcltq_u32, vcombine_u64, vcreate_u64, vdupq_n_u32, veorq_u8,
    vgetq_lane_u64, vreinterpretq_u8_u64, vreinterpretq_u32_u64, vreinterpretq_u64_u8,
    vreinterpretq_u64_u32, vsubq_u32, vtrn1q_u32, vtrn1q_u64, vtrn2q_u32, vtrn2q_u64,
};

pub(crate) use crate::stream::Dest;

/// Four words as a vector, word 0 in lane 0.
#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn words(w: [u32; 4]) -> uint32x4_t {
    let lo = vcreate_u64(u64::from(w[0]) | (u64::from(w[1]) << 32));
    let hi = vcreate_u64(u64::from(w[2]) | (u64::from(w[3]) << 32));
    vreinterpretq_u32_u64(vcombine_u64(lo, hi))
}

/// The stream-cipher input for blocks `counter .. counter + 4`, one block per
/// lane, with the 64-bit block counter in words `LO` (low) and `HI` (high).
#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn input_lanes<const LO: usize, const HI: usize>(
    state: &[u32; 16],
    counter: u64,
) -> [uint32x4_t; 16] {
    // A plain loop: `array::map` with a NEON closure is not inlined here and
    // round-trips the 16 vectors through the stack on every chunk.
    let mut x = [vdupq_n_u32(0); 16];
    for (lane, &word) in x.iter_mut().zip(state) {
        *lane = vdupq_n_u32(word);
    }
    let lo = vdupq_n_u32(counter as u32);
    let lo_lanes = vaddq_u32(lo, words([0, 1, 2, 3]));
    // A lane whose low word wrapped compares below the base; `vcltq` yields
    // all-ones there, so subtracting it carries into the high word.
    let carry = vcltq_u32(lo_lanes, lo);
    x[LO] = lo_lanes;
    x[HI] = vsubq_u32(vdupq_n_u32((counter >> 32) as u32), carry);
    x
}

/// Loads 16 bytes as a vector (a single `ldr q` once inlined).
#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn load(bytes: &[u8; 16]) -> uint8x16_t {
    let halves = bytes.as_chunks::<8>().0;
    let lo = vcreate_u64(u64::from_le_bytes(halves[0]));
    let hi = vcreate_u64(u64::from_le_bytes(halves[1]));
    vreinterpretq_u8_u64(vcombine_u64(lo, hi))
}

/// Stores a vector as 16 bytes (a single `str q` once inlined).
#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn store(bytes: &mut [u8; 16], v: uint8x16_t) {
    let v = vreinterpretq_u64_u8(v);
    let halves = bytes.as_chunks_mut::<8>().0;
    halves[0] = vgetq_lane_u64::<0>(v).to_le_bytes();
    halves[1] = vgetq_lane_u64::<1>(v).to_le_bytes();
}

/// Transposes the 4x4 word matrix `(a, b, c, d)` so that element `i` of the
/// result holds lane `i` of each input, i.e. four consecutive words of block
/// `i`, reinterpreted as bytes.
#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn transpose(
    a: uint32x4_t,
    b: uint32x4_t,
    c: uint32x4_t,
    d: uint32x4_t,
) -> [uint8x16_t; 4] {
    let ab_even = vreinterpretq_u64_u32(vtrn1q_u32(a, b));
    let ab_odd = vreinterpretq_u64_u32(vtrn2q_u32(a, b));
    let cd_even = vreinterpretq_u64_u32(vtrn1q_u32(c, d));
    let cd_odd = vreinterpretq_u64_u32(vtrn2q_u32(c, d));
    [
        vreinterpretq_u8_u64(vtrn1q_u64(ab_even, cd_even)),
        vreinterpretq_u8_u64(vtrn1q_u64(ab_odd, cd_odd)),
        vreinterpretq_u8_u64(vtrn2q_u64(ab_even, cd_even)),
        vreinterpretq_u8_u64(vtrn2q_u64(ab_odd, cd_odd)),
    ]
}

/// XORs the four 16-byte rows of `keystream` into block `index` of `dest`.
#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn xor_block(keystream: [uint8x16_t; 4], index: usize, dest: &mut Dest<'_>) {
    let Some((source, out)) = dest.block(index) else {
        return;
    };
    let source = source.map(|source| source.as_chunks::<16>().0);
    let out = out.as_chunks_mut::<16>().0;
    for (row, keystream) in keystream.iter().enumerate() {
        let data = match source {
            Some(source) => veorq_u8(load(&source[row]), *keystream),
            None => veorq_u8(load(&out[row]), *keystream),
        };
        store(&mut out[row], data);
    }
}
