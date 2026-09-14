//! NEON helpers shared by the AArch64 stream-cipher kernels (`chacha20`,
//! `salsa20`): 16-byte loads and stores, the lane-set transpose and the
//! keystream XOR into a [`Dest`].

use std::arch::aarch64::{
    uint8x16_t, uint32x4_t, vcombine_u64, vcreate_u64, veorq_u8, vgetq_lane_u64,
    vreinterpretq_u8_u64, vreinterpretq_u64_u8, vreinterpretq_u64_u32, vtrn1q_u32, vtrn1q_u64,
    vtrn2q_u32, vtrn2q_u64,
};

pub(crate) use crate::stream::Dest;

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
    for (row, keystream) in keystream.into_iter().enumerate() {
        let data = match source {
            Some(source) => veorq_u8(load(&source[row]), keystream),
            None => veorq_u8(load(&out[row]), keystream),
        };
        store(&mut out[row], data);
    }
}
