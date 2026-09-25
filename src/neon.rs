//! NEON helpers shared by the AArch64 stream-cipher kernels (`chacha20`,
//! `salsa20`): 16-byte loads and stores, word-vector construction, the
//! per-lane counter input, the lane-set transpose and the keystream XOR into
//! a [`Dest`].

use core::arch::aarch64::{
    uint8x16_t, uint32x4_t, vcombine_u64, vcreate_u64, vgetq_lane_u64, vreinterpretq_u8_u64,
    vreinterpretq_u32_u64, vreinterpretq_u64_u8, vreinterpretq_u64_u32, vtrn1q_u32, vtrn1q_u64,
    vtrn2q_u32, vtrn2q_u64,
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

/// The stream-cipher input for blocks `$counter .. $counter + 4`, one block
/// per lane, with the 64-bit block counter in words `$lo` (low) and `$hi`
/// (high).
///
/// A macro rather than a function so it expands inside the kernel: as a
/// `#[target_feature]` function (which cannot be `#[inline(always)]`) it was
/// out of line at opt-level `z` and returned the broadcast key words through
/// a stack buffer. The broadcast is spelled out for the same reason: a `zip`
/// over `state` built the lanes in a stack array behind an out-of-line
/// `Iter::size` at opt-level `z` and `s`.
macro_rules! input_lanes {
    ($state:expr, $counter:expr, $lo:literal, $hi:literal) => {{
        use ::core::arch::aarch64::{vaddq_u32, vcltq_u32, vdupq_n_u32, vsubq_u32};
        let state: &[u32; 16] = $state;
        let counter: u64 = $counter;
        let mut x = [
            vdupq_n_u32(state[0]),
            vdupq_n_u32(state[1]),
            vdupq_n_u32(state[2]),
            vdupq_n_u32(state[3]),
            vdupq_n_u32(state[4]),
            vdupq_n_u32(state[5]),
            vdupq_n_u32(state[6]),
            vdupq_n_u32(state[7]),
            vdupq_n_u32(state[8]),
            vdupq_n_u32(state[9]),
            vdupq_n_u32(state[10]),
            vdupq_n_u32(state[11]),
            vdupq_n_u32(state[12]),
            vdupq_n_u32(state[13]),
            vdupq_n_u32(state[14]),
            vdupq_n_u32(state[15]),
        ];
        let lo = vdupq_n_u32(counter as u32);
        let lo_lanes = vaddq_u32(lo, $crate::neon::words([0, 1, 2, 3]));
        // A lane whose low word wrapped compares below the base; `vcltq`
        // yields all-ones there, so subtracting it carries into the high
        // word.
        let carry = vcltq_u32(lo_lanes, lo);
        x[$lo] = lo_lanes;
        x[$hi] = vsubq_u32(vdupq_n_u32((counter >> 32) as u32), carry);
        x
    }};
}
pub(crate) use input_lanes;

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

/// XORs the four 16-byte rows of the keystream `$keystream` (a
/// `[uint8x16_t; 4]`) into block `$index` of `$dest`.
///
/// A macro rather than a function for the same reason as [`input_lanes`]:
/// out of line at opt-level `z`, the keystream rows were passed through a
/// stack copy. The rows are spelled out rather than iterated so no iterator
/// takes their address.
macro_rules! xor_block {
    ($keystream:expr, $index:expr, $dest:expr) => {
        if let Some((source, out)) = $dest.block($index) {
            let [k0, k1, k2, k3]: [::core::arch::aarch64::uint8x16_t; 4] = $keystream;
            let source = source.map(|source| source.as_chunks::<16>().0);
            let out = out.as_chunks_mut::<16>().0;
            let (d0, d1, d2, d3) = match source {
                Some(source) => (
                    $crate::neon::load(&source[0]),
                    $crate::neon::load(&source[1]),
                    $crate::neon::load(&source[2]),
                    $crate::neon::load(&source[3]),
                ),
                None => (
                    $crate::neon::load(&out[0]),
                    $crate::neon::load(&out[1]),
                    $crate::neon::load(&out[2]),
                    $crate::neon::load(&out[3]),
                ),
            };
            $crate::neon::store(&mut out[0], ::core::arch::aarch64::veorq_u8(d0, k0));
            $crate::neon::store(&mut out[1], ::core::arch::aarch64::veorq_u8(d1, k1));
            $crate::neon::store(&mut out[2], ::core::arch::aarch64::veorq_u8(d2, k2));
            $crate::neon::store(&mut out[3], ::core::arch::aarch64::veorq_u8(d3, k3));
        }
    };
}
pub(crate) use xor_block;
