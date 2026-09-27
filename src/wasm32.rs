//! WebAssembly `simd128` helpers shared by the `*_wasm32.rs` kernels:
//! 16-byte loads and stores (of bytes, and of the `i16` coefficient rows used
//! by ML-KEM), word-vector construction, the per-lane counter input, the
//! lane-set transpose and the keystream XOR into a [`Dest`].
//!
//! WebAssembly has no runtime feature detection, so this module and the
//! kernels built on it are compiled only when the crate itself is built with
//! `-Ctarget-feature=+simd128`; the intrinsics are then safe to call from any
//! function of the crate.

use core::arch::wasm32::{
    i8x16_shuffle, i32x4_add, i32x4_splat, i32x4_sub, u32x4, u32x4_lt, v128, v128_load, v128_store,
    v128_xor,
};

pub(crate) use crate::stream::Dest;

/// Four words as a vector, word 0 in lane 0.
#[inline(always)]
pub(crate) fn words(w: [u32; 4]) -> v128 {
    u32x4(w[0], w[1], w[2], w[3])
}

/// The stream-cipher input for blocks `counter .. counter + 4`, one block per
/// lane, with the 64-bit block counter in words `LO` (low) and `HI` (high).
#[inline(always)]
pub(crate) fn input_lanes<const LO: usize, const HI: usize>(
    state: &[u32; 16],
    counter: u64,
) -> [v128; 16] {
    let mut x = [i32x4_splat(0); 16];
    for (lane, &word) in x.iter_mut().zip(state) {
        *lane = i32x4_splat(word as i32);
    }
    let lo = i32x4_splat(counter as u32 as i32);
    let lo_lanes = i32x4_add(lo, words([0, 1, 2, 3]));
    // A lane whose low word wrapped compares below the base; the compare
    // yields all-ones (-1) there, so subtracting it carries into the high
    // word.
    let carry = u32x4_lt(lo_lanes, lo);
    x[LO] = lo_lanes;
    x[HI] = i32x4_sub(i32x4_splat((counter >> 32) as u32 as i32), carry);
    x
}

/// Loads 16 bytes as a vector (one `v128.load`).
#[inline(always)]
pub(crate) fn load(bytes: &[u8; 16]) -> v128 {
    // SAFETY: `bytes` is a live shared reference to exactly 16 initialized
    // bytes, and `v128_load` performs an unaligned (align 1) 16-byte load.
    unsafe { v128_load(bytes.as_ptr().cast()) }
}

/// Stores a vector as 16 bytes (one `v128.store`).
#[inline(always)]
pub(crate) fn store(bytes: &mut [u8; 16], v: v128) {
    // SAFETY: `bytes` is a live exclusive reference to exactly 16 bytes, and
    // `v128_store` performs an unaligned (align 1) 16-byte store.
    unsafe { v128_store(bytes.as_mut_ptr().cast(), v) }
}

/// Transposes the 4x4 word matrix `(a, b, c, d)` so that element `i` of the
/// result holds lane `i` of each input, i.e. four consecutive words of block
/// `i`, as bytes.
#[inline(always)]
pub(crate) fn transpose(a: v128, b: v128, c: v128, d: v128) -> [v128; 4] {
    // Interleave words: `ab_lo = a0 b0 a1 b1`, `ab_hi = a2 b2 a3 b3`.
    let ab_lo = i8x16_shuffle::<0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23>(a, b);
    let ab_hi = i8x16_shuffle::<8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31>(a, b);
    let cd_lo = i8x16_shuffle::<0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23>(c, d);
    let cd_hi = i8x16_shuffle::<8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31>(c, d);
    // Then 64-bit halves: `a0 b0 c0 d0`, `a1 b1 c1 d1`, ...
    [
        i8x16_shuffle::<0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23>(ab_lo, cd_lo),
        i8x16_shuffle::<8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31>(ab_lo, cd_lo),
        i8x16_shuffle::<0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23>(ab_hi, cd_hi),
        i8x16_shuffle::<8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31>(ab_hi, cd_hi),
    ]
}

/// XORs the four 16-byte rows of `keystream` into block `index` of `dest`.
#[inline(always)]
pub(crate) fn xor_block(keystream: [v128; 4], index: usize, dest: &mut Dest<'_>) {
    let Some((source, out)) = dest.block(index) else {
        return;
    };
    let source = source.map(|source| source.as_chunks::<16>().0);
    let out = out.as_chunks_mut::<16>().0;
    for (row, keystream) in keystream.iter().enumerate() {
        let data = match source {
            Some(source) => v128_xor(load(&source[row]), *keystream),
            None => v128_xor(load(&out[row]), *keystream),
        };
        store(&mut out[row], data);
    }
}

/// Loads eight 16-bit lanes, lane `i` from `lanes[i]` (one `v128.load`).
#[inline(always)]
pub(crate) fn load_i16s(lanes: &[i16; 8]) -> v128 {
    // SAFETY: `lanes` is a live shared reference to exactly 16 initialized
    // bytes, and `v128_load` performs an unaligned (align 1) 16-byte load.
    unsafe { v128_load(lanes.as_ptr().cast()) }
}

/// Stores eight 16-bit lanes, lane `i` to `lanes[i]` (one `v128.store`).
#[inline(always)]
pub(crate) fn store_i16s(lanes: &mut [i16; 8], v: v128) {
    // SAFETY: `lanes` is a live exclusive reference to exactly 16 bytes, and
    // `v128_store` performs an unaligned (align 1) 16-byte store.
    unsafe { v128_store(lanes.as_mut_ptr().cast(), v) }
}
