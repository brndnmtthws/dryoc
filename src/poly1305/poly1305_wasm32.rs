//! WebAssembly `simd128` bulk path for Poly1305.
//!
//! The scalar backend keeps `h` in three 44-bit limbs. This module processes
//! eight 16-byte blocks (`CHUNK` = 128 bytes) per iteration as eight
//! independent Horner lanes in the 5x26-bit representation, each multiplied
//! by `r^8` per iteration: two chains of four lanes (chain `A` holds blocks
//! `0..4`, chain `B` blocks `4..8`, with limb `k` of the four blocks in one
//! `u32x4`). The final iteration uses `r^8, r^7, ..., r` (one power per
//! block) so that summing the eight lanes yields exactly the sequential
//! Horner value.
//!
//! The 25 limb products per chain are `u64x2.extmul_{low,high}_u32x4` pairs
//! (one widening multiply per two lanes) summed with `i64x2.add`. The hot
//! loop multiplies every lane by the same power, so its nine multiplier
//! words are splatted across the lanes once per call; the final chunk and the
//! key-power setup use per-lane multipliers with the same instructions. The
//! key powers are computed in the vector domain too, so the kernel needs no
//! 64x64-bit multiplications, which WebAssembly lacks.
//!
//! Every iteration performs the same instructions regardless of data, so
//! there are no secret-dependent branches or memory accesses. The only
//! branches depend on the input length.
//!
//! Wiping: the key powers, multipliers, accumulators and products only flow
//! through inlined helpers, so they live in the engine's registers or spill
//! slots (the kernel uses no linear-memory stack frame), which are out of
//! Rust's reach and not wiped; a wipe would only force them into linear
//! memory. `h` is the caller's state, which the driver wipes.

use core::arch::wasm32::{
    i32x4_add, i32x4_shl, i32x4_shuffle, i64x2_add, i64x2_shl, u32x4, u32x4_extract_lane,
    u32x4_shr, u32x4_splat, u64x2_extmul_high_u32x4, u64x2_extmul_low_u32x4, u64x2_shr,
    u64x2_splat, v128, v128_and, v128_or,
};

use super::{M26, canonical, carry44, limbs26, pack_limbs26};
use crate::wasm32::{load, transpose};

/// Blocks per chain: one block per 32-bit lane.
const LANES: usize = 4;
/// Independent four-lane chains per iteration.
const CHAINS: usize = 2;
/// Blocks per iteration; also the highest key power needed.
const BLOCKS: usize = LANES * CHAINS;
const _: () = assert!(BLOCKS == 8);
/// Bytes per iteration. `blocks` takes a non-empty multiple of this.
pub(super) const CHUNK: usize = 16 * BLOCKS;

/// Four-lane 5x26-bit accumulator: limb `k` of four blocks in `0[k]`. Also
/// used for four key powers, one per lane.
#[derive(Clone, Copy)]
struct Acc([v128; 5]);

impl Acc {
    /// The 5x26-bit limbs `l` in every lane.
    #[inline(always)]
    fn splat(l: &[u32; 5]) -> Self {
        Self([
            u32x4_splat(l[0]),
            u32x4_splat(l[1]),
            u32x4_splat(l[2]),
            u32x4_splat(l[3]),
            u32x4_splat(l[4]),
        ])
    }
}

/// Multiplier word indices: `R0..R4` are the limbs of the power, `S1..S4` are
/// `5 *` limbs `1..4`.
const R0: usize = 0;
const R1: usize = 1;
const R2: usize = 2;
const R3: usize = 3;
const R4: usize = 4;
const S1: usize = 5;
const S2: usize = 6;
const S3: usize = 7;
const S4: usize = 8;

/// Per-lane multiplier: word `W` of the power for lane `l` in lane `l` of
/// `0[W]`.
#[derive(Clone, Copy)]
struct Mult([v128; 9]);

impl Mult {
    /// The four powers held in the lanes of `powers`.
    #[inline(always)]
    fn from_lanes(powers: &Acc) -> Self {
        let [r0, r1, r2, r3, r4] = powers.0;
        // `5 * x` as `(x << 2) + x`; limbs are below `2^27`, so it fits.
        Self([
            r0,
            r1,
            r2,
            r3,
            r4,
            i32x4_add(i32x4_shl(r1, 2), r1),
            i32x4_add(i32x4_shl(r2, 2), r2),
            i32x4_add(i32x4_shl(r3, 2), r3),
            i32x4_add(i32x4_shl(r4, 2), r4),
        ])
    }

    /// The power held in lane `L` of `powers`, in every lane.
    #[inline(always)]
    fn from_lane<const L: usize>(powers: &Acc) -> Self {
        let [p0, p1, p2, p3, p4] = powers.0;
        let splat = |x: v128| i32x4_shuffle::<L, L, L, L>(x, x);
        Self::from_lanes(&Acc([
            splat(p0),
            splat(p1),
            splat(p2),
            splat(p3),
            splat(p4),
        ]))
    }
}

/// 64-bit products of one output limb: lanes 0, 1 in `lo`, lanes 2, 3 in
/// `hi`.
#[derive(Clone, Copy)]
struct Prod {
    lo: v128,
    hi: v128,
}

#[inline(always)]
fn mull<const W: usize>(a: v128, m: &Mult) -> Prod {
    Prod {
        lo: u64x2_extmul_low_u32x4(a, m.0[W]),
        hi: u64x2_extmul_high_u32x4(a, m.0[W]),
    }
}

#[inline(always)]
fn mlal<const W: usize>(d: Prod, a: v128, m: &Mult) -> Prod {
    let p = mull::<W>(a, m);
    Prod {
        lo: i64x2_add(d.lo, p.lo),
        hi: i64x2_add(d.hi, p.hi),
    }
}

/// The 25 lane-wise limb products of `acc * m mod p` before carrying.
///
/// Input bound: `acc` and `m` limbs below `2^27 + 2^10` (a reduced state
/// plus one message block, or a partially reduced power), so each product
/// sum is below `2^58`.
#[inline(always)]
fn products(acc: Acc, m: &Mult) -> [Prod; 5] {
    let [a0, a1, a2, a3, a4] = acc.0;

    let mut d0 = mull::<R0>(a0, m);
    d0 = mlal::<S4>(d0, a1, m);
    d0 = mlal::<S3>(d0, a2, m);
    d0 = mlal::<S2>(d0, a3, m);
    d0 = mlal::<S1>(d0, a4, m);

    let mut d1 = mull::<R1>(a0, m);
    d1 = mlal::<R0>(d1, a1, m);
    d1 = mlal::<S4>(d1, a2, m);
    d1 = mlal::<S3>(d1, a3, m);
    d1 = mlal::<S2>(d1, a4, m);

    let mut d2 = mull::<R2>(a0, m);
    d2 = mlal::<R1>(d2, a1, m);
    d2 = mlal::<R0>(d2, a2, m);
    d2 = mlal::<S4>(d2, a3, m);
    d2 = mlal::<S3>(d2, a4, m);

    let mut d3 = mull::<R3>(a0, m);
    d3 = mlal::<R2>(d3, a1, m);
    d3 = mlal::<R1>(d3, a2, m);
    d3 = mlal::<R0>(d3, a3, m);
    d3 = mlal::<S4>(d3, a4, m);

    let mut d4 = mull::<R4>(a0, m);
    d4 = mlal::<R3>(d4, a1, m);
    d4 = mlal::<R2>(d4, a2, m);
    d4 = mlal::<R1>(d4, a3, m);
    d4 = mlal::<R0>(d4, a4, m);

    [d0, d1, d2, d3, d4]
}

/// Loads four consecutive 16-byte blocks into 5x26-bit limbs (with the 2^128
/// high bit set) and adds them lane-wise to `acc`.
#[inline(always)]
fn add_blocks(acc: Acc, blocks: &[u8; 64]) -> Acc {
    let (b, _) = blocks.as_chunks::<16>();
    // `w[i]` holds 32-bit word `i` of each block.
    let [w0, w1, w2, w3] = transpose(load(&b[0]), load(&b[1]), load(&b[2]), load(&b[3]));

    let mask = u32x4_splat(M26 as u32);
    let hibit = u32x4_splat(1 << 24);
    // Limb k of a block is bits 26k..26k+26: the top bits of one word and
    // the low bits of the next.
    let [a0, a1, a2, a3, a4] = acc.0;
    let l0 = v128_and(w0, mask);
    let l1 = v128_and(v128_or(u32x4_shr(w0, 26), i32x4_shl(w1, 6)), mask);
    let l2 = v128_and(v128_or(u32x4_shr(w1, 20), i32x4_shl(w2, 12)), mask);
    let l3 = v128_and(v128_or(u32x4_shr(w2, 14), i32x4_shl(w3, 18)), mask);
    let l4 = v128_or(u32x4_shr(w3, 8), hibit);
    Acc([
        i32x4_add(a0, l0),
        i32x4_add(a1, l1),
        i32x4_add(a2, l2),
        i32x4_add(a3, l3),
        i32x4_add(a4, l4),
    ])
}

/// Low 32 bits of each 64-bit lane, as a four-lane vector.
#[inline(always)]
fn narrow(x: Prod) -> v128 {
    i32x4_shuffle::<0, 2, 4, 6>(x.lo, x.hi)
}

/// Partial carry of the limb products (each below `2^58`) so every limb ends
/// below `2^26 + 2^10`, narrowed back to a four-lane accumulator.
#[inline(always)]
fn carry(d: [Prod; 5]) -> Acc {
    let [d0, d1, d2, d3, d4] = d;
    let mask = u64x2_splat(M26);
    let mask32 = u32x4_splat(M26 as u32);
    let and = |x: Prod| Prod {
        lo: v128_and(x.lo, mask),
        hi: v128_and(x.hi, mask),
    };
    // `x + (y >> 26)`.
    let sra = |x: Prod, y: Prod| Prod {
        lo: i64x2_add(x.lo, u64x2_shr(y.lo, 26)),
        hi: i64x2_add(x.hi, u64x2_shr(y.hi, 26)),
    };

    // Carry chain: d3 -> d4, then d4 -> (x5) d0, then d0 -> d1 -> d2 -> d3
    // -> d4. Folding the wrapped carry into d0 before d0 is carried out means
    // every limb receives exactly one carry-in, so only the two limbs that
    // receive a carry after being masked (h3, h4) need a 64-bit mask; the
    // others are masked once, as 32-bit lanes after narrowing. Bounds: every
    // d is below 2^58 and every carry below 2^32 + 1 (5x: 2^35), so no 64-bit
    // sum overflows; on exit h0..h3 are exact 26-bit limbs and h4 < 2^26 +
    // 2^7.
    let d4 = sra(d4, d3);
    let h3 = and(d3);
    let h4 = and(d4);
    // d0 += 5 * (d4 >> 26), as the carry plus the carry shifted left by 2.
    let wrap = |x: v128, y: v128| {
        let c = u64x2_shr(y, 26);
        i64x2_add(i64x2_add(x, c), i64x2_shl(c, 2))
    };
    let d0 = Prod {
        lo: wrap(d0.lo, d4.lo),
        hi: wrap(d0.hi, d4.hi),
    };
    let d1 = sra(d1, d0);
    let d2 = sra(d2, d1);
    let h3 = sra(h3, d2);
    let h4 = sra(h4, h3);

    Acc([
        v128_and(narrow(d0), mask32),
        v128_and(narrow(d1), mask32),
        v128_and(narrow(d2), mask32),
        v128_and(narrow(h3), mask32),
        narrow(h4),
    ])
}

/// `acc * m mod p` lane-wise, partially carried.
#[inline(always)]
fn mul_reduce(acc: Acc, m: &Mult) -> Acc {
    carry(products(acc, m))
}

/// The key powers `[r^4, r^3, r^2, r]` (lane 0 first), partially reduced,
/// from the 5x26-bit limbs of `r`, with two lane-wise multiplies.
#[inline(always)]
fn seed_powers(r: &[u32; 5]) -> Acc {
    // `[r^2, r^2, r^2, r] = [r, r, r, r] * [r, r, r, 1]`.
    let one = [1, 0, 0, 0, 0];
    let mut m = [u32x4_splat(0); 5];
    for ((word, &limb), &one) in m.iter_mut().zip(r).zip(&one) {
        *word = u32x4(limb, limb, limb, one);
    }
    let x = mul_reduce(Acc::splat(r), &Mult::from_lanes(&Acc(m)));
    // `[r^4, r^3, r^2, r] = x * [r^2, r, 1, 1]`, taking `r^2` from lane 0 and
    // `r` from lane 3 of `x`.
    for ((word, &limb), &one) in m.iter_mut().zip(&x.0).zip(&one) {
        *word = i32x4_shuffle::<0, 3, 4, 4>(limb, u32x4_splat(one));
    }
    mul_reduce(x, &Mult::from_lanes(&Acc(m)))
}

/// Sum of the four lanes of `x` (each below `2^30`), widened.
#[inline(always)]
fn lane_sum(x: v128) -> u64 {
    u64::from(u32x4_extract_lane::<0>(x))
        + u64::from(u32x4_extract_lane::<1>(x))
        + u64::from(u32x4_extract_lane::<2>(x))
        + u64::from(u32x4_extract_lane::<3>(x))
}

/// Processes `input` (a non-empty multiple of `CHUNK` bytes) into `h` using
/// the clamped key limbs `r`.
///
/// `h` is the scalar backend's partially reduced 3x44-bit state on entry and
/// exit.
pub(super) fn blocks(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
    debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK));

    // Key powers: `low = [r^4, r^3, r^2, r]` and `high = low * r^4 = [r^8,
    // r^7, r^6, r^5]` are exactly the per-lane powers of the final chunk,
    // with `r^BLOCKS` in lane 0 of `high` for the hot loop. The clamped `r`
    // is below `p`, so its limbs split directly.
    let low = seed_powers(&limbs26(*r));
    let high = mul_reduce(low, &Mult::from_lane::<0>(&low));
    let top = Mult::from_lane::<0>(&high);

    // Convert h into 5x26 limbs in lane 0 of chain A (block 0 of each chunk).
    let start = limbs26(canonical(h));
    let zero = u32x4_splat(0);
    let mut a = Acc([zero; 5]);
    for (lane, &limb) in a.0.iter_mut().zip(&start) {
        *lane = u32x4(limb, 0, 0, 0);
    }
    let mut b = Acc([zero; 5]);

    let (chunks, _) = input.as_chunks::<CHUNK>();
    let (last, body) = chunks.split_last().unwrap();
    for chunk in body {
        let (half, _) = chunk.as_chunks::<64>();
        a = mul_reduce(add_blocks(a, &half[0]), &top);
        b = mul_reduce(add_blocks(b, &half[1]), &top);
    }

    // Final chunk: block `i` gets `r^(BLOCKS - i)` so the lane sum is the
    // exact sequential Horner value.
    let (half, _) = last.as_chunks::<64>();
    a = mul_reduce(add_blocks(a, &half[0]), &Mult::from_lanes(&high));
    b = mul_reduce(add_blocks(b, &half[1]), &Mult::from_lanes(&low));

    // Sum the eight lanes (each limb below 2^26 + 2^7, so every sum is below
    // 2^30) and convert back to the scalar backend's 3x44-bit form.
    let mut l = [0u64; 5];
    for ((limb, &a), &b) in l.iter_mut().zip(&a.0).zip(&b.0) {
        *limb = lane_sum(i32x4_add(a, b));
    }
    *h = carry44(pack_limbs26(l));
}
