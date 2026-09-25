//! AArch64 bulk path for Poly1305: NEON lanes plus scalar lanes.
//!
//! The scalar backend keeps `h` in three 44-bit limbs. This module processes
//! ten 16-byte blocks (`CHUNK` = 160 bytes) per iteration as ten independent
//! Horner lanes, each multiplied by `r^10` per iteration:
//!
//! * blocks `0..8` in NEON, using the 5x26-bit representation as two chains of
//!   four lanes (chain `A` holds blocks `0..4`, chain `B` blocks `4..8`, with
//!   limb `k` of the four blocks in one `uint32x4_t`);
//! * blocks `8..10` in two scalar 3x44-bit lanes, using the same limb
//!   multiplication as the scalar backend.
//!
//! The final iteration uses `r^10, r^9, ..., r` (one power per block) so
//! that summing the ten lanes yields exactly the sequential Horner value.
//!
//! Why both: the NEON part is bound by vector issue bandwidth. Per 128 bytes
//! it needs 100 widening multiplies, which only two of the four vector pipes
//! execute, plus ~100 carry, shift and permute operations, and the core
//! sustains roughly three of these per cycle in any mix. The integer
//! multipliers and ALUs sit idle meanwhile, so the scalar lanes ride along
//! on them at a fraction of the cost of a NEON block. More scalar lanes
//! spill integer registers and lengthen the scalar remainder of mid-sized
//! messages; two was the measured sweet spot.
//!
//! NEON register budget: the products of a 5x5 limb multiplication need ten
//! `uint64x2_t` per chain (low and high lane pairs of five limbs). Packing the
//! nine multiplier words (`r^10` limbs and `5 * r^10` limbs) into three
//! `uint32x4_t` and using by-element multiplies (`umull v, v, v.s[lane]`)
//! keeps the hot loop at 10 accumulator + 10 product + 3 multiplier registers
//! plus temporaries. The final chunk needs distinct powers per lane and uses
//! plain vector multiplies with nine multiplier registers per chain; it runs
//! once per call.
//!
//! Every iteration performs the same instructions regardless of data, so
//! there are no secret-dependent branches or memory accesses. The only
//! branches depend on the input length.

use core::arch::aarch64::*;

use zeroize::Zeroize;

use super::{M26, M42, M44, canonical, carry44, limbs26, mul_mod_p, pack_limbs26};
use crate::aarch64::Neon;

/// Blocks handled by the two four-lane NEON chains per iteration.
const NEON_BLOCKS: usize = 8;
/// Blocks handled by scalar lanes per iteration.
const SCALAR_LANES: usize = 2;
/// Blocks per iteration; also the highest key power needed. `powers!`
/// spells out the addition chain for this value.
const BLOCKS: usize = NEON_BLOCKS + SCALAR_LANES;
const _: () = assert!(BLOCKS == 10);
/// Bytes per iteration. `blocks` takes a non-empty multiple of this.
pub(super) const CHUNK: usize = 16 * BLOCKS;

/// Key powers the scalar lanes need, as partially reduced 44/44/42-bit limbs
/// (the form `mul_mod_p` produces).
#[derive(Clone, Copy)]
struct Powers {
    /// `r`, `r^2` (final chunk of the scalar lanes) and `r^BLOCKS` (hot loop).
    r1: [u64; 3],
    r2: [u64; 3],
    top: [u64; 3],
}

impl Zeroize for Powers {
    fn zeroize(&mut self) {
        self.r1.zeroize();
        self.r2.zeroize();
        self.top.zeroize();
    }
}

/// Computes the scalar [`Powers`] from the clamped 3x44-bit key limbs `$r:
/// &[u64; 3]`, plus the vector `[r^4, r^3, r^2, r]` (lane 0 first) in
/// 5x26-bit limbs that seeds the NEON power vectors, as `(Powers, Acc)`.
///
/// A macro so it expands inside [`blocks`]; see there.
macro_rules! powers {
    ($r:expr) => {{
        let r: &[u64; 3] = $r;
        let r2 = mul_mod_p(r, r);
        let mut r3 = mul_mod_p(&r2, r);
        let mut r4 = mul_mod_p(&r2, &r2);
        let mut r8 = mul_mod_p(&r4, &r4);
        let top = mul_mod_p(&r8, &r2);
        const _: () = assert!(BLOCKS == 10);

        // Spelled out: `array::map` with a closure is not inlined here, and
        // at opt-level `s` a loop over the limb index is not unrolled, which
        // keeps the limb arrays in stack memory nothing wipes.
        let l4 = limbs26(canonical(&r4));
        let l3 = limbs26(canonical(&r3));
        let l2 = limbs26(canonical(&r2));
        let l1 = limbs26(canonical(r));
        let seed = Acc([
            quad([l4[0], l3[0], l2[0], l1[0]]),
            quad([l4[1], l3[1], l2[1], l1[1]]),
            quad([l4[2], l3[2], l2[2], l1[2]]),
            quad([l4[3], l3[3], l2[3], l1[3]]),
            quad([l4[4], l3[4], l2[4], l1[4]]),
        ]);
        r3.zeroize();
        r4.zeroize();
        r8.zeroize();

        (Powers { r1: *r, r2, top }, seed)
    }};
}

/// One Horner step of a scalar lane: `(h + m) * r mod p` in 3x44-bit limbs,
/// the same computation as the scalar backend's block loop.
#[inline(always)]
fn scalar_step(h: [u64; 3], block: &[u8; 16], r: &[u64; 3]) -> [u64; 3] {
    let t0 = u64::from_le_bytes(block[..8].try_into().unwrap());
    let t1 = u64::from_le_bytes(block[8..].try_into().unwrap());
    let h = [
        h[0] + (t0 & M44),
        h[1] + (((t0 >> 44) | (t1 << 20)) & M44),
        h[2] + ((t1 >> 24) & M42) + (1 << 40),
    ];
    mul_mod_p(&h, r)
}

/// Advances every scalar lane by its block of `chunk` (blocks `NEON_BLOCKS..`),
/// multiplying by `r`.
#[inline(always)]
fn scalar_chunk(lanes: &mut [[u64; 3]; SCALAR_LANES], chunk: &[u8; CHUNK], r: &[u64; 3]) {
    let (blocks, _) = chunk[16 * NEON_BLOCKS..].as_chunks::<16>();
    for (lane, block) in lanes.iter_mut().zip(blocks) {
        *lane = scalar_step(*lane, block, r);
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

#[inline]
#[target_feature(enable = "neon")]
fn pair(a: u32, b: u32) -> uint32x2_t {
    vcreate_u32(u64::from(a) | (u64::from(b) << 32))
}

#[inline]
#[target_feature(enable = "neon")]
fn quad(w: [u32; 4]) -> uint32x4_t {
    vcombine_u32(pair(w[0], w[1]), pair(w[2], w[3]))
}

/// One power's nine multiplier words packed for by-element multiplies: word
/// `W` lives in lane `W % 4` of register `W / 4`.
#[derive(Clone, Copy, Zeroize)]
struct LaneMult([uint32x4_t; 3]);

/// The [`LaneMult`] of the power held in lane `$lane` (a literal) of
/// `$powers: &Acc`. A macro so it expands inside [`blocks`]; see there.
macro_rules! lane_mult {
    ($powers:expr, $lane:literal) => {{
        let powers: &Acc = $powers;
        let [p0, p1, p2, p3, p4] = powers.0;
        let r = [
            vgetq_lane_u32::<$lane>(p0),
            vgetq_lane_u32::<$lane>(p1),
            vgetq_lane_u32::<$lane>(p2),
            vgetq_lane_u32::<$lane>(p3),
            vgetq_lane_u32::<$lane>(p4),
        ];
        LaneMult([
            quad([r[0], r[1], r[2], r[3]]),
            quad([r[4], r[1] * 5, r[2] * 5, r[3] * 5]),
            quad([r[4] * 5, 0, 0, 0]),
        ])
    }};
}

/// Per-lane multiplier: word `W` of the power for lane `l` in lane `l` of
/// register `W`.
#[derive(Clone, Copy)]
struct FullMult([uint32x4_t; 9]);

/// The [`FullMult`] of the four powers held in the lanes of `$powers:
/// &Acc`. A macro so it expands inside [`blocks`]; see there.
macro_rules! full_mult {
    ($powers:expr) => {{
        let powers: &Acc = $powers;
        let [r0, r1, r2, r3, r4] = powers.0;
        FullMult([
            r0,
            r1,
            r2,
            r3,
            r4,
            vmulq_n_u32(r1, 5),
            vmulq_n_u32(r2, 5),
            vmulq_n_u32(r3, 5),
            vmulq_n_u32(r4, 5),
        ])
    }};
}

/// Four-lane 5x26-bit accumulator: limb `k` of four consecutive blocks in
/// `0[k]`. Also used for four key powers, one per lane.
#[derive(Clone, Copy, Zeroize)]
struct Acc([uint32x4_t; 5]);

/// 64-bit products of one output limb: lanes 0, 1 in `lo`, lanes 2, 3 in
/// `hi`.
#[derive(Clone, Copy)]
struct Prod {
    lo: uint64x2_t,
    hi: uint64x2_t,
}

#[inline]
#[target_feature(enable = "neon")]
fn mull_lane<const W: usize>(a: uint32x4_t, m: &LaneMult) -> Prod {
    let m = m.0[W / 4];
    let al = vget_low_u32(a);
    match W % 4 {
        0 => Prod {
            lo: vmull_laneq_u32::<0>(al, m),
            hi: vmull_high_laneq_u32::<0>(a, m),
        },
        1 => Prod {
            lo: vmull_laneq_u32::<1>(al, m),
            hi: vmull_high_laneq_u32::<1>(a, m),
        },
        2 => Prod {
            lo: vmull_laneq_u32::<2>(al, m),
            hi: vmull_high_laneq_u32::<2>(a, m),
        },
        _ => Prod {
            lo: vmull_laneq_u32::<3>(al, m),
            hi: vmull_high_laneq_u32::<3>(a, m),
        },
    }
}

#[inline]
#[target_feature(enable = "neon")]
fn mlal_lane<const W: usize>(d: Prod, a: uint32x4_t, m: &LaneMult) -> Prod {
    let m = m.0[W / 4];
    let al = vget_low_u32(a);
    match W % 4 {
        0 => Prod {
            lo: vmlal_laneq_u32::<0>(d.lo, al, m),
            hi: vmlal_high_laneq_u32::<0>(d.hi, a, m),
        },
        1 => Prod {
            lo: vmlal_laneq_u32::<1>(d.lo, al, m),
            hi: vmlal_high_laneq_u32::<1>(d.hi, a, m),
        },
        2 => Prod {
            lo: vmlal_laneq_u32::<2>(d.lo, al, m),
            hi: vmlal_high_laneq_u32::<2>(d.hi, a, m),
        },
        _ => Prod {
            lo: vmlal_laneq_u32::<3>(d.lo, al, m),
            hi: vmlal_high_laneq_u32::<3>(d.hi, a, m),
        },
    }
}

#[inline]
#[target_feature(enable = "neon")]
fn mull_full<const W: usize>(a: uint32x4_t, m: &FullMult) -> Prod {
    let m = m.0[W];
    Prod {
        lo: vmull_u32(vget_low_u32(a), vget_low_u32(m)),
        hi: vmull_high_u32(a, m),
    }
}

#[inline]
#[target_feature(enable = "neon")]
fn mlal_full<const W: usize>(d: Prod, a: uint32x4_t, m: &FullMult) -> Prod {
    let m = m.0[W];
    Prod {
        lo: vmlal_u32(d.lo, vget_low_u32(a), vget_low_u32(m)),
        hi: vmlal_high_u32(d.hi, a, m),
    }
}

/// The 25 lane-wise limb products of `acc * m mod p` before carrying, with
/// `$mull::<W>(a, m)` / `$mlal::<W>(d, a, m)` selecting the multiplier word.
///
/// Input bound: `acc` limbs below `2^27 + 2^10` (a reduced state plus one
/// message block), so each product sum is below `2^58`.
macro_rules! products {
    ($acc:expr, $m:expr, $mull:ident, $mlal:ident) => {{
        let [a0, a1, a2, a3, a4] = $acc.0;
        let m = $m;

        let mut d0 = $mull::<R0>(a0, m);
        d0 = $mlal::<S4>(d0, a1, m);
        d0 = $mlal::<S3>(d0, a2, m);
        d0 = $mlal::<S2>(d0, a3, m);
        d0 = $mlal::<S1>(d0, a4, m);

        let mut d1 = $mull::<R1>(a0, m);
        d1 = $mlal::<R0>(d1, a1, m);
        d1 = $mlal::<S4>(d1, a2, m);
        d1 = $mlal::<S3>(d1, a3, m);
        d1 = $mlal::<S2>(d1, a4, m);

        let mut d2 = $mull::<R2>(a0, m);
        d2 = $mlal::<R1>(d2, a1, m);
        d2 = $mlal::<R0>(d2, a2, m);
        d2 = $mlal::<S4>(d2, a3, m);
        d2 = $mlal::<S3>(d2, a4, m);

        let mut d3 = $mull::<R3>(a0, m);
        d3 = $mlal::<R2>(d3, a1, m);
        d3 = $mlal::<R1>(d3, a2, m);
        d3 = $mlal::<R0>(d3, a3, m);
        d3 = $mlal::<S4>(d3, a4, m);

        let mut d4 = $mull::<R4>(a0, m);
        d4 = $mlal::<R3>(d4, a1, m);
        d4 = $mlal::<R2>(d4, a2, m);
        d4 = $mlal::<R1>(d4, a3, m);
        d4 = $mlal::<R0>(d4, a4, m);

        [d0, d1, d2, d3, d4]
    }};
}

/// The 32-bit words of four consecutive 16-byte blocks: word `i` of block
/// `j` in lane `j` of element `i`. Message bytes only, so this may stay a
/// function; kept separate so LLVM sees the loads on their own and merges
/// them into one de-interleaving `ld4`.
#[inline]
#[target_feature(enable = "neon")]
fn block_words(blocks: &[u8; 64]) -> [uint32x4_t; 4] {
    // `lo[j]`/`hi[j]` are the low/high 64-bit halves of block `j`.
    let word = |b: &[u8]| vcreate_u64(u64::from_le_bytes(b.try_into().unwrap()));
    let (b, _) = blocks.as_chunks::<16>();
    let lo01 = vreinterpretq_u32_u64(vcombine_u64(word(&b[0][..8]), word(&b[1][..8])));
    let hi01 = vreinterpretq_u32_u64(vcombine_u64(word(&b[0][8..]), word(&b[1][8..])));
    let lo23 = vreinterpretq_u32_u64(vcombine_u64(word(&b[2][..8]), word(&b[3][..8])));
    let hi23 = vreinterpretq_u32_u64(vcombine_u64(word(&b[2][8..]), word(&b[3][8..])));

    // De-interleave so `w[i]` holds 32-bit word `i` of each block.
    [
        vuzp1q_u32(lo01, lo23),
        vuzp2q_u32(lo01, lo23),
        vuzp1q_u32(hi01, hi23),
        vuzp2q_u32(hi01, hi23),
    ]
}

/// Loads the four consecutive 16-byte blocks `$blocks: &[u8; 64]` into
/// 5x26-bit limbs (with the 2^128 high bit set) and adds them lane-wise to
/// `$acc: Acc`. A macro so it expands inside [`hot_loop`] and [`blocks`]; see
/// [`blocks`].
macro_rules! add_blocks {
    ($acc:expr, $blocks:expr) => {{
        let acc: Acc = $acc;
        let [w0, w1, w2, w3] = block_words($blocks);

        let hibit = vdupq_n_u32(1 << 24);

        // Limb k of a block is bits 26k..26k+26, i.e. the top `32 - a` bits
        // of word `w_i` and the low `a - 6` bits of `w_{i+1}`. Each limb is
        // accumulated as `(w_i >> a) + ((w_{i+1} << (38 - a)) >> 6)` with
        // `vsraq_n::<N>(x, y) = x + (y >> N)`, which needs no mask
        // registers: the left shift drops the bits that belong to the next
        // limb.
        let [a0, a1, a2, a3, a4] = acc.0;
        let a0 = vsraq_n_u32::<6>(a0, vshlq_n_u32::<6>(w0));
        let a1 = vsraq_n_u32::<26>(a1, w0);
        let a1 = vsraq_n_u32::<6>(a1, vshlq_n_u32::<12>(w1));
        let a2 = vsraq_n_u32::<20>(a2, w1);
        let a2 = vsraq_n_u32::<6>(a2, vshlq_n_u32::<18>(w2));
        let a3 = vsraq_n_u32::<14>(a3, w2);
        let a3 = vsraq_n_u32::<6>(a3, vshlq_n_u32::<24>(w3));
        let a4 = vsraq_n_u32::<8>(vaddq_u32(a4, hibit), w3);
        Acc([a0, a1, a2, a3, a4])
    }};
}

#[inline]
#[target_feature(enable = "neon")]
fn sra<const N: i32>(x: Prod, y: Prod) -> Prod {
    Prod {
        lo: vsraq_n_u64::<N>(x.lo, y.lo),
        hi: vsraq_n_u64::<N>(x.hi, y.hi),
    }
}

/// Low 32 bits of each 64-bit lane, as a four-lane vector.
#[inline]
#[target_feature(enable = "neon")]
fn narrow(x: Prod) -> uint32x4_t {
    vuzp1q_u32(vreinterpretq_u32_u64(x.lo), vreinterpretq_u32_u64(x.hi))
}

/// `x & mask` on both halves.
#[inline]
#[target_feature(enable = "neon")]
fn and(x: Prod, mask: uint64x2_t) -> Prod {
    Prod {
        lo: vandq_u64(x.lo, mask),
        hi: vandq_u64(x.hi, mask),
    }
}

/// `x & !mask` on both halves.
#[inline]
#[target_feature(enable = "neon")]
fn bic(x: Prod, mask: uint64x2_t) -> Prod {
    Prod {
        lo: vbicq_u64(x.lo, mask),
        hi: vbicq_u64(x.hi, mask),
    }
}

/// Partial carry of the limb products `$d: [Prod; 5]` (each below `2^58`) so
/// every limb ends below `2^26 + 2^10`, narrowed back to a four-lane
/// accumulator. A macro so it expands inside [`hot_loop`] and [`blocks`]; see
/// [`blocks`].
macro_rules! carry {
    ($d:expr) => {{
        let [d0, d1, d2, d3, d4]: [Prod; 5] = $d;
        let mask = vdupq_n_u64(M26);
        let mask32 = vdupq_n_u32(M26 as u32);

        // Carry chain (`vsraq_n::<26>(x, y)` is `x + (y >> 26)`):
        //   d3 -> d4, then d4 -> (x5) d0, then d0 -> d1 -> d2 -> d3 -> d4.
        // Folding the wrapped carry into d0 before d0 is carried out means
        // every limb receives exactly one carry-in, so only the two limbs
        // that receive a carry after being masked (h3, h4) need a 64-bit
        // mask; the others are masked once, as 32-bit lanes after narrowing.
        // Bounds: every d is below 2^58 and every carry below 2^32 + 1, so no
        // 64-bit sum overflows; on exit h0..h3 are exact 26-bit limbs and h4
        // < 2^26 + 2^7. The chain is six shift-accumulates deep, which the
        // other chain and the scalar lanes hide.
        let d4 = sra::<26>(d4, d3);
        let h3 = and(d3, mask);
        let h4 = and(d4, mask);
        // d0 += 5 * (d4 >> 26): the carry plus four times the carry, the
        // latter as the masked-off high part of d4 shifted right by 24.
        let d0 = sra::<26>(d0, d4);
        let d0 = sra::<24>(d0, bic(d4, mask));
        let d1 = sra::<26>(d1, d0);
        let d2 = sra::<26>(d2, d1);
        let h3 = sra::<26>(h3, d2);
        let h4 = sra::<26>(h4, h3);

        Acc([
            vandq_u32(narrow(d0), mask32),
            vandq_u32(narrow(d1), mask32),
            vandq_u32(narrow(d2), mask32),
            vandq_u32(narrow(h3), mask32),
            narrow(h4),
        ])
    }};
}

/// Hot loop: every lane is multiplied by `r^BLOCKS` per chunk.
///
/// Kept out of line so the NEON multiplier reaches the loop through memory:
/// when LLVM can see how the multiplier vectors were assembled it splits them
/// into 64-bit halves for the by-element multiplies, doubling their register
/// footprint and spilling accumulators.
#[inline(never)]
#[target_feature(enable = "neon")]
fn hot_loop(
    a: &mut Acc,
    b: &mut Acc,
    lanes: &mut [[u64; 3]; SCALAR_LANES],
    m: &LaneMult,
    r: &[u64; 3],
    body: &[[u8; CHUNK]],
) {
    let Some((first, rest)) = body.split_first() else {
        return;
    };
    // Chain B runs half an iteration behind chain A: its products are
    // carried at the start of the next iteration, so the multiplies of one
    // chain are always independent of the carry chain of the other and the
    // out-of-order core overlaps them instead of alternating between a burst
    // of multiplies and a latency-bound carry chain.
    let (half, _) = first.as_chunks::<64>();
    let mut acc_a = carry!(products!(
        add_blocks!(*a, &half[0]),
        m,
        mull_lane,
        mlal_lane
    ));
    let mut db = products!(add_blocks!(*b, &half[1]), m, mull_lane, mlal_lane);
    scalar_chunk(lanes, first, r);
    for chunk in rest {
        let (half, _) = chunk.as_chunks::<64>();
        let acc_b = add_blocks!(carry!(db), &half[1]);
        let da = products!(add_blocks!(acc_a, &half[0]), m, mull_lane, mlal_lane);
        db = products!(acc_b, m, mull_lane, mlal_lane);
        acc_a = carry!(da);
        scalar_chunk(lanes, chunk, r);
    }
    *a = acc_a;
    *b = carry!(db);
}

/// Processes `input` (a non-empty multiple of `CHUNK` bytes) into `h` using
/// the clamped key limbs `r`.
///
/// `h` is the scalar backend's partially reduced 3x44-bit state on entry and
/// exit. Other than the `zeroize` calls (out of line at opt-level `z` and
/// `s`, where they only get `&mut` to the storage they wipe), the only
/// function this kernel hands key-derived storage to is the out-of-line
/// [`hot_loop`]; the working copies it reaches through memory (the scalar
/// key powers, the `r^BLOCKS` multiplier, both accumulators and the scalar
/// lanes) are wiped once before returning.
///
/// Every step on key-derived values is expanded here and in `hot_loop`:
/// `powers!`, `lane_mult!`, `full_mult!`, `add_blocks!`, `products!` and
/// `carry!` are macros, because a `#[target_feature]` function cannot be
/// `#[inline(always)]` and LLVM keeps the larger ones out of line, handing
/// them their `Acc`/`Prod` arguments and results through stack temporaries.
/// The remaining `#[inline]` helpers on key-derived values (`pair`, `quad`,
/// `sra`, `and`, `bic`, `narrow` and the `mull_*`/`mlal_*` multiplies) each
/// wrap one or two intrinsics and inline like the intrinsics themselves, and
/// the limb helpers are `#[inline(always)]`. [`block_words`] sees message
/// bytes only and may stay out of line. The other key-derived values
/// (`seed`, `low`, `high`, `tail_a`/`tail_b`, `start`, `l`) therefore live
/// only in registers and compiler spill slots, which are out of Rust's reach
/// and are not wiped, since wiping them would force them into memory.
#[target_feature(enable = "neon")]
fn blocks_unchecked(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
    debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK));

    // Key powers: the scalar lanes get 3x44-bit values; the NEON lanes get
    // `[r^4, r^3, r^2, r]`, from which two lane-wise multiplies produce
    // `low = [r^6, r^5, r^4, r^3]` and `high = [r^10, r^9, r^8, r^7]`, i.e.
    // exactly the per-lane powers of the final chunk, with `r^BLOCKS` in
    // lane 0 of `high` for the hot loop. This costs two vector multiplies
    // instead of six scalar ones plus eight limb conversions.
    let (mut powers, seed) = powers!(r);
    let low = carry!(products!(seed, &lane_mult!(&seed, 2), mull_lane, mlal_lane));
    let high = carry!(products!(low, &lane_mult!(&seed, 0), mull_lane, mlal_lane));
    let mut top = lane_mult!(&high, 0);

    // Convert h into 5x26 limbs in lane 0 of chain A (block 0 of each chunk).
    // Spelled out like the seed in `powers!` so `start` stays in registers.
    let start = limbs26(canonical(h));
    let mut a = Acc([
        quad([start[0], 0, 0, 0]),
        quad([start[1], 0, 0, 0]),
        quad([start[2], 0, 0, 0]),
        quad([start[3], 0, 0, 0]),
        quad([start[4], 0, 0, 0]),
    ]);
    let mut b = Acc([vdupq_n_u32(0); 5]);
    let mut lanes = [[0u64; 3]; SCALAR_LANES];

    let (chunks, _) = input.as_chunks::<CHUNK>();
    let (last, body) = chunks.split_last().unwrap();

    hot_loop(&mut a, &mut b, &mut lanes, &top, &powers.top, body);

    // Final chunk: block `i` gets `r^(BLOCKS - i)` so the lane sum is the
    // exact sequential Horner value.
    let tail_a = full_mult!(&high);
    let tail_b = full_mult!(&low);
    let (half, _) = last.as_chunks::<64>();
    a = carry!(products!(
        add_blocks!(a, &half[0]),
        &tail_a,
        mull_full,
        mlal_full
    ));
    b = carry!(products!(
        add_blocks!(b, &half[1]),
        &tail_b,
        mull_full,
        mlal_full
    ));
    let (tail_blocks, _) = last[16 * NEON_BLOCKS..].as_chunks::<16>();
    lanes[0] = scalar_step(lanes[0], &tail_blocks[0], &powers.r2);
    lanes[1] = scalar_step(lanes[1], &tail_blocks[1], &powers.r1);
    powers.zeroize();

    // Sum the eight NEON lanes and convert back to 3x44-bit limbs (spelled
    // out for the same reason).
    let [a0, a1, a2, a3, a4] = a.0;
    let [b0, b1, b2, b3, b4] = b.0;
    let l = [
        vaddlvq_u32(vaddq_u32(a0, b0)),
        vaddlvq_u32(vaddq_u32(a1, b1)),
        vaddlvq_u32(vaddq_u32(a2, b2)),
        vaddlvq_u32(vaddq_u32(a3, b3)),
        vaddlvq_u32(vaddq_u32(a4, b4)),
    ];
    let [mut h0, mut h1, mut h2] = pack_limbs26(l);

    // Add the scalar lanes (each partially reduced: limbs below 2^44, 2^44 +
    // small, 2^42 + small) and carry once more so the result is in the same
    // partially reduced form the scalar backend produces.
    for lane in &lanes {
        h0 += lane[0];
        h1 += lane[1];
        h2 += lane[2];
    }
    *h = carry44([h0, h1, h2]);
    top.zeroize();
    a.zeroize();
    b.zeroize();
    lanes.zeroize();
}

/// [`blocks_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
pub(super) fn blocks(_: Neon, h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { blocks_unchecked(h, r, input) }
}
