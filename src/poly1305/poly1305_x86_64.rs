//! x86-64 bulk paths for Poly1305, chosen at runtime by [`full_blocks`]:
//! AVX2 or AVX-512F lanes in 5x26-bit limbs ([`blocks`], [`blocks_avx512`])
//! or AVX-512 IFMA lanes in 3x44-bit limbs ([`blocks_ifma`], [`blocks_ifma2`],
//! preferred when the CPU has `avx512ifma`).
//!
//! The scalar backend keeps `h` in three 44-bit limbs. Every kernel here
//! processes one chunk of consecutive 16-byte blocks per iteration as
//! independent Horner lanes (block `i` of the chunk in lane `i`, limb `k` of
//! all lanes in one vector), each multiplied by `r^N` per iteration for `N`
//! blocks per chunk. The final iteration uses `r^N, r^(N-1), ..., r` (one
//! power per block) so that summing the lanes yields exactly the sequential
//! Horner value.
//!
//! The 5x26-bit kernels are two instances of [`poly1305_26!`]: two chains of
//! `LANES` blocks each (chain `A` holds the first `LANES` blocks of each
//! chunk, chain `B` the rest), with four lanes per `__m256i` under AVX2 and
//! eight per `__m512i` under AVX-512F. Two chains because one chain's carry
//! propagation is a dependency chain of about twenty vector instructions per
//! iteration, while the 25 `vpmuludq` products and their sums are
//! independent; interleaving two chains keeps the multiply and ALU pipes
//! busy through both. A third chain would spill the 16 `ymm` registers (each
//! chain needs five accumulators and five product registers alongside the
//! nine multiplier words).
//!
//! The 3x44-bit IFMA kernels keep the scalar backend's limb split and
//! multiply with `vpmadd52luq`/`vpmadd52huq`: [`blocks_ifma`] runs one chain
//! of eight lanes, [`blocks_ifma2`] two chains for long runs.
//!
//! Every iteration performs the same instructions regardless of data, so
//! there are no secret-dependent branches or memory accesses. The only
//! branches depend on the input length and the detected CPU features.

use core::arch::x86_64::{
    __m256i, __m512i, _mm256_extract_epi64, _mm256_permute2x128_si256, _mm256_permute4x64_epi64,
    _mm256_unpackhi_epi64, _mm256_unpacklo_epi64, _mm512_add_epi64, _mm512_and_si512,
    _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64, _mm512_or_si512,
    _mm512_permutex2var_epi64, _mm512_permutexvar_epi64, _mm512_reduce_add_epi64,
    _mm512_set1_epi64, _mm512_setr_epi64, _mm512_setzero_si512, _mm512_slli_epi64,
    _mm512_srli_epi64,
};

use zeroize::Zeroize;

use super::{M42, M44, canonical, carry44, limbs26, mul_mod_p};
use crate::x86_64::{load, load512};

/// Minimum run of full blocks worth handing to the AVX2 path; below this the
/// eight key powers and limb conversions cost more than they save. Must be
/// at least one [`CHUNK`].
const AVX2_MIN_BYTES: usize = 512;

/// Minimum run of full blocks worth handing to the AVX-512 path, whose
/// sixteen key powers cost twice the AVX2 path's; below this the AVX2 path
/// is as fast or faster. Must be at least one [`CHUNK512`].
const AVX512_MIN_BYTES: usize = 2048;

/// Minimum run of full blocks worth handing to the AVX-512 IFMA path, whose
/// eight key powers come from three vector multiplies; measured to beat the
/// scalar loop from two 128-byte chunks (one chunk is a draw). Must be at
/// least one [`CHUNK_IFMA`].
const IFMA_MIN_BYTES: usize = 256;

/// Minimum run of full blocks worth handing to the two-chain AVX-512 IFMA
/// path, which needs one more vector multiply for its sixteen key powers;
/// measured crossover against the single chain. Must be at least one
/// [`CHUNK_IFMA2`].
const IFMA2_MIN_BYTES: usize = 1024;

/// Processes the longest kernel-eligible prefix of `input` (a whole number
/// of full blocks) into `h` with the clamped key limbs `r`, using the best
/// kernel the CPU supports: the two-chain IFMA kernel with the single chain
/// taking its remainder, else AVX-512F, else AVX2. Returns the number of
/// leading bytes processed; 0 when no kernel applies or the run is shorter
/// than the kernel's threshold, in which case `h` is untouched.
#[inline]
pub(super) fn full_blocks(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) -> usize {
    if input.len() >= IFMA_MIN_BYTES
        && crate::x86_64::has_avx512f()
        && has_x86_feature!("avx512ifma")
    {
        let mut bulk = 0;
        if input.len() >= IFMA2_MIN_BYTES {
            bulk = input.len() - input.len() % CHUNK_IFMA2;
            // SAFETY: `blocks_ifma2` requires the `avx512f` and `avx512ifma`
            // target features: the checks above confirmed `avx512ifma`, and
            // `avx512f` together with the `avx2` that rustc's `avx512f`
            // implies.
            unsafe { blocks_ifma2(h, r, &input[..bulk]) };
        }
        // The single chain takes what is left over from the two-chain run
        // when that is at least one of its chunks: recomputing its powers is
        // cheaper than eight scalar blocks.
        let rest = input.len() - bulk;
        if rest >= CHUNK_IFMA {
            let end = input.len() - rest % CHUNK_IFMA;
            // SAFETY: `blocks_ifma` requires the `avx512f` and `avx512ifma`
            // target features: the checks above confirmed `avx512ifma`, and
            // `avx512f` together with the `avx2` that rustc's `avx512f`
            // implies.
            unsafe { blocks_ifma(h, r, &input[bulk..end]) };
            bulk = end;
        }
        return bulk;
    }
    if input.len() >= AVX512_MIN_BYTES && crate::x86_64::has_avx512f() {
        let bulk = input.len() - input.len() % CHUNK512;
        // SAFETY: `blocks_avx512` requires the `avx512f` target feature,
        // which the check above confirmed together with the `avx2` that
        // rustc's `avx512f` implies.
        unsafe { blocks_avx512(h, r, &input[..bulk]) };
        return bulk;
    }
    if input.len() >= AVX2_MIN_BYTES && has_x86_feature!("avx2") {
        let bulk = input.len() - input.len() % CHUNK;
        // SAFETY: `blocks` requires the `avx2` target feature, which the
        // feature check above confirmed is present.
        unsafe { blocks(h, r, &input[..bulk]) };
        return bulk;
    }
    0
}

/// The canonical key powers `r^1 .. r^N` as 3x44-bit limbs, `powers[i] =
/// r^(i + 1)`.
///
/// `r^n` is `(r^(n/2))^2` when `n` is a power of two and otherwise `r^h *
/// r^(n - h)` for the largest power of two `h < n`, so the multiplications
/// form a tree of depth `log2(N) + 1` instead of a chain of `N - 1`
/// dependent products; the multiplications are short enough that their
/// latency, not their count, sets the cost of a bulk call.
#[inline(always)]
fn key_powers44<const N: usize>(r: &[u64; 3]) -> [[u64; 3]; N] {
    let mut powers = [[0u64; 3]; N];
    powers[0] = *r;
    for n in 2..=N {
        // `n` is a loop index, not secret, so branching on it is fine.
        let (a, b) = if n.is_power_of_two() {
            (n / 2, n / 2)
        } else {
            let high = 1 << n.ilog2();
            (high, n - high)
        };
        powers[n - 1] = mul_mod_p(&powers[a - 1], &powers[b - 1]);
    }
    for power in &mut powers {
        *power = canonical(power);
    }
    powers
}

/// [`key_powers44`] as 5x26-bit limbs, with the 3x44-bit intermediates
/// wiped.
#[inline(always)]
fn key_powers<const N: usize>(r: &[u64; 3]) -> [[u32; 5]; N] {
    let mut powers = key_powers44::<N>(r);
    let mut limbs = [[0u32; 5]; N];
    for (limb, power) in limbs.iter_mut().zip(&powers) {
        *limb = limbs26(*power);
    }
    powers.zeroize();
    limbs
}

/// Lane 0 of `word` in every lane.
#[inline]
#[target_feature(enable = "avx2")]
fn first_lane(word: __m256i) -> __m256i {
    _mm256_permute4x64_epi64::<0x00>(word)
}

/// Lane 0 of `word` in every lane.
#[inline]
#[target_feature(enable = "avx512f")]
fn first_lane512(word: __m512i) -> __m512i {
    _mm512_permutexvar_epi64(_mm512_setzero_si512(), word)
}

/// The first and second qwords of four consecutive 16-byte blocks,
/// `(t0, t1)`, block `i` in lane `i` of each.
#[inline]
#[target_feature(enable = "avx2")]
fn gather_qwords(blocks: &[u8; 64]) -> (__m256i, __m256i) {
    let (halves, _) = blocks.as_chunks::<32>();
    // `lo`/`hi` hold blocks 0,1 / 2,3 as `[t0, t1, t0, t1]`; regroup into
    // `t0 = [b0.t0, b1.t0, b2.t0, b3.t0]` and likewise `t1`.
    let lo = load(&halves[0]);
    let hi = load(&halves[1]);
    let even = _mm256_permute2x128_si256::<0x20>(lo, hi);
    let odd = _mm256_permute2x128_si256::<0x31>(lo, hi);
    (
        _mm256_unpacklo_epi64(even, odd),
        _mm256_unpackhi_epi64(even, odd),
    )
}

/// The first and second qwords of eight consecutive 16-byte blocks,
/// `(t0, t1)`, block `i` in lane `i` of each.
#[inline]
#[target_feature(enable = "avx512f")]
fn gather_qwords512(blocks: &[u8; 128]) -> (__m512i, __m512i) {
    let (halves, _) = blocks.as_chunks::<64>();
    // `lo`/`hi` hold blocks 0..4 / 4..8 as `[t0, t1, ...]`; gather the even
    // qwords into `t0` and the odd ones into `t1`.
    let lo = load512(&halves[0]);
    let hi = load512(&halves[1]);
    (
        _mm512_permutex2var_epi64(lo, _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14), hi),
        _mm512_permutex2var_epi64(lo, _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15), hi),
    )
}

/// Sums the four lanes of `v`.
#[inline]
#[target_feature(enable = "avx2")]
fn lane_sum(v: __m256i) -> u64 {
    (_mm256_extract_epi64::<0>(v) as u64)
        + (_mm256_extract_epi64::<1>(v) as u64)
        + (_mm256_extract_epi64::<2>(v) as u64)
        + (_mm256_extract_epi64::<3>(v) as u64)
}

/// Sums the eight lanes of `v`.
#[inline]
#[target_feature(enable = "avx512f")]
fn lane_sum512(v: __m512i) -> u64 {
    _mm512_reduce_add_epi64(v) as u64
}

/// Defines one two-chain 5x26-bit kernel as the module `$name`, exporting
/// `LANES`, `BLOCKS`, `CHUNK` and `blocks`.
///
/// - `$name`: the module; leading attributes (docs) are applied to it.
/// - `$feature`: the `#[target_feature(enable = ...)]` string.
/// - `$detected`: a `bool` expression, whether the CPU supports `$feature`
///   (tests only).
/// - `$lanes`: 64-bit lanes per vector, the blocks per chain per iteration.
/// - `$vec`: the vector type.
/// - `$set1`: `fn(i64) -> $vec`, the value in every lane.
/// - `$mul_epu32`, `$add_epi64`, `$and`, `$or`, `$srli_epi64`, `$slli_epi64`:
///   the lane-wise intrinsics of `$vec` (the shifts take the count as a const
///   generic).
/// - `$load_words`: `fn(&[u64; $lanes]) -> $vec`, word `i` in lane `i`.
/// - `$store_words`: its inverse (tests only).
/// - `$first_lane`: `fn($vec) -> $vec`, lane 0 in every lane.
/// - `$gather_qwords`: `fn(&[u8; 16 * $lanes]) -> ($vec, $vec)`, the first and
///   second qwords of `$lanes` blocks, block `i` in lane `i` of each.
/// - `$lane_sum`: `fn($vec) -> u64`, the sum of the lanes.
macro_rules! poly1305_26 {
    (
        $(#[$meta:meta])*
        mod $name:ident {
            feature: $feature:tt,
            detected: $detected:expr,
            lanes: $lanes:literal,
            vec: $vec:ident,
            set1: $set1:ident,
            mul_epu32: $mul_epu32:ident,
            add_epi64: $add_epi64:ident,
            and: $and:ident,
            or: $or:ident,
            srli_epi64: $srli_epi64:ident,
            slli_epi64: $slli_epi64:ident,
            load_words: $load_words:path,
            store_words: $store_words:path,
            first_lane: $first_lane:path,
            gather_qwords: $gather_qwords:path,
            lane_sum: $lane_sum:path,
        }
    ) => {
        $(#[$meta])*
        mod $name {
            use core::arch::x86_64::{
                $add_epi64, $and, $mul_epu32, $or, $set1, $slli_epi64, $srli_epi64, $vec,
            };

            use zeroize::Zeroize;

            use super::key_powers;
            use crate::poly1305::{M26, canonical, carry44, limbs26, pack_limbs26};

            /// Blocks per chain per iteration: the 64-bit lanes of a vector.
            pub(crate) const LANES: usize = $lanes;
            /// Bytes per chain per iteration.
            const LANE_BYTES: usize = 16 * LANES;
            /// Blocks per iteration; also the highest key power needed.
            pub(crate) const BLOCKS: usize = 2 * LANES;
            /// Bytes per iteration. `blocks` takes a non-empty multiple of
            /// this.
            pub(crate) const CHUNK: usize = 16 * BLOCKS;

            /// One chain's 5x26-bit accumulator: limb `k` of `LANES`
            /// consecutive blocks in the 64-bit lanes of `0[k]`. Limbs stay
            /// below `2^32` so `vpmuludq`, which multiplies the low 32 bits
            /// of each lane, sees them whole.
            #[derive(Clone, Copy, Zeroize)]
            struct Acc([$vec; 5]);

            /// Multiplier words for one `acc * m mod p`: `r[k]` holds limb
            /// `k` of the power, `s[k - 1]` holds `5 * ` limb `k` for `k >=
            /// 1`. Either the same power in every lane (hot loop) or one
            /// power per lane (final chunk).
            #[derive(Clone, Copy, Zeroize)]
            struct Mult {
                r: [$vec; 5],
                s: [$vec; 4],
            }

            impl Mult {
                /// The same power `p` (5x26-bit limbs) in every lane.
                #[inline]
                #[target_feature(enable = $feature)]
                fn broadcast(p: &[u32; 5]) -> Self {
                    Self::with_s([
                        $set1(i64::from(p[0])),
                        $set1(i64::from(p[1])),
                        $set1(i64::from(p[2])),
                        $set1(i64::from(p[3])),
                        $set1(i64::from(p[4])),
                    ])
                }

                /// The powers `p` (5x26-bit limbs, `p[i] = r^(i + 1)`) in
                /// descending order: `p[LANES - 1 - i]` in lane `i`, so lane
                /// 0 holds `r^LANES`.
                #[inline]
                #[target_feature(enable = $feature)]
                fn descending(p: &[[u32; 5]; LANES]) -> Self {
                    let mut r = [$set1(0); 5];
                    let mut lanes = [0u64; LANES];
                    for (k, word) in r.iter_mut().enumerate() {
                        for (lane, power) in lanes.iter_mut().zip(p.iter().rev()) {
                            *lane = u64::from(power[k]);
                        }
                        *word = $load_words(&lanes);
                    }
                    // The staging array held key material.
                    lanes.zeroize();
                    Self::with_s(r)
                }

                /// The per-lane powers held in `acc` (partially carried limbs).
                #[inline]
                #[target_feature(enable = $feature)]
                fn from_acc(acc: Acc) -> Self {
                    Self::with_s(acc.0)
                }

                /// Lane 0 of the powers held in `acc` in every lane.
                #[inline]
                #[target_feature(enable = $feature)]
                fn from_lane0(acc: Acc) -> Self {
                    let [w0, w1, w2, w3, w4] = acc.0;
                    Self::with_s([
                        $first_lane(w0),
                        $first_lane(w1),
                        $first_lane(w2),
                        $first_lane(w3),
                        $first_lane(w4),
                    ])
                }

                #[inline]
                #[target_feature(enable = $feature)]
                fn with_s(r: [$vec; 5]) -> Self {
                    let times5 = |x: $vec| $add_epi64(x, $slli_epi64::<2>(x));
                    Self {
                        r,
                        s: [times5(r[1]), times5(r[2]), times5(r[3]), times5(r[4])],
                    }
                }
            }

            /// Loads `LANES` consecutive 16-byte blocks into 5x26-bit limbs
            /// (with the `2^128` high bit set) and adds them lane-wise to
            /// `acc`.
            #[inline]
            #[target_feature(enable = $feature)]
            fn add_blocks(acc: Acc, blocks: &[u8; LANE_BYTES]) -> Acc {
                let (t0, t1) = $gather_qwords(blocks);

                let mask = $set1(M26 as i64);
                let hibit = $set1(1 << 24);
                let m = [
                    $and(t0, mask),
                    $and($srli_epi64::<26>(t0), mask),
                    $and($or($srli_epi64::<52>(t0), $slli_epi64::<12>(t1)), mask),
                    $and($srli_epi64::<14>(t1), mask),
                    $or($srli_epi64::<40>(t1), hibit),
                ];
                let mut out = acc;
                for (limb, m) in out.0.iter_mut().zip(m) {
                    *limb = $add_epi64(*limb, m);
                }
                out
            }

            /// `acc * m mod p`, partially carried so every limb ends below
            /// `2^26 + 2^10`.
            ///
            /// Input bound: `acc` limbs below `2^27 + 2^11` (a reduced state
            /// plus one message block), multiplier limbs below `2^26 + 2^10`
            /// (`r`, a canonical or partially carried power) and `5 *` that
            /// (`s`), so each of the five product sums is below `2^59`.
            #[inline]
            #[target_feature(enable = $feature)]
            fn mul_reduce(acc: Acc, m: &Mult) -> Acc {
                let [h0, h1, h2, h3, h4] = acc.0;
                let Mult { r, s } = m;
                let mul = $mul_epu32;
                let add = $add_epi64;

                let d0 = add(
                    add(
                        add(mul(h0, r[0]), mul(h1, s[3])),
                        add(mul(h2, s[2]), mul(h3, s[1])),
                    ),
                    mul(h4, s[0]),
                );
                let d1 = add(
                    add(
                        add(mul(h0, r[1]), mul(h1, r[0])),
                        add(mul(h2, s[3]), mul(h3, s[2])),
                    ),
                    mul(h4, s[1]),
                );
                let d2 = add(
                    add(
                        add(mul(h0, r[2]), mul(h1, r[1])),
                        add(mul(h2, r[0]), mul(h3, s[3])),
                    ),
                    mul(h4, s[2]),
                );
                let d3 = add(
                    add(
                        add(mul(h0, r[3]), mul(h1, r[2])),
                        add(mul(h2, r[1]), mul(h3, r[0])),
                    ),
                    mul(h4, s[3]),
                );
                let d4 = add(
                    add(
                        add(mul(h0, r[4]), mul(h1, r[3])),
                        add(mul(h2, r[2]), mul(h3, r[1])),
                    ),
                    mul(h4, r[0]),
                );

                let mask = $set1(M26 as i64);
                let mut c = $srli_epi64::<26>(d0);
                let mut h0 = $and(d0, mask);
                let d1 = add(d1, c);
                c = $srli_epi64::<26>(d1);
                let mut h1 = $and(d1, mask);
                let d2 = add(d2, c);
                c = $srli_epi64::<26>(d2);
                let h2 = $and(d2, mask);
                let d3 = add(d3, c);
                c = $srli_epi64::<26>(d3);
                let h3 = $and(d3, mask);
                let d4 = add(d4, c);
                c = $srli_epi64::<26>(d4);
                let h4 = $and(d4, mask);
                h0 = add(h0, add(c, $slli_epi64::<2>(c)));
                c = $srli_epi64::<26>(h0);
                h0 = $and(h0, mask);
                h1 = add(h1, c);
                Acc([h0, h1, h2, h3, h4])
            }

            /// Hot loop: every lane is multiplied by `r^BLOCKS` per chunk.
            /// Kept out of line so its schedule does not change with the
            /// inlining context.
            #[inline(never)]
            #[target_feature(enable = $feature)]
            fn hot_loop(a: &mut Acc, b: &mut Acc, m: &Mult, body: &[[u8; CHUNK]]) {
                for chunk in body {
                    let (half, _) = chunk.as_chunks::<LANE_BYTES>();
                    *a = mul_reduce(add_blocks(*a, &half[0]), m);
                    *b = mul_reduce(add_blocks(*b, &half[1]), m);
                }
            }

            /// Processes `input` (a non-empty multiple of `CHUNK` bytes) into
            /// `h` using the clamped key limbs `r`.
            ///
            /// `h` is the scalar backend's partially reduced 3x44-bit state
            /// on entry and exit. The staging arrays, the `r^BLOCKS`
            /// multiplier and both accumulators (which the out-of-line
            /// `hot_loop` reaches through memory) are wiped once before
            /// returning; values that live only in registers and compiler
            /// spill slots are out of Rust's reach and are not wiped, since
            /// wiping them would force them into memory.
            ///
            /// Opt-level assumption: the limb helpers and `key_powers` are
            /// `#[inline(always)]` and the multipliers and lane sums are
            /// built without closures or index loops, so at opt-level 2, 3
            /// and `s` nothing but `hot_loop` is out of line and the other
            /// key-derived values (`low`, `high`, `tail_a`/`tail_b`, `l`)
            /// stay in registers and spill slots. At opt-level `z` LLVM
            /// also outlines the `#[target_feature]` helpers `add_blocks`
            /// and `mul_reduce`, which stable Rust cannot mark
            /// `#[inline(always)]`; their by-value `Acc` arguments and
            /// results (`low`, `high`, the accumulators, also in
            /// `hot_loop`) then pass through stack temporaries that are not
            /// wiped.
            #[target_feature(enable = $feature)]
            pub(crate) fn blocks(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
                debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK));

                // Key powers: `[r^LANES, .., r]` from the scalar powers
                // r^1..r^LANES, then one lane-wise multiply by `r^LANES`
                // gives `[r^BLOCKS, .., r^(LANES + 1)]`, whose lane 0 is the
                // hot loop's `r^BLOCKS`. This costs one vector multiply
                // instead of `LANES` scalar ones plus `LANES` limb
                // conversions.
                let mut limbs = key_powers::<LANES>(r);
                let low = Acc(Mult::descending(&limbs).r);
                let high = mul_reduce(low, &Mult::broadcast(&limbs[LANES - 1]));
                limbs.zeroize();
                let mut top = Mult::from_lane0(high);
                let tail_a = Mult::from_acc(high);
                let tail_b = Mult::from_acc(low);

                // Convert h into 5x26 limbs in lane 0 of chain A (block 0 of
                // each chunk).
                let mut start = limbs26(canonical(h));
                let mut lanes = [0u64; LANES];
                let mut a = Acc([$set1(0); 5]);
                for (word, &limb) in a.0.iter_mut().zip(&start) {
                    lanes[0] = u64::from(limb);
                    *word = $load_words(&lanes);
                }
                // The staging arrays held the authenticator state.
                lanes.zeroize();
                start.zeroize();
                let mut b = Acc([$set1(0); 5]);

                let (chunks, _) = input.as_chunks::<CHUNK>();
                let (last, body) = chunks.split_last().unwrap();

                hot_loop(&mut a, &mut b, &top, body);

                // Final chunk: block `i` gets `r^(BLOCKS - i)` so the lane sum
                // is the exact sequential Horner value.
                let (half, _) = last.as_chunks::<LANE_BYTES>();
                a = mul_reduce(add_blocks(a, &half[0]), &tail_a);
                b = mul_reduce(add_blocks(b, &half[1]), &tail_b);

                // Sum the `BLOCKS` lanes (each limb below 2^27, so the sums
                // below 2^27 * BLOCKS <= 2^31) and convert back to 3x44-bit
                // limbs. Spelled out: a loop opt-level `s` may not
                // unroll would keep `l` in stack memory nothing wipes.
                let [a0, a1, a2, a3, a4] = a.0;
                let [b0, b1, b2, b3, b4] = b.0;
                let l = [
                    $lane_sum($add_epi64(a0, b0)),
                    $lane_sum($add_epi64(a1, b1)),
                    $lane_sum($add_epi64(a2, b2)),
                    $lane_sum($add_epi64(a3, b3)),
                    $lane_sum($add_epi64(a4, b4)),
                ];
                *h = carry44(pack_limbs26(l));
                top.zeroize();
                a.zeroize();
                b.zeroize();
            }

            #[cfg(test)]
            mod tests {
                use super::super::tests::{
                    assert_multiplier_bound, carry_keys, lane_value, serial_powers,
                };
                use super::*;

                /// Lanes of the five words, as `[u64; 8]` with the unused
                /// lanes zero.
                #[target_feature(enable = $feature)]
                fn lanes(r: &[$vec; 5]) -> [[u64; 8]; 5] {
                    let mut out = [[0u64; 8]; 5];
                    for (word, v) in out.iter_mut().zip(r) {
                        let mut lanes = [0u64; LANES];
                        $store_words(&mut lanes, *v);
                        word[..LANES].copy_from_slice(&lanes);
                    }
                    out
                }

                /// The multipliers `blocks` derives with one vector multiply
                /// hold exactly `[r^LANES .. r]` (`low`), `[r^BLOCKS ..
                /// r^(LANES + 1)]` (`high`) and `r^BLOCKS` in every lane
                /// (`top`), for carry-heavy keys.
                #[test]
                fn vector_powers_match_serial_chain() {
                    if !$detected {
                        return;
                    }
                    for r in &carry_keys() {
                        let serial = serial_powers::<BLOCKS>(r);
                        // SAFETY: the kernel's feature was detected above.
                        let (low, high, top) = unsafe {
                            let mut limbs = key_powers::<LANES>(r);
                            let low = Acc(Mult::descending(&limbs).r);
                            let high = mul_reduce(low, &Mult::broadcast(&limbs[LANES - 1]));
                            limbs.zeroize();
                            (
                                lanes(&low.0),
                                lanes(&high.0),
                                lanes(&Mult::from_lane0(high).r),
                            )
                        };
                        for lane in 0..LANES {
                            assert_eq!(
                                lane_value(low, lane),
                                serial[LANES - 1 - lane],
                                "low lane {lane}"
                            );
                            assert_eq!(
                                lane_value(high, lane),
                                serial[BLOCKS - 1 - lane],
                                "high lane {lane}"
                            );
                            assert_eq!(lane_value(top, lane), serial[BLOCKS - 1], "top lane {lane}");
                        }
                        assert_multiplier_bound(low, LANES, "low");
                        assert_multiplier_bound(high, LANES, "high");
                        assert_multiplier_bound(top, LANES, "top");
                    }
                }
            }
        }
    };
}

poly1305_26! {
    /// The AVX2 kernel: two chains of four blocks, the 64-bit lanes of a
    /// `__m256i`.
    mod avx2 {
        feature: "avx2",
        detected: has_x86_feature!("avx2"),
        lanes: 4,
        vec: __m256i,
        set1: _mm256_set1_epi64x,
        mul_epu32: _mm256_mul_epu32,
        add_epi64: _mm256_add_epi64,
        and: _mm256_and_si256,
        or: _mm256_or_si256,
        srli_epi64: _mm256_srli_epi64,
        slli_epi64: _mm256_slli_epi64,
        load_words: crate::x86_64::load_words,
        store_words: crate::x86_64::store_words,
        first_lane: super::first_lane,
        gather_qwords: super::gather_qwords,
        lane_sum: super::lane_sum,
    }
}

poly1305_26! {
    /// The AVX-512F kernel: two chains of eight blocks, the 64-bit lanes of a
    /// `__m512i`.
    mod avx512 {
        feature: "avx512f",
        detected: crate::x86_64::has_avx512f(),
        lanes: 8,
        vec: __m512i,
        set1: _mm512_set1_epi64,
        mul_epu32: _mm512_mul_epu32,
        add_epi64: _mm512_add_epi64,
        and: _mm512_and_si512,
        or: _mm512_or_si512,
        srli_epi64: _mm512_srli_epi64,
        slli_epi64: _mm512_slli_epi64,
        load_words: crate::x86_64::load_words512,
        store_words: crate::x86_64::store_words512,
        first_lane: super::first_lane512,
        gather_qwords: super::gather_qwords512,
        lane_sum: super::lane_sum512,
    }
}

pub(super) use avx2::{CHUNK, blocks};
pub(super) use avx512::{CHUNK as CHUNK512, blocks as blocks_avx512};

/// Bytes per iteration of the AVX-512 IFMA kernel: one block per 64-bit
/// lane of a `__m512i`. `blocks_ifma` takes a non-empty multiple of this.
pub(super) const CHUNK_IFMA: usize = 16 * avx512::LANES;

/// Eight-lane 3x44-bit accumulator for the IFMA kernel: limb `k` of eight
/// consecutive blocks in the 64-bit lanes of `0[k]`, the same 44/44/42-bit
/// split as the scalar backend's `h`. Every limb handed to
/// `vpmadd52luq`/`vpmadd52huq`, which multiply the low 52 bits of each
/// lane, stays far below `2^52`; see [`mul_reduce44`].
#[derive(Clone, Copy, Zeroize)]
struct Acc44([__m512i; 3]);

/// Canonical 3x44-bit limbs `p` in every lane.
#[inline]
#[target_feature(enable = "avx512f")]
fn splat44(p: &[u64; 3]) -> [__m512i; 3] {
    [
        _mm512_set1_epi64(p[0] as i64),
        _mm512_set1_epi64(p[1] as i64),
        _mm512_set1_epi64(p[2] as i64),
    ]
}

/// Multiplier words for one `acc * m mod p` on 3x44-bit limbs: `r[k]` holds
/// limb `k` of the power and `s[k - 1]` holds `20 *` limb `k` for `k >= 1`,
/// the scalar backend's `s1`/`s2` (a product wrapped past `2^132` is
/// multiplied by `2^132 mod p = 20`).
#[derive(Clone, Copy, Zeroize)]
struct Mult44 {
    r: [__m512i; 3],
    s: [__m512i; 2],
}

impl Mult44 {
    /// The same canonical power `p` in every lane (the kernels derive their
    /// multipliers from accumulators; tests use this for a known value).
    #[cfg(test)]
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn broadcast(p: [u64; 3]) -> Self {
        Self::with_s(splat44(&p))
    }

    /// The per-lane powers held in `acc` (partially carried limbs).
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn from_acc(acc: Acc44) -> Self {
        Self::with_s(acc.0)
    }

    /// Lane 0 of the powers held in `acc` in every lane.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn from_lane0(acc: Acc44) -> Self {
        let [w0, w1, w2] = acc.0;
        Self::with_s([first_lane512(w0), first_lane512(w1), first_lane512(w2)])
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    fn with_s(r: [__m512i; 3]) -> Self {
        let times20 =
            |x: __m512i| _mm512_slli_epi64::<2>(_mm512_add_epi64(x, _mm512_slli_epi64::<2>(x)));
        Self {
            r,
            s: [times20(r[1]), times20(r[2])],
        }
    }
}

/// Loads eight consecutive 16-byte blocks as 3x44-bit limbs (with the
/// `2^128` high bit set, so limbs below `2^44`, `2^44` and `2^41`) and adds
/// them lane-wise to `acc`.
#[inline]
#[target_feature(enable = "avx512f")]
fn add_blocks44(acc: Acc44, blocks: &[u8; CHUNK_IFMA]) -> Acc44 {
    let (t0, t1) = gather_qwords512(blocks);

    let mask = _mm512_set1_epi64(M44 as i64);
    let hibit = _mm512_set1_epi64(1 << 40);
    let m = [
        _mm512_and_si512(t0, mask),
        _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64::<44>(t0), _mm512_slli_epi64::<20>(t1)),
            mask,
        ),
        _mm512_or_si512(_mm512_srli_epi64::<24>(t1), hibit),
    ];
    let mut out = acc;
    for (limb, m) in out.0.iter_mut().zip(m) {
        *limb = _mm512_add_epi64(*limb, m);
    }
    out
}

/// `acc * m mod p` on eight lanes of 3x44-bit limbs: the scalar backend's
/// block multiplication (`mul_mod_p`) with each `u128` column split into
/// the `vpmadd52luq` sum of the products' low 52 bits and the `vpmadd52huq`
/// sum of their bits `52..104`, which weigh `2^52 = 2^8 * 2^44` (one limb
/// up) and, out of the top column, `2^140 = 2^130 * 2^10 = 5 * 2^10 mod p`.
/// This is the reduction of OpenSSL's `poly1305_blocks_vpmadd52_8x`.
///
/// Bounds: `acc` limbs are below `2^44 + 2^44`, `2^44 + 2^8 + 2^44` and
/// `2^42 + 2^41` (a partially carried accumulator plus a block), `m.r` limbs
/// are canonical or partially carried outputs of this function (below
/// `2^44`, `2^44 + 2^8`, `2^42`) so `m.s` limbs are below `20 * (2^44 +
/// 2^8) < 2^49`; every operand is below `2^52` and every product below
/// `2^45.1 * 2^49 < 2^95`. Each `lo` column sums three values below `2^52`,
/// each `hi` column three values below `2^43`; after the `<< 8` (`<< 10` for
/// the top column) and the carries they stay far below `2^64`, and the
/// result is partially carried to `h0 < 2^44`, `h1 < 2^44 + 2^8`, `h2 <
/// 2^42`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_reduce44(acc: Acc44, m: &Mult44) -> Acc44 {
    let [h0, h1, h2] = acc.0;
    let Mult44 { r, s } = m;
    let lo = _mm512_madd52lo_epu64;
    let hi = _mm512_madd52hi_epu64;
    let add = _mm512_add_epi64;
    let zero = _mm512_setzero_si512();

    // d0 = h0 r0 + h1 s2 + h2 s1; d1 = h0 r1 + h1 r0 + h2 s2;
    // d2 = h0 r2 + h1 r1 + h2 r0.
    let d0lo = lo(lo(lo(zero, h0, r[0]), h1, s[1]), h2, s[0]);
    let d0hi = hi(hi(hi(zero, h0, r[0]), h1, s[1]), h2, s[0]);
    let d1lo = lo(lo(lo(zero, h0, r[1]), h1, r[0]), h2, s[1]);
    let d1hi = hi(hi(hi(zero, h0, r[1]), h1, r[0]), h2, s[1]);
    let d2lo = lo(lo(lo(zero, h0, r[2]), h1, r[1]), h2, r[0]);
    let d2hi = hi(hi(hi(zero, h0, r[2]), h1, r[1]), h2, r[0]);

    let mask44 = _mm512_set1_epi64(M44 as i64);
    let mask42 = _mm512_set1_epi64(M42 as i64);
    let c = _mm512_srli_epi64::<44>(d0lo);
    let h0 = _mm512_and_si512(d0lo, mask44);
    let d1lo = add(d1lo, add(_mm512_slli_epi64::<8>(d0hi), c));
    let c = _mm512_srli_epi64::<44>(d1lo);
    let h1 = _mm512_and_si512(d1lo, mask44);
    let d2lo = add(d2lo, add(_mm512_slli_epi64::<8>(d1hi), c));
    let c = _mm512_srli_epi64::<42>(d2lo);
    let h2 = _mm512_and_si512(d2lo, mask42);
    // Everything past 2^130 folds back as `5 *` into the low limb.
    let wrap = add(_mm512_slli_epi64::<10>(d2hi), c);
    let h0 = add(h0, add(wrap, _mm512_slli_epi64::<2>(wrap)));
    let c = _mm512_srli_epi64::<44>(h0);
    let h0 = _mm512_and_si512(h0, mask44);
    let h1 = add(h1, c);
    Acc44([h0, h1, h2])
}

/// Hot loop of the IFMA kernel: every lane is multiplied by `r^8` per
/// chunk.
#[inline(never)]
#[target_feature(enable = "avx512f,avx512ifma")]
fn hot_loop44(a: &mut Acc44, m: &Mult44, body: &[[u8; CHUNK_IFMA]]) {
    for chunk in body {
        *a = mul_reduce44(add_blocks44(*a, chunk), m);
    }
}

/// `[r^8, r^7, ..., r]` (lane `i` holds `r^(8 - i)`) as an [`Acc44`] from
/// the clamped key `$r: &[u64; 3]`, by three lane-wise multiplies: starting
/// from `r` in every lane, each step multiplies half of the lanes by lane 0
/// (`r`, then `r^2`, then `r^4`) and the other half by one. Three dependent
/// vector multiplies replace the scalar power tree's four dependent
/// `mul_mod_p` and eight limb conversions. The limbs are partially carried
/// ([`mul_reduce44`]'s output bound), which is what the multipliers built
/// from them require.
///
/// A macro, expanded in `avx512f,avx512ifma` code, rather than a
/// `#[target_feature]` function, which cannot be `#[inline(always)]`: with
/// two callers, opt-level `s` outlines such a function and returns the eight
/// key powers through a stack slot nothing wipes.
macro_rules! descending_powers {
    ($r:expr) => {{
        let one = splat44(&[1, 0, 0]);
        let mut v = Acc44(splat44(&canonical($r)));
        // Lanes selected by each mask take lane 0 of `v` as their multiplier,
        // the rest take one: 0b0101_0101, then 0b0011_0011, then 0b0000_1111.
        for mask in [0x55u8, 0x33, 0x0f] {
            let mut m = one;
            for (word, &limb) in m.iter_mut().zip(&v.0) {
                *word = _mm512_mask_blend_epi64(mask, *word, first_lane512(limb));
            }
            v = mul_reduce44(v, &Mult44::with_s(m));
        }
        v
    }};
}

/// [`blocks`] with the AVX-512 IFMA kernel: `input` is a non-empty multiple
/// of `CHUNK_IFMA` bytes. One chain of eight Horner lanes (block `i` of each
/// chunk in lane `i`), each multiplied by `r^8` per chunk; the final chunk
/// uses `r^8, r^7, ..., r` so the lane sum is the sequential Horner value.
///
/// The multiplier and the accumulator the out-of-line `hot_loop44` reaches
/// through memory are wiped once before returning; values that live only in
/// registers and compiler spill slots are out of Rust's reach and are not
/// wiped, since wiping them would force them into memory.
///
/// Opt-level assumption: the limb helpers are `#[inline(always)]`,
/// `descending_powers!` is a macro and the limb vectors and lane sums are
/// built without closures or index loops, so at opt-level 2, 3 and `s`
/// nothing but `hot_loop44` is out of line and the other key-derived values
/// (`low`, `tail`, `start`, `l`) stay in registers and spill slots. At
/// opt-level `z` LLVM also outlines the `#[target_feature]` helpers
/// `add_blocks44` and `mul_reduce44`, which stable Rust cannot mark
/// `#[inline(always)]`; their by-value `Acc44` arguments and results (the
/// powers inside `descending_powers`, the accumulator, also in `hot_loop44`)
/// then pass through stack temporaries that are not wiped.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) fn blocks_ifma(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
    debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK_IFMA));

    let low = descending_powers!(r);
    let mut top = Mult44::from_lane0(low);
    let tail = Mult44::from_acc(low);

    // `h` goes into lane 0 (block 0 of each chunk), canonical so it meets
    // the accumulator bound. Spelled out, like the lane sums below: a loop
    // opt-level `s` may not unroll would keep the limbs in stack memory
    // nothing wipes.
    let [s0, s1, s2] = canonical(h);
    let mut a = Acc44([
        _mm512_setr_epi64(s0 as i64, 0, 0, 0, 0, 0, 0, 0),
        _mm512_setr_epi64(s1 as i64, 0, 0, 0, 0, 0, 0, 0),
        _mm512_setr_epi64(s2 as i64, 0, 0, 0, 0, 0, 0, 0),
    ]);

    let (chunks, _) = input.as_chunks::<CHUNK_IFMA>();
    let (last, body) = chunks.split_last().unwrap();

    hot_loop44(&mut a, &top, body);
    a = mul_reduce44(add_blocks44(a, last), &tail);

    // Sum the eight lanes (each limb below 2^44 + 2^8, so the sums below
    // 2^48) and carry back to the scalar backend's partially reduced form.
    let [a0, a1, a2] = a.0;
    let l = [lane_sum512(a0), lane_sum512(a1), lane_sum512(a2)];
    *h = carry44(l);
    top.zeroize();
    a.zeroize();
}

/// Bytes per iteration of the two-chain AVX-512 IFMA kernel.
/// `blocks_ifma2` takes a non-empty multiple of this.
pub(super) const CHUNK_IFMA2: usize = 2 * CHUNK_IFMA;

/// Hot loop of the two-chain IFMA kernel: every lane of both chains is
/// multiplied by `r^16` per chunk.
#[inline(never)]
#[target_feature(enable = "avx512f,avx512ifma")]
fn hot_loop44x2(a: &mut Acc44, b: &mut Acc44, m: &Mult44, body: &[[u8; CHUNK_IFMA2]]) {
    for chunk in body {
        let (half, _) = chunk.as_chunks::<CHUNK_IFMA>();
        *a = mul_reduce44(add_blocks44(*a, &half[0]), m);
        *b = mul_reduce44(add_blocks44(*b, &half[1]), m);
    }
}

/// [`blocks_ifma`] with two interleaved chains for long runs: `input` is a
/// non-empty multiple of `CHUNK_IFMA2` bytes. Chain `A` holds blocks `0..8`
/// of each chunk and chain `B` blocks `8..16`, each lane multiplied by
/// `r^16` per chunk; the final chunk uses `r^16, ..., r^9` on `A` and `r^8,
/// ..., r` on `B`. One chain's iteration is a dependency chain of three
/// accumulating multiplies and the carries, about as long as the issue time
/// of its instructions; the second chain fills those gaps.
///
/// Wipes the working copies `hot_loop44x2` reaches through memory as
/// [`blocks_ifma`] does, under the same opt-level assumption (`high`,
/// `tail_a`/`tail_b` join the values at stake at opt-level `z`).
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) fn blocks_ifma2(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
    debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK_IFMA2));

    let low = descending_powers!(r);
    let high = mul_reduce44(low, &Mult44::from_lane0(low));
    let mut top = Mult44::from_lane0(high);
    let tail_a = Mult44::from_acc(high);
    let tail_b = Mult44::from_acc(low);

    let [s0, s1, s2] = canonical(h);
    let mut a = Acc44([
        _mm512_setr_epi64(s0 as i64, 0, 0, 0, 0, 0, 0, 0),
        _mm512_setr_epi64(s1 as i64, 0, 0, 0, 0, 0, 0, 0),
        _mm512_setr_epi64(s2 as i64, 0, 0, 0, 0, 0, 0, 0),
    ]);
    let mut b = Acc44([_mm512_setzero_si512(); 3]);

    let (chunks, _) = input.as_chunks::<CHUNK_IFMA2>();
    let (last, body) = chunks.split_last().unwrap();

    hot_loop44x2(&mut a, &mut b, &top, body);
    let (half, _) = last.as_chunks::<CHUNK_IFMA>();
    a = mul_reduce44(add_blocks44(a, &half[0]), &tail_a);
    b = mul_reduce44(add_blocks44(b, &half[1]), &tail_b);

    // Sum the sixteen lanes (each limb below 2^44 + 2^8, so the sums below
    // 2^49) and carry back to the scalar backend's partially reduced form.
    let [a0, a1, a2] = a.0;
    let [b0, b1, b2] = b.0;
    let l = [
        lane_sum512(_mm512_add_epi64(a0, b0)),
        lane_sum512(_mm512_add_epi64(a1, b1)),
        lane_sum512(_mm512_add_epi64(a2, b2)),
    ];
    *h = carry44(l);
    top.zeroize();
    a.zeroize();
    b.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly1305::pack_limbs26;
    use crate::test_prelude::*;

    /// The tree-shaped key powers equal the serial chain `r, r*r, r*r*r,
    /// ...` for keys with carry-heavy limbs, for both kernel widths.
    #[test]
    fn test_key_powers_match_serial_chain() {
        for r in &carry_keys() {
            let expected: Vec<[u32; 5]> = serial_powers::<{ avx512::BLOCKS }>(r)
                .iter()
                .map(|p| limbs26(*p))
                .collect();
            assert_eq!(
                key_powers::<{ avx512::BLOCKS }>(r).to_vec(),
                expected,
                "{r:x?}"
            );
            assert_eq!(
                key_powers::<{ avx2::BLOCKS }>(r).to_vec(),
                expected[..avx2::BLOCKS],
                "{r:x?}"
            );
        }
    }

    /// Canonical 3x44-bit value of the 5x26-bit limbs (partially carried or
    /// not) in lane `lane` of every vector of `words`.
    pub(super) fn lane_value(words: [[u64; 8]; 5], lane: usize) -> [u64; 3] {
        canonical(&carry44(pack_limbs26([
            words[0][lane],
            words[1][lane],
            words[2][lane],
            words[3][lane],
            words[4][lane],
        ])))
    }

    /// Every raw limb of the multipliers (before canonicalisation) must be
    /// below `2^26 + 2^10`, the bound `mul_reduce` documents for `r` so that
    /// `5 * r` and the five-product column sums cannot overflow.
    pub(super) fn assert_multiplier_bound(words: [[u64; 8]; 5], lanes: usize, what: &str) {
        for (k, word) in words.iter().enumerate() {
            for (lane, &limb) in word.iter().enumerate().take(lanes) {
                assert!(
                    limb < (1 << 26) + (1 << 10),
                    "{what} limb {k} lane {lane}: {limb:#x}"
                );
            }
        }
    }

    /// Lanes of the three IFMA words.
    #[target_feature(enable = "avx512f")]
    fn lanes44(r: &[__m512i; 3]) -> [[u64; 8]; 3] {
        let mut out = [[0u64; 8]; 3];
        for (word, v) in out.iter_mut().zip(r) {
            crate::x86_64::store_words512(word, *v);
        }
        out
    }

    /// One `add_blocks44` + `mul_reduce44` step equals `mul_mod_p` of
    /// `(lane + block)` in every lane, and its raw limbs meet the partially
    /// carried bound `mul_reduce44` documents (`h0 < 2^44`, `h1 < 2^44 +
    /// 2^8`, `h2 < 2^42`). The multipliers are adversarial canonical field
    /// elements (the `carry_keys` elements made canonical; production uses
    /// the canonical powers `r^1 .. r^8`, a subset of those), the accumulator
    /// is component-wise maximal within the documented input bound, and the
    /// blocks are all ones.
    #[test]
    fn test_ifma_step_matches_scalar_and_bound() {
        if !crate::x86_64::has_avx512f() || !has_x86_feature!("avx512ifma") {
            return;
        }
        let blocks = [0xffu8; CHUNK_IFMA];
        // Every lane starts at the component-wise maximum of the partially
        // carried accumulator bound `mul_reduce44` documents.
        let start = [M44, M44 + (1 << 8) - 1, M42];
        let block = |i: usize| -> [u64; 3] {
            let t0 = u64::from_le_bytes(blocks[16 * i..16 * i + 8].try_into().unwrap());
            let t1 = u64::from_le_bytes(blocks[16 * i + 8..16 * i + 16].try_into().unwrap());
            [
                t0 & M44,
                ((t0 >> 44) | (t1 << 20)) & M44,
                (t1 >> 24) | (1 << 40),
            ]
        };
        for r in &carry_keys() {
            let r = canonical(r);
            // SAFETY: `avx512f` (with the `avx2` it implies) and `avx512ifma`
            // were detected above.
            let out = unsafe {
                let acc = Acc44(start.map(|limb| _mm512_set1_epi64(limb as i64)));
                lanes44(&mul_reduce44(add_blocks44(acc, &blocks), &Mult44::broadcast(r)).0)
            };
            for (lane, ((&h0, &h1), &h2)) in out[0].iter().zip(&out[1]).zip(&out[2]).enumerate() {
                assert!(h0 < 1 << 44, "h0 lane {lane}: {h0:#x}");
                assert!(h1 < (1 << 44) + (1 << 8), "h1 lane {lane}: {h1:#x}");
                assert!(h2 < 1 << 42, "h2 lane {lane}: {h2:#x}");
                let m = block(lane);
                let sum = [start[0] + m[0], start[1] + m[1], start[2] + m[2]];
                assert_eq!(
                    canonical(&[h0, h1, h2]),
                    canonical(&mul_mod_p(&sum, &r)),
                    "lane {lane} r={r:x?}"
                );
            }
        }
    }

    /// The multipliers the IFMA kernels derive with lane-wise multiplies hold
    /// exactly `[r^8 .. r]` (`low`), `[r^16 .. r^9]` (`high`) and `r^8` /
    /// `r^16` in every lane (`top8` / `top16`), for carry-heavy multipliers,
    /// and every raw limb meets the partially carried multiplier bound
    /// `mul_reduce44` documents.
    #[test]
    fn test_ifma_vector_powers_match_serial_chain() {
        if !crate::x86_64::has_avx512f() || !has_x86_feature!("avx512ifma") {
            return;
        }
        let assert_bound = |words: [[u64; 8]; 3], what: &str| {
            for (lane, ((&h0, &h1), &h2)) in
                words[0].iter().zip(&words[1]).zip(&words[2]).enumerate()
            {
                assert!(h0 < 1 << 44, "{what} h0 lane {lane}: {h0:#x}");
                assert!(h1 < (1 << 44) + (1 << 8), "{what} h1 lane {lane}: {h1:#x}");
                assert!(h2 < 1 << 42, "{what} h2 lane {lane}: {h2:#x}");
            }
        };
        let lane_value = |words: [[u64; 8]; 3], lane: usize| {
            canonical(&[words[0][lane], words[1][lane], words[2][lane]])
        };
        for r in &carry_keys() {
            let serial = serial_powers::<16>(r);
            // SAFETY: `avx512f` (with the `avx2` it implies) and `avx512ifma`
            // were detected above.
            let (low, high, top8, top16) = unsafe {
                let low = descending_powers!(r);
                let high = mul_reduce44(low, &Mult44::from_lane0(low));
                (
                    lanes44(&low.0),
                    lanes44(&high.0),
                    lanes44(&Mult44::from_lane0(low).r),
                    lanes44(&Mult44::from_lane0(high).r),
                )
            };
            for lane in 0..8 {
                assert_eq!(lane_value(low, lane), serial[7 - lane], "low lane {lane}");
                assert_eq!(
                    lane_value(high, lane),
                    serial[15 - lane],
                    "high lane {lane}"
                );
                assert_eq!(lane_value(top8, lane), serial[7], "top8 lane {lane}");
                assert_eq!(lane_value(top16, lane), serial[15], "top16 lane {lane}");
            }
            assert_bound(low, "low");
            assert_bound(high, "high");
            assert_bound(top8, "top8");
            assert_bound(top16, "top16");
        }
    }

    /// Carry-heavy 3x44-bit multipliers (within the 44/44/42-bit limb widths
    /// but not necessarily clamped keys): a near-all-ones element, `r = 1`,
    /// mixed and carry-edge limbs.
    pub(super) fn carry_keys() -> [[u64; 3]; 4] {
        [
            [0x0ffc_0fff_ffff, 0x0fff_ffc0_ffff, 0x00ff_ffff_fc0f],
            [1, 0, 0],
            [0x0123_4567_89ab, 0x0fed_cba9_8765, 0x00f0_f0f0_f0f0],
            [0x0800_0000_0001, 0x0000_0000_0001, 0x00ff_0000_0000],
        ]
    }

    /// Canonical `r^1 .. r^N` by the serial chain.
    pub(super) fn serial_powers<const N: usize>(r: &[u64; 3]) -> [[u64; 3]; N] {
        let mut serial = [[0u64; 3]; N];
        serial[0] = *r;
        for i in 1..N {
            serial[i] = mul_mod_p(&serial[i - 1], r);
        }
        serial.map(|p| canonical(&p))
    }
}
