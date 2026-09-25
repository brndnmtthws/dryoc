//! NEON ML-KEM polynomial arithmetic, eight 16-bit coefficients per vector.
//!
//! Every lane computes exactly the portable operation of `mlkem_soft.rs` on
//! its coefficient, so results are bit-identical, not merely congruent:
//!
//! - Montgomery multiplication `fqmul(a, b) = hi(a * b) - hi(t * q)` with `t =
//!   lo(a * b) * q^-1` uses `sqdmulh` for both high halves. It returns
//!   `floor(2xy / 2^16)`; the doubled products `2ab` and `2tq` have equal low
//!   halves, so the difference of the two is exactly `2 * (ab - tq) / 2^16` and
//!   the halving subtract `shsub`, which works at full precision, gives exactly
//!   `(ab - tq) / 2^16`.
//! - The flooring Barrett quotient `floor(a * v / 2^26)` is `sqdmulh(a, v) =
//!   floor(a * v / 2^15)` shifted right by 11 more bits.
//!
//! `sqdmulh` saturates only when both operands are `-2^15`, which no call can
//! produce: one factor is always a twiddle, `q`, the Barrett multiplier or a
//! multiply-add input below `2^12` in magnitude.
//!
//! The NTT layers whose butterflies span at least eight coefficients pair
//! whole vectors; the last two forward (first two inverse) layers regroup two
//! vectors with 64-bit and 32-bit transposes so that each butterfly's inputs
//! again sit in the same lane of two vectors. Coefficients enter and leave
//! every operation in the portable order. All control flow and memory access
//! is independent of the coefficients.
//!
//! Zeroization: the kernels load rows of the caller's polynomial, transform
//! them in vector registers and store them back in place. The polynomials
//! belong to [`super`], which keeps secret ones in `Zeroizing` buffers or
//! wipes them explicitly. The vector arrays are iterated by reference and
//! stay in registers and spill slots. Rust cannot reliably wipe those, and
//! wiping them would force them into memory, so the kernels add no wipes of
//! their own.

use core::arch::aarch64::{
    int16x8_t, vaddq_s16, vdupq_n_s16, vhsubq_s16, vld1q_s16, vmlsq_n_s16, vmulq_n_s16, vmulq_s16,
    vqdmulhq_n_s16, vqdmulhq_s16, vreinterpretq_s16_s32, vreinterpretq_s16_s64,
    vreinterpretq_s32_s16, vreinterpretq_s64_s16, vshrq_n_s16, vst1q_s16, vsubq_s16, vtrn1q_s32,
    vtrn1q_s64, vtrn2q_s32, vtrn2q_s64, vuzp1q_s16, vuzp1q_s32, vuzp2q_s16, vuzp2q_s32, vzip1q_s16,
    vzip1q_s32, vzip2q_s16, vzip2q_s32,
};

use super::mlkem_soft::{BARRETT_V, INVNTT_F, QINV, ZETAS};
use super::{Poly, Q};
use crate::aarch64::Neon;

/// A kernel the running CPU has been verified to support: it holds the
/// [`Neon`] token that makes its methods' calls into the
/// `#[target_feature(enable = "neon")]` kernels safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kernel(Neon);

/// The NEON kernel, if the running CPU supports it.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    Neon::new().map(Kernel)
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        detect().into_iter().collect()
    }

    #[inline]
    pub(super) fn ntt(self, r: &mut Poly) {
        ntt(self.0, r)
    }

    #[inline]
    pub(super) fn invntt_tomont(self, r: &mut Poly) {
        invntt_tomont(self.0, r)
    }

    #[inline]
    pub(super) fn basemul_acc<const K: usize>(self, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
        basemul_acc(self.0, r, a, b)
    }
}

/// Per-lane twiddle factors with their Montgomery multipliers `zeta * q^-1
/// mod 2^16`, so a product by a twiddle needs no low multiply by `q^-1`.
#[derive(Clone, Copy)]
struct Twiddle {
    zeta: [i16; 8],
    zeta_qinv: [i16; 8],
}

/// `ZETAS[i] * q^-1 mod 2^16`, for the layers that use one twiddle per
/// vector.
const ZETAS_QINV: [i16; 128] = {
    let mut table = [0; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = ZETAS[i].wrapping_mul(QINV);
        i += 1;
    }
    table
};

/// Sixteen per-lane twiddle vectors, one per pair of coefficient vectors
/// `p`: lane `l` holds `ZETAS[base + i]` (or `ZETAS[base - i]` when
/// `descending`) for `i = step * p + l / (8 / step)`, i.e. `step` twiddles
/// per pair, each repeated over `8 / step` lanes; with `alternate`, odd
/// lanes are negated.
const fn twiddles(base: usize, step: usize, descending: bool, alternate: bool) -> [Twiddle; 16] {
    let mut table = [Twiddle {
        zeta: [0; 8],
        zeta_qinv: [0; 8],
    }; 16];
    let mut p = 0;
    while p < 16 {
        let mut l = 0;
        while l < 8 {
            let i = step * p + l / (8 / step);
            let zeta = ZETAS[if descending { base - i } else { base + i }];
            let zeta = if alternate && l % 2 == 1 { -zeta } else { zeta };
            table[p].zeta[l] = zeta;
            table[p].zeta_qinv[l] = zeta.wrapping_mul(QINV);
            l += 1;
        }
        p += 1;
    }
    table
}

/// Forward layer `len = 4` on the pair regrouped as `[0..4, 8..12]` and
/// `[4..8, 12..16]`: blocks `2p` and `2p + 1`.
const NTT_LEN4: [Twiddle; 16] = twiddles(32, 2, false, false);
/// Forward layer `len = 2` on the pair regrouped as 32-bit lanes `[0, 4, 8,
/// 12]` and `[2, 6, 10, 14]`: blocks `4p .. 4p + 4`.
const NTT_LEN2: [Twiddle; 16] = twiddles(64, 4, false, false);
/// Inverse layer `len = 2`, same grouping as [`NTT_LEN2`], twiddles from the
/// top of the table down.
const INVNTT_LEN2: [Twiddle; 16] = twiddles(127, 4, true, false);
/// Inverse layer `len = 4`, same grouping as [`NTT_LEN4`].
const INVNTT_LEN4: [Twiddle; 16] = twiddles(63, 2, true, false);
/// Base multiplication on the even/odd coefficients of sixteen: lane `m` is
/// the degree-one residue `m`, of group `4p + m / 2`, whose modulus is
/// `X^2 - zeta` for even `m` and `X^2 + zeta` for odd `m`.
const BASEMUL: [Twiddle; 16] = twiddles(64, 4, false, true);

/// Loads eight coefficients (`ldr q`).
#[inline]
#[target_feature(enable = "neon")]
fn load(c: &[i16; 8]) -> int16x8_t {
    // SAFETY: `c` refers to eight initialized `i16`s, exactly the 16 bytes
    // `ld1` reads, and `ld1` has no alignment requirement beyond that of
    // `i16`.
    unsafe { vld1q_s16(c.as_ptr()) }
}

/// Stores eight coefficients (`str q`).
#[inline]
#[target_feature(enable = "neon")]
fn store(c: &mut [i16; 8], v: int16x8_t) {
    // SAFETY: `c` is an exclusive reference to eight `i16`s, exactly the 16
    // bytes `st1` writes, and `st1` has no alignment requirement beyond that
    // of `i16`.
    unsafe { vst1q_s16(c.as_mut_ptr(), v) }
}

/// Loads a per-lane twiddle vector and its Montgomery multipliers.
#[inline]
#[target_feature(enable = "neon")]
fn twiddle(t: &Twiddle) -> (int16x8_t, int16x8_t) {
    (load(&t.zeta), load(&t.zeta_qinv))
}

/// Lane-wise `fqmul(a, b)`, given `b_qinv = b * q^-1 mod 2^16`.
#[inline]
#[target_feature(enable = "neon")]
fn fqmul(a: int16x8_t, b: int16x8_t, b_qinv: int16x8_t) -> int16x8_t {
    let t = vmulq_s16(a, b_qinv);
    vhsubq_s16(vqdmulhq_s16(a, b), vqdmulhq_n_s16(t, Q))
}

/// Lane-wise `fqmul(a, ZETAS[k])`.
#[inline]
#[target_feature(enable = "neon")]
fn fqmul_zeta(a: int16x8_t, k: usize) -> int16x8_t {
    let t = vmulq_n_s16(a, ZETAS_QINV[k]);
    vhsubq_s16(vqdmulhq_n_s16(a, ZETAS[k]), vqdmulhq_n_s16(t, Q))
}

/// Lane-wise flooring `barrett_reduce`.
#[inline]
#[target_feature(enable = "neon")]
fn barrett_reduce(a: int16x8_t) -> int16x8_t {
    let t = vshrq_n_s16::<11>(vqdmulhq_n_s16(a, BARRETT_V));
    vmlsq_n_s16(a, t, Q)
}

/// Forward (Cooley-Tukey) butterfly `(a + t, a - t)` with `t = fqmul(zeta,
/// b)` for the partner `b` of `a`.
#[inline]
#[target_feature(enable = "neon")]
fn ct(a: int16x8_t, t: int16x8_t) -> (int16x8_t, int16x8_t) {
    (vaddq_s16(a, t), vsubq_s16(a, t))
}

/// Forward butterflies `len = 8 * d` over `v`, with twiddles from `k` on.
#[inline]
#[target_feature(enable = "neon")]
fn ct_layer<const L: usize>(v: &mut [int16x8_t; L], d: usize, mut k: usize) {
    for start in (0..L).step_by(2 * d) {
        for j in start..start + d {
            (v[j], v[j + d]) = ct(v[j], fqmul_zeta(v[j + d], k));
        }
        k += 1;
    }
}

/// Inverse (Gentleman-Sande) butterfly `(barrett_reduce(a + b), fqmul(zeta,
/// b - a))`, with the product by `zeta` applied by `mul`.
#[inline]
#[target_feature(enable = "neon")]
fn gs(a: int16x8_t, b: int16x8_t, mul: impl Fn(int16x8_t) -> int16x8_t) -> (int16x8_t, int16x8_t) {
    (barrett_reduce(vaddq_s16(a, b)), mul(vsubq_s16(b, a)))
}

/// Inverse butterflies `len = 8 * d` over `v`, with twiddles from `k` down.
#[inline]
#[target_feature(enable = "neon")]
fn gs_layer<const L: usize>(v: &mut [int16x8_t; L], d: usize, mut k: usize) {
    for start in (0..L).step_by(2 * d) {
        for j in start..start + d {
            (v[j], v[j + d]) = gs(v[j], v[j + d], |x| fqmul_zeta(x, k));
        }
        k -= 1;
    }
}

/// Transposes the 64-bit halves of `(a, b)`: `([a.lo, b.lo], [a.hi, b.hi])`.
#[inline]
#[target_feature(enable = "neon")]
fn trn64(a: int16x8_t, b: int16x8_t) -> (int16x8_t, int16x8_t) {
    let (a, b) = (vreinterpretq_s64_s16(a), vreinterpretq_s64_s16(b));
    (
        vreinterpretq_s16_s64(vtrn1q_s64(a, b)),
        vreinterpretq_s16_s64(vtrn2q_s64(a, b)),
    )
}

/// Transposes the 32-bit lanes of `(a, b)`: `([a0, b0, a2, b2], [a1, b1,
/// a3, b3])`.
#[inline]
#[target_feature(enable = "neon")]
fn trn32(a: int16x8_t, b: int16x8_t) -> (int16x8_t, int16x8_t) {
    let (a, b) = (vreinterpretq_s32_s16(a), vreinterpretq_s32_s16(b));
    (
        vreinterpretq_s16_s32(vtrn1q_s32(a, b)),
        vreinterpretq_s16_s32(vtrn2q_s32(a, b)),
    )
}

/// Interleaves the 32-bit lanes of `(a, b)`: `([a0, b0, a1, b1], [a2, b2,
/// a3, b3])`.
#[inline]
#[target_feature(enable = "neon")]
fn zip32(a: int16x8_t, b: int16x8_t) -> (int16x8_t, int16x8_t) {
    let (a, b) = (vreinterpretq_s32_s16(a), vreinterpretq_s32_s16(b));
    (
        vreinterpretq_s16_s32(vzip1q_s32(a, b)),
        vreinterpretq_s16_s32(vzip2q_s32(a, b)),
    )
}

/// De-interleaves the 32-bit lanes of `(a, b)`: `([a0, a2, b0, b2], [a1, a3,
/// b1, b3])`, the inverse of [`zip32`].
#[inline]
#[target_feature(enable = "neon")]
fn uzp32(a: int16x8_t, b: int16x8_t) -> (int16x8_t, int16x8_t) {
    let (a, b) = (vreinterpretq_s32_s16(a), vreinterpretq_s32_s16(b));
    (
        vreinterpretq_s16_s32(vuzp1q_s32(a, b)),
        vreinterpretq_s16_s32(vuzp2q_s32(a, b)),
    )
}

/// The forward layers `len = 4` and `len = 2` and the final reduction on
/// sixteen coefficients `(v0, v1)`, pair `p` of the polynomial.
#[inline]
#[target_feature(enable = "neon")]
fn ntt_pair(v0: int16x8_t, v1: int16x8_t, p: usize) -> (int16x8_t, int16x8_t) {
    // `a` holds coefficients 0..4 and 8..12, `b` their partners 4..8 and
    // 12..16.
    let (a, b) = trn64(v0, v1);
    let (zeta, zeta_qinv) = twiddle(&NTT_LEN4[p]);
    let (a, b) = ct(a, fqmul(b, zeta, zeta_qinv));
    // As 32-bit lanes, `a` holds coefficient pairs 0, 4, 8, 12 (each the
    // first half of a block of four) and `b` pairs 2, 6, 10, 14.
    let (a, b) = trn32(a, b);
    let (zeta, zeta_qinv) = twiddle(&NTT_LEN2[p]);
    let (a, b) = ct(a, fqmul(b, zeta, zeta_qinv));
    zip32(barrett_reduce(a), barrett_reduce(b))
}

/// The inverse layers `len = 2` and `len = 4` on sixteen coefficients `(v0,
/// v1)`, pair `p` of the polynomial: the reverse of [`ntt_pair`].
#[inline]
#[target_feature(enable = "neon")]
fn invntt_pair(v0: int16x8_t, v1: int16x8_t, p: usize) -> (int16x8_t, int16x8_t) {
    let (a, b) = uzp32(v0, v1);
    let (zeta, zeta_qinv) = twiddle(&INVNTT_LEN2[p]);
    let (a, b) = gs(a, b, |x| fqmul(x, zeta, zeta_qinv));
    let (a, b) = trn32(a, b);
    let (zeta, zeta_qinv) = twiddle(&INVNTT_LEN4[p]);
    let (a, b) = gs(a, b, |x| fqmul(x, zeta, zeta_qinv));
    trn64(a, b)
}

/// The polynomial as 32 rows of eight coefficients.
#[inline]
fn rows(r: &mut Poly) -> &mut [[i16; 8]; 32] {
    r.as_chunks_mut::<8>().0.try_into().unwrap()
}

/// `mlkem_soft::ntt`.
#[target_feature(enable = "neon")]
fn ntt_unchecked(r: &mut Poly) {
    let rows = rows(r);
    // Layers len = 128, 64, 32 on rows j, j + 4, ..., j + 28.
    for j in 0..4 {
        let mut v: [int16x8_t; 8] = core::array::from_fn(|m| load(&rows[j + 4 * m]));
        ct_layer(&mut v, 4, 1);
        ct_layer(&mut v, 2, 2);
        ct_layer(&mut v, 1, 4);
        for (m, v) in v.iter().enumerate() {
            store(&mut rows[j + 4 * m], *v);
        }
    }
    // Layers len = 16, 8, 4, 2 on 64 consecutive coefficients.
    for (q, rows) in rows.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut v: [int16x8_t; 8] = core::array::from_fn(|m| load(&rows[m]));
        ct_layer(&mut v, 2, 8 + 2 * q);
        ct_layer(&mut v, 1, 16 + 4 * q);
        for i in 0..4 {
            (v[2 * i], v[2 * i + 1]) = ntt_pair(v[2 * i], v[2 * i + 1], 4 * q + i);
        }
        for (row, v) in rows.iter_mut().zip(&v) {
            store(row, *v);
        }
    }
}

/// [`ntt_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn ntt(_: Neon, r: &mut Poly) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { ntt_unchecked(r) }
}

/// `mlkem_soft::invntt_tomont`.
#[target_feature(enable = "neon")]
fn invntt_tomont_unchecked(r: &mut Poly) {
    let rows = rows(r);
    // Layers len = 2, 4, 8, 16 on 64 consecutive coefficients.
    for (q, rows) in rows.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut v: [int16x8_t; 8] = core::array::from_fn(|m| load(&rows[m]));
        for i in 0..4 {
            (v[2 * i], v[2 * i + 1]) = invntt_pair(v[2 * i], v[2 * i + 1], 4 * q + i);
        }
        gs_layer(&mut v, 1, 31 - 4 * q);
        gs_layer(&mut v, 2, 15 - 2 * q);
        for (row, v) in rows.iter_mut().zip(&v) {
            store(row, *v);
        }
    }
    // Layers len = 32, 64, 128 and the final scaling on rows j, j + 4, ...,
    // j + 28.
    let f = vdupq_n_s16(INVNTT_F);
    let f_qinv = vdupq_n_s16(INVNTT_F.wrapping_mul(QINV));
    for j in 0..4 {
        let mut v: [int16x8_t; 8] = core::array::from_fn(|m| load(&rows[j + 4 * m]));
        gs_layer(&mut v, 1, 7);
        gs_layer(&mut v, 2, 3);
        gs_layer(&mut v, 4, 1);
        for (m, v) in v.iter().enumerate() {
            store(&mut rows[j + 4 * m], fqmul(*v, f, f_qinv));
        }
    }
}

/// [`invntt_tomont_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn invntt_tomont(_: Neon, r: &mut Poly) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { invntt_tomont_unchecked(r) }
}

/// The polynomial as sixteen pairs of rows of eight coefficients.
#[inline]
fn pairs(r: &Poly) -> &[[[i16; 8]; 2]; 16] {
    r.as_chunks::<8>().0.as_chunks::<2>().0.try_into().unwrap()
}

/// `mlkem_soft::basemul_acc`, sixteen coefficients at a time with the even
/// (constant) and odd (linear) coefficients of each residue de-interleaved.
#[target_feature(enable = "neon")]
fn basemul_acc_unchecked<const K: usize>(r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    let split = |[lo, hi]: &[[i16; 8]; 2]| {
        let (lo, hi) = (load(lo), load(hi));
        (vuzp1q_s16(lo, hi), vuzp2q_s16(lo, hi))
    };
    let out: &mut [[[i16; 8]; 2]; 16] = r
        .as_chunks_mut::<8>()
        .0
        .as_chunks_mut::<2>()
        .0
        .try_into()
        .unwrap();
    for (p, out) in out.iter_mut().enumerate() {
        let (zeta, zeta_qinv) = twiddle(&BASEMUL[p]);
        let (mut c0, mut c1) = (vdupq_n_s16(0), vdupq_n_s16(0));
        for (a, b) in a.iter().zip(b) {
            let (a0, a1) = split(&pairs(a)[p]);
            let (b0, b1) = split(&pairs(b)[p]);
            let b0_qinv = vmulq_n_s16(b0, QINV);
            let b1_qinv = vmulq_n_s16(b1, QINV);
            let x = vaddq_s16(
                fqmul(fqmul(a1, b1, b1_qinv), zeta, zeta_qinv),
                fqmul(a0, b0, b0_qinv),
            );
            let y = vaddq_s16(fqmul(a0, b1, b1_qinv), fqmul(a1, b0, b0_qinv));
            c0 = vaddq_s16(c0, x);
            c1 = vaddq_s16(c1, y);
        }
        let (c0, c1) = (barrett_reduce(c0), barrett_reduce(c1));
        store(&mut out[0], vzip1q_s16(c0, c1));
        store(&mut out[1], vzip2q_s16(c0, c1));
    }
}

/// [`basemul_acc_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn basemul_acc<const K: usize>(_: Neon, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { basemul_acc_unchecked::<K>(r, a, b) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::mlkem_soft;
    use crate::test_prelude::*;

    /// Lane `i` of `v`.
    #[target_feature(enable = "neon")]
    fn lanes(v: int16x8_t) -> [i16; 8] {
        let mut out = [0; 8];
        store(&mut out, v);
        out
    }

    #[target_feature(enable = "neon")]
    fn check_lanes() {
        // Barrett reduction of every 16-bit value.
        for chunk in (i16::MIN..=i16::MAX).collect::<Vec<_>>().as_chunks::<8>().0 {
            let expected = chunk.map(mlkem_soft::barrett_reduce);
            assert_eq!(
                lanes(barrett_reduce(load(chunk))),
                expected,
                "barrett {chunk:?}"
            );
        }
        // Montgomery products of every 16-bit value by every twiddle factor
        // (either sign) and the inverse NTT scale, and of every pair of
        // multiply-add inputs below 2^12 in magnitude (plus 4096 to fill the
        // last vector).
        let mut factors: Vec<i16> = ZETAS.iter().flat_map(|&z| [z, -z]).collect();
        factors.push(INVNTT_F);
        let all: Vec<i16> = (i16::MIN..=i16::MAX).collect();
        let small: Vec<i16> = (-4095..=4096).collect();
        let pairs = factors
            .iter()
            .map(|&b| (&all, b))
            .chain((-4095..=4095).map(|b| (&small, b)));
        for (inputs, b) in pairs {
            let (bv, bq) = (vdupq_n_s16(b), vdupq_n_s16(b.wrapping_mul(QINV)));
            for chunk in inputs.as_chunks::<8>().0 {
                let expected = chunk.map(|a| mlkem_soft::fqmul(a, b));
                assert_eq!(
                    lanes(fqmul(load(chunk), bv, bq)),
                    expected,
                    "fqmul {chunk:?} {b}"
                );
            }
        }
    }

    /// The lane-wise reductions equal the portable scalar ones exactly over
    /// their whole input ranges.
    #[test]
    fn test_lanes_match_scalar_exhaustive() {
        let _neon = Neon::new().expect("NEON must be detected on this machine");
        // SAFETY: test-only; the `Neon` token above proves `neon`, the one
        // feature `check_lanes` is compiled for.
        unsafe { check_lanes() };
    }
}
