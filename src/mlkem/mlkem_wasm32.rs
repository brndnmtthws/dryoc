//! WebAssembly `simd128` ML-KEM polynomial arithmetic, eight 16-bit
//! coefficients per vector.
//!
//! Every lane computes exactly the portable operation of `mlkem_soft.rs` on
//! its coefficient, so results are bit-identical, not merely congruent:
//!
//! - Montgomery multiplication `fqmul(a, b) = hi(a * b) - hi(t * q)` with `t =
//!   lo(a * b) * q^-1` uses `i16x8.q15mulr_sat` for both high halves. It
//!   returns `floor((2xy + 2^15) / 2^16)`; the doubled products `2ab` and `2tq`
//!   have equal low halves, so the rounding adds the same carry to both and
//!   their difference is exactly `2 * (ab - tq) / 2^16`, an even value below
//!   `2q` in magnitude that an arithmetic shift halves exactly.
//! - The flooring Barrett quotient `floor(a * v / 2^26)` is the high half of
//!   the 32-bit products `i32x4.extmul_{low,high}_i16x8(a, v)`, gathered by a
//!   shuffle and shifted right by 10 more bits. (A rounding high multiply would
//!   round up ten inputs, such as `-q`, whose products lie just below a
//!   multiple of `2^26`.)
//!
//! `q15mulr_sat` saturates only when both operands are `-2^15`, which no call
//! can produce: one factor is always a twiddle, `q`, the inverse NTT scale or
//! a multiply-add input below `2^12` in magnitude.
//!
//! The layout mirrors the NEON kernel: the NTT layers whose butterflies span
//! at least eight coefficients pair whole vectors; the last two forward
//! (first two inverse) layers regroup two vectors with 64-bit and 32-bit
//! transposes so that each butterfly's inputs again sit in the same lane of
//! two vectors. Coefficients enter and leave every operation in the portable
//! order. All control flow and memory access is independent of the
//! coefficients.
//!
//! Wiping: the coefficient vectors only flow through inlined helpers, so
//! they live in the engine's registers or spill slots (the kernels use no
//! linear-memory stack frame), which are out of Rust's reach and not wiped;
//! a wipe would only force them into linear memory. Results go straight into
//! the caller's polynomials, which the KEM operations wipe.

use core::arch::wasm32::{
    i16x8_add, i16x8_mul, i16x8_q15mulr_sat, i16x8_shr, i16x8_shuffle, i16x8_splat, i16x8_sub,
    i32x4_extmul_high_i16x8, i32x4_extmul_low_i16x8, i32x4_shuffle, i64x2_shuffle, v128,
};

use super::mlkem_soft::{BARRETT_V, INVNTT_F, QINV, ZETAS};
use super::{Poly, Q};
use crate::wasm32::{load_i16s as load, store_i16s as store};

/// The `simd128` kernel. WebAssembly has no runtime feature detection: this
/// module is only compiled when the crate is built with `simd128` enabled,
/// so the kernel is always available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    Simd128,
}

/// The `simd128` kernel, always available in this build.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    Some(Kernel::Simd128)
}

impl Kernel {
    /// Every kernel of this build.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        vec![Kernel::Simd128]
    }

    /// [`super::mlkem_soft::ntt`].
    #[inline]
    pub(super) fn ntt(self, r: &mut Poly) {
        ntt(r)
    }

    /// [`super::mlkem_soft::invntt_tomont`].
    #[inline]
    pub(super) fn invntt_tomont(self, r: &mut Poly) {
        invntt_tomont(r)
    }

    /// [`super::mlkem_soft::basemul_acc`].
    #[inline]
    pub(super) fn basemul_acc<const K: usize>(self, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
        basemul_acc(r, a, b)
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
static NTT_LEN4: [Twiddle; 16] = twiddles(32, 2, false, false);
/// Forward layer `len = 2` on the pair regrouped as 32-bit lanes `[0, 4, 8,
/// 12]` and `[2, 6, 10, 14]`: blocks `4p .. 4p + 4`.
static NTT_LEN2: [Twiddle; 16] = twiddles(64, 4, false, false);
/// Inverse layer `len = 2`, same grouping as [`NTT_LEN2`], twiddles from the
/// top of the table down.
static INVNTT_LEN2: [Twiddle; 16] = twiddles(127, 4, true, false);
/// Inverse layer `len = 4`, same grouping as [`NTT_LEN4`].
static INVNTT_LEN4: [Twiddle; 16] = twiddles(63, 2, true, false);
/// Base multiplication on the even/odd coefficients of sixteen: lane `m` is
/// the degree-one residue `m`, of group `4p + m / 2`, whose modulus is
/// `X^2 - zeta` for even `m` and `X^2 + zeta` for odd `m`.
static BASEMUL: [Twiddle; 16] = twiddles(64, 4, false, true);

/// Loads a per-lane twiddle vector and its Montgomery multipliers.
#[inline(always)]
fn twiddle(t: &Twiddle) -> (v128, v128) {
    (load(&t.zeta), load(&t.zeta_qinv))
}

/// Lane-wise `fqmul(a, b)`, given `b_qinv = b * q^-1 mod 2^16`.
#[inline(always)]
fn fqmul(a: v128, b: v128, b_qinv: v128) -> v128 {
    let t = i16x8_mul(a, b_qinv);
    let hi2 = i16x8_sub(
        i16x8_q15mulr_sat(a, b),
        i16x8_q15mulr_sat(t, i16x8_splat(Q)),
    );
    i16x8_shr(hi2, 1)
}

/// Lane-wise `fqmul(a, ZETAS[k])`.
#[inline(always)]
fn fqmul_zeta(a: v128, k: usize) -> v128 {
    fqmul(a, i16x8_splat(ZETAS[k]), i16x8_splat(ZETAS_QINV[k]))
}

/// Lane-wise flooring `barrett_reduce`.
#[inline(always)]
fn barrett_reduce(a: v128) -> v128 {
    let v = i16x8_splat(BARRETT_V);
    let (lo, hi) = (i32x4_extmul_low_i16x8(a, v), i32x4_extmul_high_i16x8(a, v));
    // The high 16-bit halves of the eight 32-bit products.
    let t = i16x8_shr(i16x8_shuffle::<1, 3, 5, 7, 9, 11, 13, 15>(lo, hi), 10);
    i16x8_sub(a, i16x8_mul(t, i16x8_splat(Q)))
}

/// Forward (Cooley-Tukey) butterfly `(a + t, a - t)` with `t = fqmul(zeta,
/// b)` for the partner `b` of `a`.
#[inline(always)]
fn ct(a: v128, t: v128) -> (v128, v128) {
    (i16x8_add(a, t), i16x8_sub(a, t))
}

/// Forward butterflies `len = 8 * d` over `v`, with twiddles from `k` on.
#[inline(always)]
fn ct_layer<const L: usize>(v: &mut [v128; L], d: usize, mut k: usize) {
    for start in (0..L).step_by(2 * d) {
        for j in start..start + d {
            (v[j], v[j + d]) = ct(v[j], fqmul_zeta(v[j + d], k));
        }
        k += 1;
    }
}

/// Inverse (Gentleman-Sande) butterfly `(barrett_reduce(a + b), fqmul(zeta,
/// b - a))`, with the product by `zeta` applied by `mul`.
#[inline(always)]
fn gs(a: v128, b: v128, mul: impl Fn(v128) -> v128) -> (v128, v128) {
    (barrett_reduce(i16x8_add(a, b)), mul(i16x8_sub(b, a)))
}

/// Inverse butterflies `len = 8 * d` over `v`, with twiddles from `k` down.
#[inline(always)]
fn gs_layer<const L: usize>(v: &mut [v128; L], d: usize, mut k: usize) {
    for start in (0..L).step_by(2 * d) {
        for j in start..start + d {
            (v[j], v[j + d]) = gs(v[j], v[j + d], |x| fqmul_zeta(x, k));
        }
        k -= 1;
    }
}

/// Transposes the 64-bit halves of `(a, b)`: `([a.lo, b.lo], [a.hi, b.hi])`.
#[inline(always)]
fn trn64(a: v128, b: v128) -> (v128, v128) {
    (i64x2_shuffle::<0, 2>(a, b), i64x2_shuffle::<1, 3>(a, b))
}

/// Transposes the 32-bit lanes of `(a, b)`: `([a0, b0, a2, b2], [a1, b1,
/// a3, b3])`.
#[inline(always)]
fn trn32(a: v128, b: v128) -> (v128, v128) {
    (
        i32x4_shuffle::<0, 4, 2, 6>(a, b),
        i32x4_shuffle::<1, 5, 3, 7>(a, b),
    )
}

/// Interleaves the 32-bit lanes of `(a, b)`: `([a0, b0, a1, b1], [a2, b2,
/// a3, b3])`.
#[inline(always)]
fn zip32(a: v128, b: v128) -> (v128, v128) {
    (
        i32x4_shuffle::<0, 4, 1, 5>(a, b),
        i32x4_shuffle::<2, 6, 3, 7>(a, b),
    )
}

/// De-interleaves the 32-bit lanes of `(a, b)`: `([a0, a2, b0, b2], [a1, a3,
/// b1, b3])`, the inverse of [`zip32`].
#[inline(always)]
fn uzp32(a: v128, b: v128) -> (v128, v128) {
    (
        i32x4_shuffle::<0, 2, 4, 6>(a, b),
        i32x4_shuffle::<1, 3, 5, 7>(a, b),
    )
}

/// The forward layers `len = 4` and `len = 2` and the final reduction on
/// sixteen coefficients `(v0, v1)`, pair `p` of the polynomial.
#[inline(always)]
fn ntt_pair(v0: v128, v1: v128, p: usize) -> (v128, v128) {
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
#[inline(always)]
fn invntt_pair(v0: v128, v1: v128, p: usize) -> (v128, v128) {
    let (a, b) = uzp32(v0, v1);
    let (zeta, zeta_qinv) = twiddle(&INVNTT_LEN2[p]);
    let (a, b) = gs(a, b, |x| fqmul(x, zeta, zeta_qinv));
    let (a, b) = trn32(a, b);
    let (zeta, zeta_qinv) = twiddle(&INVNTT_LEN4[p]);
    let (a, b) = gs(a, b, |x| fqmul(x, zeta, zeta_qinv));
    trn64(a, b)
}

/// `(v[2i], v[2i + 1]) = f(v[2i], v[2i + 1], p + i)` for the four vector
/// pairs of `v`, written out: a loop is not unrolled, which leaves `v` in a
/// linear-memory stack frame.
#[inline(always)]
fn each_pair(v: &mut [v128; 8], p: usize, f: impl Fn(v128, v128, usize) -> (v128, v128)) {
    (v[0], v[1]) = f(v[0], v[1], p);
    (v[2], v[3]) = f(v[2], v[3], p + 1);
    (v[4], v[5]) = f(v[4], v[5], p + 2);
    (v[6], v[7]) = f(v[6], v[7], p + 3);
}

/// The polynomial as 32 rows of eight coefficients.
#[inline(always)]
fn rows(r: &mut Poly) -> &mut [[i16; 8]; 32] {
    r.as_chunks_mut::<8>().0.try_into().unwrap()
}

/// `mlkem_soft::ntt`.
fn ntt(r: &mut Poly) {
    let rows = rows(r);
    // Layers len = 128, 64, 32 on rows j, j + 4, ..., j + 28.
    for j in 0..4 {
        let mut v: [v128; 8] = core::array::from_fn(|m| load(&rows[j + 4 * m]));
        ct_layer(&mut v, 4, 1);
        ct_layer(&mut v, 2, 2);
        ct_layer(&mut v, 1, 4);
        for (m, v) in v.iter().enumerate() {
            store(&mut rows[j + 4 * m], *v);
        }
    }
    // Layers len = 16, 8, 4, 2 on 64 consecutive coefficients.
    for (q, rows) in rows.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut v: [v128; 8] = core::array::from_fn(|m| load(&rows[m]));
        ct_layer(&mut v, 2, 8 + 2 * q);
        ct_layer(&mut v, 1, 16 + 4 * q);
        each_pair(&mut v, 4 * q, ntt_pair);
        for (row, v) in rows.iter_mut().zip(&v) {
            store(row, *v);
        }
    }
}

/// `mlkem_soft::invntt_tomont`.
fn invntt_tomont(r: &mut Poly) {
    let rows = rows(r);
    // Layers len = 2, 4, 8, 16 on 64 consecutive coefficients.
    for (q, rows) in rows.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut v: [v128; 8] = core::array::from_fn(|m| load(&rows[m]));
        each_pair(&mut v, 4 * q, invntt_pair);
        gs_layer(&mut v, 1, 31 - 4 * q);
        gs_layer(&mut v, 2, 15 - 2 * q);
        for (row, v) in rows.iter_mut().zip(&v) {
            store(row, *v);
        }
    }
    // Layers len = 32, 64, 128 and the final scaling on rows j, j + 4, ...,
    // j + 28.
    let f = i16x8_splat(INVNTT_F);
    let f_qinv = i16x8_splat(INVNTT_F.wrapping_mul(QINV));
    for j in 0..4 {
        let mut v: [v128; 8] = core::array::from_fn(|m| load(&rows[j + 4 * m]));
        gs_layer(&mut v, 1, 7);
        gs_layer(&mut v, 2, 3);
        gs_layer(&mut v, 4, 1);
        for (m, v) in v.iter().enumerate() {
            store(&mut rows[j + 4 * m], fqmul(*v, f, f_qinv));
        }
    }
}

/// The polynomial as sixteen pairs of rows of eight coefficients.
#[inline(always)]
fn pairs(r: &Poly) -> &[[[i16; 8]; 2]; 16] {
    r.as_chunks::<8>().0.as_chunks::<2>().0.try_into().unwrap()
}

/// `mlkem_soft::basemul_acc`, sixteen coefficients at a time with the even
/// (constant) and odd (linear) coefficients of each residue de-interleaved.
fn basemul_acc<const K: usize>(r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    let split = |[lo, hi]: &[[i16; 8]; 2]| {
        let (lo, hi) = (load(lo), load(hi));
        (
            i16x8_shuffle::<0, 2, 4, 6, 8, 10, 12, 14>(lo, hi),
            i16x8_shuffle::<1, 3, 5, 7, 9, 11, 13, 15>(lo, hi),
        )
    };
    let qinv = i16x8_splat(QINV);
    let out: &mut [[[i16; 8]; 2]; 16] = r
        .as_chunks_mut::<8>()
        .0
        .as_chunks_mut::<2>()
        .0
        .try_into()
        .unwrap();
    for (p, out) in out.iter_mut().enumerate() {
        let (zeta, zeta_qinv) = twiddle(&BASEMUL[p]);
        let (mut c0, mut c1) = (i16x8_splat(0), i16x8_splat(0));
        for (a, b) in a.iter().zip(b) {
            let (a0, a1) = split(&pairs(a)[p]);
            let (b0, b1) = split(&pairs(b)[p]);
            let b0_qinv = i16x8_mul(b0, qinv);
            let b1_qinv = i16x8_mul(b1, qinv);
            let x = i16x8_add(
                fqmul(fqmul(a1, b1, b1_qinv), zeta, zeta_qinv),
                fqmul(a0, b0, b0_qinv),
            );
            let y = i16x8_add(fqmul(a0, b1, b1_qinv), fqmul(a1, b0, b0_qinv));
            c0 = i16x8_add(c0, x);
            c1 = i16x8_add(c1, y);
        }
        let (c0, c1) = (barrett_reduce(c0), barrett_reduce(c1));
        store(
            &mut out[0],
            i16x8_shuffle::<0, 8, 1, 9, 2, 10, 3, 11>(c0, c1),
        );
        store(
            &mut out[1],
            i16x8_shuffle::<4, 12, 5, 13, 6, 14, 7, 15>(c0, c1),
        );
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    #[cfg(target_os = "unknown")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::mlkem::mlkem_soft;

    /// Lane `i` of `v`.
    fn lanes(v: v128) -> [i16; 8] {
        let mut out = [0; 8];
        store(&mut out, v);
        out
    }

    /// The lane-wise reductions equal the portable scalar ones exactly over
    /// their whole input ranges: Barrett reduction of every 16-bit value,
    /// Montgomery products of every 16-bit value by every twiddle factor
    /// (either sign) and the inverse NTT scale, and of every pair of
    /// multiply-add inputs below 2^12 in magnitude (plus 4096 to fill the
    /// last vector).
    #[test]
    fn test_lanes_match_scalar_exhaustive() {
        let all: Vec<i16> = (i16::MIN..=i16::MAX).collect();
        for chunk in all.as_chunks::<8>().0 {
            let expected = chunk.map(mlkem_soft::barrett_reduce);
            assert_eq!(
                lanes(barrett_reduce(load(chunk))),
                expected,
                "barrett {chunk:?}"
            );
        }
        let mut factors: Vec<i16> = ZETAS.iter().flat_map(|&z| [z, -z]).collect();
        factors.push(INVNTT_F);
        let small: Vec<i16> = (-4095..=4096).collect();
        let pairs = factors
            .iter()
            .map(|&b| (&all, b))
            .chain((-4095..=4095).map(|b| (&small, b)));
        for (inputs, b) in pairs {
            let (bv, bq) = (i16x8_splat(b), i16x8_splat(b.wrapping_mul(QINV)));
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
}
