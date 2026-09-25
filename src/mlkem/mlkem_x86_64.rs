//! AVX2 ML-KEM polynomial arithmetic.
//!
//! A polynomial is sixteen vectors of sixteen 16-bit coefficients, vector
//! `i` holding coefficients `16 * i .. 16 * i + 16`. Each lane computes the
//! portable code's formulas: the Montgomery product is `hi(x * zeta) -
//! hi(lo(x * zeta * q^-1) * q)` from `vpmullw`/`vpmulhw` (with `zeta * q^-1`
//! precomputed), and the Barrett quotient is `vpmulhw` by the multiplier
//! followed by an arithmetic shift of 10, so every coefficient matches
//! `mlkem_soft.rs` exactly.
//!
//! Each NTT runs in two register-resident passes over memory. The layers
//! of span 128, 64 and 32 pair whole vectors and only combine vectors of
//! the same parity, so they run on the eight even and then the eight odd
//! vectors. The layers of span 16, 8, 4 and 2 stay within one pair of
//! vectors (32 coefficients): 2x2 transposes of 128-, 64- and 32-bit
//! blocks between the two vectors bring the butterfly partners into
//! matching lanes, with per-lane twiddle tables laid out to match, and the
//! same transposes (each is its own inverse) restore the natural order
//! before the pair is stored. The base multiplication splits each vector pair
//! into even and odd coefficients with 16-bit transposes, keeps the sum in
//! that layout and interleaves once at the end. No layout leaks out of an
//! operation, and control flow and memory access are independent of the
//! data.

use core::arch::x86_64::{
    __m256i, _mm256_add_epi16, _mm256_blend_epi16, _mm256_blend_epi32, _mm256_mulhi_epi16,
    _mm256_mullo_epi16, _mm256_permute2x128_si256, _mm256_set1_epi16, _mm256_setzero_si256,
    _mm256_slli_epi32, _mm256_slli_epi64, _mm256_srai_epi16, _mm256_srli_epi32, _mm256_srli_epi64,
    _mm256_sub_epi16, _mm256_unpackhi_epi64, _mm256_unpacklo_epi64,
};

use super::mlkem_soft::{BARRETT_V, INVNTT_F, QINV, ZETAS};
use super::{Poly, Q};
use crate::x86_64::{load_i16s, store_i16s};

/// A vector kernel the running CPU has been verified to support.
///
/// Values are only created by [`detect`] after checking the CPU features the
/// kernels are compiled for, which is what makes the operations safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// AVX2: sixteen 16-bit lanes per `ymm` register.
    Avx2,
}

/// The best kernel the running CPU supports.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    if has_x86_feature!("avx2") {
        Some(Kernel::Avx2)
    } else {
        None
    }
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        detect().into_iter().collect()
    }

    /// [`super::mlkem_soft::ntt`].
    #[inline]
    pub(super) fn ntt(self, r: &mut Poly) {
        match self {
            // SAFETY: `Kernel::Avx2` is only constructed after
            // `has_x86_feature!("avx2")` succeeded.
            Kernel::Avx2 => unsafe { ntt_avx2(r) },
        }
    }

    /// [`super::mlkem_soft::invntt_tomont`].
    #[inline]
    pub(super) fn invntt_tomont(self, r: &mut Poly) {
        match self {
            // SAFETY: `Kernel::Avx2` is only constructed after
            // `has_x86_feature!("avx2")` succeeded.
            Kernel::Avx2 => unsafe { invntt_tomont_avx2(r) },
        }
    }

    /// [`super::mlkem_soft::basemul_acc`].
    #[inline]
    pub(super) fn basemul_acc<const K: usize>(self, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
        match self {
            // SAFETY: `Kernel::Avx2` is only constructed after
            // `has_x86_feature!("avx2")` succeeded.
            Kernel::Avx2 => unsafe { basemul_acc_avx2(r, a, b) },
        }
    }
}

/// `ZETAS[i] * q^-1 mod 2^16`, the low-product factor of each twiddle.
static ZETAS_QINV: [i16; 128] = {
    let mut table = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = ZETAS[i].wrapping_mul(QINV);
        i += 1;
    }
    table
};

/// Per-lane twiddle factors for one layer, one row per vector pair
/// `m in 0..8` (coefficients `32 * m .. 32 * m + 32`), with each factor's
/// `* q^-1` companion.
struct Twiddles {
    zeta: [[i16; 16]; 8],
    zeta_qinv: [[i16; 16]; 8],
}

impl Twiddles {
    /// The twiddles of the NTT layer (`inverse = false`) or inverse NTT
    /// layer (`inverse = true`) of butterfly span `len` in `{2, 4, 8}`, for
    /// the transposed layout that layer runs in: lanes `len * i ..
    /// len * i + len` of pair `m` belong to butterfly group `16 / len * m +
    /// i`, which uses `ZETAS[256 / len - 1 - group]` in the inverse NTT and
    /// `ZETAS[128 / len + group]` in the forward one, as in the portable
    /// loops.
    const fn layer(len: usize, inverse: bool) -> Self {
        let mut zeta = [[0i16; 16]; 8];
        let mut m = 0;
        while m < 8 {
            let mut lane = 0;
            while lane < 16 {
                let group = 16 / len * m + lane / len;
                zeta[m][lane] = if inverse {
                    ZETAS[256 / len - 1 - group]
                } else {
                    ZETAS[128 / len + group]
                };
                lane += 1;
            }
            m += 1;
        }
        Self::with_qinv(zeta)
    }

    /// The base-multiplication twiddles in the even/odd layout of
    /// [`deinterleave`]: lane `2 * t` of pair `m` is coefficient pair `16 *
    /// m + t` and lane `2 * t + 1` is pair `16 * m + 8 + t`; pair `p` uses
    /// `ZETAS[64 + p / 2]`, negated for odd `p`.
    const fn basemul() -> Self {
        let mut zeta = [[0i16; 16]; 8];
        let mut m = 0;
        while m < 8 {
            let mut lane = 0;
            while lane < 16 {
                let pair = 16 * m + 8 * (lane % 2) + lane / 2;
                let z = ZETAS[64 + pair / 2];
                zeta[m][lane] = if pair % 2 == 0 { z } else { -z };
                lane += 1;
            }
            m += 1;
        }
        Self::with_qinv(zeta)
    }

    const fn with_qinv(zeta: [[i16; 16]; 8]) -> Self {
        let mut zeta_qinv = [[0i16; 16]; 8];
        let mut m = 0;
        while m < 8 {
            let mut lane = 0;
            while lane < 16 {
                zeta_qinv[m][lane] = zeta[m][lane].wrapping_mul(QINV);
                lane += 1;
            }
            m += 1;
        }
        Self { zeta, zeta_qinv }
    }

    /// The twiddle vectors of pair `m`.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn get(&self, m: usize) -> Twiddle {
        Twiddle {
            zeta: load_i16s(&self.zeta[m]),
            zeta_qinv: load_i16s(&self.zeta_qinv[m]),
        }
    }
}

static NTT_LEN8: Twiddles = Twiddles::layer(8, false);
static NTT_LEN4: Twiddles = Twiddles::layer(4, false);
static NTT_LEN2: Twiddles = Twiddles::layer(2, false);
static INVNTT_LEN2: Twiddles = Twiddles::layer(2, true);
static INVNTT_LEN4: Twiddles = Twiddles::layer(4, true);
static INVNTT_LEN8: Twiddles = Twiddles::layer(8, true);
static BASEMUL: Twiddles = Twiddles::basemul();

/// A multiplier vector and its `* q^-1` companion.
#[derive(Clone, Copy)]
struct Twiddle {
    zeta: __m256i,
    zeta_qinv: __m256i,
}

/// `ZETAS[k]` in every lane.
#[inline]
#[target_feature(enable = "avx2")]
fn broadcast(k: usize) -> Twiddle {
    Twiddle {
        zeta: _mm256_set1_epi16(ZETAS[k]),
        zeta_qinv: _mm256_set1_epi16(ZETAS_QINV[k]),
    }
}

/// Lane-wise `fqmul(x, w)`: `hi(x * w) - hi(lo(x * w * q^-1) * q)`.
#[inline]
#[target_feature(enable = "avx2")]
fn fqmul(x: __m256i, w: Twiddle) -> __m256i {
    let t = _mm256_mullo_epi16(x, w.zeta_qinv);
    _mm256_sub_epi16(
        _mm256_mulhi_epi16(x, w.zeta),
        _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q)),
    )
}

/// Lane-wise `fqmul(x, y)` of two variables, given `x_qinv = x * q^-1`.
#[inline]
#[target_feature(enable = "avx2")]
fn fqmul_vars(x: __m256i, x_qinv: __m256i, y: __m256i) -> __m256i {
    let t = _mm256_mullo_epi16(x_qinv, y);
    _mm256_sub_epi16(
        _mm256_mulhi_epi16(x, y),
        _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q)),
    )
}

/// Lane-wise flooring `barrett_reduce`.
#[inline]
#[target_feature(enable = "avx2")]
fn barrett_reduce(a: __m256i) -> __m256i {
    let t = _mm256_srai_epi16::<10>(_mm256_mulhi_epi16(a, _mm256_set1_epi16(BARRETT_V)));
    _mm256_sub_epi16(a, _mm256_mullo_epi16(t, _mm256_set1_epi16(Q)))
}

/// The forward (Cooley-Tukey) butterfly `(a + t, a - t)` with `t =
/// fqmul(b, w)`.
#[inline]
#[target_feature(enable = "avx2")]
fn ct(a: &mut __m256i, b: &mut __m256i, w: Twiddle) {
    let t = fqmul(*b, w);
    *b = _mm256_sub_epi16(*a, t);
    *a = _mm256_add_epi16(*a, t);
}

/// The inverse (Gentleman-Sande) butterfly `(barrett(a + b), fqmul(b - a,
/// w))`.
#[inline]
#[target_feature(enable = "avx2")]
fn gs(a: &mut __m256i, b: &mut __m256i, w: Twiddle) {
    let t = *a;
    *a = barrett_reduce(_mm256_add_epi16(t, *b));
    *b = fqmul(_mm256_sub_epi16(*b, t), w);
}

/// Swaps the high 128-bit half of `a` with the low half of `b`.
#[inline]
#[target_feature(enable = "avx2")]
fn transpose128(a: &mut __m256i, b: &mut __m256i) {
    let (x, y) = (*a, *b);
    *a = _mm256_permute2x128_si256::<0x20>(x, y);
    *b = _mm256_permute2x128_si256::<0x31>(x, y);
}

/// Swaps the odd 64-bit blocks of `a` with the even blocks of `b`.
#[inline]
#[target_feature(enable = "avx2")]
fn transpose64(a: &mut __m256i, b: &mut __m256i) {
    let (x, y) = (*a, *b);
    *a = _mm256_unpacklo_epi64(x, y);
    *b = _mm256_unpackhi_epi64(x, y);
}

/// Swaps the odd 32-bit blocks of `a` with the even blocks of `b`.
#[inline]
#[target_feature(enable = "avx2")]
fn transpose32(a: &mut __m256i, b: &mut __m256i) {
    let (x, y) = (*a, *b);
    *a = _mm256_blend_epi32::<0xAA>(x, _mm256_slli_epi64::<32>(y));
    *b = _mm256_blend_epi32::<0xAA>(_mm256_srli_epi64::<32>(x), y);
}

/// Swaps the odd 16-bit lanes of `a` with the even lanes of `b`: from
/// natural order, `a` gets the even and `b` the odd coefficients.
#[inline]
#[target_feature(enable = "avx2")]
fn transpose16(a: &mut __m256i, b: &mut __m256i) {
    let (x, y) = (*a, *b);
    *a = _mm256_blend_epi16::<0xAA>(x, _mm256_slli_epi32::<16>(y));
    *b = _mm256_blend_epi16::<0xAA>(_mm256_srli_epi32::<16>(x), y);
}

/// The polynomial as eight pairs of 16-lane rows (coefficients `32 * m ..
/// 32 * m + 16` and `32 * m + 16 .. 32 * m + 32`).
#[inline(always)]
fn pairs(p: &Poly) -> &[[[i16; 16]; 2]] {
    p.as_chunks::<16>().0.as_chunks::<2>().0
}

#[inline(always)]
fn pairs_mut(p: &mut Poly) -> &mut [[[i16; 16]; 2]] {
    p.as_chunks_mut::<16>().0.as_chunks_mut::<2>().0
}

/// The even and odd coefficients of vector pair `m` of `p`, in the layout
/// of [`Twiddles::basemul`].
#[inline]
#[target_feature(enable = "avx2")]
fn deinterleave(p: &Poly, m: usize) -> (__m256i, __m256i) {
    let [a, b] = &pairs(p)[m];
    let (mut even, mut odd) = (load_i16s(a), load_i16s(b));
    transpose16(&mut even, &mut odd);
    (even, odd)
}

/// Loads vector `j` of every pair: vectors `j, j + 2, .., j + 14`, which
/// the layers of span 128, 64 and 32 combine only among themselves.
#[inline]
#[target_feature(enable = "avx2")]
fn load_strided(r: &Poly, j: usize) -> [__m256i; 8] {
    let mut v = [_mm256_setzero_si256(); 8];
    for (v, pair) in v.iter_mut().zip(pairs(r)) {
        *v = load_i16s(&pair[j]);
    }
    v
}

#[inline]
#[target_feature(enable = "avx2")]
fn store_strided(r: &mut Poly, j: usize, v: [__m256i; 8]) {
    for (v, pair) in v.into_iter().zip(pairs_mut(r)) {
        store_i16s(&mut pair[j], v);
    }
}

#[target_feature(enable = "avx2")]
fn ntt_avx2(r: &mut Poly) {
    // Spans 128, 64 and 32 on each strided half, in registers: span `len`
    // strided vectors has `4 / len` groups, the first using `ZETAS[4 / len]`.
    for j in 0..2 {
        let mut v = load_strided(r, j);
        for len in [4, 2, 1] {
            for (g, group) in v.chunks_exact_mut(2 * len).enumerate() {
                let w = broadcast(4 / len + g);
                let (lo, hi) = group.split_at_mut(len);
                for (a, b) in lo.iter_mut().zip(hi) {
                    ct(a, b, w);
                }
            }
        }
        store_strided(r, j, v);
    }
    // Spans 16, 8, 4 and 2 and the final reduction on each pair.
    for (m, [a_row, b_row]) in pairs_mut(r).iter_mut().enumerate() {
        let (mut a, mut b) = (load_i16s(a_row), load_i16s(b_row));
        let (a, b) = (&mut a, &mut b);
        ct(a, b, broadcast(8 + m));
        transpose128(a, b);
        ct(a, b, NTT_LEN8.get(m));
        transpose64(a, b);
        ct(a, b, NTT_LEN4.get(m));
        transpose32(a, b);
        ct(a, b, NTT_LEN2.get(m));
        *a = barrett_reduce(*a);
        *b = barrett_reduce(*b);
        transpose32(a, b);
        transpose64(a, b);
        transpose128(a, b);
        store_i16s(a_row, *a);
        store_i16s(b_row, *b);
    }
}

#[target_feature(enable = "avx2")]
fn invntt_tomont_avx2(r: &mut Poly) {
    // Spans 2, 4, 8 and 16 on each pair.
    for (m, [a_row, b_row]) in pairs_mut(r).iter_mut().enumerate() {
        let (mut a, mut b) = (load_i16s(a_row), load_i16s(b_row));
        let (a, b) = (&mut a, &mut b);
        transpose128(a, b);
        transpose64(a, b);
        transpose32(a, b);
        gs(a, b, INVNTT_LEN2.get(m));
        transpose32(a, b);
        gs(a, b, INVNTT_LEN4.get(m));
        transpose64(a, b);
        gs(a, b, INVNTT_LEN8.get(m));
        transpose128(a, b);
        gs(a, b, broadcast(15 - m));
        store_i16s(a_row, *a);
        store_i16s(b_row, *b);
    }
    // Spans 32, 64 and 128 and the final scaling on each strided half:
    // span `len` strided vectors has `4 / len` groups, the first using
    // `ZETAS[8 / len - 1]` and the rest counting down.
    let f = Twiddle {
        zeta: _mm256_set1_epi16(INVNTT_F),
        zeta_qinv: _mm256_set1_epi16(INVNTT_F.wrapping_mul(QINV)),
    };
    for j in 0..2 {
        let mut v = load_strided(r, j);
        for len in [1, 2, 4] {
            for (g, group) in v.chunks_exact_mut(2 * len).enumerate() {
                let w = broadcast(8 / len - 1 - g);
                let (lo, hi) = group.split_at_mut(len);
                for (a, b) in lo.iter_mut().zip(hi) {
                    gs(a, b, w);
                }
            }
        }
        for x in &mut v {
            *x = fqmul(*x, f);
        }
        store_strided(r, j, v);
    }
}

#[target_feature(enable = "avx2")]
fn basemul_acc_avx2<const K: usize>(r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    let qinv = _mm256_set1_epi16(QINV);
    for (m, [r0, r1]) in pairs_mut(r).iter_mut().enumerate() {
        let w = BASEMUL.get(m);
        let (mut c0, mut c1) = (_mm256_setzero_si256(), _mm256_setzero_si256());
        for (a, b) in a.iter().zip(b) {
            let (a0, a1) = deinterleave(a, m);
            let (b0, b1) = deinterleave(b, m);
            let (a0_qinv, a1_qinv) = (_mm256_mullo_epi16(a0, qinv), _mm256_mullo_epi16(a1, qinv));
            let even = _mm256_add_epi16(
                fqmul(fqmul_vars(a1, a1_qinv, b1), w),
                fqmul_vars(a0, a0_qinv, b0),
            );
            let odd = _mm256_add_epi16(fqmul_vars(a0, a0_qinv, b1), fqmul_vars(a1, a1_qinv, b0));
            c0 = _mm256_add_epi16(c0, even);
            c1 = _mm256_add_epi16(c1, odd);
        }
        c0 = barrett_reduce(c0);
        c1 = barrett_reduce(c1);
        transpose16(&mut c0, &mut c1);
        store_i16s(r0, c0);
        store_i16s(r1, c1);
    }
}
