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
//!
//! Zeroization: the kernels work in place on the caller's polynomials, which
//! [`super`] keeps in `Zeroizing` buffers or wipes explicitly when they hold
//! secrets. The vectors of a pass live in registers and in the few spill
//! slots the compiler adds (see [`ntt_avx2_unchecked`]). Rust cannot reliably
//! wipe those, and wiping them would force the values into memory, so the
//! kernels add no wipes of their own.

use core::arch::x86_64::{
    __m256i, _mm256_add_epi16, _mm256_blend_epi16, _mm256_blend_epi32, _mm256_mulhi_epi16,
    _mm256_mullo_epi16, _mm256_permute2x128_si256, _mm256_set1_epi16, _mm256_setzero_si256,
    _mm256_slli_epi32, _mm256_slli_epi64, _mm256_srai_epi16, _mm256_srli_epi32, _mm256_srli_epi64,
    _mm256_sub_epi16, _mm256_unpackhi_epi64, _mm256_unpacklo_epi64,
};

use super::mlkem_soft::{BARRETT_V, INVNTT_F, QINV, ZETAS};
use super::{Poly, Q};
use crate::x86_64::{Avx2, load_i16s, store_i16s};

/// A vector kernel the running CPU has been verified to support: its variant
/// holds the token for the CPU feature the kernels are compiled for, which
/// is what makes the operations safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// AVX2: sixteen 16-bit lanes per `ymm` register.
    Avx2(Avx2),
}

/// The best kernel the running CPU supports.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    Avx2::new().map(Kernel::Avx2)
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
            Kernel::Avx2(avx2) => ntt_avx2(avx2, r),
        }
    }

    /// [`super::mlkem_soft::invntt_tomont`].
    #[inline]
    pub(super) fn invntt_tomont(self, r: &mut Poly) {
        match self {
            Kernel::Avx2(avx2) => invntt_tomont_avx2(avx2, r),
        }
    }

    /// [`super::mlkem_soft::basemul_acc`].
    #[inline]
    pub(super) fn basemul_acc<const K: usize>(self, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
        match self {
            Kernel::Avx2(avx2) => basemul_acc_avx2(avx2, r, a, b),
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
    ///
    /// Out of line at opt-level `z`, which adds no copy: it only reads a
    /// public twiddle table, and its result is public.
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
///
/// Out of line at opt-level `z`, which adds no copy: it only reads the
/// public twiddle table, and its result is public.
#[inline]
#[target_feature(enable = "avx2")]
fn broadcast(k: usize) -> Twiddle {
    Twiddle {
        zeta: _mm256_set1_epi16(ZETAS[k]),
        zeta_qinv: _mm256_set1_epi16(ZETAS_QINV[k]),
    }
}

/// Lane-wise `fqmul($x, $w)` for `$x: __m256i`, `$w: Twiddle`: `hi(x * w) -
/// hi(lo(x * w * q^-1) * q)`.
macro_rules! fqmul {
    ($x:expr, $w:expr) => {{
        let (x, w): (__m256i, Twiddle) = ($x, $w);
        let t = _mm256_mullo_epi16(x, w.zeta_qinv);
        _mm256_sub_epi16(
            _mm256_mulhi_epi16(x, w.zeta),
            _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q)),
        )
    }};
}

/// Lane-wise `fqmul($x, $y)` of two variables, given `$x_qinv = x * q^-1`.
macro_rules! fqmul_vars {
    ($x:expr, $x_qinv:expr, $y:expr) => {{
        let (x, x_qinv, y): (__m256i, __m256i, __m256i) = ($x, $x_qinv, $y);
        let t = _mm256_mullo_epi16(x_qinv, y);
        _mm256_sub_epi16(
            _mm256_mulhi_epi16(x, y),
            _mm256_mulhi_epi16(t, _mm256_set1_epi16(Q)),
        )
    }};
}

/// Lane-wise flooring `barrett_reduce`.
#[inline]
#[target_feature(enable = "avx2")]
fn barrett_reduce(a: __m256i) -> __m256i {
    let t = _mm256_srai_epi16::<10>(_mm256_mulhi_epi16(a, _mm256_set1_epi16(BARRETT_V)));
    _mm256_sub_epi16(a, _mm256_mullo_epi16(t, _mm256_set1_epi16(Q)))
}

/// The forward (Cooley-Tukey) butterfly `(a + t, a - t)` with `t =
/// fqmul(b, w)` on the places `$a`, `$b`.
macro_rules! ct {
    ($a:expr, $b:expr, $w:expr) => {{
        let t = fqmul!($b, $w);
        $b = _mm256_sub_epi16($a, t);
        $a = _mm256_add_epi16($a, t);
    }};
}

/// The inverse (Gentleman-Sande) butterfly `(barrett(a + b), fqmul(b - a,
/// w))` on the places `$a`, `$b`.
macro_rules! gs {
    ($a:expr, $b:expr, $w:expr) => {{
        let t = $a;
        $a = barrett_reduce(_mm256_add_epi16(t, $b));
        $b = fqmul!(_mm256_sub_epi16($b, t), $w);
    }};
}

/// Butterflies `$bf` (`ct` or `gs`) of span `$len` strided vectors over the
/// eight vectors `$v`, group `g` using `broadcast($k + g)` (`+`) or
/// `broadcast($k - g)` (`-`). Spelled out so every index is a constant;
/// see [`ntt_avx2_unchecked`].
macro_rules! strided_layer {
    ($bf:ident, $v:ident, 4, $k:literal $sign:tt) => {{
        let w = broadcast($k);
        $bf!($v[0], $v[4], w);
        $bf!($v[1], $v[5], w);
        $bf!($v[2], $v[6], w);
        $bf!($v[3], $v[7], w);
    }};
    ($bf:ident, $v:ident, 2, $k:literal $sign:tt) => {{
        let w = broadcast($k);
        $bf!($v[0], $v[2], w);
        $bf!($v[1], $v[3], w);
        let w = broadcast($k $sign 1);
        $bf!($v[4], $v[6], w);
        $bf!($v[5], $v[7], w);
    }};
    ($bf:ident, $v:ident, 1, $k:literal $sign:tt) => {{
        let w = broadcast($k);
        $bf!($v[0], $v[1], w);
        let w = broadcast($k $sign 1);
        $bf!($v[2], $v[3], w);
        let w = broadcast($k $sign 2);
        $bf!($v[4], $v[5], w);
        let w = broadcast($k $sign 3);
        $bf!($v[6], $v[7], w);
    }};
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

/// The even and odd coefficients of vector pair `$m` of `$p: &Poly`, in the
/// layout of [`Twiddles::basemul`].
macro_rules! deinterleave {
    ($p:expr, $m:expr) => {{
        let [a, b] = &pairs($p)[$m];
        let (mut even, mut odd) = (load_i16s(a), load_i16s(b));
        transpose16(&mut even, &mut odd);
        (even, odd)
    }};
}

/// Loads vector `$j` of every pair of `$r: &Poly`: vectors `j, j + 2, ..,
/// j + 14`, which the layers of span 128, 64 and 32 combine only among
/// themselves.
macro_rules! load_strided {
    ($r:expr, $j:expr) => {{
        let (pairs, j): (&[[[i16; 16]; 2]], usize) = (pairs($r), $j);
        [
            load_i16s(&pairs[0][j]),
            load_i16s(&pairs[1][j]),
            load_i16s(&pairs[2][j]),
            load_i16s(&pairs[3][j]),
            load_i16s(&pairs[4][j]),
            load_i16s(&pairs[5][j]),
            load_i16s(&pairs[6][j]),
            load_i16s(&pairs[7][j]),
        ]
    }};
}

/// Stores the eight vectors `$v` as vector `$j` of every pair of `$r: &mut
/// Poly`, the reverse of `load_strided!`.
macro_rules! store_strided {
    ($r:expr, $j:expr, $v:expr) => {{
        let [v0, v1, v2, v3, v4, v5, v6, v7]: [__m256i; 8] = $v;
        let (pairs, j): (&mut [[[i16; 16]; 2]], usize) = (pairs_mut($r), $j);
        store_i16s(&mut pairs[0][j], v0);
        store_i16s(&mut pairs[1][j], v1);
        store_i16s(&mut pairs[2][j], v2);
        store_i16s(&mut pairs[3][j], v3);
        store_i16s(&mut pairs[4][j], v4);
        store_i16s(&mut pairs[5][j], v5);
        store_i16s(&mut pairs[6][j], v6);
        store_i16s(&mut pairs[7][j], v7);
    }};
}

/// `mlkem_soft::ntt`.
///
/// The strided pass is spelled out, and the butterflies, Montgomery
/// products and strided loads and stores are macros: at opt-level `z` LLVM
/// kept the `#[inline]` helpers out of line and handed them the
/// coefficient vectors (copies of secret coefficients) through the stack,
/// and at `z`, `s` and `2` the rolled layer loops kept the strided vectors
/// in stack memory nothing wipes. The twiddle helpers, still out of line at
/// `z`, only produce public vectors; the coefficient vectors live across
/// those calls in spill slots.
#[target_feature(enable = "avx2")]
fn ntt_avx2_unchecked(r: &mut Poly) {
    // Spans 128, 64 and 32 on each strided half, in registers: span `len`
    // strided vectors has `4 / len` groups, the first using `ZETAS[4 / len]`.
    for j in 0..2 {
        let mut v = load_strided!(r, j);
        strided_layer!(ct, v, 4, 1 +);
        strided_layer!(ct, v, 2, 2 +);
        strided_layer!(ct, v, 1, 4 +);
        store_strided!(r, j, v);
    }
    // Spans 16, 8, 4 and 2 and the final reduction on each pair.
    for (m, [a_row, b_row]) in pairs_mut(r).iter_mut().enumerate() {
        let (mut a, mut b) = (load_i16s(a_row), load_i16s(b_row));
        let (a, b) = (&mut a, &mut b);
        ct!(*a, *b, broadcast(8 + m));
        transpose128(a, b);
        ct!(*a, *b, NTT_LEN8.get(m));
        transpose64(a, b);
        ct!(*a, *b, NTT_LEN4.get(m));
        transpose32(a, b);
        ct!(*a, *b, NTT_LEN2.get(m));
        *a = barrett_reduce(*a);
        *b = barrett_reduce(*b);
        transpose32(a, b);
        transpose64(a, b);
        transpose128(a, b);
        store_i16s(a_row, *a);
        store_i16s(b_row, *b);
    }
}

/// [`ntt_avx2_unchecked`], safe to call with an [`Avx2`] token.
#[inline(always)]
fn ntt_avx2(_: Avx2, r: &mut Poly) {
    // SAFETY: an `Avx2` token exists only after detection of `avx2`,
    // the feature the kernel is compiled for.
    unsafe { ntt_avx2_unchecked(r) }
}

/// `mlkem_soft::invntt_tomont`, spelled out like [`ntt_avx2_unchecked`].
#[target_feature(enable = "avx2")]
fn invntt_tomont_avx2_unchecked(r: &mut Poly) {
    // Spans 2, 4, 8 and 16 on each pair.
    for (m, [a_row, b_row]) in pairs_mut(r).iter_mut().enumerate() {
        let (mut a, mut b) = (load_i16s(a_row), load_i16s(b_row));
        let (a, b) = (&mut a, &mut b);
        transpose128(a, b);
        transpose64(a, b);
        transpose32(a, b);
        gs!(*a, *b, INVNTT_LEN2.get(m));
        transpose32(a, b);
        gs!(*a, *b, INVNTT_LEN4.get(m));
        transpose64(a, b);
        gs!(*a, *b, INVNTT_LEN8.get(m));
        transpose128(a, b);
        gs!(*a, *b, broadcast(15 - m));
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
        let mut v = load_strided!(r, j);
        strided_layer!(gs, v, 1, 7 -);
        strided_layer!(gs, v, 2, 3 -);
        strided_layer!(gs, v, 4, 1 -);
        let [v0, v1, v2, v3, v4, v5, v6, v7] = v;
        store_strided!(
            r,
            j,
            [
                fqmul!(v0, f),
                fqmul!(v1, f),
                fqmul!(v2, f),
                fqmul!(v3, f),
                fqmul!(v4, f),
                fqmul!(v5, f),
                fqmul!(v6, f),
                fqmul!(v7, f),
            ]
        );
    }
}

/// [`invntt_tomont_avx2_unchecked`], safe to call with an [`Avx2`] token.
#[inline(always)]
fn invntt_tomont_avx2(_: Avx2, r: &mut Poly) {
    // SAFETY: an `Avx2` token exists only after detection of `avx2`,
    // the feature the kernel is compiled for.
    unsafe { invntt_tomont_avx2_unchecked(r) }
}

/// `mlkem_soft::basemul_acc`, with the de-interleaving and the products as
/// macros like [`ntt_avx2_unchecked`]'s.
#[target_feature(enable = "avx2")]
fn basemul_acc_avx2_unchecked<const K: usize>(r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    let qinv = _mm256_set1_epi16(QINV);
    for (m, [r0, r1]) in pairs_mut(r).iter_mut().enumerate() {
        let w = BASEMUL.get(m);
        let (mut c0, mut c1) = (_mm256_setzero_si256(), _mm256_setzero_si256());
        for (a, b) in a.iter().zip(b) {
            let (a0, a1) = deinterleave!(a, m);
            let (b0, b1) = deinterleave!(b, m);
            let (a0_qinv, a1_qinv) = (_mm256_mullo_epi16(a0, qinv), _mm256_mullo_epi16(a1, qinv));
            let even = _mm256_add_epi16(
                fqmul!(fqmul_vars!(a1, a1_qinv, b1), w),
                fqmul_vars!(a0, a0_qinv, b0),
            );
            let odd = _mm256_add_epi16(fqmul_vars!(a0, a0_qinv, b1), fqmul_vars!(a1, a1_qinv, b0));
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

/// [`basemul_acc_avx2_unchecked`], safe to call with an [`Avx2`] token.
#[inline(always)]
fn basemul_acc_avx2<const K: usize>(_: Avx2, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    // SAFETY: an `Avx2` token exists only after detection of `avx2`,
    // the feature the kernel is compiled for.
    unsafe { basemul_acc_avx2_unchecked::<K>(r, a, b) }
}
