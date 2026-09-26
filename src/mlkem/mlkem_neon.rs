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
//! of the arithmetic is independent of the coefficients; only the
//! rejection sampler of the public matrix ([`rej_uniform_unchecked`])
//! branches on and indexes a shuffle table by its candidates.
//!
//! Zeroization: the kernels load rows of the caller's polynomial, transform
//! them in vector registers and store them back in place. The polynomials
//! belong to [`super`], which keeps secret ones in `Zeroizing` buffers or
//! wipes them explicitly. The NTT's vector arrays are indexed only by
//! constants (see [`ntt_unchecked`]) and stay in registers and spill slots.
//! Rust cannot reliably wipe those, and wiping them would force them into
//! memory, so the kernels add no wipes of their own.

use core::arch::aarch64::{
    int16x8_t, uint8x16_t, uint16x8_t, vaddq_s16, vaddvq_u16, vandq_u16, vcltq_u16, vdup_n_u16,
    vdupq_n_s16, vdupq_n_u16, vget_low_u16, vhsubq_s16, vld1q_s16, vld1q_u8, vld1q_u16,
    vmlsq_n_s16, vmull_high_u16, vmull_u16, vmulq_n_s16, vmulq_s16, vqdmulhq_n_s16, vqdmulhq_s16,
    vqtbl1q_u8, vreinterpretq_s16_s32, vreinterpretq_s16_s64, vreinterpretq_s16_u8,
    vreinterpretq_s16_u16, vreinterpretq_s32_s16, vreinterpretq_s64_s16, vreinterpretq_u8_u16,
    vreinterpretq_u16_s16, vreinterpretq_u16_u8, vrshrn_high_n_u32, vrshrn_n_u32, vshlq_u16,
    vshrq_n_s16, vst1q_s16, vsubq_s16, vtrn1q_s32, vtrn1q_s64, vtrn2q_s32, vtrn2q_s64, vuzp1q_s16,
    vuzp1q_s32, vuzp2q_s16, vuzp2q_s32, vzip1q_s16, vzip1q_s32, vzip2q_s16, vzip2q_s32,
};

use super::mlkem_soft::{BARRETT_V, INVNTT_F, QINV, R2, ZETAS};
use super::{N, Poly, Q};
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

    #[inline]
    pub(super) fn basemul_rows<const K: usize, const R: usize>(
        self,
        r: [&mut Poly; R],
        a: [&[Poly; K]; R],
        b: &[Poly; K],
    ) {
        basemul_rows(self.0, r, a, b)
    }

    #[inline]
    pub(super) fn reduce(self, r: &mut Poly) {
        reduce(self.0, r)
    }

    /// `super::poly_to_msg` of a Barrett-reduced polynomial.
    #[inline]
    pub(super) fn poly_to_msg(self, m: &mut [u8; 32], a: &Poly) {
        poly_to_msg(self.0, m, a)
    }

    /// `super::decompress_u` on the coefficients as rows of eight, from ten
    /// bytes each.
    #[inline]
    pub(super) fn decompress10(self, rows: &mut [[i16; 8]], bytes: &[u8]) {
        decompress10(self.0, rows, bytes)
    }

    #[inline]
    pub(super) fn add_reduce<const M: usize>(self, r: &mut Poly, addends: [&Poly; M]) {
        add_reduce(self.0, r, addends)
    }

    #[inline]
    pub(super) fn tomont_add_reduce(self, r: &mut Poly, a: &Poly) {
        tomont_add_reduce(self.0, r, a)
    }

    /// The bulk of `super::rej_uniform`: samples from the start of `bytes`
    /// while whole eight-candidate groups fit, and returns how many bytes it
    /// consumed (a multiple of three) for the scalar loop to finish.
    #[inline]
    pub(super) fn rej_uniform(self, poly: &mut Poly, filled: &mut usize, bytes: &[u8]) -> usize {
        rej_uniform(self.0, poly, filled, bytes)
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

/// Lane-wise `fqmul($a, ZETAS[$k])` for `$a: int16x8_t`, `$k: usize`.
macro_rules! fqmul_zeta {
    ($a:expr, $k:expr) => {{
        let (a, k): (int16x8_t, usize) = ($a, $k);
        let t = vmulq_n_s16(a, ZETAS_QINV[k]);
        vhsubq_s16(vqdmulhq_n_s16(a, ZETAS[k]), vqdmulhq_n_s16(t, Q))
    }};
}

/// Lane-wise flooring `barrett_reduce`.
#[inline]
#[target_feature(enable = "neon")]
fn barrett_reduce(a: int16x8_t) -> int16x8_t {
    let t = vshrq_n_s16::<11>(vqdmulhq_n_s16(a, BARRETT_V));
    vmlsq_n_s16(a, t, Q)
}

/// `super::poly_reduce`: every coefficient through [`barrett_reduce`],
/// eight at a time.
#[target_feature(enable = "neon")]
fn reduce_unchecked(r: &mut Poly) {
    for row in rows(r) {
        store(row, barrett_reduce(load(row)));
    }
}

/// `super::poly_add_assign` of each of `addends`, then `super::poly_reduce`,
/// in one pass.
#[target_feature(enable = "neon")]
fn add_reduce_unchecked<const M: usize>(r: &mut Poly, addends: [&Poly; M]) {
    let addends = addends.map(|a| a.as_chunks::<8>().0);
    for (i, row) in rows(r).iter_mut().enumerate() {
        let mut x = load(row);
        for a in &addends {
            x = vaddq_s16(x, load(&a[i]));
        }
        store(row, barrett_reduce(x));
    }
}

/// [`add_reduce_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn add_reduce<const M: usize>(_: Neon, r: &mut Poly, addends: [&Poly; M]) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { add_reduce_unchecked::<M>(r, addends) }
}

/// `super::poly_tomont`, `super::poly_add_assign` of `a` and
/// `super::poly_reduce`, in one pass.
#[target_feature(enable = "neon")]
fn tomont_add_reduce_unchecked(r: &mut Poly, a: &Poly) {
    let (r2, r2_qinv) = (vdupq_n_s16(R2), vdupq_n_s16(R2.wrapping_mul(QINV)));
    for (row, a) in rows(r).iter_mut().zip(a.as_chunks::<8>().0) {
        let x = vaddq_s16(fqmul(load(row), r2, r2_qinv), load(a));
        store(row, barrett_reduce(x));
    }
}

/// [`tomont_add_reduce_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn tomont_add_reduce(_: Neon, r: &mut Poly, a: &Poly) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { tomont_add_reduce_unchecked(r, a) }
}

/// [`reduce_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn reduce(_: Neon, r: &mut Poly) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { reduce_unchecked(r) }
}

/// Forward (Cooley-Tukey) butterfly `(a + t, a - t)` with `t = fqmul(zeta,
/// b)` for the partner `b` of `a`.
#[inline]
#[target_feature(enable = "neon")]
fn ct(a: int16x8_t, t: int16x8_t) -> (int16x8_t, int16x8_t) {
    (vaddq_s16(a, t), vsubq_s16(a, t))
}

/// Forward butterflies `len = 8 * $d` over the eight vectors `$v`, with
/// twiddles from `$k` on. Spelled out so every index is a constant; see
/// [`ntt_unchecked`].
macro_rules! ct_layer {
    (@butterflies $v:ident, $k:expr; $($j:literal $partner:literal),+) => {
        $(($v[$j], $v[$partner]) = ct($v[$j], fqmul_zeta!($v[$partner], $k));)+
    };
    ($v:ident, 4, $k:expr) => {{
        let k: usize = $k;
        ct_layer!(@butterflies $v, k; 0 4, 1 5, 2 6, 3 7);
    }};
    ($v:ident, 2, $k:expr) => {{
        let k: usize = $k;
        ct_layer!(@butterflies $v, k; 0 2, 1 3);
        ct_layer!(@butterflies $v, k + 1; 4 6, 5 7);
    }};
    ($v:ident, 1, $k:expr) => {{
        let k: usize = $k;
        ct_layer!(@butterflies $v, k; 0 1);
        ct_layer!(@butterflies $v, k + 1; 2 3);
        ct_layer!(@butterflies $v, k + 2; 4 5);
        ct_layer!(@butterflies $v, k + 3; 6 7);
    }};
}

/// Inverse (Gentleman-Sande) butterfly without its product by `zeta`:
/// `(barrett_reduce(a + b), b - a)`, the second of which the caller
/// multiplies by the twiddle.
#[inline]
#[target_feature(enable = "neon")]
fn gs(a: int16x8_t, b: int16x8_t) -> (int16x8_t, int16x8_t) {
    (barrett_reduce(vaddq_s16(a, b)), vsubq_s16(b, a))
}

/// Inverse butterflies `len = 8 * $d` over the eight vectors `$v`, with
/// twiddles from `$k` down. Spelled out like `ct_layer!`.
macro_rules! gs_layer {
    (@butterflies $v:ident, $k:expr; $($j:literal $partner:literal),+) => {
        $({
            let (sum, difference) = gs($v[$j], $v[$partner]);
            ($v[$j], $v[$partner]) = (sum, fqmul_zeta!(difference, $k));
        })+
    };
    ($v:ident, 4, $k:expr) => {{
        let k: usize = $k;
        gs_layer!(@butterflies $v, k; 0 4, 1 5, 2 6, 3 7);
    }};
    ($v:ident, 2, $k:expr) => {{
        let k: usize = $k;
        gs_layer!(@butterflies $v, k; 0 2, 1 3);
        gs_layer!(@butterflies $v, k - 1; 4 6, 5 7);
    }};
    ($v:ident, 1, $k:expr) => {{
        let k: usize = $k;
        gs_layer!(@butterflies $v, k; 0 1);
        gs_layer!(@butterflies $v, k - 1; 2 3);
        gs_layer!(@butterflies $v, k - 2; 4 5);
        gs_layer!(@butterflies $v, k - 3; 6 7);
    }};
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
/// the sixteen coefficients `($v[$lo], $v[$hi])`, pair `$p` of the
/// polynomial. A macro like `ct_layer!`.
macro_rules! ntt_pair {
    ($v:ident, $lo:literal $hi:literal, $p:expr) => {{
        let p: usize = $p;
        // `a` holds coefficients 0..4 and 8..12, `b` their partners 4..8 and
        // 12..16.
        let (a, b) = trn64($v[$lo], $v[$hi]);
        let (zeta, zeta_qinv) = twiddle(&NTT_LEN4[p]);
        let (a, b) = ct(a, fqmul(b, zeta, zeta_qinv));
        // As 32-bit lanes, `a` holds coefficient pairs 0, 4, 8, 12 (each the
        // first half of a block of four) and `b` pairs 2, 6, 10, 14.
        let (a, b) = trn32(a, b);
        let (zeta, zeta_qinv) = twiddle(&NTT_LEN2[p]);
        let (a, b) = ct(a, fqmul(b, zeta, zeta_qinv));
        ($v[$lo], $v[$hi]) = zip32(barrett_reduce(a), barrett_reduce(b));
    }};
}

/// The inverse layers `len = 2` and `len = 4` on the sixteen coefficients
/// `($v[$lo], $v[$hi])`, pair `$p` of the polynomial: the reverse of
/// `ntt_pair!`.
macro_rules! invntt_pair {
    ($v:ident, $lo:literal $hi:literal, $p:expr) => {{
        let p: usize = $p;
        let (a, b) = uzp32($v[$lo], $v[$hi]);
        let (zeta, zeta_qinv) = twiddle(&INVNTT_LEN2[p]);
        let (a, b) = gs(a, b);
        let b = fqmul(b, zeta, zeta_qinv);
        let (a, b) = trn32(a, b);
        let (zeta, zeta_qinv) = twiddle(&INVNTT_LEN4[p]);
        let (a, b) = gs(a, b);
        let b = fqmul(b, zeta, zeta_qinv);
        ($v[$lo], $v[$hi]) = trn64(a, b);
    }};
}

/// The polynomial as 32 rows of eight coefficients.
#[inline]
fn rows(r: &mut Poly) -> &mut [[i16; 8]; 32] {
    r.as_chunks_mut::<8>().0.try_into().unwrap()
}

/// The eight rows `$rows[$j + $s * m]`, `m in 0..8`, as vectors. Spelled
/// out so every index into the vectors is a constant; see [`ntt_unchecked`].
macro_rules! load_rows {
    ($rows:ident, $j:expr, $s:literal) => {{
        let j: usize = $j;
        [
            load(&$rows[j]),
            load(&$rows[j + $s]),
            load(&$rows[j + 2 * $s]),
            load(&$rows[j + 3 * $s]),
            load(&$rows[j + 4 * $s]),
            load(&$rows[j + 5 * $s]),
            load(&$rows[j + 6 * $s]),
            load(&$rows[j + 7 * $s]),
        ]
    }};
}

/// Stores the eight vectors `$v` to the rows `$rows[$j + $s * m]`, the
/// reverse of `load_rows!`.
macro_rules! store_rows {
    ($rows:ident, $j:expr, $s:literal, $v:expr) => {{
        let j: usize = $j;
        let [v0, v1, v2, v3, v4, v5, v6, v7]: [int16x8_t; 8] = $v;
        store(&mut $rows[j], v0);
        store(&mut $rows[j + $s], v1);
        store(&mut $rows[j + 2 * $s], v2);
        store(&mut $rows[j + 3 * $s], v3);
        store(&mut $rows[j + 4 * $s], v4);
        store(&mut $rows[j + 5 * $s], v5);
        store(&mut $rows[j + 6 * $s], v6);
        store(&mut $rows[j + 7 * $s], v7);
    }};
}

/// `mlkem_soft::ntt`.
///
/// The eight vectors of each pass are spelled out, with the layers,
/// `fqmul_zeta`, the loads and the stores as macros: at opt-level `z` LLVM
/// kept `#[inline]` layer and twiddle helpers out of line (and at `z` and
/// `s` left the index loops rolled), which put the vectors, copies of the
/// secret coefficients, in stack memory nothing wipes.
///
/// Each pass processes two independent groups of eight vectors together:
/// one group's three dependent layers leave the vector pipes idle, and the
/// interleaved second group fills them.
#[target_feature(enable = "neon")]
fn ntt_unchecked(r: &mut Poly) {
    let rows = rows(r);
    // Layers len = 128, 64, 32 on rows j, j + 4, ..., j + 28.
    for j in [0, 2] {
        let mut v = load_rows!(rows, j, 4);
        let mut w = load_rows!(rows, j + 1, 4);
        ct_layer!(v, 4, 1);
        ct_layer!(w, 4, 1);
        ct_layer!(v, 2, 2);
        ct_layer!(w, 2, 2);
        ct_layer!(v, 1, 4);
        ct_layer!(w, 1, 4);
        store_rows!(rows, j, 4, v);
        store_rows!(rows, j + 1, 4, w);
    }
    // Layers len = 16, 8, 4, 2 on 64 consecutive coefficients.
    for (h, rows) in rows.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        let (q, r) = (2 * h, 2 * h + 1);
        let (rows_q, rows_r) = halves(rows);
        let mut v = load_rows!(rows_q, 0, 1);
        let mut w = load_rows!(rows_r, 0, 1);
        ct_layer!(v, 2, 8 + 2 * q);
        ct_layer!(w, 2, 8 + 2 * r);
        ct_layer!(v, 1, 16 + 4 * q);
        ct_layer!(w, 1, 16 + 4 * r);
        ntt_pair!(v, 0 1, 4 * q);
        ntt_pair!(w, 0 1, 4 * r);
        ntt_pair!(v, 2 3, 4 * q + 1);
        ntt_pair!(w, 2 3, 4 * r + 1);
        ntt_pair!(v, 4 5, 4 * q + 2);
        ntt_pair!(w, 4 5, 4 * r + 2);
        ntt_pair!(v, 6 7, 4 * q + 3);
        ntt_pair!(w, 6 7, 4 * r + 3);
        store_rows!(rows_q, 0, 1, v);
        store_rows!(rows_r, 0, 1, w);
    }
}

/// [`ntt_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn ntt(_: Neon, r: &mut Poly) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { ntt_unchecked(r) }
}

/// The two halves of sixteen rows, as arrays.
#[inline(always)]
fn halves(rows: &mut [[i16; 8]; 16]) -> (&mut [[i16; 8]; 8], &mut [[i16; 8]; 8]) {
    let (a, b) = rows.split_at_mut(8);
    (a.try_into().unwrap(), b.try_into().unwrap())
}

/// `mlkem_soft::invntt_tomont`, spelled out and two groups at a time like
/// [`ntt_unchecked`].
#[target_feature(enable = "neon")]
fn invntt_tomont_unchecked(r: &mut Poly) {
    let rows = rows(r);
    // Layers len = 2, 4, 8, 16 on 64 consecutive coefficients.
    for (h, rows) in rows.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        let (q, r) = (2 * h, 2 * h + 1);
        let (rows_q, rows_r) = halves(rows);
        let mut v = load_rows!(rows_q, 0, 1);
        let mut w = load_rows!(rows_r, 0, 1);
        invntt_pair!(v, 0 1, 4 * q);
        invntt_pair!(w, 0 1, 4 * r);
        invntt_pair!(v, 2 3, 4 * q + 1);
        invntt_pair!(w, 2 3, 4 * r + 1);
        invntt_pair!(v, 4 5, 4 * q + 2);
        invntt_pair!(w, 4 5, 4 * r + 2);
        invntt_pair!(v, 6 7, 4 * q + 3);
        invntt_pair!(w, 6 7, 4 * r + 3);
        gs_layer!(v, 1, 31 - 4 * q);
        gs_layer!(w, 1, 31 - 4 * r);
        gs_layer!(v, 2, 15 - 2 * q);
        gs_layer!(w, 2, 15 - 2 * r);
        store_rows!(rows_q, 0, 1, v);
        store_rows!(rows_r, 0, 1, w);
    }
    // Layers len = 32, 64, 128 and the final scaling on rows j, j + 4, ...,
    // j + 28.
    let f = vdupq_n_s16(INVNTT_F);
    let f_qinv = vdupq_n_s16(INVNTT_F.wrapping_mul(QINV));
    macro_rules! scaled {
        ($v:expr) => {{
            let [v0, v1, v2, v3, v4, v5, v6, v7] = $v;
            [
                fqmul(v0, f, f_qinv),
                fqmul(v1, f, f_qinv),
                fqmul(v2, f, f_qinv),
                fqmul(v3, f, f_qinv),
                fqmul(v4, f, f_qinv),
                fqmul(v5, f, f_qinv),
                fqmul(v6, f, f_qinv),
                fqmul(v7, f, f_qinv),
            ]
        }};
    }
    for j in [0, 2] {
        let mut v = load_rows!(rows, j, 4);
        let mut w = load_rows!(rows, j + 1, 4);
        gs_layer!(v, 1, 7);
        gs_layer!(w, 1, 7);
        gs_layer!(v, 2, 3);
        gs_layer!(w, 2, 3);
        gs_layer!(v, 4, 1);
        gs_layer!(w, 4, 1);
        store_rows!(rows, j, 4, scaled!(v));
        store_rows!(rows, j + 1, 4, scaled!(w));
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

/// [`basemul_acc_unchecked`] for `R` rows `a[i]` against the same `b`, whose
/// de-interleaved coefficients and Montgomery multipliers are formed once per
/// sixteen coefficients for all rows. Each row's arithmetic is exactly
/// `basemul_acc`'s.
#[target_feature(enable = "neon")]
fn basemul_rows_unchecked<const K: usize, const R: usize>(
    r: [&mut Poly; R],
    a: [&[Poly; K]; R],
    b: &[Poly; K],
) {
    let split = |[lo, hi]: &[[i16; 8]; 2]| {
        let (lo, hi) = (load(lo), load(hi));
        (vuzp1q_s16(lo, hi), vuzp2q_s16(lo, hi))
    };
    let mut outs: [&mut [[[i16; 8]; 2]; 16]; R] = r.map(|r| {
        r.as_chunks_mut::<8>()
            .0
            .as_chunks_mut::<2>()
            .0
            .try_into()
            .unwrap()
    });
    for p in 0..16 {
        let (zeta, zeta_qinv) = twiddle(&BASEMUL[p]);
        let bs: [_; K] = core::array::from_fn(|k| {
            let (b0, b1) = split(&pairs(&b[k])[p]);
            (b0, b1, vmulq_n_s16(b0, QINV), vmulq_n_s16(b1, QINV))
        });
        for (out, a) in outs.iter_mut().zip(a) {
            let (mut c0, mut c1) = (vdupq_n_s16(0), vdupq_n_s16(0));
            for (a, &(b0, b1, b0_qinv, b1_qinv)) in a.iter().zip(&bs) {
                let (a0, a1) = split(&pairs(a)[p]);
                let x = vaddq_s16(
                    fqmul(fqmul(a1, b1, b1_qinv), zeta, zeta_qinv),
                    fqmul(a0, b0, b0_qinv),
                );
                let y = vaddq_s16(fqmul(a0, b1, b1_qinv), fqmul(a1, b0, b0_qinv));
                c0 = vaddq_s16(c0, x);
                c1 = vaddq_s16(c1, y);
            }
            let (c0, c1) = (barrett_reduce(c0), barrett_reduce(c1));
            store(&mut out[p][0], vzip1q_s16(c0, c1));
            store(&mut out[p][1], vzip2q_s16(c0, c1));
        }
    }
}

/// [`basemul_rows_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn basemul_rows<const K: usize, const R: usize>(
    _: Neon,
    r: [&mut Poly; R],
    a: [&[Poly; K]; R],
    b: &[Poly; K],
) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { basemul_rows_unchecked::<K, R>(r, a, b) }
}

/// [`basemul_acc_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn basemul_acc<const K: usize>(_: Neon, r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { basemul_acc_unchecked::<K>(r, a, b) }
}

/// Byte gather that puts candidate `j` of twelve bytes (two per three
/// bytes) in 16-bit lane `j`: bytes `3j/2, 3j/2 + 1`, still to be masked
/// (even `j`) or shifted right by four (odd `j`).
const REJ_GATHER: [u8; 16] = [0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11];
/// Per-lane shifts for [`REJ_GATHER`]'s lanes: odd candidates are the high
/// twelve bits of their pair.
const REJ_SHIFT: [i16; 8] = [0, -4, 0, -4, 0, -4, 0, -4];
/// Lane `j`'s bit in the acceptance mask.
const REJ_BITS: [u16; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
/// Entry `m` moves the 16-bit lanes whose bit is set in `m` to the front,
/// in order; the remaining bytes select zero (an out-of-range `tbl` index).
const REJ_COMPRESS: [[u8; 16]; 256] = {
    let mut table = [[0xff; 16]; 256];
    let mut m = 0;
    while m < 256 {
        let (mut lane, mut k) = (0, 0);
        while lane < 8 {
            if m >> lane & 1 == 1 {
                table[m][2 * k] = 2 * lane as u8;
                table[m][2 * k + 1] = 2 * lane as u8 + 1;
                k += 1;
            }
            lane += 1;
        }
        m += 1;
    }
    table
};

/// Accepted candidates per acceptance mask of [`REJ_COMPRESS`].
const REJ_COUNT: [u8; 256] = {
    let mut table = [0; 256];
    let mut m = 0;
    while m < 256 {
        table[m] = (m as u8).count_ones() as u8;
        m += 1;
    }
    table
};

/// `super::poly_to_msg` (`ByteEncode_1(Compress_1(a))`) of a
/// Barrett-reduced polynomial, coefficients in `[0, q]`: `Compress_1` is 1
/// exactly for the coefficients in `[833, 2496]` (`q` itself maps to 0), so
/// bit `j` of byte `i` is one unsigned compare of coefficient `8 i + j`
/// minus 833 against 1664, and the byte the sum of the lane weights
/// [`REJ_BITS`] the compare selects. No branch or index depends on the
/// coefficients, which are secret (the decrypted message).
#[target_feature(enable = "neon")]
fn poly_to_msg_unchecked(m: &mut [u8; 32], a: &Poly) {
    let bits = load_u16(&REJ_BITS);
    let (low, width) = (vdupq_n_s16(833), vdupq_n_u16(1664));
    for (byte, row) in m.iter_mut().zip(a.as_chunks::<8>().0) {
        let d = vreinterpretq_u16_s16(vsubq_s16(load(row), low));
        *byte = vaddvq_u16(vandq_u16(vcltq_u16(d, width), bits)) as u8;
    }
}

/// [`poly_to_msg_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn poly_to_msg(_: Neon, m: &mut [u8; 32], a: &Poly) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { poly_to_msg_unchecked(m, a) }
}

/// For eight 10-bit fields in ten bytes: the two bytes holding field `j`,
/// as the low and high byte of 16-bit lane `j`.
const DECOMPRESS10_GATHER: [u8; 16] = [0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9];
/// The right shift (as a negative left shift) that brings each field of
/// [`DECOMPRESS10_GATHER`]'s lanes to bit 0.
const DECOMPRESS10_SHIFT: [i16; 8] = [0, -2, -4, -6, 0, -2, -4, -6];

/// `super::decompress_u` (`ByteDecode_10` then `Decompress_10`): eight
/// coefficients from each ten bytes, `(t * q + 512) >> 10` as a widening
/// multiply and a rounding narrowing shift. The last row, whose sixteen-byte
/// load would run past `bytes`, goes through the scalar code. The input is
/// the public ciphertext.
#[target_feature(enable = "neon")]
fn decompress10_unchecked(rows: &mut [[i16; 8]], bytes: &[u8]) {
    debug_assert_eq!(bytes.len(), rows.len() * 10);
    let gather = load_u8(&DECOMPRESS10_GATHER);
    let shift = load(&DECOMPRESS10_SHIFT);
    let mask = vdupq_n_u16(0x3ff);
    let (q, q_half) = (vdupq_n_u16(Q as u16), vdup_n_u16(Q as u16));
    for (i, row) in rows.iter_mut().enumerate() {
        let group = &bytes[10 * i..10 * i + 10];
        let Some(chunk) = bytes.get(10 * i..10 * i + 16) else {
            let (halves, _) = row.as_chunks_mut::<4>();
            let (fives, _) = group.as_chunks::<5>();
            super::decompress10(&mut halves[0], &fives[0]);
            super::decompress10(&mut halves[1], &fives[1]);
            continue;
        };
        let raw = load_u8(chunk.try_into().expect("sixteen bytes"));
        let t = vandq_u16(
            vshlq_u16(vreinterpretq_u16_u8(vqtbl1q_u8(raw, gather)), shift),
            mask,
        );
        let lo = vmull_u16(vget_low_u16(t), q_half);
        let hi = vmull_high_u16(t, q);
        let r = vrshrn_high_n_u32::<10>(vrshrn_n_u32::<10>(lo), hi);
        store(row, vreinterpretq_s16_u16(r));
    }
}

/// [`decompress10_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn decompress10(_: Neon, rows: &mut [[i16; 8]], bytes: &[u8]) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { decompress10_unchecked(rows, bytes) }
}

/// Loads sixteen bytes (`ldr q`).
#[inline]
#[target_feature(enable = "neon")]
fn load_u8(c: &[u8; 16]) -> uint8x16_t {
    // SAFETY: `c` refers to sixteen initialized bytes, exactly what `ld1`
    // reads, and `ld1` of bytes has no alignment requirement.
    unsafe { vld1q_u8(c.as_ptr()) }
}

/// Loads eight 16-bit lanes (`ldr q`).
#[inline]
#[target_feature(enable = "neon")]
fn load_u16(c: &[u16; 8]) -> uint16x8_t {
    // SAFETY: `c` refers to eight initialized `u16`s, exactly the 16 bytes
    // `ld1` reads, and `ld1` has no alignment requirement beyond that of
    // `u16`.
    unsafe { vld1q_u16(c.as_ptr()) }
}

/// `super::rej_uniform` eight candidates (twelve bytes) at a time, while
/// `poly` has room for all eight: the accepted ones are packed to the front
/// by a [`REJ_COMPRESS`] shuffle and stored at `poly[*filled..]` with the
/// rest zeroed, and `*filled` advances by their number, so the next group
/// overwrites the zeros. Returns the bytes consumed. The table index and
/// the loop depend on the candidates, which is fine: the matrix is public.
#[target_feature(enable = "neon")]
fn rej_uniform_unchecked(poly: &mut Poly, filled: &mut usize, bytes: &[u8]) -> usize {
    let gather = load_u8(&REJ_GATHER);
    let shift = load(&REJ_SHIFT);
    let bits = load_u16(&REJ_BITS);
    let (mask12, q) = (vdupq_n_u16(0x0fff), vdupq_n_u16(Q as u16));
    let (mut n, mut used) = (*filled, 0);
    // Each group reads sixteen bytes and consumes twelve.
    while n <= N - 8 {
        let Some(chunk) = bytes.get(used..used + 16) else {
            break;
        };
        let raw = load_u8(chunk.try_into().expect("sixteen bytes"));
        let d = vandq_u16(
            vshlq_u16(vreinterpretq_u16_u8(vqtbl1q_u8(raw, gather)), shift),
            mask12,
        );
        let accept = vcltq_u16(d, q);
        // The eight lane bits sum to at most 255: as a `u8` the index needs
        // no bounds check against the 256-entry tables.
        let mask = usize::from(vaddvq_u16(vandq_u16(accept, bits)) as u8);
        let count = REJ_COUNT[mask];
        let packed = vqtbl1q_u8(vreinterpretq_u8_u16(d), load_u8(&REJ_COMPRESS[mask]));
        let slots: &mut [i16; 8] = (&mut poly[n..n + 8]).try_into().expect("eight slots");
        store(slots, vreinterpretq_s16_u8(packed));
        n += usize::from(count);
        used += 12;
    }
    *filled = n;
    used
}

/// [`rej_uniform_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn rej_uniform(_: Neon, poly: &mut Poly, filled: &mut usize, bytes: &[u8]) -> usize {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { rej_uniform_unchecked(poly, filled, bytes) }
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
