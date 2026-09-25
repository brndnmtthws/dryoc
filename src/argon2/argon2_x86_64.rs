//! AVX2 and AVX-512 Argon2 block compression.
//!
//! The 1 KiB block is 32 vectors of four 64-bit words (or 16 of eight). The
//! permutation `P` is a message-less BLAKE2b round (with the fBlaMka mixing)
//! over each of the eight 16-word rows and then over each of the eight
//! 16-word columns. A 16-word state is held as four vectors (rows `a`, `b`,
//! `c`, `d` of its 4x4 layout), so the four `G` mixings of a step are one
//! lane-wise `G`, and rotating `b`, `c`, `d` by one, two and three lanes
//! lines the diagonals up in columns. The AVX2 kernel processes two
//! independent states per round call so their dependency chains overlap; the
//! AVX-512 kernel holds two states side by side in each 512-bit vector and
//! rotates with `vprorq`. Control flow and memory access are independent of
//! the data.
//!
//! Zeroization: the permutation runs in place on the caller's `dst` block,
//! and the XORs around it use the caller's `scratch` block. Both are
//! [`Block`]s, which wipe themselves on drop. `permute_avx2_unchecked` and
//! `permute_avx512_unchecked` are out of line at every opt-level, which adds
//! no copy: they only get `&mut` to `dst`. Every step on the vectors inside
//! them is a macro or a few-intrinsic `#[inline]` helper, so at every
//! opt-level they touch no stack memory and call no functions and the vectors
//! live only in registers. Rust cannot reliably wipe registers, and wiping
//! these values would force them into memory, so the kernels add no wipes of
//! their own.

use core::arch::x86_64::{
    __m256i, __m512i, _mm256_add_epi64, _mm256_mul_epu32, _mm256_permute2x128_si256,
    _mm256_permute4x64_epi64, _mm256_shuffle_epi8, _mm256_xor_si256, _mm512_add_epi64,
    _mm512_mul_epu32, _mm512_permutex_epi64, _mm512_permutex2var_epi64, _mm512_ror_epi64,
    _mm512_setr_epi64, _mm512_shuffle_i64x2, _mm512_xor_si512,
};

use super::{Block, finish_in_place, prepare_in_place};
use crate::x86_64::{
    Avx2, Avx512, load_words, load_words512, ror16_table, ror24_table, ror32, ror63, store_words,
    store_words512,
};

/// A vector kernel the running CPU has been verified to support: each
/// variant holds the token for the CPU feature its kernel is compiled for,
/// which is what makes [`Kernel::fill_block`] safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kernel {
    /// AVX2: two 16-word states per round call in eight `ymm` registers.
    Avx2(Avx2),
    /// AVX-512F: two 16-word states side by side in four `zmm` registers.
    Avx512(Avx512),
}

/// The best kernel the running CPU supports.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    if let Some(avx512) = Avx512::new() {
        Some(Kernel::Avx512(avx512))
    } else {
        Avx2::new().map(Kernel::Avx2)
    }
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        let mut kernels = alloc::vec::Vec::new();
        if let Some(avx2) = Avx2::new() {
            kernels.push(Kernel::Avx2(avx2));
        }
        if let Some(avx512) = Avx512::new() {
            kernels.push(Kernel::Avx512(avx512));
        }
        kernels
    }

    /// Overwrites `dst` with `P(R) ^ R [^ old dst]` for `R = prev_block ^
    /// ref_block`; see [`super::fill_block`]. Only the permutation is
    /// kernel-specific; the XORs around it are the portable ones.
    #[inline]
    pub(super) fn fill_block(
        self,
        dst: &mut Block,
        prev_block: &Block,
        ref_block: &Block,
        xor_old: bool,
        scratch: &mut Block,
    ) {
        prepare_in_place(dst, prev_block, ref_block, xor_old, scratch);
        match self {
            Kernel::Avx2(avx2) => permute_avx2(avx2, dst),
            Kernel::Avx512(avx512) => permute_avx512(avx512, dst),
        }
        finish_in_place(dst, prev_block, ref_block, xor_old, scratch);
    }
}

/// `x + y + 2 * lo32(x) * lo32(y)` per lane, the Argon2 fBlaMka mixing
/// function; `vpmuludq` multiplies exactly the low 32 bits of each lane.
#[inline]
#[target_feature(enable = "avx2")]
fn fblamka(x: __m256i, y: __m256i) -> __m256i {
    let xy = _mm256_mul_epu32(x, y);
    _mm256_add_epi64(_mm256_add_epi64(x, y), _mm256_add_epi64(xy, xy))
}

/// The four lane-wise `G` mixings of one step (column or diagonal) over the
/// rows `$a, $b, $c, $d` of one state.
macro_rules! g {
    ($a:ident, $b:ident, $c:ident, $d:ident, $r24:ident, $r16:ident) => {
        $a = fblamka($a, $b);
        $d = ror32(_mm256_xor_si256($d, $a));
        $c = fblamka($c, $d);
        $b = _mm256_shuffle_epi8(_mm256_xor_si256($b, $c), $r24);
        $a = fblamka($a, $b);
        $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), $r16);
        $c = fblamka($c, $d);
        $b = ror63(_mm256_xor_si256($b, $c));
    };
}

/// One message-less BLAKE2b round over two independent 16-word states held
/// in `($a0, $b0, $c0, $d0)` and `($a1, $b1, $c1, $d1)`, interleaved
/// statement by statement so the two dependency chains overlap. A macro
/// rather than a `#[target_feature]` fn, which cannot be `#[inline(always)]`:
/// at opt-level `z` LLVM kept such a `round` out of line and passed it the
/// two states (a copy of the password-derived block) and its result through
/// memory.
macro_rules! round {
    (
        $a0:ident,
        $b0:ident,
        $c0:ident,
        $d0:ident,
        $a1:ident,
        $b1:ident,
        $c1:ident,
        $d1:ident,
        $r24:ident,
        $r16:ident
    ) => {
        g!($a0, $b0, $c0, $d0, $r24, $r16);
        g!($a1, $b1, $c1, $d1, $r24, $r16);
        // Rotate rows 1..4 by 1..3 lanes so each diagonal is a column.
        $b0 = _mm256_permute4x64_epi64::<0x39>($b0);
        $c0 = _mm256_permute4x64_epi64::<0x4E>($c0);
        $d0 = _mm256_permute4x64_epi64::<0x93>($d0);
        $b1 = _mm256_permute4x64_epi64::<0x39>($b1);
        $c1 = _mm256_permute4x64_epi64::<0x4E>($c1);
        $d1 = _mm256_permute4x64_epi64::<0x93>($d1);
        g!($a0, $b0, $c0, $d0, $r24, $r16);
        g!($a1, $b1, $c1, $d1, $r24, $r16);
        $b0 = _mm256_permute4x64_epi64::<0x93>($b0);
        $c0 = _mm256_permute4x64_epi64::<0x4E>($c0);
        $d0 = _mm256_permute4x64_epi64::<0x39>($d0);
        $b1 = _mm256_permute4x64_epi64::<0x93>($b1);
        $c1 = _mm256_permute4x64_epi64::<0x4E>($c1);
        $d1 = _mm256_permute4x64_epi64::<0x39>($d1);
    };
}

/// Row `$row` (`a` to `d` for 0 to 3) of the column states `2 * $i` and
/// `2 * $i + 1`: the low and the high 128-bit halves of vectors `8 * $row +
/// $i` and `8 * $row + 4 + $i`.
macro_rules! load_column_rows {
    ($v:ident, $i:ident, $row:literal) => {{
        let lo = load_words(&$v[8 * $row + $i]);
        let hi = load_words(&$v[8 * $row + 4 + $i]);
        (
            _mm256_permute2x128_si256::<0x20>(lo, hi),
            _mm256_permute2x128_si256::<0x31>(lo, hi),
        )
    }};
}

/// Inverse of `load_column_rows!`.
macro_rules! store_column_rows {
    ($v:ident, $i:ident, $row:literal, $x0:ident, $x1:ident) => {
        store_words(
            &mut $v[8 * $row + $i],
            _mm256_permute2x128_si256::<0x20>($x0, $x1),
        );
        store_words(
            &mut $v[8 * $row + 4 + $i],
            _mm256_permute2x128_si256::<0x31>($x0, $x1),
        );
    };
}

/// The permutation `P` over the block in place: a round over every pair of
/// 16-word rows, then over every pair of 16-word columns.
#[inline(never)]
#[target_feature(enable = "avx2")]
fn permute_avx2_unchecked(block: &mut Block) {
    let r24 = ror24_table();
    let r16 = ror16_table();
    // `v[k]` holds block words `4k .. 4k + 4`.
    let v = block.v.as_chunks_mut::<4>().0;

    // Rows `2i` and `2i + 1` are words `32i .. 32i + 16` and `32i + 16 ..
    // 32i + 32`: vectors `8i .. 8i + 4` and `8i + 4 .. 8i + 8`, each already
    // in `a, b, c, d` order.
    for i in 0..4 {
        let w = &mut v[8 * i..8 * i + 8];
        let mut a0 = load_words(&w[0]);
        let mut b0 = load_words(&w[1]);
        let mut c0 = load_words(&w[2]);
        let mut d0 = load_words(&w[3]);
        let mut a1 = load_words(&w[4]);
        let mut b1 = load_words(&w[5]);
        let mut c1 = load_words(&w[6]);
        let mut d1 = load_words(&w[7]);
        round!(a0, b0, c0, d0, a1, b1, c1, d1, r24, r16);
        store_words(&mut w[0], a0);
        store_words(&mut w[1], b0);
        store_words(&mut w[2], c0);
        store_words(&mut w[3], d0);
        store_words(&mut w[4], a1);
        store_words(&mut w[5], b1);
        store_words(&mut w[6], c1);
        store_words(&mut w[7], d1);
    }

    // Column `2i` is the word pairs `(16k + 4i, 16k + 4i + 1)` for `k` in
    // `0..8`, column `2i + 1` the pairs `(16k + 4i + 2, 16k + 4i + 3)`: the
    // low and high 128-bit halves of vectors `4k + i`. Row `a` of column `2i`
    // is the low halves of vectors `i` and `4 + i`, row `a` of column `2i + 1`
    // their high halves, and so on for `b`, `c`, `d`.
    for i in 0..4 {
        let (mut a0, mut a1) = load_column_rows!(v, i, 0);
        let (mut b0, mut b1) = load_column_rows!(v, i, 1);
        let (mut c0, mut c1) = load_column_rows!(v, i, 2);
        let (mut d0, mut d1) = load_column_rows!(v, i, 3);
        round!(a0, b0, c0, d0, a1, b1, c1, d1, r24, r16);
        store_column_rows!(v, i, 0, a0, a1);
        store_column_rows!(v, i, 1, b0, b1);
        store_column_rows!(v, i, 2, c0, c1);
        store_column_rows!(v, i, 3, d0, d1);
    }
}

/// [`permute_avx2_unchecked`], safe to call with an [`Avx2`] token.
#[inline(always)]
fn permute_avx2(_: Avx2, block: &mut Block) {
    // SAFETY: an `Avx2` token exists only after detection of `avx2`,
    // the feature the kernel is compiled for.
    unsafe { permute_avx2_unchecked(block) }
}

/// `x + y + 2 * lo32(x) * lo32(y)` per lane; see [`fblamka`].
#[inline]
#[target_feature(enable = "avx512f")]
fn fblamka512(x: __m512i, y: __m512i) -> __m512i {
    let xy = _mm512_mul_epu32(x, y);
    _mm512_add_epi64(_mm512_add_epi64(x, y), _mm512_add_epi64(xy, xy))
}

/// The `G` mixings of one step over the rows `$a, $b, $c, $d` of two states
/// held side by side (one per 256-bit half).
macro_rules! g512 {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $a = fblamka512($a, $b);
        $d = _mm512_ror_epi64::<32>(_mm512_xor_si512($d, $a));
        $c = fblamka512($c, $d);
        $b = _mm512_ror_epi64::<24>(_mm512_xor_si512($b, $c));
        $a = fblamka512($a, $b);
        $d = _mm512_ror_epi64::<16>(_mm512_xor_si512($d, $a));
        $c = fblamka512($c, $d);
        $b = _mm512_ror_epi64::<63>(_mm512_xor_si512($b, $c));
    };
}

/// One message-less BLAKE2b round over the two 16-word states held side by
/// side in `($a, $b, $c, $d)`, one state per 256-bit half. `vpermq` with an
/// immediate permutes within each half, so the diagonal rotation is the
/// same as for one state. A macro for the same reason as `round!`.
macro_rules! round512 {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        g512!($a, $b, $c, $d);
        $b = _mm512_permutex_epi64::<0x39>($b);
        $c = _mm512_permutex_epi64::<0x4E>($c);
        $d = _mm512_permutex_epi64::<0x93>($d);
        g512!($a, $b, $c, $d);
        $b = _mm512_permutex_epi64::<0x93>($b);
        $c = _mm512_permutex_epi64::<0x4E>($c);
        $d = _mm512_permutex_epi64::<0x39>($d);
    };
}

/// The permutation `P` over the block in place with AVX-512: a round over
/// every pair of 16-word rows, then over every pair of 16-word columns.
#[inline(never)]
#[target_feature(enable = "avx512f")]
fn permute_avx512_unchecked(block: &mut Block) {
    // `v[k]` holds block words `8k .. 8k + 8`.
    let v = block.v.as_chunks_mut::<8>().0;

    // Rows `2i` and `2i + 1` are vectors `4i, 4i + 1` (their `a | b` and
    // `c | d` halves) and `4i + 2, 4i + 3`. `0x44` takes the low 256 bits of
    // both operands, `0xEE` the high 256 bits.
    for i in 0..4 {
        let w = &mut v[4 * i..4 * i + 4];
        let r0 = load_words512(&w[0]);
        let r1 = load_words512(&w[1]);
        let r2 = load_words512(&w[2]);
        let r3 = load_words512(&w[3]);
        let mut a = _mm512_shuffle_i64x2::<0x44>(r0, r2);
        let mut b = _mm512_shuffle_i64x2::<0xEE>(r0, r2);
        let mut c = _mm512_shuffle_i64x2::<0x44>(r1, r3);
        let mut d = _mm512_shuffle_i64x2::<0xEE>(r1, r3);
        round512!(a, b, c, d);
        store_words512(&mut w[0], _mm512_shuffle_i64x2::<0x44>(a, b));
        store_words512(&mut w[1], _mm512_shuffle_i64x2::<0x44>(c, d));
        store_words512(&mut w[2], _mm512_shuffle_i64x2::<0xEE>(a, b));
        store_words512(&mut w[3], _mm512_shuffle_i64x2::<0xEE>(c, d));
    }

    // Column `c` is the word pairs `(16k + 2c, 16k + 2c + 1)` for `k` in
    // `0..8`: 128-bit lane `c % 4` of vectors `2k + c / 4`. For the four
    // columns `4j .. 4j + 4`, row `a` of each is in vectors `j` and `2 + j`,
    // row `b` in `4 + j` and `6 + j`, and so on. Columns `4j + 2h` and
    // `4j + 2h + 1` (lanes `2h` and `2h + 1`) form one side-by-side pair,
    // state `h`. Spelled out rather than looping over arrays of rows and
    // states, which kept those arrays in memory at opt-level `z`.
    let gather0 = _mm512_setr_epi64(0, 1, 8, 9, 2, 3, 10, 11);
    let gather1 = _mm512_setr_epi64(4, 5, 12, 13, 6, 7, 14, 15);
    let scatter_lo = _mm512_setr_epi64(0, 1, 4, 5, 8, 9, 12, 13);
    let scatter_hi = _mm512_setr_epi64(2, 3, 6, 7, 10, 11, 14, 15);
    for j in 0..2 {
        let (a_lo, a_hi) = (load_words512(&v[j]), load_words512(&v[2 + j]));
        let (b_lo, b_hi) = (load_words512(&v[4 + j]), load_words512(&v[6 + j]));
        let (c_lo, c_hi) = (load_words512(&v[8 + j]), load_words512(&v[10 + j]));
        let (d_lo, d_hi) = (load_words512(&v[12 + j]), load_words512(&v[14 + j]));
        let mut a0 = _mm512_permutex2var_epi64(a_lo, gather0, a_hi);
        let mut b0 = _mm512_permutex2var_epi64(b_lo, gather0, b_hi);
        let mut c0 = _mm512_permutex2var_epi64(c_lo, gather0, c_hi);
        let mut d0 = _mm512_permutex2var_epi64(d_lo, gather0, d_hi);
        let mut a1 = _mm512_permutex2var_epi64(a_lo, gather1, a_hi);
        let mut b1 = _mm512_permutex2var_epi64(b_lo, gather1, b_hi);
        let mut c1 = _mm512_permutex2var_epi64(c_lo, gather1, c_hi);
        let mut d1 = _mm512_permutex2var_epi64(d_lo, gather1, d_hi);
        round512!(a0, b0, c0, d0);
        round512!(a1, b1, c1, d1);
        store_words512(&mut v[j], _mm512_permutex2var_epi64(a0, scatter_lo, a1));
        store_words512(&mut v[2 + j], _mm512_permutex2var_epi64(a0, scatter_hi, a1));
        store_words512(&mut v[4 + j], _mm512_permutex2var_epi64(b0, scatter_lo, b1));
        store_words512(&mut v[6 + j], _mm512_permutex2var_epi64(b0, scatter_hi, b1));
        store_words512(&mut v[8 + j], _mm512_permutex2var_epi64(c0, scatter_lo, c1));
        store_words512(
            &mut v[10 + j],
            _mm512_permutex2var_epi64(c0, scatter_hi, c1),
        );
        store_words512(
            &mut v[12 + j],
            _mm512_permutex2var_epi64(d0, scatter_lo, d1),
        );
        store_words512(
            &mut v[14 + j],
            _mm512_permutex2var_epi64(d0, scatter_hi, d1),
        );
    }
}

/// [`permute_avx512_unchecked`], safe to call with an [`Avx512`] token.
#[inline(always)]
fn permute_avx512(_: Avx512, block: &mut Block) {
    // SAFETY: an `Avx512` token exists only after detection of
    // `avx512f`, the feature the kernel is compiled for.
    unsafe { permute_avx512_unchecked(block) }
}
