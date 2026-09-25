//! 4-way AVX2 Keccak-p[1600].
//!
//! Four independent states are permuted together: vector `i` holds lane
//! `i` (`x + 5 * y`) of all four, one state per 64-bit word, so each step
//! of a round is the scalar step on vectors. The states are transposed into
//! that layout on load and back on store, 4x4 words at a time. Rotations
//! are shift pairs, `andnot` gives the `chi` step, and the round constant
//! is broadcast. Control flow and memory access are independent of the
//! state.

use core::arch::x86_64::{
    __m256i, _mm256_andnot_si256, _mm256_or_si256, _mm256_set1_epi64x, _mm256_setr_epi8,
    _mm256_setr_epi64x, _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_slli_epi64,
    _mm256_srli_epi64, _mm256_xor_si256,
};

use zeroize::Zeroize;

use crate::x86_64::{load_words, store_words, transpose_words};

/// A vector kernel the running CPU has been verified to support.
///
/// Values are only created by [`detect`] after checking the CPU features the
/// kernel is compiled for, which is what makes [`Kernel::permute_selected`]
/// safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kernel {
    /// AVX2: four states in 25 `ymm` vectors.
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

    /// Applies Keccak-p[1600, `ROUNDS`] to the states in `selected`, four
    /// at a time in lane order, and clears their flags. Three leftover
    /// states run beside a spare zero state, since one 4-way permutation
    /// costs less than three single ones; one or two leftover states stay
    /// selected for the caller.
    pub(super) fn permute_selected<const ROUNDS: usize, const N: usize>(
        self,
        states: &mut [[u64; 25]; N],
        selected: &mut [bool; N],
    ) {
        let mut lanes = [0; N];
        let mut count = 0;
        for (lane, _) in selected.iter().enumerate().filter(|(_, s)| **s) {
            lanes[count] = lane;
            count += 1;
        }
        let (groups, rest) = lanes[..count].as_chunks::<4>();
        for &group in groups {
            self.permute4::<ROUNDS>(
                states
                    .get_disjoint_mut(group)
                    .expect("selected lanes are distinct and in bounds"),
            );
        }
        if let &[l0, l1, l2] = rest {
            let [s0, s1, s2] = states
                .get_disjoint_mut([l0, l1, l2])
                .expect("selected lanes are distinct and in bounds");
            self.permute4::<ROUNDS>([s0, s1, s2, &mut [0; 25]]);
        }
        let done = if rest.len() == 3 {
            count
        } else {
            count - rest.len()
        };
        for &lane in &lanes[..done] {
            selected[lane] = false;
        }
    }

    /// Keccak-p[1600, `ROUNDS`] on four states.
    #[inline]
    fn permute4<const ROUNDS: usize>(self, states: [&mut [u64; 25]; 4]) {
        match self {
            // SAFETY: `Kernel::Avx2` is only constructed after
            // `has_x86_feature!("avx2")` succeeded.
            Kernel::Avx2 => unsafe { permute4_avx2::<ROUNDS>(states) },
        }
    }
}

/// The Keccak-f[1600] round constants, from the FIPS 202 `rc` LFSR (`x^8 +
/// x^6 + x^5 + x^4 + 1`): bit `2^j - 1` of constant `i` is output `7 * i +
/// j`. Keccak-p[1600, `ROUNDS`] uses the last `ROUNDS` of them.
const RC: [u64; 24] = {
    let mut rc = [0u64; 24];
    let mut lfsr: u8 = 1;
    let mut round = 0;
    while round < 24 {
        let mut j = 0;
        while j < 7 {
            if lfsr & 1 == 1 {
                rc[round] |= 1 << ((1 << j) - 1);
            }
            lfsr = if lfsr & 0x80 == 0 {
                lfsr << 1
            } else {
                (lfsr << 1) ^ 0x71
            };
            j += 1;
        }
        round += 1;
    }
    rc
};

/// The `rho` rotation of each lane `x + 5 * y`: `(t + 1)(t + 2) / 2 mod 64`
/// for the lane that step `t` of the walk `(x, y) -> (y, 2x + 3y)` from
/// `(1, 0)` reaches; lane `(0, 0)` is not rotated.
const RHO: [i32; 25] = {
    let mut rho = [0i32; 25];
    let (mut x, mut y) = (1, 0);
    let mut t = 0;
    while t < 24 {
        rho[x + 5 * y] = (t + 1) * (t + 2) / 2 % 64;
        (x, y) = (y, (2 * x + 3 * y) % 5);
        t += 1;
    }
    rho
};

/// Runs `$body` five times with `$x` bound to the constants `0..5`, so every
/// lane index and rotation count in the round is a constant.
macro_rules! unroll5 {
    ($x:ident, $body:block) => {{
        {
            const $x: usize = 0;
            $body
        }
        {
            const $x: usize = 1;
            $body
        }
        {
            const $x: usize = 2;
            $body
        }
        {
            const $x: usize = 3;
            $body
        }
        {
            const $x: usize = 4;
            $body
        }
    }};
}

/// Rotates every 64-bit word of `$v` left by the constant `$n < 64`: a byte
/// shuffle for 8 and 56, otherwise a pair of shifts.
macro_rules! rotl {
    ($v:expr, $n:expr, $bytes:expr) => {{
        let v = $v;
        match $n {
            0 => v,
            8 => _mm256_shuffle_epi8(v, $bytes.rol8),
            56 => _mm256_shuffle_epi8(v, $bytes.rol56),
            _ => _mm256_or_si256(
                _mm256_slli_epi64::<{ $n }>(v),
                _mm256_srli_epi64::<{ 64 - $n }>(v),
            ),
        }
    }};
}

/// `vpshufb` tables (per 128-bit half) rotating every 64-bit word left by
/// 8 and by 56 bits.
#[derive(Clone, Copy)]
struct ByteRotations {
    rol8: __m256i,
    rol56: __m256i,
}

impl ByteRotations {
    #[inline]
    #[target_feature(enable = "avx2")]
    fn new() -> Self {
        Self {
            rol8: _mm256_setr_epi8(
                7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14, 7, 0, 1, 2, 3, 4, 5, 6, 15,
                8, 9, 10, 11, 12, 13, 14,
            ),
            rol56: _mm256_setr_epi8(
                1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8, 1, 2, 3, 4, 5, 6, 7, 0, 9,
                10, 11, 12, 13, 14, 15, 8,
            ),
        }
    }
}

/// One Keccak-p[1600] round with round constant `rc` on the four states.
#[inline]
#[target_feature(enable = "avx2")]
fn round(a: &mut [__m256i; 25], rc: u64, bytes: ByteRotations) {
    // theta: the column parities `c`, then `d[x] = c[x - 1] ^ (c[x + 1] <<<
    // 1)`.
    let mut c = [_mm256_setzero_si256(); 5];
    unroll5!(X, {
        c[X] = _mm256_xor_si256(
            _mm256_xor_si256(a[X], a[X + 5]),
            _mm256_xor_si256(_mm256_xor_si256(a[X + 10], a[X + 15]), a[X + 20]),
        );
    });
    let mut d = [_mm256_setzero_si256(); 5];
    unroll5!(X, {
        d[X] = _mm256_xor_si256(c[(X + 4) % 5], rotl!(c[(X + 1) % 5], 1, bytes));
    });
    // theta's XOR of `d`, rho and pi: lane `(x, y)` moves to `(y, 2x + 3y)`.
    let mut b = [_mm256_setzero_si256(); 25];
    unroll5!(Y, {
        unroll5!(X, {
            b[Y + 5 * ((2 * X + 3 * Y) % 5)] =
                rotl!(_mm256_xor_si256(a[X + 5 * Y], d[X]), RHO[X + 5 * Y], bytes);
        });
    });
    // chi.
    unroll5!(Y, {
        unroll5!(X, {
            a[X + 5 * Y] = _mm256_xor_si256(
                b[X + 5 * Y],
                _mm256_andnot_si256(b[(X + 1) % 5 + 5 * Y], b[(X + 2) % 5 + 5 * Y]),
            );
        });
    });
    // iota; the constant's bit pattern is XORed as is.
    a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(rc as i64));
}

/// Keccak-p[1600, `ROUNDS`] on four states.
///
/// The transposed lanes and the staging words are wiped once before
/// returning; the rounds' column parities, `theta` offsets and `rho`/`pi`
/// lanes, like every other value that lives only in registers and compiler
/// spill slots, are out of Rust's reach and are not wiped.
#[target_feature(enable = "avx2")]
fn permute4_avx2<const ROUNDS: usize>(mut states: [&mut [u64; 25]; 4]) {
    const { assert!(ROUNDS <= 24) };
    let mut a = [_mm256_setzero_si256(); 25];
    let (blocks, [last]) = a.as_chunks_mut::<4>() else {
        unreachable!("25 lanes are six blocks of four and one more");
    };
    for (j, block) in blocks.iter_mut().enumerate() {
        // Loaded straight from the states: an `each_ref().map` of the rows
        // stayed out of line at opt-level `z` and `s` and returned copies of
        // the state words through memory.
        let [s0, s1, s2, s3] = &states;
        *block = transpose_words([
            load_words(&s0.as_chunks::<4>().0[j]),
            load_words(&s1.as_chunks::<4>().0[j]),
            load_words(&s2.as_chunks::<4>().0[j]),
            load_words(&s3.as_chunks::<4>().0[j]),
        ]);
    }
    *last = _mm256_setr_epi64x(
        states[0][24] as i64,
        states[1][24] as i64,
        states[2][24] as i64,
        states[3][24] as i64,
    );

    let bytes = ByteRotations::new();
    for &rc in &RC[24 - ROUNDS..] {
        round(&mut a, rc, bytes);
    }

    let (blocks, [last]) = a.as_chunks::<4>() else {
        unreachable!("25 lanes are six blocks of four and one more");
    };
    for (j, block) in blocks.iter().enumerate() {
        for (state, row) in states.iter_mut().zip(&transpose_words(*block)) {
            store_words(&mut state.as_chunks_mut::<4>().0[j], *row);
        }
    }
    let mut words = [0; 4];
    store_words(&mut words, *last);
    for (state, word) in states.iter_mut().zip(&words) {
        state[24] = *word;
    }
    // The working copies hold the (possibly secret) states.
    a.zeroize();
    words.zeroize();
}
