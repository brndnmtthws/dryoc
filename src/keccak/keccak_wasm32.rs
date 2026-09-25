//! WebAssembly `simd128` 2-way Keccak-p[1600].
//!
//! Two independent states are permuted together: vector `i` holds lane `i`
//! (`x + 5 * y`) of both, one state per 64-bit word, so each step of a round
//! is the scalar step on vectors. Rotations are shift pairs (a byte shuffle
//! for 8 and 56), `v128_andnot` gives the `chi` step, and the round constant
//! is splatted. Control flow and memory access are independent of the
//! state. One 2-way permutation costs less than one scalar permutation in
//! both V8 and Wasmtime, so a leftover state runs beside a spare zero state
//! instead of going to the `keccak` crate.
//!
//! Wiping: the 25 lane vectors and the rounds' temporaries only flow through
//! inlined helpers, so they live in the engine's registers or spill slots
//! (`permute2` uses no linear-memory stack frame), which are out of Rust's
//! reach and not wiped; a wipe would only force them into linear memory. The
//! states are read from and written back to the caller's arrays, which the
//! sponge wipes; the spare state only ever holds the permuted zero state.

use core::arch::wasm32::{
    i8x16_shuffle, i64x2_shl, u64x2, u64x2_extract_lane, u64x2_shr, u64x2_splat, v128, v128_andnot,
    v128_or, v128_xor,
};

use super::{RC, RHO};

/// The `simd128` kernel. WebAssembly has no runtime feature detection: this
/// module is only compiled when the crate is built with `simd128` enabled,
/// so the kernel is always available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kernel {
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

    /// Applies Keccak-p[1600, `ROUNDS`] to the states in `selected`, two at
    /// a time in lane order, and clears their flags. A leftover state runs
    /// beside a spare zero state, since one 2-way permutation costs less
    /// than a scalar one.
    pub(super) fn permute_selected<const ROUNDS: usize, const N: usize>(
        self,
        states: &mut [[u64; 25]; N],
        selected: &mut [bool; N],
    ) {
        let mut pending = None;
        for (state, selected) in states.iter_mut().zip(selected) {
            if !core::mem::take(selected) {
                continue;
            }
            match pending.take() {
                Some(first) => self.permute2::<ROUNDS>([first, state]),
                None => pending = Some(state),
            }
        }
        if let Some(last) = pending {
            self.permute2::<ROUNDS>([last, &mut [0; 25]]);
        }
    }

    /// Keccak-p[1600, `ROUNDS`] on two states.
    #[inline]
    fn permute2<const ROUNDS: usize>(self, states: [&mut [u64; 25]; 2]) {
        match self {
            Kernel::Simd128 => permute2::<ROUNDS>(states),
        }
    }
}

/// Rotates both 64-bit words of `$v` left by the constant `$n < 64`: a byte
/// shuffle for 8 and 56, otherwise a pair of shifts.
macro_rules! rotl {
    ($v:expr, $n:expr) => {{
        let v = $v;
        match $n {
            0 => v,
            8 => i8x16_shuffle::<7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14>(v, v),
            56 => i8x16_shuffle::<1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8>(v, v),
            n => v128_or(i64x2_shl(v, n), u64x2_shr(v, 64 - n)),
        }
    }};
}

/// One Keccak-p[1600] round with round constant `rc` on the two states.
#[inline(always)]
fn round(a: &mut [v128; 25], rc: u64) {
    // theta: the column parities `c`, then `d[x] = c[x - 1] ^ (c[x + 1] <<<
    // 1)`.
    let mut c = [u64x2_splat(0); 5];
    unroll5!(X, {
        c[X] = v128_xor(
            v128_xor(a[X], a[X + 5]),
            v128_xor(v128_xor(a[X + 10], a[X + 15]), a[X + 20]),
        );
    });
    let mut d = [u64x2_splat(0); 5];
    unroll5!(X, {
        d[X] = v128_xor(c[(X + 4) % 5], rotl!(c[(X + 1) % 5], 1));
    });
    // theta's XOR of `d`, rho and pi: lane `(x, y)` moves to `(y, 2x + 3y)`.
    let mut b = [u64x2_splat(0); 25];
    unroll5!(Y, {
        unroll5!(X, {
            b[Y + 5 * ((2 * X + 3 * Y) % 5)] = rotl!(v128_xor(a[X + 5 * Y], d[X]), RHO[X + 5 * Y]);
        });
    });
    // chi: `b[x] ^ (!b[x + 1] & b[x + 2])`.
    unroll5!(Y, {
        unroll5!(X, {
            a[X + 5 * Y] = v128_xor(
                b[X + 5 * Y],
                v128_andnot(b[(X + 2) % 5 + 5 * Y], b[(X + 1) % 5 + 5 * Y]),
            );
        });
    });
    // iota.
    a[0] = v128_xor(a[0], u64x2_splat(rc));
}

/// Keccak-p[1600, `ROUNDS`] on two states.
fn permute2<const ROUNDS: usize>([s0, s1]: [&mut [u64; 25]; 2]) {
    const { assert!(ROUNDS <= 24) };
    let mut a: [v128; 25] = core::array::from_fn(|i| u64x2(s0[i], s1[i]));
    for &rc in &RC[24 - ROUNDS..] {
        round(&mut a, rc);
    }
    for (i, lane) in a.iter().enumerate() {
        s0[i] = u64x2_extract_lane::<0>(*lane);
        s1[i] = u64x2_extract_lane::<1>(*lane);
    }
}
