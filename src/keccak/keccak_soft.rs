//! Portable scalar Keccak-p[1600] with lazy rotations, the single-state
//! permutation on AArch64.
//!
//! The `rho` rotation of every lane is not applied when the lane is
//! computed but carried as a pending rotation into the next round, where it
//! folds into the rotated-operand forms of `eor` and `bic` (A64 applies a
//! rotation to the second operand of both for free); iota's constant is
//! rotated to match. After the last round the pending rotations are applied
//! once. The pending amounts depend only on the round number, so they are
//! the compile-time table [`LAZY`] and every rotation count is a constant.
//! Round `k`'s theta, rho-pi and chi then take about 100 instructions with
//! no separate rotation, against about 125 for the plain round (and about
//! 65 SHA3-extension vector instructions, which are fewer but limited to
//! the vector pipes). On Neoverse V3 this is faster than the one-state
//! SHA3-extension kernel, whose second lane is wasted.
//!
//! The lanes are 25 named locals, so they live in registers and compiler
//! spill slots, which Rust cannot reliably wipe; wiping them would only
//! force them into memory. Control flow and memory access are independent
//! of the state.

use super::{RC, RHO};

/// `(a - b) mod 64`: the rotation taking a lane pending `b` to pending `a`.
const fn sub(a: u32, b: u32) -> u32 {
    (a + 64 - b) % 64
}

/// Pending left rotation of each lane at the start of round `k` (row `k`)
/// of a permutation that starts with none: rho adds each lane's offset and
/// pi moves lane `(x, y)` to `(y, 2x + 3y)`.
const LAZY: [[u32; 25]; 25] = {
    let mut p = [[0u32; 25]; 25];
    let mut k = 0;
    while k < 24 {
        let mut i = 0;
        while i < 25 {
            let (x, y) = (i % 5, i / 5);
            p[k + 1][y + 5 * ((2 * x + 3 * y) % 5)] = (p[k][i] + RHO[i]) % 64;
            i += 1;
        }
        k += 1;
    }
    p
};

/// `a ^ b.rotate_left(N)`, as one `eor` with a rotated operand on AArch64.
///
/// Written as an `asm!` instruction because LLVM otherwise shares a rotated
/// value between uses with the same amount, spending a separate `ror` to
/// save nothing (the rotated-operand forms cost the same as the plain ones
/// on Neoverse V3: six per cycle, one cycle latency).
#[inline(always)]
fn xor_rol<const N: u32>(a: u64, b: u64) -> u64 {
    #[cfg(not(miri))]
    {
        let out;
        // SAFETY: one register-only instruction: it reads `a` and `b`,
        // writes `out`, and touches no memory, stack or flags.
        unsafe {
            core::arch::asm!(
                "eor {out}, {a}, {b}, ror #{r}",
                out = lateout(reg) out,
                a = in(reg) a,
                b = in(reg) b,
                r = const (64 - N) % 64,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        out
    }
    #[cfg(miri)]
    {
        a ^ b.rotate_left(N)
    }
}

/// `a & !b.rotate_left(N)`, as one `bic` with a rotated operand on AArch64;
/// see [`xor_rol`].
#[inline(always)]
fn bic_rol<const N: u32>(a: u64, b: u64) -> u64 {
    #[cfg(not(miri))]
    {
        let out;
        // SAFETY: one register-only instruction: it reads `a` and `b`,
        // writes `out`, and touches no memory, stack or flags.
        unsafe {
            core::arch::asm!(
                "bic {out}, {a}, {b}, ror #{r}",
                out = lateout(reg) out,
                a = in(reg) a,
                b = in(reg) b,
                r = const (64 - N) % 64,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        out
    }
    #[cfg(miri)]
    {
        a & !b.rotate_left(N)
    }
}

/// Keccak-p[1600, `ROUNDS`] on one state, in place.
pub(super) fn permute<const ROUNDS: usize>(state: &mut [u64; 25]) {
    permute_xor::<ROUNDS>(state, &[]);
}

/// [`permute`], then XORs the whole little-endian words of `block` (at most
/// 200 bytes) into the first lanes, folded into the permutation's final
/// stores: a sponge absorbing a full block after a full block saves a pass
/// over the state.
pub(super) fn permute_xor<const ROUNDS: usize>(state: &mut [u64; 25], block: &[u8]) {
    const { assert!(ROUNDS <= 24) };
    let [
        mut a0,
        mut a1,
        mut a2,
        mut a3,
        mut a4,
        mut a5,
        mut a6,
        mut a7,
        mut a8,
        mut a9,
        mut a10,
        mut a11,
        mut a12,
        mut a13,
        mut a14,
        mut a15,
        mut a16,
        mut a17,
        mut a18,
        mut a19,
        mut a20,
        mut a21,
        mut a22,
        mut a23,
        mut a24,
    ] = *state;
    macro_rules! round {
        ($k:literal) => {{
            const P: [u32; 25] = LAZY[$k];
            const Q: [u32; 25] = LAZY[$k + 1];
            let c0 = xor_rol::<{ sub(P[20], P[0]) }>(
                xor_rol::<{ sub(P[10], P[0]) }>(
                    xor_rol::<{ sub(P[5], P[0]) }>(a0, a5),
                    xor_rol::<{ sub(P[15], P[10]) }>(a10, a15),
                ),
                a20,
            );
            let c1 = xor_rol::<{ sub(P[21], P[1]) }>(
                xor_rol::<{ sub(P[11], P[1]) }>(
                    xor_rol::<{ sub(P[6], P[1]) }>(a1, a6),
                    xor_rol::<{ sub(P[16], P[11]) }>(a11, a16),
                ),
                a21,
            );
            let c2 = xor_rol::<{ sub(P[22], P[2]) }>(
                xor_rol::<{ sub(P[12], P[2]) }>(
                    xor_rol::<{ sub(P[7], P[2]) }>(a2, a7),
                    xor_rol::<{ sub(P[17], P[12]) }>(a12, a17),
                ),
                a22,
            );
            let c3 = xor_rol::<{ sub(P[23], P[3]) }>(
                xor_rol::<{ sub(P[13], P[3]) }>(
                    xor_rol::<{ sub(P[8], P[3]) }>(a3, a8),
                    xor_rol::<{ sub(P[18], P[13]) }>(a13, a18),
                ),
                a23,
            );
            let c4 = xor_rol::<{ sub(P[24], P[4]) }>(
                xor_rol::<{ sub(P[14], P[4]) }>(
                    xor_rol::<{ sub(P[9], P[4]) }>(a4, a9),
                    xor_rol::<{ sub(P[19], P[14]) }>(a14, a19),
                ),
                a24,
            );
            let d0 = xor_rol::<{ sub(P[1] + 1, P[4]) }>(c4, c1);
            let d1 = xor_rol::<{ sub(P[2] + 1, P[0]) }>(c0, c2);
            let d2 = xor_rol::<{ sub(P[3] + 1, P[1]) }>(c1, c3);
            let d3 = xor_rol::<{ sub(P[4] + 1, P[2]) }>(c2, c4);
            let d4 = xor_rol::<{ sub(P[0] + 1, P[3]) }>(c3, c0);
            let b0 = xor_rol::<{ sub(P[4], P[0]) }>(a0, d0);
            let b1 = xor_rol::<{ sub(P[0], P[6]) }>(a6, d1);
            let b2 = xor_rol::<{ sub(P[1], P[12]) }>(a12, d2);
            let b3 = xor_rol::<{ sub(P[2], P[18]) }>(a18, d3);
            let b4 = xor_rol::<{ sub(P[3], P[24]) }>(a24, d4);
            let b5 = xor_rol::<{ sub(P[2], P[3]) }>(a3, d3);
            let b6 = xor_rol::<{ sub(P[3], P[9]) }>(a9, d4);
            let b7 = xor_rol::<{ sub(P[4], P[10]) }>(a10, d0);
            let b8 = xor_rol::<{ sub(P[0], P[16]) }>(a16, d1);
            let b9 = xor_rol::<{ sub(P[1], P[22]) }>(a22, d2);
            let b10 = xor_rol::<{ sub(P[0], P[1]) }>(a1, d1);
            let b11 = xor_rol::<{ sub(P[1], P[7]) }>(a7, d2);
            let b12 = xor_rol::<{ sub(P[2], P[13]) }>(a13, d3);
            let b13 = xor_rol::<{ sub(P[3], P[19]) }>(a19, d4);
            let b14 = xor_rol::<{ sub(P[4], P[20]) }>(a20, d0);
            let b15 = xor_rol::<{ sub(P[3], P[4]) }>(a4, d4);
            let b16 = xor_rol::<{ sub(P[4], P[5]) }>(a5, d0);
            let b17 = xor_rol::<{ sub(P[0], P[11]) }>(a11, d1);
            let b18 = xor_rol::<{ sub(P[1], P[17]) }>(a17, d2);
            let b19 = xor_rol::<{ sub(P[2], P[23]) }>(a23, d3);
            let b20 = xor_rol::<{ sub(P[1], P[2]) }>(a2, d2);
            let b21 = xor_rol::<{ sub(P[2], P[8]) }>(a8, d3);
            let b22 = xor_rol::<{ sub(P[3], P[14]) }>(a14, d4);
            let b23 = xor_rol::<{ sub(P[4], P[15]) }>(a15, d0);
            let b24 = xor_rol::<{ sub(P[0], P[21]) }>(a21, d1);
            a0 = xor_rol::<{ sub(Q[2], Q[0]) }>(b0, bic_rol::<{ sub(Q[1], Q[2]) }>(b2, b1));
            a1 = xor_rol::<{ sub(Q[3], Q[1]) }>(b1, bic_rol::<{ sub(Q[2], Q[3]) }>(b3, b2));
            a2 = xor_rol::<{ sub(Q[4], Q[2]) }>(b2, bic_rol::<{ sub(Q[3], Q[4]) }>(b4, b3));
            a3 = xor_rol::<{ sub(Q[0], Q[3]) }>(b3, bic_rol::<{ sub(Q[4], Q[0]) }>(b0, b4));
            a4 = xor_rol::<{ sub(Q[1], Q[4]) }>(b4, bic_rol::<{ sub(Q[0], Q[1]) }>(b1, b0));
            a5 = xor_rol::<{ sub(Q[7], Q[5]) }>(b5, bic_rol::<{ sub(Q[6], Q[7]) }>(b7, b6));
            a6 = xor_rol::<{ sub(Q[8], Q[6]) }>(b6, bic_rol::<{ sub(Q[7], Q[8]) }>(b8, b7));
            a7 = xor_rol::<{ sub(Q[9], Q[7]) }>(b7, bic_rol::<{ sub(Q[8], Q[9]) }>(b9, b8));
            a8 = xor_rol::<{ sub(Q[5], Q[8]) }>(b8, bic_rol::<{ sub(Q[9], Q[5]) }>(b5, b9));
            a9 = xor_rol::<{ sub(Q[6], Q[9]) }>(b9, bic_rol::<{ sub(Q[5], Q[6]) }>(b6, b5));
            a10 = xor_rol::<{ sub(Q[12], Q[10]) }>(b10, bic_rol::<{ sub(Q[11], Q[12]) }>(b12, b11));
            a11 = xor_rol::<{ sub(Q[13], Q[11]) }>(b11, bic_rol::<{ sub(Q[12], Q[13]) }>(b13, b12));
            a12 = xor_rol::<{ sub(Q[14], Q[12]) }>(b12, bic_rol::<{ sub(Q[13], Q[14]) }>(b14, b13));
            a13 = xor_rol::<{ sub(Q[10], Q[13]) }>(b13, bic_rol::<{ sub(Q[14], Q[10]) }>(b10, b14));
            a14 = xor_rol::<{ sub(Q[11], Q[14]) }>(b14, bic_rol::<{ sub(Q[10], Q[11]) }>(b11, b10));
            a15 = xor_rol::<{ sub(Q[17], Q[15]) }>(b15, bic_rol::<{ sub(Q[16], Q[17]) }>(b17, b16));
            a16 = xor_rol::<{ sub(Q[18], Q[16]) }>(b16, bic_rol::<{ sub(Q[17], Q[18]) }>(b18, b17));
            a17 = xor_rol::<{ sub(Q[19], Q[17]) }>(b17, bic_rol::<{ sub(Q[18], Q[19]) }>(b19, b18));
            a18 = xor_rol::<{ sub(Q[15], Q[18]) }>(b18, bic_rol::<{ sub(Q[19], Q[15]) }>(b15, b19));
            a19 = xor_rol::<{ sub(Q[16], Q[19]) }>(b19, bic_rol::<{ sub(Q[15], Q[16]) }>(b16, b15));
            a20 = xor_rol::<{ sub(Q[22], Q[20]) }>(b20, bic_rol::<{ sub(Q[21], Q[22]) }>(b22, b21));
            a21 = xor_rol::<{ sub(Q[23], Q[21]) }>(b21, bic_rol::<{ sub(Q[22], Q[23]) }>(b23, b22));
            a22 = xor_rol::<{ sub(Q[24], Q[22]) }>(b22, bic_rol::<{ sub(Q[23], Q[24]) }>(b24, b23));
            a23 = xor_rol::<{ sub(Q[20], Q[23]) }>(b23, bic_rol::<{ sub(Q[24], Q[20]) }>(b20, b24));
            a24 = xor_rol::<{ sub(Q[21], Q[24]) }>(b24, bic_rol::<{ sub(Q[20], Q[21]) }>(b21, b20));
            a0 ^= RC[24 - ROUNDS + $k].rotate_right(Q[0]);
        }};
    }
    macro_rules! rounds {
        ($($k:literal)*) => {
            $(
                if $k < ROUNDS {
                    round!($k);
                }
            )*
        };
    }
    rounds!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23);
    let q = &LAZY[ROUNDS];
    *state = [
        a0.rotate_left(q[0]),
        a1.rotate_left(q[1]),
        a2.rotate_left(q[2]),
        a3.rotate_left(q[3]),
        a4.rotate_left(q[4]),
        a5.rotate_left(q[5]),
        a6.rotate_left(q[6]),
        a7.rotate_left(q[7]),
        a8.rotate_left(q[8]),
        a9.rotate_left(q[9]),
        a10.rotate_left(q[10]),
        a11.rotate_left(q[11]),
        a12.rotate_left(q[12]),
        a13.rotate_left(q[13]),
        a14.rotate_left(q[14]),
        a15.rotate_left(q[15]),
        a16.rotate_left(q[16]),
        a17.rotate_left(q[17]),
        a18.rotate_left(q[18]),
        a19.rotate_left(q[19]),
        a20.rotate_left(q[20]),
        a21.rotate_left(q[21]),
        a22.rotate_left(q[22]),
        a23.rotate_left(q[23]),
        a24.rotate_left(q[24]),
    ];
    for (lane, word) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*word);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lazy-rotation rounds equal the `keccak` crate's Keccak-p[1600]
    /// with 24 and 12 rounds, and the table returns every lane to its place
    /// with a rotation below 64.
    #[test]
    fn test_permute_matches_crate() {
        fn check<const ROUNDS: usize>(seed: u64) {
            let mut seed = seed;
            let mut state: [u64; 25] = core::array::from_fn(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            });
            let keccak = keccak::Keccak::new();
            for _ in 0..4 {
                let mut expected = state;
                keccak.with_p1600::<ROUNDS>(|p1600| p1600(&mut expected));
                permute::<ROUNDS>(&mut state);
                assert_eq!(state, expected, "{ROUNDS} rounds");
            }
        }
        for seed in [1, 0x9e37_79b9_7f4a_7c15, 0x2545_f491_4f6c_dd1d] {
            check::<24>(seed);
            check::<12>(seed);
            check::<1>(seed);
        }
        assert!(LAZY.iter().flatten().all(|&r| r < 64));
        assert_eq!(LAZY[0], [0; 25]);
    }
}
