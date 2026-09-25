//! Register-scheduled scalar ChaCha20 rounds for AArch64.
//!
//! `z = (z ^ x) <<< r` is computed as `ror z, z, #(32 - r)` followed by
//! `eor z, z, x, ror #(32 - r)`, so the rotation of `z` leaves the critical
//! path and each quarter-round step is two dependent instructions (`add`,
//! `eor`) instead of three (`add`, `eor`, `ror`). LLVM folds the two
//! rotations back into one when this is written in Rust, which is why the
//! schedule is pinned in assembly. Base A64 integer instructions only, so no
//! feature detection is needed.

/// One quarter-round step `x += y; z = (z ^ x) <<< (32 - $k)` as
/// `add`, an off-path `ror` of `z`, and an `eor` with a rotated `x`.
macro_rules! step {
    ($x:literal, $y:literal, $z:literal, $k:literal) => {
        concat!(
            "add {",
            $x,
            ":w}, {",
            $x,
            ":w}, {",
            $y,
            ":w}\n",
            "ror {",
            $z,
            ":w}, {",
            $z,
            ":w}, #",
            $k,
            "\n",
            "eor {",
            $z,
            ":w}, {",
            $z,
            ":w}, {",
            $x,
            ":w}, ror #",
            $k,
            "\n",
        )
    };
}

/// Four independent quarter rounds, interleaved step by step so the four
/// dependency chains are visible to the scheduler.
macro_rules! round {
    (
        $a0:literal,
        $b0:literal,
        $c0:literal,
        $d0:literal,
        $a1:literal,
        $b1:literal,
        $c1:literal,
        $d1:literal,
        $a2:literal,
        $b2:literal,
        $c2:literal,
        $d2:literal,
        $a3:literal,
        $b3:literal,
        $c3:literal,
        $d3:literal
    ) => {
        concat!(
            step!($a0, $b0, $d0, 16),
            step!($a1, $b1, $d1, 16),
            step!($a2, $b2, $d2, 16),
            step!($a3, $b3, $d3, 16),
            step!($c0, $d0, $b0, 20),
            step!($c1, $d1, $b1, 20),
            step!($c2, $d2, $b2, 20),
            step!($c3, $d3, $b3, 20),
            step!($a0, $b0, $d0, 24),
            step!($a1, $b1, $d1, 24),
            step!($a2, $b2, $d2, 24),
            step!($a3, $b3, $d3, 24),
            step!($c0, $d0, $b0, 25),
            step!($c1, $d1, $b1, 25),
            step!($c2, $d2, $b2, 25),
            step!($c3, $d3, $b3, 25),
        )
    };
}

/// The 20 ChaCha rounds over the 16 state words held in registers.
/// `#[inline(always)]`: out of line (opt-level `z`) it took the caller's
/// working copy of the key state through memory.
#[inline(always)]
pub(super) fn rounds(x: &mut [u32; 16]) {
    let [
        mut x0,
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x5,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
        mut x10,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x15,
    ] = *x;
    // SAFETY: register-only integer arithmetic; the block touches no
    // memory, and every state word is an `inout` register operand.
    unsafe {
        core::arch::asm!(
            "mov {n:w}, #10",
            "2:",
            round!("x0", "x4", "x8", "x12", "x1", "x5", "x9", "x13",
                   "x2", "x6", "x10", "x14", "x3", "x7", "x11", "x15"),
            round!("x0", "x5", "x10", "x15", "x1", "x6", "x11", "x12",
                   "x2", "x7", "x8", "x13", "x3", "x4", "x9", "x14"),
            "subs {n:w}, {n:w}, #1",
            "b.ne 2b",
            x0 = inout(reg) x0,
            x1 = inout(reg) x1,
            x2 = inout(reg) x2,
            x3 = inout(reg) x3,
            x4 = inout(reg) x4,
            x5 = inout(reg) x5,
            x6 = inout(reg) x6,
            x7 = inout(reg) x7,
            x8 = inout(reg) x8,
            x9 = inout(reg) x9,
            x10 = inout(reg) x10,
            x11 = inout(reg) x11,
            x12 = inout(reg) x12,
            x13 = inout(reg) x13,
            x14 = inout(reg) x14,
            x15 = inout(reg) x15,
            n = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    *x = [
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
    ];
}
