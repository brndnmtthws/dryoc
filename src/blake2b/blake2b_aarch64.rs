//! Register-scheduled rounds for AArch64.
//!
//! Each `G` step `z = (z ^ x) >>> r` is emitted as `ror z, z, #r` followed by
//! `eor z, z, x, ror #r`: the rotation of `z` (ready one step earlier) leaves
//! the dependency chain, so a step costs two dependent instructions instead
//! of three. The message word is added to `a` before `b` is, for the same
//! reason. Message words are loaded straight from the little-endian block
//! with immediate offsets, so the working state and four temporaries fit in
//! registers without spilling.

use super::BLOCKBYTES;

/// The first or second half of `G`: `a += b + m[$x]`, then two
/// add/xor-rotate steps with rotations `$r1` and `$r2`.
macro_rules! half_g {
    (
        $t:literal,
        $a:literal,
        $b:literal,
        $c:literal,
        $d:literal,
        $x:literal,
        $r1:literal,
        $r2:literal
    ) => {
        concat!(
            "ldr {",
            $t,
            "}, [{m}, #",
            $x,
            "*8]\n",
            "add {",
            $a,
            "}, {",
            $a,
            "}, {",
            $t,
            "}\n",
            "add {",
            $a,
            "}, {",
            $a,
            "}, {",
            $b,
            "}\n",
            "ror {",
            $d,
            "}, {",
            $d,
            "}, #",
            $r1,
            "\n",
            "eor {",
            $d,
            "}, {",
            $d,
            "}, {",
            $a,
            "}, ror #",
            $r1,
            "\n",
            "add {",
            $c,
            "}, {",
            $c,
            "}, {",
            $d,
            "}\n",
            "ror {",
            $b,
            "}, {",
            $b,
            "}, #",
            $r2,
            "\n",
            "eor {",
            $b,
            "}, {",
            $b,
            "}, {",
            $c,
            "}, ror #",
            $r2,
            "\n",
        )
    };
}

/// Four independent `G` functions (a column or diagonal half round),
/// interleaved half by half.
macro_rules! half_round {
    (
        $a0:literal,
        $b0:literal,
        $c0:literal,
        $d0:literal,
        $x0:literal,
        $y0:literal,
        $a1:literal,
        $b1:literal,
        $c1:literal,
        $d1:literal,
        $x1:literal,
        $y1:literal,
        $a2:literal,
        $b2:literal,
        $c2:literal,
        $d2:literal,
        $x2:literal,
        $y2:literal,
        $a3:literal,
        $b3:literal,
        $c3:literal,
        $d3:literal,
        $x3:literal,
        $y3:literal
    ) => {
        concat!(
            half_g!("t0", $a0, $b0, $c0, $d0, $x0, 32, 24),
            half_g!("t1", $a1, $b1, $c1, $d1, $x1, 32, 24),
            half_g!("t2", $a2, $b2, $c2, $d2, $x2, 32, 24),
            half_g!("t3", $a3, $b3, $c3, $d3, $x3, 32, 24),
            half_g!("t0", $a0, $b0, $c0, $d0, $y0, 16, 63),
            half_g!("t1", $a1, $b1, $c1, $d1, $y1, 16, 63),
            half_g!("t2", $a2, $b2, $c2, $d2, $y2, 16, 63),
            half_g!("t3", $a3, $b3, $c3, $d3, $y3, 16, 63),
        )
    };
}

/// One round: the column half round followed by the diagonal half round,
/// with the sixteen SIGMA entries `$s*` as message word indices.
macro_rules! round {
    (
        $s0:literal,
        $s1:literal,
        $s2:literal,
        $s3:literal,
        $s4:literal,
        $s5:literal,
        $s6:literal,
        $s7:literal,
        $s8:literal,
        $s9:literal,
        $s10:literal,
        $s11:literal,
        $s12:literal,
        $s13:literal,
        $s14:literal,
        $s15:literal
    ) => {
        concat!(
            half_round!(
                "v0", "v4", "v8", "v12", $s0, $s1, "v1", "v5", "v9", "v13", $s2, $s3, "v2", "v6",
                "v10", "v14", $s4, $s5, "v3", "v7", "v11", "v15", $s6, $s7
            ),
            half_round!(
                "v0", "v5", "v10", "v15", $s8, $s9, "v1", "v6", "v11", "v12", $s10, $s11, "v2",
                "v7", "v8", "v13", $s12, $s13, "v3", "v4", "v9", "v14", $s14, $s15
            ),
        )
    };
}

/// The twelve BLAKE2b rounds over the working state `v` with the message
/// words of `block`.
///
/// The state words are `asm!` register operands and the message words are
/// loaded straight into scratch registers, so the rounds make no memory copy
/// of either; registers and compiler spill slots are out of Rust's reach and
/// are not wiped. `#[inline(always)]`: out of line, the state words would
/// go through memory at `v`.
#[inline(always)]
pub(super) fn rounds(v: &mut [u64; 16], block: &[u8; BLOCKBYTES]) {
    let [
        mut v0,
        mut v1,
        mut v2,
        mut v3,
        mut v4,
        mut v5,
        mut v6,
        mut v7,
        mut v8,
        mut v9,
        mut v10,
        mut v11,
        mut v12,
        mut v13,
        mut v14,
        mut v15,
    ] = *v;
    // SAFETY: the only memory accesses are 192 unaligned 8-byte loads
    // (two per `G`, one per `half_g!`) at immediate offsets 0..=120 from
    // `block`, a live `&[u8; 128]` that stays borrowed for the duration
    // of the block; nothing is written. The state words are `inout`
    // registers, the four temporaries are scratch outputs, and no stack
    // or flags are touched.
    unsafe {
        core::arch::asm!(
            round!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            round!(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            round!(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            round!(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            round!(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            round!(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            round!(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            round!(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            round!(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            round!(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            round!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            round!(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            m = in(reg) block.as_ptr(),
            v0 = inout(reg) v0,
            v1 = inout(reg) v1,
            v2 = inout(reg) v2,
            v3 = inout(reg) v3,
            v4 = inout(reg) v4,
            v5 = inout(reg) v5,
            v6 = inout(reg) v6,
            v7 = inout(reg) v7,
            v8 = inout(reg) v8,
            v9 = inout(reg) v9,
            v10 = inout(reg) v10,
            v11 = inout(reg) v11,
            v12 = inout(reg) v12,
            v13 = inout(reg) v13,
            v14 = inout(reg) v14,
            v15 = inout(reg) v15,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            options(readonly, nostack, preserves_flags),
        );
    }
    *v = [
        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
    ];
}
