//! AArch64 SVE2 Argon2 block compression.
//!
//! The permutation `P` is a message-less BLAKE2b round (with the fBlaMka
//! mixing) over each of the eight 16-word rows of the 1 KiB block and then
//! over each of the eight 16-word columns. Each of the two passes is one
//! `asm!` block: three states run as vectors while the other five run one
//! after the other on the integer registers, so the vector pipes and the
//! integer pipes work at the same time (the portable rounds alone fill the
//! integer pipes, and a vector `G` step has about twice their latency).
//!
//! A vector state is eight 128-bit registers holding its words in pairs,
//! `(v0, v1)` to `(v14, v15)`, so the four `G` mixings of a step are two
//! lane-wise chains, and turning `b` and `d` one and three words across their
//! register pairs (`ext`) and swapping `c`'s lines the diagonals up. A `G`
//! step is `add`, `umullb` (the product of the low 32-bit halves of each
//! lane), `adr` (`x + y + 2 * xy` as an address computation) and `xar` (XOR
//! then rotate), all lane-wise, so the lanes beyond the low 128 bits (on a
//! CPU with longer vectors) compute unused values the NEON stores ignore. The
//! integer state's `G` step is `ubfiz`, `mov`, `add`, `madd` and a `ror`
//! plus an `eor` with a rotated operand. Control flow and memory access are
//! independent of the data.
//!
//! Zeroization: the permutation runs in place on the caller's `dst` block,
//! and the XORs around it use the caller's `scratch` block. Both are
//! [`Block`]s, which wipe themselves on drop. The `asm!` blocks load and
//! store every state themselves and use no stack, so the working values
//! live only in registers. Rust cannot reliably wipe those, and wiping them
//! would only add work, so the kernel adds no wipes of its own.

use super::{Block, finish_in_place, prepare_in_place};
use crate::aarch64::Sve2;

/// The SVE2 kernel, holding the token that proves the CPU supports it, which
/// is what makes [`Kernel::fill_block`] safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Kernel(Sve2);

/// The kernel, if the running CPU supports it.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    Sve2::new().map(Kernel)
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        detect().into_iter().collect()
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
        permute(self.0, dst);
        finish_in_place(dst, prev_block, ref_block, xor_old, scratch);
    }
}

/// [`permute_unchecked`], safe to call with an [`Sve2`] token.
#[inline(always)]
fn permute(_: Sve2, block: &mut Block) {
    // SAFETY: an `Sve2` token exists only after detection of `sve2` (which
    // implies `neon`), the features the kernel is compiled for.
    unsafe { permute_unchecked(block) }
}

/// `x = fBlaMka(x, y); z = (z ^ x) >>> r` on vector lanes, with `z24` and
/// `z25` as scratch.
#[rustfmt::skip]
macro_rules! vpair {
    ($x:literal, $y:literal, $z:literal, $r:literal) => {
        concat!(
            "add z24.d, z", $x, ".d, z", $y, ".d\n",
            "umullb z25.d, z", $x, ".s, z", $y, ".s\n",
            "adr z", $x, ".d, [z24.d, z25.d, lsl #1]\n",
            "xar z", $z, ".d, z", $z, ".d, z", $x, ".d, #", $r, "\n",
        )
    };
}

/// `x = fBlaMka(x, y); z = (z ^ x) >>> r` on integer operands, with `t` and
/// `u` as scratch: `2 lo32(x)` (`ubfiz`) times `lo32(y)` (a zero-extending
/// `mov`) added to `x + y` by one `madd`, the form LLVM picks for the portable
/// rounds (`umull` and a shifted `add` is one instruction fewer but measured
/// slower). `z` is rotated first, off the path from `x`, so the rotation of
/// `x` folds into the `eor`.
#[rustfmt::skip]
macro_rules! spair {
    ($x:literal, $y:literal, $z:literal, $r:literal) => {
        concat!(
            "ubfiz {t}, {", $x, "}, #1, #32\n",
            "mov {u:w}, {", $y, ":w}\n",
            "add {", $x, "}, {", $x, "}, {", $y, "}\n",
            "madd {", $x, "}, {t}, {u}, {", $x, "}\n",
            "ror {", $z, "}, {", $z, "}, #", $r, "\n",
            "eor {", $z, "}, {", $z, "}, {", $x, "}, ror #", $r, "\n",
        )
    };
}

/// Lines a vector state's diagonals up: `b = (b0, b1)` becomes `tb = (v5,
/// v6)` and `b1 = (v7, v4)`, `d = (d0, d1)` becomes `td = (v15, v12)` and
/// `d1 = (v13, v14)`.
#[rustfmt::skip]
macro_rules! diagonalize {
    ($b0:literal, $b1:literal, $d0:literal, $d1:literal, $tb:literal, $td:literal) => {
        concat!(
            "ext v", $tb, ".16b, v", $b0, ".16b, v", $b1, ".16b, #8\n",
            "ext v", $b1, ".16b, v", $b1, ".16b, v", $b0, ".16b, #8\n",
            "ext v", $td, ".16b, v", $d1, ".16b, v", $d0, ".16b, #8\n",
            "ext v", $d1, ".16b, v", $d0, ".16b, v", $d1, ".16b, #8\n",
        )
    };
}

/// Undoes [`diagonalize`].
#[rustfmt::skip]
macro_rules! undiagonalize {
    ($b0:literal, $b1:literal, $d0:literal, $d1:literal, $tb:literal, $td:literal) => {
        concat!(
            "ext v", $b0, ".16b, v", $b1, ".16b, v", $tb, ".16b, #8\n",
            "ext v", $b1, ".16b, v", $tb, ".16b, v", $b1, ".16b, #8\n",
            "ext v", $d0, ".16b, v", $td, ".16b, v", $d1, ".16b, #8\n",
            "ext v", $d1, ".16b, v", $d1, ".16b, v", $td, ".16b, #8\n",
        )
    };
}

/// Loads the vector state registers `$k` through `$p`, advancing it by
/// `{st}` bytes per register.
#[rustfmt::skip]
macro_rules! vload {
    ($p:literal, $($k:literal),+) => {
        concat!($("ld1 {{v", $k, ".2d}}, [{", $p, "}], {st}\n",)+)
    };
}

/// Rewinds `$p` over what [`vload`] advanced it by and stores the registers
/// back the same way.
#[rustfmt::skip]
macro_rules! vstore {
    ($p:literal, $($k:literal),+) => {
        concat!(
            "sub {", $p, "}, {", $p, "}, {st}, lsl #3\n",
            $("st1 {{v", $k, ".2d}}, [{", $p, "}], {st}\n",)+
        )
    };
}

/// Loads (`ldp`) or stores (`stp`) the integer state's eight word pairs
/// through `$q`, `$st` bytes apart, then moves `$q` back by `$adj` bytes to
/// the next state.
#[rustfmt::skip]
macro_rules! spairs {
    ($op:literal, $q:literal, $st:literal, $adj:literal) => {
        concat!(
            $op, " {s0}, {s1}, [{", $q, "}], #", $st, "\n",
            $op, " {s2}, {s3}, [{", $q, "}], #", $st, "\n",
            $op, " {s4}, {s5}, [{", $q, "}], #", $st, "\n",
            $op, " {s6}, {s7}, [{", $q, "}], #", $st, "\n",
            $op, " {s8}, {s9}, [{", $q, "}], #", $st, "\n",
            $op, " {s10}, {s11}, [{", $q, "}], #", $st, "\n",
            $op, " {s12}, {s13}, [{", $q, "}], #", $st, "\n",
            $op, " {s14}, {s15}, [{", $q, "}], #", $st, "\n",
            "sub {", $q, "}, {", $q, "}, #", $adj, "\n",
        )
    };
}

macro_rules! sload {
    ($st:literal, $adj:literal) => {
        spairs!("ldp", "ql", $st, $adj)
    };
}

macro_rules! sstore {
    ($st:literal, $adj:literal) => {
        spairs!("stp", "qs", $st, $adj)
    };
}

/// One pass of `P` over eight states: the vector states start at `$p0`,
/// `$p1` and `$p2` and the five integer states one after the other at `$q`;
/// each state's eight word pairs follow each other every `$st` (`$stride`)
/// bytes, and
/// the integer states start `8 * $st - $adj` bytes apart.
macro_rules! pass {
    ($st:literal, $stride:expr, $adj:literal, $p0:expr, $p1:expr, $p2:expr, $q:expr) => {
        core::arch::asm!(
            vload!("p0", "0", "1", "2", "3", "4", "5", "6", "7"),
            vload!("p1", "8", "9", "10", "11", "12", "13", "14", "15"),
            vload!("p2", "16", "17", "18", "19", "20", "21", "22", "23"),
            sload!($st, $adj),
            spair!("s0", "s4", "s12", "32"),
            spair!("s1", "s5", "s13", "32"),
            spair!("s2", "s6", "s14", "32"),
            spair!("s3", "s7", "s15", "32"),
            spair!("s8", "s12", "s4", "24"),
            spair!("s9", "s13", "s5", "24"),
            spair!("s10", "s14", "s6", "24"),
            spair!("s11", "s15", "s7", "24"),
            spair!("s0", "s4", "s12", "16"),
            spair!("s1", "s5", "s13", "16"),
            spair!("s2", "s6", "s14", "16"),
            spair!("s3", "s7", "s15", "16"),
            vpair!("0", "2", "6", "32"),
            vpair!("1", "3", "7", "32"),
            vpair!("8", "10", "14", "32"),
            vpair!("9", "11", "15", "32"),
            vpair!("16", "18", "22", "32"),
            vpair!("17", "19", "23", "32"),
            spair!("s8", "s12", "s4", "63"),
            spair!("s9", "s13", "s5", "63"),
            spair!("s10", "s14", "s6", "63"),
            spair!("s11", "s15", "s7", "63"),
            spair!("s0", "s5", "s15", "32"),
            spair!("s1", "s6", "s12", "32"),
            spair!("s2", "s7", "s13", "32"),
            spair!("s3", "s4", "s14", "32"),
            spair!("s10", "s15", "s5", "24"),
            spair!("s11", "s12", "s6", "24"),
            spair!("s8", "s13", "s7", "24"),
            spair!("s9", "s14", "s4", "24"),
            spair!("s0", "s5", "s15", "16"),
            spair!("s1", "s6", "s12", "16"),
            spair!("s2", "s7", "s13", "16"),
            spair!("s3", "s4", "s14", "16"),
            vpair!("4", "6", "2", "24"),
            vpair!("5", "7", "3", "24"),
            vpair!("12", "14", "10", "24"),
            vpair!("13", "15", "11", "24"),
            vpair!("20", "22", "18", "24"),
            vpair!("21", "23", "19", "24"),
            spair!("s10", "s15", "s5", "63"),
            spair!("s11", "s12", "s6", "63"),
            spair!("s8", "s13", "s7", "63"),
            spair!("s9", "s14", "s4", "63"),
            sstore!($st, $adj),
            sload!($st, $adj),
            spair!("s0", "s4", "s12", "32"),
            spair!("s1", "s5", "s13", "32"),
            spair!("s2", "s6", "s14", "32"),
            spair!("s3", "s7", "s15", "32"),
            vpair!("0", "2", "6", "16"),
            vpair!("1", "3", "7", "16"),
            vpair!("8", "10", "14", "16"),
            vpair!("9", "11", "15", "16"),
            vpair!("16", "18", "22", "16"),
            vpair!("17", "19", "23", "16"),
            spair!("s8", "s12", "s4", "24"),
            spair!("s9", "s13", "s5", "24"),
            spair!("s10", "s14", "s6", "24"),
            spair!("s11", "s15", "s7", "24"),
            spair!("s0", "s4", "s12", "16"),
            spair!("s1", "s5", "s13", "16"),
            spair!("s2", "s6", "s14", "16"),
            spair!("s3", "s7", "s15", "16"),
            spair!("s8", "s12", "s4", "63"),
            spair!("s9", "s13", "s5", "63"),
            spair!("s10", "s14", "s6", "63"),
            spair!("s11", "s15", "s7", "63"),
            spair!("s0", "s5", "s15", "32"),
            spair!("s1", "s6", "s12", "32"),
            spair!("s2", "s7", "s13", "32"),
            spair!("s3", "s4", "s14", "32"),
            spair!("s10", "s15", "s5", "24"),
            spair!("s11", "s12", "s6", "24"),
            spair!("s8", "s13", "s7", "24"),
            spair!("s9", "s14", "s4", "24"),
            vpair!("4", "6", "2", "63"),
            vpair!("5", "7", "3", "63"),
            vpair!("12", "14", "10", "63"),
            vpair!("13", "15", "11", "63"),
            vpair!("20", "22", "18", "63"),
            vpair!("21", "23", "19", "63"),
            spair!("s0", "s5", "s15", "16"),
            spair!("s1", "s6", "s12", "16"),
            spair!("s2", "s7", "s13", "16"),
            spair!("s3", "s4", "s14", "16"),
            spair!("s10", "s15", "s5", "63"),
            spair!("s11", "s12", "s6", "63"),
            spair!("s8", "s13", "s7", "63"),
            spair!("s9", "s14", "s4", "63"),
            sstore!($st, $adj),
            sload!($st, $adj),
            diagonalize!("2", "3", "6", "7", "26", "27"),
            diagonalize!("10", "11", "14", "15", "28", "29"),
            diagonalize!("18", "19", "22", "23", "30", "31"),
            spair!("s0", "s4", "s12", "32"),
            spair!("s1", "s5", "s13", "32"),
            spair!("s2", "s6", "s14", "32"),
            spair!("s3", "s7", "s15", "32"),
            spair!("s8", "s12", "s4", "24"),
            spair!("s9", "s13", "s5", "24"),
            spair!("s10", "s14", "s6", "24"),
            spair!("s11", "s15", "s7", "24"),
            spair!("s0", "s4", "s12", "16"),
            spair!("s1", "s5", "s13", "16"),
            spair!("s2", "s6", "s14", "16"),
            spair!("s3", "s7", "s15", "16"),
            spair!("s8", "s12", "s4", "63"),
            spair!("s9", "s13", "s5", "63"),
            spair!("s10", "s14", "s6", "63"),
            spair!("s11", "s15", "s7", "63"),
            vpair!("0", "26", "27", "32"),
            vpair!("1", "3", "7", "32"),
            vpair!("8", "28", "29", "32"),
            vpair!("9", "11", "15", "32"),
            vpair!("16", "30", "31", "32"),
            vpair!("17", "19", "23", "32"),
            spair!("s0", "s5", "s15", "32"),
            spair!("s1", "s6", "s12", "32"),
            spair!("s2", "s7", "s13", "32"),
            spair!("s3", "s4", "s14", "32"),
            spair!("s10", "s15", "s5", "24"),
            spair!("s11", "s12", "s6", "24"),
            spair!("s8", "s13", "s7", "24"),
            spair!("s9", "s14", "s4", "24"),
            spair!("s0", "s5", "s15", "16"),
            spair!("s1", "s6", "s12", "16"),
            spair!("s2", "s7", "s13", "16"),
            spair!("s3", "s4", "s14", "16"),
            spair!("s10", "s15", "s5", "63"),
            spair!("s11", "s12", "s6", "63"),
            spair!("s8", "s13", "s7", "63"),
            spair!("s9", "s14", "s4", "63"),
            vpair!("5", "27", "26", "24"),
            vpair!("4", "7", "3", "24"),
            vpair!("13", "29", "28", "24"),
            vpair!("12", "15", "11", "24"),
            vpair!("21", "31", "30", "24"),
            vpair!("20", "23", "19", "24"),
            sstore!($st, $adj),
            sload!($st, $adj),
            spair!("s0", "s4", "s12", "32"),
            spair!("s1", "s5", "s13", "32"),
            spair!("s2", "s6", "s14", "32"),
            spair!("s3", "s7", "s15", "32"),
            spair!("s8", "s12", "s4", "24"),
            spair!("s9", "s13", "s5", "24"),
            spair!("s10", "s14", "s6", "24"),
            spair!("s11", "s15", "s7", "24"),
            vpair!("0", "26", "27", "16"),
            vpair!("1", "3", "7", "16"),
            vpair!("8", "28", "29", "16"),
            vpair!("9", "11", "15", "16"),
            vpair!("16", "30", "31", "16"),
            vpair!("17", "19", "23", "16"),
            spair!("s0", "s4", "s12", "16"),
            spair!("s1", "s5", "s13", "16"),
            spair!("s2", "s6", "s14", "16"),
            spair!("s3", "s7", "s15", "16"),
            spair!("s8", "s12", "s4", "63"),
            spair!("s9", "s13", "s5", "63"),
            spair!("s10", "s14", "s6", "63"),
            spair!("s11", "s15", "s7", "63"),
            spair!("s0", "s5", "s15", "32"),
            spair!("s1", "s6", "s12", "32"),
            spair!("s2", "s7", "s13", "32"),
            spair!("s3", "s4", "s14", "32"),
            spair!("s10", "s15", "s5", "24"),
            spair!("s11", "s12", "s6", "24"),
            spair!("s8", "s13", "s7", "24"),
            spair!("s9", "s14", "s4", "24"),
            spair!("s0", "s5", "s15", "16"),
            spair!("s1", "s6", "s12", "16"),
            spair!("s2", "s7", "s13", "16"),
            spair!("s3", "s4", "s14", "16"),
            vpair!("5", "27", "26", "63"),
            vpair!("4", "7", "3", "63"),
            vpair!("13", "29", "28", "63"),
            vpair!("12", "15", "11", "63"),
            vpair!("21", "31", "30", "63"),
            vpair!("20", "23", "19", "63"),
            spair!("s10", "s15", "s5", "63"),
            spair!("s11", "s12", "s6", "63"),
            spair!("s8", "s13", "s7", "63"),
            spair!("s9", "s14", "s4", "63"),
            sstore!($st, $adj),
            sload!($st, $adj),
            spair!("s0", "s4", "s12", "32"),
            spair!("s1", "s5", "s13", "32"),
            spair!("s2", "s6", "s14", "32"),
            spair!("s3", "s7", "s15", "32"),
            undiagonalize!("2", "3", "6", "7", "26", "27"),
            undiagonalize!("10", "11", "14", "15", "28", "29"),
            undiagonalize!("18", "19", "22", "23", "30", "31"),
            spair!("s8", "s12", "s4", "24"),
            spair!("s9", "s13", "s5", "24"),
            spair!("s10", "s14", "s6", "24"),
            spair!("s11", "s15", "s7", "24"),
            spair!("s0", "s4", "s12", "16"),
            spair!("s1", "s5", "s13", "16"),
            spair!("s2", "s6", "s14", "16"),
            spair!("s3", "s7", "s15", "16"),
            spair!("s8", "s12", "s4", "63"),
            spair!("s9", "s13", "s5", "63"),
            spair!("s10", "s14", "s6", "63"),
            spair!("s11", "s15", "s7", "63"),
            spair!("s0", "s5", "s15", "32"),
            spair!("s1", "s6", "s12", "32"),
            spair!("s2", "s7", "s13", "32"),
            spair!("s3", "s4", "s14", "32"),
            vstore!("p0", "0", "1", "2", "3", "4", "5", "6", "7"),
            vstore!("p1", "8", "9", "10", "11", "12", "13", "14", "15"),
            vstore!("p2", "16", "17", "18", "19", "20", "21", "22", "23"),
            spair!("s10", "s15", "s5", "24"),
            spair!("s11", "s12", "s6", "24"),
            spair!("s8", "s13", "s7", "24"),
            spair!("s9", "s14", "s4", "24"),
            spair!("s0", "s5", "s15", "16"),
            spair!("s1", "s6", "s12", "16"),
            spair!("s2", "s7", "s13", "16"),
            spair!("s3", "s4", "s14", "16"),
            spair!("s10", "s15", "s5", "63"),
            spair!("s11", "s12", "s6", "63"),
            spair!("s8", "s13", "s7", "63"),
            spair!("s9", "s14", "s4", "63"),
            sstore!($st, $adj),
            p0 = inout(reg) $p0 => _,
            p1 = inout(reg) $p1 => _,
            p2 = inout(reg) $p2 => _,
            ql = inout(reg) $q => _,
            qs = inout(reg) $q => _,
            st = in(reg) $stride,
            t = out(reg) _,
            u = out(reg) _,
            s0 = out(reg) _, s1 = out(reg) _, s2 = out(reg) _, s3 = out(reg) _,
            s4 = out(reg) _, s5 = out(reg) _, s6 = out(reg) _, s7 = out(reg) _,
            s8 = out(reg) _, s9 = out(reg) _, s10 = out(reg) _, s11 = out(reg) _,
            s12 = out(reg) _, s13 = out(reg) _, s14 = out(reg) _, s15 = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _,
            out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _,
            out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _,
            out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _,
            out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            options(nostack, preserves_flags),
        )
    };
}

/// `P` over the rows, then over the columns, of `block`: rows (then
/// columns) 0, 1 and 2 as vectors, 3 to 7 on the integer registers.
#[target_feature(enable = "neon,sve2")]
fn permute_unchecked(block: &mut Block) {
    let base = block.v.as_mut_ptr();
    // SAFETY: row `i` is the words `16 i .. 16 i + 16` (eight 16-byte pairs
    // 16 bytes apart); the vector states are rows 0 to 2 and the integer
    // states rows 3 to 7, one after the other from word 48, so every access
    // is in the block and each word belongs to exactly one state. Column
    // `i` is the word pairs `2 i + 16 k` for `k < 8` (128 bytes apart); the
    // integer states are columns 3 to 7, and after one column the load and
    // store pointers are `8 * 128 - 16` bytes past the next. The asm reads
    // and writes only those words, through pointers derived from the one
    // `&mut` borrow, uses no stack, and declares every register it writes.
    unsafe {
        pass!(
            "16",
            16usize,
            "0",
            base,
            base.add(16),
            base.add(32),
            base.add(48)
        );
        pass!(
            "128",
            128usize,
            "1008",
            base,
            base.add(2),
            base.add(4),
            base.add(6)
        );
    }
}
