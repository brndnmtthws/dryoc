//! NEON Salsa20/20 keystream, several blocks at a time.
//!
//! Lane `i` of every state vector belongs to block `counter + i`, so the
//! Salsa20 rounds are plain lane-wise arithmetic and the blocks only have to
//! be transposed once at the end, right before being XORed into the data.
//! Control flow and memory access are independent of the key and nonce.
//!
//! Wiping: the vector set and scalar blocks only flow through registers,
//! register-only `asm!` operands and inlined helpers, so they live in
//! registers or compiler spill slots, which are out of Rust's reach and not
//! wiped; a wipe would only force them into stack slots. The keystream goes
//! straight into the caller's buffers, which the drivers wipe.

use std::arch::aarch64::{
    uint32x4_t, vaddq_u32, veor3q_u32, veorq_u32, vshlq_n_u32, vshrq_n_u32, vsliq_n_u32,
};

use super::salsa20_soft as soft;
use crate::neon::{Dest, input_lanes as shared_input_lanes, transpose, xor_block};

/// Blocks per 4-lane vector set.
const SET_BLOCKS: u64 = 4;
/// Blocks computed with scalar instructions alongside the vector set in the
/// NEON kernels: two register sets, each computing two blocks back to back.
const SCALAR_BLOCKS: u64 = 4;
/// Blocks produced per chunk by the NEON kernels.
const NEON_BLOCKS: u64 = SET_BLOCKS + SCALAR_BLOCKS;
/// Blocks produced per chunk by the SVE2 kernel: one vector set and one
/// scalar block computed inside the same asm block.
const SVE2_BLOCKS: u64 = SET_BLOCKS + 1;

/// A vector kernel the running CPU has been verified to support.
///
/// Values are only created by [`detect`] (and, in tests, `Kernel::all`)
/// after checking the CPU features the kernel is compiled for, which is what
/// makes [`Kernel::xor_chunk`] safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Kernel(Variant);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    /// Baseline NEON.
    Neon,
    /// NEON plus the SHA3 extension, whose three-way XOR shortens the
    /// quarter-round dependency chain.
    Sha3,
    /// SVE2, whose `xar` (XOR then rotate) shortens it further.
    Sve2,
}

/// The fastest kernel the running CPU supports, if any.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    if !std::arch::is_aarch64_feature_detected!("neon") {
        None
    } else if std::arch::is_aarch64_feature_detected!("sve2") {
        Some(Kernel(Variant::Sve2))
    } else if std::arch::is_aarch64_feature_detected!("sha3") {
        Some(Kernel(Variant::Sha3))
    } else {
        Some(Kernel(Variant::Neon))
    }
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> Vec<Kernel> {
        let mut kernels = Vec::new();
        if std::arch::is_aarch64_feature_detected!("neon") {
            kernels.push(Kernel(Variant::Neon));
            if std::arch::is_aarch64_feature_detected!("sha3") {
                kernels.push(Kernel(Variant::Sha3));
            }
            if std::arch::is_aarch64_feature_detected!("sve2") {
                kernels.push(Kernel(Variant::Sve2));
            }
        }
        kernels
    }
}

impl super::Kernel for Kernel {
    #[inline]
    fn blocks(self) -> usize {
        match self.0 {
            Variant::Neon | Variant::Sha3 => NEON_BLOCKS as usize,
            Variant::Sve2 => SVE2_BLOCKS as usize,
        }
    }

    /// A run costs the latency of one block's rounds, about four scalar
    /// blocks for the NEON kernels (tuned on Neoverse V3) and about one and
    /// a half for SVE2.
    #[inline]
    fn tail_min(self) -> usize {
        match self.0 {
            Variant::Neon | Variant::Sha3 => 4 * 64,
            Variant::Sve2 => 2 * 64,
        }
    }

    #[inline]
    fn xor_chunk(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
    ) {
        match self.0 {
            // SAFETY: a `Kernel` is only constructed after
            // `is_aarch64_feature_detected!` confirmed the features its
            // variant needs; `Variant::Neon` requires `neon`.
            Variant::Neon => unsafe { xor_chunk_neon(state, counter, input, output, partial) },
            // SAFETY: as above; `Variant::Sha3` requires `neon` and `sha3`.
            Variant::Sha3 => unsafe { xor_chunk_sha3(state, counter, input, output, partial) },
            // SAFETY: as above; `Variant::Sve2` requires `neon` and `sve2`.
            Variant::Sve2 => unsafe { xor_chunk_sve2(state, counter, input, output, partial) },
        }
    }
}

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r` with the
/// rotation computed as `ushr` + `sli` (shift left and insert).
macro_rules! step_neon {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        let sum = vaddq_u32($x[$a], $x[$c]);
        $x[$b] = veorq_u32(
            $x[$b],
            vsliq_n_u32::<$r>(vshrq_n_u32::<{ 32 - $r }>(sum), sum),
        );
    };
}

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r` with the
/// two shifted halves of the rotation folded into a single `eor3`, so the
/// step is three dependent instructions instead of four.
macro_rules! step_sha3 {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        let sum = vaddq_u32($x[$a], $x[$c]);
        $x[$b] = veor3q_u32(
            $x[$b],
            vshlq_n_u32::<$r>(sum),
            vshrq_n_u32::<{ 32 - $r }>(sum),
        );
    };
}

/// The Salsa20 input for blocks `counter .. counter + 4`, one block per lane;
/// the 64-bit block counter lives in words 8 and 9.
#[inline]
#[target_feature(enable = "neon")]
fn input_lanes(state: &[u32; 16], counter: u64) -> [uint32x4_t; 16] {
    shared_input_lanes::<8, 9>(state, counter)
}

/// Finalises a 4-block vector set: adds the input back, transposes into block
/// order and XORs the keystream into blocks `0..4` of `$dest`.
///
/// A macro rather than a function so it expands inside whichever kernel uses
/// it (a `#[target_feature]` function cannot be `#[inline(always)]`, and the
/// SVE2 kernel's results would otherwise take a round trip through memory).
macro_rules! finish_set {
    ($x:expr, $initial:expr, $dest:expr) => {{
        let mut x: [uint32x4_t; 16] = $x;
        for (word, init) in x.iter_mut().zip($initial) {
            *word = vaddq_u32(*word, *init);
        }
        // `r<i>[block]` holds words `4 * i .. 4 * i + 4` of `block`.
        let r0 = transpose(x[0], x[1], x[2], x[3]);
        let r1 = transpose(x[4], x[5], x[6], x[7]);
        let r2 = transpose(x[8], x[9], x[10], x[11]);
        let r3 = transpose(x[12], x[13], x[14], x[15]);
        xor_block([r0[0], r1[0], r2[0], r3[0]], 0, $dest);
        xor_block([r0[1], r1[1], r2[1], r3[1]], 1, $dest);
        xor_block([r0[2], r1[2], r2[2], r3[2]], 2, $dest);
        xor_block([r0[3], r1[3], r2[3], r3[3]], 3, $dest);
    }};
}

/// Finalises a scalar block: adds the input back and XORs the 64 keystream
/// bytes into `output`.
#[inline(always)]
fn finish_scalar_block(
    x: [u32; 16],
    initial: &[u32; 16],
    input: Option<&[u8; 64]>,
    output: &mut [u8; 64],
) {
    let input = input.map(|input| input.as_chunks::<4>().0);
    let output = output.as_chunks_mut::<4>().0;
    for (index, (word, init)) in x.into_iter().zip(initial).enumerate() {
        let source = match input {
            Some(input) => &input[index],
            None => &output[index],
        };
        output[index] = (u32::from_le_bytes(*source) ^ word.wrapping_add(*init)).to_le_bytes();
    }
}

/// Defines `$name`, which XORs the keystream for blocks `counter .. counter +
/// NEON_BLOCKS` into `output`, reading the plaintext/ciphertext from `input`
/// (or from `output` itself when `input` is `None`), using `$step` for the
/// vector quarter-round step and requiring the target features `$features`.
/// `output` holds at most `NEON_BLOCKS` whole blocks; the following block's raw
/// keystream goes to the zero-filled `partial` when given, and the rest is
/// discarded, so a short remainder costs one kernel run rather than a run of
/// dependent scalar blocks.
///
/// A Salsa20 round is a short dependency chain, so a single 4-block vector
/// set leaves most of the core idle, while a second set does not fit in the
/// 32 vector registers. The remaining blocks of the chunk are therefore
/// computed with scalar instructions in the same loop body: they run on the
/// integer pipes and general-purpose registers while the vector set occupies
/// the SIMD pipes. A scalar quarter-round step is `add` + `eor` with a
/// rotated operand, half the latency of the vector step, so each of the two
/// scalar register sets computes two blocks back to back while the vector set
/// computes one.
macro_rules! define_xor_chunk {
    ($(#[$meta:meta])* $name:ident, $features:literal, $step:ident) => {
        $(#[$meta])*
        #[target_feature(enable = $features)]
        fn $name(
            state: &[u32; 16],
            counter: u64,
            input: Option<&[u8]>,
            output: &mut [u8],
            partial: Option<&mut [u8; 64]>,
        ) {
            let mut dest = Dest::new(NEON_BLOCKS as usize, input, output, partial);

            let initial_v = input_lanes(state, counter);
            let mut v = initial_v;
            for phase in 0..2 {
                let block_a = SET_BLOCKS as usize + 2 * phase;
                let initial_a = soft::block_input(state, counter.wrapping_add(block_a as u64));
                let initial_b = soft::block_input(state, counter.wrapping_add(block_a as u64 + 1));
                let mut a = initial_a;
                let mut b = initial_b;
                // Every phase advances the vector set by 5 double rounds and
                // the two scalar blocks by all 10, i.e. two scalar double
                // rounds per vector double round. The scalar blocks are
                // named and the calls spelled out (rather than iterated) so
                // the compiler keeps them in registers and can interleave
                // them with the vector instructions.
                for _ in 0..5 {
                    super::salsa20_double_round!($step, v);
                    soft::double_round(&mut a);
                    soft::double_round(&mut b);
                    soft::double_round(&mut a);
                    soft::double_round(&mut b);
                }
                if let Some((source, out)) = dest.block(block_a) {
                    finish_scalar_block(a, &initial_a, source, out);
                }
                if let Some((source, out)) = dest.block(block_a + 1) {
                    finish_scalar_block(b, &initial_b, source, out);
                }
            }
            finish_set!(v, &initial_v, &mut dest);
        }
    };
}

define_xor_chunk!(
    /// Baseline NEON kernel.
    xor_chunk_neon,
    "neon",
    step_neon
);
define_xor_chunk!(
    /// NEON + SHA3 kernel.
    xor_chunk_sha3,
    "neon,sha3",
    step_sha3
);

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r` on the
/// vector set (`z0..z15`, one block per lane) with SVE2 `xar`: `z17` takes
/// the sum, `z16` is zero. `xar zb, zb, z16, #$r` rotates `x[$b]` right by
/// `$r`, and `xar zb, zb, z17, #$rr` (`$rr = 32 - $r`) then XORs the sum in
/// and rotates left by `$r`, which undoes the first rotation on `x[$b]` and
/// leaves the sum rotated left by `$r`. `.s` lanes make the result
/// independent of the vector length; only the low 128 bits (the NEON view)
/// are consumed.
macro_rules! sve2_step {
    ($b:literal, $a:literal, $c:literal, $r:literal, $rr:literal) => {
        concat!(
            "add z17.s, z",
            $a,
            ".s, z",
            $c,
            ".s\n",
            "xar z",
            $b,
            ".s, z",
            $b,
            ".s, z16.s, #",
            $r,
            "\n",
            "xar z",
            $b,
            ".s, z",
            $b,
            ".s, z17.s, #",
            $rr,
            "\n",
        )
    };
}

/// The same step on the scalar block held in `w0..w15`, with `w16` for the
/// sum: `add` plus `eor` with a rotated operand.
macro_rules! scalar_step {
    ($b:literal, $a:literal, $c:literal, $r:literal, $rr:literal) => {
        concat!(
            "add w16, w",
            $a,
            ", w",
            $c,
            "\n",
            "eor w",
            $b,
            ", w",
            $b,
            ", w16, ror #",
            $rr,
            "\n",
        )
    };
}

/// One Salsa20 quarter round over words `$a, $b, $c, $d` with `$step`.
/// Rotations left by 7, 9, 13 and 18 are rotations right by 25, 23, 19 and
/// 14.
macro_rules! asm_quarter_round {
    ($step:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!(
            $step!($b, $a, $d, 7, 25),
            $step!($c, $b, $a, 9, 23),
            $step!($d, $c, $b, 13, 19),
            $step!($a, $d, $c, 18, 14),
        )
    };
}

/// One Salsa20 double round (a column round followed by a row round) with
/// `$step`.
macro_rules! asm_double_round {
    ($step:ident) => {
        concat!(
            asm_quarter_round!($step, 0, 4, 8, 12),
            asm_quarter_round!($step, 5, 9, 13, 1),
            asm_quarter_round!($step, 10, 14, 2, 6),
            asm_quarter_round!($step, 15, 3, 7, 11),
            asm_quarter_round!($step, 0, 1, 2, 3),
            asm_quarter_round!($step, 5, 6, 7, 4),
            asm_quarter_round!($step, 10, 11, 8, 9),
            asm_quarter_round!($step, 15, 12, 13, 14),
        )
    };
}

/// All ten double rounds of both the vector set and the scalar block,
/// unrolled (about 6 KiB of straight-line code): no loop branch to
/// mispredict at the exit of every run, and no loop head whose alignment
/// shifts with unrelated code.
macro_rules! asm_double_rounds {
    () => {
        concat!(
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
            asm_double_round!(sve2_step),
            asm_double_round!(scalar_step),
        )
    };
}

/// Runs the Salsa20 rounds on one vector set (`v`, one block per lane) and one
/// scalar block (`s`) together, in place, with SVE2 `xar`.
///
/// A vector quarter-round step is `add` + `xar` + `xar`, a dependency chain of
/// two instructions against three for `eor3` and four for plain NEON, but the
/// zero and sum registers it needs leave no room for a second vector set, so
/// the spare integer pipes compute one more block from general-purpose
/// registers in the same loop. Every state word is pinned to a register, so
/// the asm block is pure register arithmetic: no memory access, no
/// predicates, no flags.
#[inline]
#[target_feature(enable = "neon,sve2")]
fn double_rounds_sve2(v: &mut [uint32x4_t; 16], s: &mut [u32; 16]) {
    // SAFETY: the caller has verified SVE2 support. The block reads and
    // writes only the registers bound below (`z16`/`z17` and `w16` are
    // scratch); `add`/`xar` on `.s` lanes never mix lanes, so the low 128
    // bits (the `uint32x4_t` values) are computed exactly as the scalar
    // reference does, whatever the vector length. No flags, memory or stack
    // are touched.
    unsafe {
        std::arch::asm!(
            "mov z16.s, #0",
            asm_double_rounds!(),
            inout("v0") v[0], inout("v1") v[1], inout("v2") v[2], inout("v3") v[3],
            inout("v4") v[4], inout("v5") v[5], inout("v6") v[6], inout("v7") v[7],
            inout("v8") v[8], inout("v9") v[9], inout("v10") v[10], inout("v11") v[11],
            inout("v12") v[12], inout("v13") v[13], inout("v14") v[14], inout("v15") v[15],
            out("v16") _, out("v17") _,
            inout("x0") s[0], inout("x1") s[1], inout("x2") s[2], inout("x3") s[3],
            inout("x4") s[4], inout("x5") s[5], inout("x6") s[6], inout("x7") s[7],
            inout("x8") s[8], inout("x9") s[9], inout("x10") s[10], inout("x11") s[11],
            inout("x12") s[12], inout("x13") s[13], inout("x14") s[14], inout("x15") s[15],
            out("x16") _,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
}

/// XORs the keystream for blocks `counter .. counter + SVE2_BLOCKS` into
/// `output`; see [`xor_chunk_neon`] for the `output`/`partial` contract.
/// Blocks `0..4` are the vector set, block `4` the scalar block.
#[target_feature(enable = "neon,sve2")]
fn xor_chunk_sve2(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(SVE2_BLOCKS as usize, input, output, partial);

    let mut v = input_lanes(state, counter);
    let initial_s = soft::block_input(state, counter.wrapping_add(SET_BLOCKS));
    let mut s = initial_s;
    double_rounds_sve2(&mut v, &mut s);
    if let Some((source, out)) = dest.block(SET_BLOCKS as usize) {
        finish_scalar_block(s, &initial_s, source, out);
    }
    // The initial lanes are rebuilt from `state` after the rounds rather than
    // kept across the asm block, which would spill them to the stack and make
    // the kernel's speed depend on the frame it runs in. `black_box` keeps
    // the compiler from merging the two computations into one spilled copy.
    let state = std::hint::black_box(state);
    let initial_v = input_lanes(state, counter);
    finish_set!(v, &initial_v, &mut dest);
}
