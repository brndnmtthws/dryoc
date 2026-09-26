//! NEON and SVE2 ChaCha20 keystream, several blocks at a time.
//!
//! The bulk of each chunk is a *lane set*: lane `i` of every state vector
//! belongs to block `counter + i`, so the ChaCha20 rounds are plain lane-wise
//! arithmetic (the diagonal round is the column round with permuted register
//! names) and the blocks only have to be transposed once at the end, right
//! before being XORed into the data. Control flow and memory access are
//! independent of the key and nonce.
//!
//! Wiping: the lane sets, row blocks and scalar blocks only flow through
//! registers, register-only `asm!` operands and inlined helpers (the input,
//! finish and XOR helpers are macros: as `#[inline]` functions they were kept
//! out of line at opt-level `z` and took the lanes, rows and keystream
//! through stack copies), so they live in registers or compiler spill slots,
//! which are out of Rust's reach and not wiped; a wipe would only force them
//! into stack slots. The keystream goes straight into the caller's buffers,
//! which the drivers wipe.

use core::arch::aarch64::{
    uint8x16_t, uint32x4_t, vaddq_u32, veorq_u32, vextq_u32, vqtbl1q_u8, vreinterpretq_u8_u32,
    vreinterpretq_u16_u32, vreinterpretq_u32_u8, vreinterpretq_u32_u16, vrev32q_u16, vshrq_n_u32,
    vsliq_n_u32,
};

use super::chacha20_soft as soft;
use crate::aarch64::{Neon, Sve2};
use crate::neon::{Dest, load, transpose, words, xor_block};

/// Blocks per 4-lane vector set.
const SET_BLOCKS: u64 = 4;
/// Blocks held one per four row vectors alongside the lane set in the NEON
/// kernel.
const ROW_BLOCKS: u64 = 3;
/// Blocks computed with scalar instructions alongside the vector blocks in the
/// NEON kernel.
const SCALAR_BLOCKS: u64 = 2;
/// Blocks produced per chunk by the NEON kernel.
const NEON_BLOCKS: u64 = SET_BLOCKS + ROW_BLOCKS + SCALAR_BLOCKS;
/// Blocks produced per chunk by the SVE2 kernel: two lane sets.
const SVE2_BLOCKS: u64 = 2 * SET_BLOCKS;
/// Blocks (including a trailing partial one) a run may hold to take the
/// single-lane-set SVE2 kernel: the rounds of one set are latency bound at
/// the same cost as the throughput-bound two sets, so a short run on one set
/// costs half the instructions for the same time, and the driver can fold a
/// head block into it.
pub(super) const SMALL_BLOCKS: usize = SET_BLOCKS as usize;

/// A vector kernel the running CPU has been verified to support: each
/// variant holds the token for the CPU features its kernels are compiled
/// for, which is what makes [`Kernel::xor_chunk`](super::Kernel::xor_chunk)
/// safe.
///
/// ChaCha20 rotates the result of each XOR rather than XORing a rotated sum,
/// so the SHA3 `eor3` has nothing to fold and a `neon,sha3` variant measured
/// slower; the SVE2 `xar` (XOR then rotate) however is exactly that step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kernel {
    /// NEON: one lane set, three row blocks and two scalar blocks.
    Neon(Neon),
    /// SVE2 `xar` rounds on two lane sets held in the low 128 bits of the
    /// vector registers, so it needs no particular vector length.
    Sve2(Sve2),
}

/// The best kernel the running CPU supports.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    if let Some(sve2) = Sve2::new() {
        Some(Kernel::Sve2(sve2))
    } else {
        Neon::new().map(Kernel::Neon)
    }
}

/// Bytes of keystream one stitched run produces, and of MAC input it
/// absorbs ([`Kernel::xor_chunk_poly`]).
pub(super) const POLY_CHUNK: usize = SVE2_BLOCKS as usize * 64;

impl Kernel {
    /// With SVE2, XORs the keystream of blocks `counter..counter +
    /// POLY_CHUNK / 64` into `output` (from `input`, or in place) while the
    /// same asm block advances two Poly1305 lanes over the 32 blocks of
    /// `mac_input`: `lanes[0]` over its first 16 and `lanes[1]` over its
    /// last 16, each in radix 2^64 (`h0 + h1 2^64 + h2 2^128`, `h2` small)
    /// with the key `r = [r0, r1, r1 + r1 / 4]`. The multiplies run on the
    /// integer pipes the lane sets leave idle, so they cost little beside
    /// the rounds. Returns `false`, doing nothing, without SVE2.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn xor_chunk_poly(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8; POLY_CHUNK]>,
        output: &mut [u8; POLY_CHUNK],
        lanes: &mut [[u64; 3]; 2],
        r: &[u64; 3],
        mac_input: &[u8; POLY_CHUNK],
    ) -> bool {
        match self {
            Kernel::Neon(_) => false,
            Kernel::Sve2(sve2) => {
                xor_chunk_sve2_poly(sve2, state, counter, input, output, lanes, r, mac_input);
                true
            }
        }
    }

    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        let mut kernels = alloc::vec::Vec::new();
        if let Some(neon) = Neon::new() {
            kernels.push(Kernel::Neon(neon));
        }
        if let Some(sve2) = Sve2::new() {
            kernels.push(Kernel::Sve2(sve2));
        }
        kernels
    }
}

/// The NEON kernel does not fuse an extra block (its lane set already
/// carries two scalar blocks of its own), so the trait's scalar-block
/// default applies to it; the SVE2 kernel computes one in its otherwise idle
/// integer pipes.
impl super::Kernel for Kernel {
    #[inline]
    fn blocks(self) -> usize {
        match self {
            Kernel::Neon(_) => NEON_BLOCKS as usize,
            Kernel::Sve2(_) => SVE2_BLOCKS as usize,
        }
    }

    /// A NEON run costs a little more than three scalar blocks, an SVE2 run
    /// about one and a half.
    #[inline]
    fn tail_min_blocks(self) -> usize {
        match self {
            Kernel::Neon(_) => 4,
            Kernel::Sve2(_) => 2,
        }
    }

    /// Out of line at opt-level `z`, which adds no copy: it only forwards `&`
    /// to the cipher's own state, which `ChaCha20` wipes on drop, and the
    /// caller's buffers.
    #[inline]
    fn xor_chunk(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
    ) {
        match self {
            Kernel::Neon(neon) => xor_chunk_neon(neon, state, counter, input, output, partial),
            Kernel::Sve2(sve2) => xor_chunk_sve2(sve2, state, counter, input, output, partial),
        }
    }

    #[inline]
    fn fuses_extra_block(self) -> bool {
        matches!(self, Kernel::Sve2(_))
    }

    /// On SVE2 the extra block's scalar rounds run inside the lane sets' asm
    /// block; on NEON it is a scalar block after the run.
    #[inline]
    fn xor_chunk_with_block(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
        extra: (u64, &mut [u8; 64]),
    ) {
        match self {
            Kernel::Neon(neon) => {
                xor_chunk_neon(neon, state, counter, input, output, partial);
                crate::stream::xor_scalar_block(state, extra.0, extra.1, soft::block);
            }
            Kernel::Sve2(sve2) => {
                xor_chunk_sve2_with_block(sve2, state, counter, input, output, partial, extra)
            }
        }
    }

    /// The SVE2 kernel serves a small run with a single lane set for the
    /// same latency and half the instructions.
    #[inline]
    fn xor_small(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
    ) {
        debug_assert!(output.len() / 64 + usize::from(partial.is_some()) <= SMALL_BLOCKS);
        match self {
            Kernel::Neon(_) => self.xor_chunk(state, counter, input, output, partial),
            Kernel::Sve2(sve2) => {
                xor_chunk_sve2_small(sve2, state, counter, input, output, partial)
            }
        }
    }
}

/// Byte permutation rotating every 32-bit lane left by 8 bits.
const ROT8_TABLE: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

/// Rotates every lane left by `$r` bits with `ushr` + `sli` (shift left and
/// insert).
macro_rules! rot {
    ($v:expr, $r:literal) => {{
        let v = $v;
        vsliq_n_u32::<$r>(vshrq_n_u32::<{ 32 - $r }>(v), v)
    }};
}

/// Rotates every lane left by 16 bits (a halfword swap).
#[inline]
#[target_feature(enable = "neon")]
fn rot16(v: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
}

/// Rotates every lane left by 8 bits with the byte permutation `table`
/// ([`ROT8_TABLE`]).
#[inline]
#[target_feature(enable = "neon")]
fn rot8(v: uint32x4_t, table: uint8x16_t) -> uint32x4_t {
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), table))
}

/// One ChaCha20 quarter round over the four vectors `$a, $b, $c, $d` of
/// `$x`, with the `rot8` table in `$rot8`.
macro_rules! quarter_round {
    ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal, $rot8:ident) => {
        $x[$a] = vaddq_u32($x[$a], $x[$b]);
        $x[$d] = rot16(veorq_u32($x[$d], $x[$a]));
        $x[$c] = vaddq_u32($x[$c], $x[$d]);
        $x[$b] = rot!(veorq_u32($x[$b], $x[$c]), 12);
        $x[$a] = vaddq_u32($x[$a], $x[$b]);
        $x[$d] = rot8(veorq_u32($x[$d], $x[$a]), $rot8);
        $x[$c] = vaddq_u32($x[$c], $x[$d]);
        $x[$b] = rot!(veorq_u32($x[$b], $x[$c]), 7);
    };
}

/// Rotates rows 1..4 of row block `$r` by `$s1, $s2, $s3` lanes.
macro_rules! shift_rows {
    ($r:ident, $s1:literal, $s2:literal, $s3:literal) => {
        $r[1] = vextq_u32::<$s1>($r[1], $r[1]);
        $r[2] = vextq_u32::<$s2>($r[2], $r[2]);
        $r[3] = vextq_u32::<$s3>($r[3], $r[3]);
    };
}

/// One ChaCha20 double round of a row block (4 vectors, vector = row of one
/// block): the column round is a single quarter round over the rows;
/// rotating rows 1..4 by 1..4 lanes lines the diagonals up in columns for
/// the diagonal round, after which the rows are rotated back.
macro_rules! double_round_rows {
    ($r:ident, $rot8:ident) => {
        quarter_round!($r, 0, 1, 2, 3, $rot8);
        shift_rows!($r, 1, 2, 3);
        quarter_round!($r, 0, 1, 2, 3, $rot8);
        shift_rows!($r, 3, 2, 1);
    };
}

/// One ChaCha20 quarter round over the four words `$a, $b, $c, $d` of the
/// scalar `[u32; 16]` state `$x`, spelled out here (rather than calling into
/// `soft`) so the loop body is one macro expansion whose statement order the
/// compiler's schedule follows.
macro_rules! scalar_quarter_round {
    ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $x[$a] = $x[$a].wrapping_add($x[$b]);
        $x[$d] = ($x[$d] ^ $x[$a]).rotate_left(16);
        $x[$c] = $x[$c].wrapping_add($x[$d]);
        $x[$b] = ($x[$b] ^ $x[$c]).rotate_left(12);
        $x[$a] = $x[$a].wrapping_add($x[$b]);
        $x[$d] = ($x[$d] ^ $x[$a]).rotate_left(8);
        $x[$c] = $x[$c].wrapping_add($x[$d]);
        $x[$b] = ($x[$b] ^ $x[$c]).rotate_left(7);
    };
}

/// The ChaCha20 input for blocks `$counter .. $counter + 4`, one block per
/// lane; the 64-bit block counter lives in words 12 and 13. A macro, like
/// [`crate::neon::input_lanes`], so the lanes never leave the kernel.
macro_rules! input_lanes {
    ($state:expr, $counter:expr) => {
        crate::neon::input_lanes!($state, $counter, 12, 13)
    };
}

/// The ChaCha20 input for block `$counter`, one row per vector (a
/// `[uint32x4_t; 4]`). A macro, like [`input_lanes`]: as a function it was
/// out of line at opt-level `z` and returned the key rows through a stack
/// buffer.
macro_rules! input_rows {
    ($state:expr, $counter:expr) => {{
        let input = soft::block_input($state, $counter);
        let rows = input.as_chunks::<4>().0;
        [
            words(rows[0]),
            words(rows[1]),
            words(rows[2]),
            words(rows[3]),
        ]
    }};
}

/// Finalises a lane set: adds the input back, transposes into block order
/// and XORs the keystream into blocks `$base .. $base + 4` of `$dest`.
///
/// A macro rather than a function so it expands inside whichever kernel uses
/// it (a `#[target_feature]` function cannot be `#[inline(always)]`, and the
/// SVE2 kernel's results would otherwise take a round trip through memory).
/// Spelled out per block: indexing the transposed rows by a loop variable
/// makes the compiler stage all sixteen vectors through the stack and reload
/// them, which stalls on store forwarding.
macro_rules! finish_lanes {
    ($x:expr, $initial:expr, $base:expr, $dest:expr) => {{
        let mut x: [uint32x4_t; 16] = $x;
        for (word, init) in x.iter_mut().zip($initial) {
            *word = vaddq_u32(*word, *init);
        }
        // `r<i>[block]` holds words `4 * i .. 4 * i + 4` of `block`.
        let r0 = transpose(x[0], x[1], x[2], x[3]);
        let r1 = transpose(x[4], x[5], x[6], x[7]);
        let r2 = transpose(x[8], x[9], x[10], x[11]);
        let r3 = transpose(x[12], x[13], x[14], x[15]);
        xor_block!([r0[0], r1[0], r2[0], r3[0]], $base, $dest);
        xor_block!([r0[1], r1[1], r2[1], r3[1]], $base + 1, $dest);
        xor_block!([r0[2], r1[2], r2[2], r3[2]], $base + 2, $dest);
        xor_block!([r0[3], r1[3], r2[3], r3[3]], $base + 3, $dest);
    }};
}

/// Finalises a row block `$x`: adds the input `$initial` back and XORs the
/// keystream into block `$index` of `$dest`. A macro for the same reason as
/// [`finish_lanes`]: as a function it was out of line at opt-level `z` and
/// took the rows and their input through the stack.
macro_rules! finish_rows {
    ($x:expr, $initial:expr, $index:expr, $dest:expr) => {{
        let [x0, x1, x2, x3]: [uint32x4_t; 4] = $x;
        let [i0, i1, i2, i3]: &[uint32x4_t; 4] = $initial;
        xor_block!(
            [
                vreinterpretq_u8_u32(vaddq_u32(x0, *i0)),
                vreinterpretq_u8_u32(vaddq_u32(x1, *i1)),
                vreinterpretq_u8_u32(vaddq_u32(x2, *i2)),
                vreinterpretq_u8_u32(vaddq_u32(x3, *i3)),
            ],
            $index,
            $dest
        );
    }};
}

/// Finalises a scalar block: adds the input back and XORs the 64 keystream
/// bytes into `output`. Spelled out with
/// [`each_word`](crate::stream::each_word): at opt-level `z` a `zip` over
/// `x` and `initial` was out of line and took both blocks' addresses.
#[inline(always)]
fn finish_scalar_block(
    x: &[u32; 16],
    initial: &[u32; 16],
    input: Option<&[u8; 64]>,
    output: &mut [u8; 64],
) {
    let input = input.map(|input| input.as_chunks::<4>().0);
    let output = output.as_chunks_mut::<4>().0;
    crate::stream::each_word!(I, {
        let source = match input {
            Some(input) => input[I],
            None => output[I],
        };
        output[I] = (u32::from_le_bytes(source) ^ x[I].wrapping_add(initial[I])).to_le_bytes();
    });
}

/// XORs the keystream for blocks `counter .. counter + NEON_BLOCKS` into
/// `output`, reading the plaintext/ciphertext from `input` (or from `output`
/// itself when `input` is `None`). `output` holds at most `NEON_BLOCKS` whole
/// blocks; the following block's raw keystream goes to the zero-filled
/// `partial` when given, and the rest is discarded, so a short remainder
/// costs one kernel run rather than a run of dependent scalar blocks.
///
/// A ChaCha20 column is a dependency chain of 14 vector instructions per
/// quarter round, so the lane set alone leaves half the SIMD pipes idle, and
/// a second lane set does not fit in the 32 vector registers. The spare
/// registers hold three more blocks in row layout (four vectors each), whose
/// rounds fill the idle pipes, and two further blocks are computed with
/// scalar instructions on the integer pipes and general-purpose registers.
/// All six streams advance one double round per loop iteration and the
/// compiler interleaves them. Blocks `0..4` are the lane set, `4..7` the row
/// blocks and `7..9` the scalar blocks.
///
/// The loop sits close to both the dispatch and the latency limit of the
/// core, so its schedule decides the throughput; the function is kept out of
/// line so that schedule does not change with the inlining context, and the
/// order of the streams in the loop body is the fastest one measured on
/// Neoverse V1 (the alternatives were up to 8% slower).
#[inline(never)]
#[target_feature(enable = "neon")]
fn xor_chunk_neon_unchecked(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(NEON_BLOCKS as usize, input, output, partial);

    const ROW_BASE: u64 = SET_BLOCKS;
    const SCALAR_BASE: u64 = SET_BLOCKS + ROW_BLOCKS;

    let rot8 = load(&ROT8_TABLE);
    let initial_v = input_lanes!(state, counter);
    let initial_r0 = input_rows!(state, counter.wrapping_add(ROW_BASE));
    let initial_r1 = input_rows!(state, counter.wrapping_add(ROW_BASE + 1));
    let initial_r2 = input_rows!(state, counter.wrapping_add(ROW_BASE + 2));
    let initial_a = soft::block_input(state, counter.wrapping_add(SCALAR_BASE));
    let initial_b = soft::block_input(state, counter.wrapping_add(SCALAR_BASE + 1));
    let mut v = initial_v;
    let mut r0 = initial_r0;
    let mut r1 = initial_r1;
    let mut r2 = initial_r2;
    let mut a = initial_a;
    let mut b = initial_b;
    for _ in 0..10 {
        double_round_rows!(r0, rot8);
        double_round_rows!(r1, rot8);
        double_round_rows!(r2, rot8);
        super::chacha20_double_round!(quarter_round, v, rot8);
        super::chacha20_double_round!(scalar_quarter_round, a);
        super::chacha20_double_round!(scalar_quarter_round, b);
    }
    if let Some((source, out)) = dest.block(SCALAR_BASE as usize) {
        finish_scalar_block(&a, &initial_a, source, out);
    }
    if let Some((source, out)) = dest.block(SCALAR_BASE as usize + 1) {
        finish_scalar_block(&b, &initial_b, source, out);
    }
    finish_rows!(r0, &initial_r0, ROW_BASE as usize, &mut dest);
    finish_rows!(r1, &initial_r1, ROW_BASE as usize + 1, &mut dest);
    finish_rows!(r2, &initial_r2, ROW_BASE as usize + 2, &mut dest);
    finish_lanes!(v, &initial_v, 0, &mut dest);
}

/// [`xor_chunk_neon_unchecked`], safe to call with a [`Neon`] token.
#[inline(always)]
fn xor_chunk_neon(
    _: Neon,
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    // SAFETY: a `Neon` token exists only after detection of `neon`, the
    // feature the kernel is compiled for.
    unsafe { xor_chunk_neon_unchecked(state, counter, input, output, partial) }
}

/// One ChaCha20 quarter-round step on lane-set registers: `a += b; d = (d ^
/// a) <<< rot`, as `add` plus the SVE2 `xar` (XOR then rotate right by
/// `32 - rot`). The registers are named by number; `.s` lanes make the
/// result independent of the vector length, and only the low 128 bits (the
/// NEON view) are consumed.
macro_rules! xar_step {
    ($a:literal, $b:literal, $d:literal, $ror:literal) => {
        concat!(
            "add z", $a, ".s, z", $a, ".s, z", $b, ".s\n", "xar z", $d, ".s, z", $d, ".s, z", $a,
            ".s, #", $ror, "\n",
        )
    };
}

/// The same quarter-round step for the four quarter rounds of both lane
/// sets (registers `0..16` and `16..32`), interleaved so eight independent
/// chains are in flight. `$a`/`$b`/`$d` name the first set's registers of
/// column 0; the other columns and set follow by fixed offsets.
macro_rules! xar_step_all {
    (
        $ror:literal;
        $a0:literal,
        $a1:literal,
        $a2:literal,
        $a3:literal;
        $b0:literal,
        $b1:literal,
        $b2:literal,
        $b3:literal;
        $d0:literal,
        $d1:literal,
        $d2:literal,
        $d3:literal;
        $e0:literal,
        $e1:literal,
        $e2:literal,
        $e3:literal;
        $f0:literal,
        $f1:literal,
        $f2:literal,
        $f3:literal;
        $g0:literal,
        $g1:literal,
        $g2:literal,
        $g3:literal
    ) => {
        concat!(
            xar_step!($a0, $b0, $d0, $ror),
            xar_step!($a1, $b1, $d1, $ror),
            xar_step!($a2, $b2, $d2, $ror),
            xar_step!($a3, $b3, $d3, $ror),
            xar_step!($e0, $f0, $g0, $ror),
            xar_step!($e1, $f1, $g1, $ror),
            xar_step!($e2, $f2, $g2, $ror),
            xar_step!($e3, $f3, $g3, $ror),
        )
    };
}

/// One ChaCha20 double round on two lane sets held in `z0..z15` and
/// `z16..z31`. Rotations left by 16, 12, 8 and 7 are rotations right by 16,
/// 20, 24 and 25.
macro_rules! sve2_double_round {
    () => {
        sve2_double_round_with!("", "", "", "")
    };
}

/// [`sve2_double_round`] with the instructions `$x1`, `$x3`, `$x5` and `$x7`
/// after its second, fourth, sixth and eighth quarter-round steps, so that
/// independent scalar work shares the block's issue slots.
macro_rules! sve2_double_round_with {
    ($x1:expr, $x3:expr, $x5:expr, $x7:expr) => {
        concat!(
            // Column round: quarter rounds (0,4,8,12) (1,5,9,13) (2,6,10,14)
            // (3,7,11,15) per set.
            xar_step_all!(16; 0, 1, 2, 3; 4, 5, 6, 7; 12, 13, 14, 15; 16, 17, 18, 19; 20, 21, 22, 23; 28, 29, 30, 31),
            xar_step_all!(20; 8, 9, 10, 11; 12, 13, 14, 15; 4, 5, 6, 7; 24, 25, 26, 27; 28, 29, 30, 31; 20, 21, 22, 23),
            $x1,
            xar_step_all!(24; 0, 1, 2, 3; 4, 5, 6, 7; 12, 13, 14, 15; 16, 17, 18, 19; 20, 21, 22, 23; 28, 29, 30, 31),
            xar_step_all!(25; 8, 9, 10, 11; 12, 13, 14, 15; 4, 5, 6, 7; 24, 25, 26, 27; 28, 29, 30, 31; 20, 21, 22, 23),
            $x3,
            // Diagonal round: quarter rounds (0,5,10,15) (1,6,11,12)
            // (2,7,8,13) (3,4,9,14) per set.
            xar_step_all!(16; 0, 1, 2, 3; 5, 6, 7, 4; 15, 12, 13, 14; 16, 17, 18, 19; 21, 22, 23, 20; 31, 28, 29, 30),
            xar_step_all!(20; 10, 11, 8, 9; 15, 12, 13, 14; 5, 6, 7, 4; 26, 27, 24, 25; 31, 28, 29, 30; 21, 22, 23, 20),
            $x5,
            xar_step_all!(24; 0, 1, 2, 3; 5, 6, 7, 4; 15, 12, 13, 14; 16, 17, 18, 19; 21, 22, 23, 20; 31, 28, 29, 30),
            xar_step_all!(25; 10, 11, 8, 9; 15, 12, 13, 14; 5, 6, 7, 4; 26, 27, 24, 25; 31, 28, 29, 30; 21, 22, 23, 20),
            $x7,
        )
    };
}

/// All ten double rounds as two passes of a loop over five, with the pass
/// counter in the asm operand `n` (set to 2). Fully unrolled, the rounds
/// were about 5 KiB of straight-line code, and with the stitched kernel's
/// 10 KiB beside them a secretstream message's kernels overflowed the
/// instruction cache under some link layouts (L1i misses 0.24M against
/// 1.4M, 2% of `crypto_secretstream_xchacha20poly1305_push` at 1 KiB); the
/// loop measured no slower on bulk ChaCha20-Poly1305. The loop head is
/// aligned, since the rounds' throughput varies by a few percent with how
/// unrelated code shifts them against fetch boundaries.
macro_rules! sve2_double_rounds {
    () => {
        concat!(
            ".p2align 6\n",
            "2:\n",
            sve2_double_round!(),
            sve2_double_round!(),
            sve2_double_round!(),
            sve2_double_round!(),
            sve2_double_round!(),
            "subs {n}, {n}, #1\n",
            "b.ne 2b\n",
        )
    };
}

/// Runs the ChaCha20 rounds on two lane sets with SVE2 `xar`, in place.
///
/// Every state word is pinned to a vector register (`z0..z31` are the SVE
/// views of `v0..v31`), so the asm block is pure register arithmetic: no
/// memory access, no predicates, no scalar registers.
#[inline]
#[target_feature(enable = "neon,sve2")]
fn double_rounds_sve2(a: &mut [uint32x4_t; 16], b: &mut [uint32x4_t; 16]) {
    // SAFETY: the caller has verified SVE2 support. The block reads and
    // writes only the 32 vector registers bound below and the pass counter
    // `n`, whose `subs` sets the flags (not preserved, as declared) and runs
    // the loop exactly twice; `add`/`xar` on `.s` lanes never mix lanes, so
    // the low 128 bits (the `uint32x4_t` values) are computed exactly as the
    // scalar reference does, whatever the vector length. No memory or stack
    // is touched.
    unsafe {
        core::arch::asm!(
            sve2_double_rounds!(),
            n = inout(reg) 2u64 => _,
            inout("v0") a[0], inout("v1") a[1], inout("v2") a[2], inout("v3") a[3],
            inout("v4") a[4], inout("v5") a[5], inout("v6") a[6], inout("v7") a[7],
            inout("v8") a[8], inout("v9") a[9], inout("v10") a[10], inout("v11") a[11],
            inout("v12") a[12], inout("v13") a[13], inout("v14") a[14], inout("v15") a[15],
            inout("v16") b[0], inout("v17") b[1], inout("v18") b[2], inout("v19") b[3],
            inout("v20") b[4], inout("v21") b[5], inout("v22") b[6], inout("v23") b[7],
            inout("v24") b[8], inout("v25") b[9], inout("v26") b[10], inout("v27") b[11],
            inout("v28") b[12], inout("v29") b[13], inout("v30") b[14], inout("v31") b[15],
            options(pure, nomem, nostack),
        );
    }
}

/// XORs the keystream for blocks `counter .. counter + SVE2_BLOCKS` into
/// `output`; see [`xor_chunk_neon`] for the `output`/`partial` contract.
///
/// Two lane sets fill all 32 vector registers and the SVE2 `xar` does the
/// XOR-and-rotate of each quarter-round step in one instruction, so a block
/// costs about 160 vector instructions in the rounds against roughly 280 for
/// the NEON lane set, and the eight independent chains hide the latency.
#[target_feature(enable = "neon,sve2")]
fn xor_chunk_sve2_unchecked(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(SVE2_BLOCKS as usize, input, output, partial);

    let mut a = input_lanes!(state, counter);
    let mut b = input_lanes!(state, counter.wrapping_add(SET_BLOCKS));
    double_rounds_sve2(&mut a, &mut b);
    // The rounds occupy every vector register, so the initial lanes are
    // rebuilt from `state` afterwards (16 broadcast loads per set) rather
    // than kept across the asm block, which would spill all 32 vectors to
    // the stack and reload them; those spills made the kernel's speed depend
    // on the stack frame it happened to run in. `black_box` keeps the
    // compiler from merging the two computations into one spilled copy.
    let state = core::hint::black_box(state);
    let initial_a = input_lanes!(state, counter);
    let initial_b = input_lanes!(state, counter.wrapping_add(SET_BLOCKS));
    finish_lanes!(a, &initial_a, 0, &mut dest);
    finish_lanes!(b, &initial_b, SET_BLOCKS as usize, &mut dest);
}

/// [`xor_chunk_sve2_unchecked`], safe to call with an [`Sve2`] token.
#[inline(always)]
fn xor_chunk_sve2(
    _: Sve2,
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    // SAFETY: an `Sve2` token exists only after detection of `sve2`,
    // which implies `neon`: the features the kernel is compiled for.
    unsafe { xor_chunk_sve2_unchecked(state, counter, input, output, partial) }
}

/// [`sve2_double_rounds`] with the 32 Poly1305 blocks of the two lanes (16
/// each) spread over the double rounds: four per round in the first six,
/// two per round in the last four, alternating lanes.
macro_rules! sve2_poly_double_rounds {
    () => {
        concat!(
            ".p2align 6\n",
            sve2_double_round_with!(
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b"),
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b"),
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b"),
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b"),
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b"),
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b"),
                crate::poly1305::poly_block!("a"),
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                "",
                crate::poly1305::poly_block!("a"),
                "",
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                "",
                crate::poly1305::poly_block!("a"),
                "",
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                "",
                crate::poly1305::poly_block!("a"),
                "",
                crate::poly1305::poly_block!("b")
            ),
            sve2_double_round_with!(
                "",
                crate::poly1305::poly_block!("a"),
                "",
                crate::poly1305::poly_block!("b")
            ),
        )
    };
}

/// [`double_rounds_sve2`] plus the two Poly1305 lanes over `mac_input`; see
/// [`Kernel::xor_chunk_poly`].
#[inline]
#[target_feature(enable = "neon,sve2")]
fn double_rounds_sve2_poly(
    a: &mut [uint32x4_t; 16],
    b: &mut [uint32x4_t; 16],
    lanes: &mut [[u64; 3]; 2],
    r: &[u64; 3],
    mac_input: &[u8; POLY_CHUNK],
) {
    let [[h0a, h1a, h2a], [h0b, h1b, h2b]] = lanes;
    // SAFETY: as for `double_rounds_sve2` for the vector registers. The
    // integer part reads memory only through `pa` and `pb`, which start at
    // `mac_input` and `mac_input + 256` and are each advanced by 16 bytes 16
    // times, so every load is within the 512 bytes of `mac_input`; nothing is
    // written to memory and no stack is used. Every other written register is
    // a declared output or scratch operand, and the flags are clobbered.
    unsafe {
        core::arch::asm!(
            sve2_poly_double_rounds!(),
            inout("v0") a[0], inout("v1") a[1], inout("v2") a[2], inout("v3") a[3],
            inout("v4") a[4], inout("v5") a[5], inout("v6") a[6], inout("v7") a[7],
            inout("v8") a[8], inout("v9") a[9], inout("v10") a[10], inout("v11") a[11],
            inout("v12") a[12], inout("v13") a[13], inout("v14") a[14], inout("v15") a[15],
            inout("v16") b[0], inout("v17") b[1], inout("v18") b[2], inout("v19") b[3],
            inout("v20") b[4], inout("v21") b[5], inout("v22") b[6], inout("v23") b[7],
            inout("v24") b[8], inout("v25") b[9], inout("v26") b[10], inout("v27") b[11],
            inout("v28") b[12], inout("v29") b[13], inout("v30") b[14], inout("v31") b[15],
            pa = inout(reg) mac_input.as_ptr() => _,
            pb = inout(reg) mac_input.as_ptr().wrapping_add(POLY_CHUNK / 2) => _,
            h0a = inout(reg) *h0a, h1a = inout(reg) *h1a, h2a = inout(reg) *h2a,
            h0b = inout(reg) *h0b, h1b = inout(reg) *h1b, h2b = inout(reg) *h2b,
            r0 = in(reg) r[0], r1 = in(reg) r[1], s1 = in(reg) r[2], one = in(reg) 1u64,
            t0a = out(reg) _, t1a = out(reg) _, d0a = out(reg) _, d1a = out(reg) _,
            d2a = out(reg) _, t0b = out(reg) _, t1b = out(reg) _, d0b = out(reg) _,
            d1b = out(reg) _, d2b = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
}

/// [`Kernel::xor_chunk_poly`] on SVE2: [`xor_chunk_sve2_unchecked`] for one
/// whole chunk, with the Poly1305 lanes in its asm block.
#[target_feature(enable = "neon,sve2")]
#[allow(clippy::too_many_arguments)]
fn xor_chunk_sve2_poly_unchecked(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8; POLY_CHUNK]>,
    output: &mut [u8; POLY_CHUNK],
    lanes: &mut [[u64; 3]; 2],
    r: &[u64; 3],
    mac_input: &[u8; POLY_CHUNK],
) {
    let mut dest = Dest::new(SVE2_BLOCKS as usize, input.map(|i| &i[..]), output, None);

    let mut a = input_lanes!(state, counter);
    let mut b = input_lanes!(state, counter.wrapping_add(SET_BLOCKS));
    double_rounds_sve2_poly(&mut a, &mut b, lanes, r, mac_input);
    // Initial lanes rebuilt after the rounds, as in `xor_chunk_sve2_unchecked`.
    let state = core::hint::black_box(state);
    let initial_a = input_lanes!(state, counter);
    let initial_b = input_lanes!(state, counter.wrapping_add(SET_BLOCKS));
    finish_lanes!(a, &initial_a, 0, &mut dest);
    finish_lanes!(b, &initial_b, SET_BLOCKS as usize, &mut dest);
}

/// [`xor_chunk_sve2_poly_unchecked`], safe to call with an [`Sve2`] token.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn xor_chunk_sve2_poly(
    _: Sve2,
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8; POLY_CHUNK]>,
    output: &mut [u8; POLY_CHUNK],
    lanes: &mut [[u64; 3]; 2],
    r: &[u64; 3],
    mac_input: &[u8; POLY_CHUNK],
) {
    // SAFETY: an `Sve2` token exists only after detection of `sve2`,
    // which implies `neon`: the features the kernel is compiled for.
    unsafe { xor_chunk_sve2_poly_unchecked(state, counter, input, output, lanes, r, mac_input) }
}

/// One ChaCha20 quarter-round step on the scalar block held in `w0..w15`:
/// `a += b; d = (d ^ a) >>> ror`, as `add`, `eor` and `ror`.
macro_rules! scalar_step {
    ($a:literal, $b:literal, $d:literal, $ror:literal) => {
        concat!(
            "add w", $a, ", w", $a, ", w", $b, "\n", "eor w", $d, ", w", $d, ", w", $a, "\n",
            "ror w", $d, ", w", $d, ", #", $ror, "\n",
        )
    };
}

/// One ChaCha20 quarter round over the scalar block's words `$a, $b, $c,
/// $d`; rotations as in [`sve2_double_round`].
macro_rules! scalar_quarter_round_asm {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!(
            scalar_step!($a, $b, $d, 16),
            scalar_step!($c, $d, $b, 20),
            scalar_step!($a, $b, $d, 24),
            scalar_step!($c, $d, $b, 25),
        )
    };
}

/// One ChaCha20 double round on the scalar block.
macro_rules! scalar_double_round {
    () => {
        concat!(
            scalar_quarter_round_asm!(0, 4, 8, 12),
            scalar_quarter_round_asm!(1, 5, 9, 13),
            scalar_quarter_round_asm!(2, 6, 10, 14),
            scalar_quarter_round_asm!(3, 7, 11, 15),
            scalar_quarter_round_asm!(0, 5, 10, 15),
            scalar_quarter_round_asm!(1, 6, 11, 12),
            scalar_quarter_round_asm!(2, 7, 8, 13),
            scalar_quarter_round_asm!(3, 4, 9, 14),
        )
    };
}

/// [`sve2_double_rounds`] with a scalar block's double rounds after each of
/// the lane sets'.
macro_rules! sve2_scalar_double_rounds {
    () => {
        concat!(
            ".p2align 6\n",
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
            sve2_double_round!(),
            scalar_double_round!(),
        )
    };
}

/// [`double_rounds_sve2`] plus the rounds of one scalar block `s` on the
/// general-purpose registers `x0..x15`, which the lane sets leave idle.
#[inline]
#[target_feature(enable = "neon,sve2")]
fn double_rounds_sve2_scalar(
    a: &mut [uint32x4_t; 16],
    b: &mut [uint32x4_t; 16],
    s: &mut [u32; 16],
) {
    // SAFETY: as for `double_rounds_sve2`, plus the 16 general-purpose
    // registers bound to `s`, on which only 32-bit `add`/`eor`/`ror` run
    // (the `w` forms zero the upper halves). No flags, memory or stack are
    // touched.
    unsafe {
        core::arch::asm!(
            sve2_scalar_double_rounds!(),
            inout("v0") a[0], inout("v1") a[1], inout("v2") a[2], inout("v3") a[3],
            inout("v4") a[4], inout("v5") a[5], inout("v6") a[6], inout("v7") a[7],
            inout("v8") a[8], inout("v9") a[9], inout("v10") a[10], inout("v11") a[11],
            inout("v12") a[12], inout("v13") a[13], inout("v14") a[14], inout("v15") a[15],
            inout("v16") b[0], inout("v17") b[1], inout("v18") b[2], inout("v19") b[3],
            inout("v20") b[4], inout("v21") b[5], inout("v22") b[6], inout("v23") b[7],
            inout("v24") b[8], inout("v25") b[9], inout("v26") b[10], inout("v27") b[11],
            inout("v28") b[12], inout("v29") b[13], inout("v30") b[14], inout("v31") b[15],
            inout("x0") s[0], inout("x1") s[1], inout("x2") s[2], inout("x3") s[3],
            inout("x4") s[4], inout("x5") s[5], inout("x6") s[6], inout("x7") s[7],
            inout("x8") s[8], inout("x9") s[9], inout("x10") s[10], inout("x11") s[11],
            inout("x12") s[12], inout("x13") s[13], inout("x14") s[14], inout("x15") s[15],
            options(pure, nomem, nostack, preserves_flags),
        );
    }
}

/// [`xor_chunk_sve2_unchecked`] plus the raw keystream of the unrelated
/// block `extra_counter`, XORed into the zero-filled `extra` (the AEAD
/// drivers' MAC key block), computed on the integer pipes inside the lane
/// sets' asm block for a fraction of a dependent scalar block.
#[target_feature(enable = "neon,sve2")]
fn xor_chunk_sve2_with_block_unchecked(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
    (extra_counter, extra): (u64, &mut [u8; 64]),
) {
    let mut dest = Dest::new(SVE2_BLOCKS as usize, input, output, partial);

    let mut a = input_lanes!(state, counter);
    let mut b = input_lanes!(state, counter.wrapping_add(SET_BLOCKS));
    let initial_s = soft::block_input(state, extra_counter);
    let mut s = initial_s;
    double_rounds_sve2_scalar(&mut a, &mut b, &mut s);
    finish_scalar_block(&s, &initial_s, None, extra);
    // Initial lanes rebuilt after the rounds, as in `xor_chunk_sve2_unchecked`.
    let state = core::hint::black_box(state);
    let initial_a = input_lanes!(state, counter);
    let initial_b = input_lanes!(state, counter.wrapping_add(SET_BLOCKS));
    finish_lanes!(a, &initial_a, 0, &mut dest);
    finish_lanes!(b, &initial_b, SET_BLOCKS as usize, &mut dest);
}

/// [`xor_chunk_sve2_with_block_unchecked`], safe to call with an [`Sve2`]
/// token.
#[inline(always)]
fn xor_chunk_sve2_with_block(
    _: Sve2,
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
    extra: (u64, &mut [u8; 64]),
) {
    // SAFETY: an `Sve2` token exists only after detection of `sve2`,
    // which implies `neon`: the features the kernel is compiled for.
    unsafe { xor_chunk_sve2_with_block_unchecked(state, counter, input, output, partial, extra) }
}

/// The quarter-round step for the four quarter rounds of the first lane set
/// only (registers `0..16`).
macro_rules! xar_step_set {
    (
        $ror:literal;
        $a0:literal,
        $a1:literal,
        $a2:literal,
        $a3:literal;
        $b0:literal,
        $b1:literal,
        $b2:literal,
        $b3:literal;
        $d0:literal,
        $d1:literal,
        $d2:literal,
        $d3:literal
    ) => {
        concat!(
            xar_step!($a0, $b0, $d0, $ror),
            xar_step!($a1, $b1, $d1, $ror),
            xar_step!($a2, $b2, $d2, $ror),
            xar_step!($a3, $b3, $d3, $ror),
        )
    };
}

/// One ChaCha20 double round on the lane set in `z0..z15`.
macro_rules! sve2_double_round_set {
    () => {
        concat!(
            xar_step_set!(16; 0, 1, 2, 3; 4, 5, 6, 7; 12, 13, 14, 15),
            xar_step_set!(20; 8, 9, 10, 11; 12, 13, 14, 15; 4, 5, 6, 7),
            xar_step_set!(24; 0, 1, 2, 3; 4, 5, 6, 7; 12, 13, 14, 15),
            xar_step_set!(25; 8, 9, 10, 11; 12, 13, 14, 15; 4, 5, 6, 7),
            xar_step_set!(16; 0, 1, 2, 3; 5, 6, 7, 4; 15, 12, 13, 14),
            xar_step_set!(20; 10, 11, 8, 9; 15, 12, 13, 14; 5, 6, 7, 4),
            xar_step_set!(24; 0, 1, 2, 3; 5, 6, 7, 4; 15, 12, 13, 14),
            xar_step_set!(25; 10, 11, 8, 9; 15, 12, 13, 14; 5, 6, 7, 4),
        )
    };
}

/// All ten double rounds of one lane set, as two passes of a loop over five
/// with the pass counter in `n`; see [`sve2_double_rounds`].
macro_rules! sve2_double_rounds_set {
    () => {
        concat!(
            ".p2align 6\n",
            "2:\n",
            sve2_double_round_set!(),
            sve2_double_round_set!(),
            sve2_double_round_set!(),
            sve2_double_round_set!(),
            sve2_double_round_set!(),
            "subs {n}, {n}, #1\n",
            "b.ne 2b\n",
        )
    };
}

/// Runs the ChaCha20 rounds on one lane set with SVE2 `xar`, in place; see
/// [`double_rounds_sve2`].
#[inline]
#[target_feature(enable = "neon,sve2")]
fn double_rounds_sve2_set(a: &mut [uint32x4_t; 16]) {
    // SAFETY: the caller has verified SVE2 support. The block reads and
    // writes only the 16 vector registers bound below and the pass counter
    // `n`, whose `subs` sets the flags (not preserved, as declared) and runs
    // the loop exactly twice; `add`/`xar` on `.s` lanes never mix lanes, so
    // the low 128 bits (the `uint32x4_t` values) are computed exactly as the
    // scalar reference does, whatever the vector length. No memory or stack
    // is touched.
    unsafe {
        core::arch::asm!(
            sve2_double_rounds_set!(),
            n = inout(reg) 2u64 => _,
            inout("v0") a[0], inout("v1") a[1], inout("v2") a[2], inout("v3") a[3],
            inout("v4") a[4], inout("v5") a[5], inout("v6") a[6], inout("v7") a[7],
            inout("v8") a[8], inout("v9") a[9], inout("v10") a[10], inout("v11") a[11],
            inout("v12") a[12], inout("v13") a[13], inout("v14") a[14], inout("v15") a[15],
            options(pure, nomem, nostack),
        );
    }
}

/// XORs the keystream for blocks `counter .. counter + SMALL_BLOCKS` into
/// `output`; see [`xor_chunk_neon`] for the `output`/`partial` contract. One
/// lane set: the same latency as [`xor_chunk_sve2`] for half the work, so
/// runs of up to four blocks take this kernel.
#[target_feature(enable = "neon,sve2")]
fn xor_chunk_sve2_small_unchecked(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(SMALL_BLOCKS, input, output, partial);

    let mut a = input_lanes!(state, counter);
    double_rounds_sve2_set(&mut a);
    // Rebuilt after the rounds rather than spilled; see `xor_chunk_sve2`.
    let state = core::hint::black_box(state);
    let initial = input_lanes!(state, counter);
    finish_lanes!(a, &initial, 0, &mut dest);
}

/// [`xor_chunk_sve2_small_unchecked`], safe to call with an [`Sve2`] token.
#[inline(always)]
fn xor_chunk_sve2_small(
    _: Sve2,
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    // SAFETY: an `Sve2` token exists only after detection of `sve2`,
    // which implies `neon`: the features the kernel is compiled for.
    unsafe { xor_chunk_sve2_small_unchecked(state, counter, input, output, partial) }
}
