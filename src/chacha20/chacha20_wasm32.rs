//! WebAssembly `simd128` ChaCha20 keystream, several blocks at a time.
//!
//! Full runs are two *lane sets*: lane `i` of every state vector belongs to
//! block `counter + i`, so the ChaCha20 rounds are plain lane-wise arithmetic
//! (the diagonal round is the column round with permuted register names) and
//! the blocks only have to be transposed once at the end, right before being
//! XORed into the data. Runs of at most four blocks use a single lane set.
//! Runs of one or two blocks are left to the scalar block function, which
//! measured faster for them (see [`TAIL_MIN`] and [`FUSED_MIN`]). Control
//! flow and memory access are independent of the key and nonce; the layout
//! depends only on the public run length.
//!
//! Wiping: the lane sets and block inputs only flow through
//! inlined helpers, so they live in the engine's registers or spill slots
//! (the kernels use no linear-memory stack frame), which are out of Rust's
//! reach and not wiped; a wipe would only force them into linear memory. The
//! keystream goes straight into the caller's buffers, which the drivers
//! wipe.

use core::arch::wasm32::{i8x16_shuffle, i32x4_add, u32x4_shl, u32x4_shr, v128, v128_or, v128_xor};

use crate::wasm32::{Dest, input_lanes as shared_input_lanes, transpose, xor_block};

/// Blocks per 4-lane vector set.
const SET_BLOCKS: usize = 4;
/// Blocks per full run: two lane sets. One set leaves the quarter-round
/// dependency chains exposed and three spill; two measured fastest in both
/// V8 and Wasmtime.
const WIDE_BLOCKS: usize = 2 * SET_BLOCKS;
/// Shortest remainder, in blocks including a trailing partial one, worth a
/// kernel run rather than scalar blocks. Measured through the
/// ChaCha20-Poly1305 decryption (whose keystream takes this path) in V8 and
/// Wasmtime: one or two scalar blocks beat a lane set, which also beat a
/// two-block row layout tried for them.
const TAIL_MIN: usize = 3;
/// Fewest blocks (the head included) worth one fused run through the
/// driver's staging buffer, by the same measurement through the
/// ChaCha20-Poly1305 encryption: a head and one data block are cheaper as
/// two scalar blocks, and three blocks already gain from a staged lane set
/// (a minimum of four measured slower at 112 and 128 bytes).
const FUSED_MIN: usize = 3;
/// Blocks (including a trailing partial one) a run may hold to take a
/// single-lane-set run.
pub(super) const SMALL_BLOCKS: usize = SET_BLOCKS;

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
}

/// The kernel fuses no extra block, so the trait's scalar-block default
/// applies; runs of at most [`SMALL_BLOCKS`] are a single call, so the
/// default [`xor_small`](super::Kernel::xor_small) applies too.
impl super::Kernel for Kernel {
    #[inline]
    fn blocks(self) -> usize {
        WIDE_BLOCKS
    }

    #[inline]
    fn tail_min_blocks(self) -> usize {
        TAIL_MIN
    }

    #[inline]
    fn fused_head_min_blocks(self) -> usize {
        FUSED_MIN
    }

    /// Short runs (the driver's tail and head-block runs) take a single lane
    /// set when it covers them.
    #[inline]
    fn xor_chunk(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
    ) {
        let blocks = output.len() / 64 + usize::from(partial.is_some());
        if blocks <= SET_BLOCKS {
            xor_chunk_set(state, counter, input, output, partial);
        } else {
            xor_chunk_wide(state, counter, input, output, partial);
        }
    }
}

/// Rotates every lane left by `$r` bits with two shifts and an OR.
macro_rules! rot {
    ($v:expr, $r:literal) => {{
        let v = $v;
        v128_or(u32x4_shl(v, $r), u32x4_shr(v, 32 - $r))
    }};
}

/// Rotates every lane left by 16 bits (a halfword swap). The byte-multiple
/// rotations are shuffles (a single `rev32`/`tbl` on AArch64 hosts,
/// `pshufb` on x86-64 ones); they measured faster than shifts in V8 and on
/// par in Wasmtime.
#[inline(always)]
fn rot16(v: v128) -> v128 {
    i8x16_shuffle::<2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13>(v, v)
}

/// Rotates every lane left by 8 bits (a byte rotation).
#[inline(always)]
fn rot8(v: v128) -> v128 {
    i8x16_shuffle::<3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14>(v, v)
}

/// One ChaCha20 quarter round over the four vectors `$a, $b, $c, $d` of
/// `$x`.
macro_rules! quarter_round {
    ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $x[$a] = i32x4_add($x[$a], $x[$b]);
        $x[$d] = rot16(v128_xor($x[$d], $x[$a]));
        $x[$c] = i32x4_add($x[$c], $x[$d]);
        $x[$b] = rot!(v128_xor($x[$b], $x[$c]), 12);
        $x[$a] = i32x4_add($x[$a], $x[$b]);
        $x[$d] = rot8(v128_xor($x[$d], $x[$a]));
        $x[$c] = i32x4_add($x[$c], $x[$d]);
        $x[$b] = rot!(v128_xor($x[$b], $x[$c]), 7);
    };
}

/// The ChaCha20 input for blocks `counter .. counter + 4`, one block per
/// lane; the 64-bit block counter lives in words 12 and 13.
#[inline(always)]
fn input_lanes(state: &[u32; 16], counter: u64) -> [v128; 16] {
    shared_input_lanes::<12, 13>(state, counter)
}

/// Finalises a lane set: adds the input back, transposes into block order
/// and XORs the keystream into blocks `base .. base + 4` of `dest`.
#[inline(always)]
fn finish_lanes(mut x: [v128; 16], initial: &[v128; 16], base: usize, dest: &mut Dest<'_>) {
    for (word, init) in x.iter_mut().zip(initial) {
        *word = i32x4_add(*word, *init);
    }
    // `r<i>[block]` holds words `4 * i .. 4 * i + 4` of `block`.
    let r0 = transpose(x[0], x[1], x[2], x[3]);
    let r1 = transpose(x[4], x[5], x[6], x[7]);
    let r2 = transpose(x[8], x[9], x[10], x[11]);
    let r3 = transpose(x[12], x[13], x[14], x[15]);
    xor_block([r0[0], r1[0], r2[0], r3[0]], base, dest);
    xor_block([r0[1], r1[1], r2[1], r3[1]], base + 1, dest);
    xor_block([r0[2], r1[2], r2[2], r3[2]], base + 2, dest);
    xor_block([r0[3], r1[3], r2[3], r3[3]], base + 3, dest);
}

/// XORs the keystream for blocks `counter .. counter + WIDE_BLOCKS` into
/// `output`, reading the plaintext/ciphertext from `input` (or from `output`
/// itself when `input` is `None`). `output` holds at most `WIDE_BLOCKS` whole
/// blocks; the following block's raw keystream goes to the zero-filled
/// `partial` when given, and the rest is discarded.
///
/// Out of line so each layout is compiled once, with its own register
/// allocation, whatever the driver it is called from.
#[inline(never)]
fn xor_chunk_wide(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(WIDE_BLOCKS, input, output, partial);
    let initial_a = input_lanes(state, counter);
    let initial_b = input_lanes(state, counter.wrapping_add(SET_BLOCKS as u64));
    let mut a = initial_a;
    let mut b = initial_b;
    for _ in 0..10 {
        super::chacha20_double_round!(quarter_round, a);
        super::chacha20_double_round!(quarter_round, b);
    }
    finish_lanes(a, &initial_a, 0, &mut dest);
    finish_lanes(b, &initial_b, SET_BLOCKS, &mut dest);
}

/// [`xor_chunk_wide`] for one lane set: blocks `counter .. counter +
/// SET_BLOCKS`.
#[inline(never)]
fn xor_chunk_set(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(SET_BLOCKS, input, output, partial);
    let initial = input_lanes(state, counter);
    let mut x = initial;
    for _ in 0..10 {
        super::chacha20_double_round!(quarter_round, x);
    }
    finish_lanes(x, &initial, 0, &mut dest);
}
