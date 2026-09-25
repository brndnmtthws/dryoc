//! WebAssembly `simd128` Salsa20/20 keystream, several blocks at a time.
//!
//! Lane `i` of every state vector belongs to block `counter + i`, so the
//! Salsa20 rounds are plain lane-wise arithmetic and the blocks only have to
//! be transposed once at the end, right before being XORed into the data.
//! Control flow and memory access are independent of the key and nonce.
//!
//! Wiping: the lane sets only flow through inlined helpers, so they live in
//! the engine's registers or spill slots, which are out of Rust's reach and
//! not wiped; a wipe would only force them into linear memory. The keystream
//! goes straight into the caller's buffers, which the drivers wipe.

use core::arch::wasm32::{i32x4_add, u32x4_shl, u32x4_shr, v128, v128_or, v128_xor};

use crate::wasm32::{Dest, input_lanes as shared_input_lanes, transpose, xor_block};

/// Blocks per 4-lane vector set.
const SET_BLOCKS: usize = 4;
/// Lane sets per run.
const SETS: usize = 2;
/// Blocks produced per run.
const BLOCKS: usize = SETS * SET_BLOCKS;

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

impl super::Kernel for Kernel {
    #[inline]
    fn blocks(self) -> usize {
        BLOCKS
    }

    #[inline]
    fn tail_min(self) -> usize {
        TAIL_MIN * 64
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
        if output.len() / 64 + usize::from(partial.is_some()) <= SET_BLOCKS {
            xor_chunk_set(state, counter, input, output, partial);
        } else {
            xor_chunk_wide(state, counter, input, output, partial);
        }
    }
}

const TAIL_MIN: usize = 2;

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r`, the
/// rotation as two shifts and an OR.
macro_rules! step {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        let sum = i32x4_add($x[$a], $x[$c]);
        $x[$b] = v128_xor($x[$b], v128_or(u32x4_shl(sum, $r), u32x4_shr(sum, 32 - $r)));
    };
}

/// The Salsa20 input for blocks `counter .. counter + 4`, one block per lane;
/// the 64-bit block counter lives in words 8 and 9.
#[inline(always)]
fn input_lanes(state: &[u32; 16], counter: u64) -> [v128; 16] {
    shared_input_lanes::<8, 9>(state, counter)
}

/// Finalises a lane set: adds the input back, transposes into block order
/// and XORs the keystream into blocks `base .. base + 4` of `dest`.
#[inline(always)]
fn finish_set(mut x: [v128; 16], initial: &[v128; 16], base: usize, dest: &mut Dest<'_>) {
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

/// XORs the keystream for blocks `counter .. counter + BLOCKS` into
/// `output`, reading the plaintext/ciphertext from `input` (or from `output`
/// itself when `input` is `None`). `output` holds at most `BLOCKS` whole
/// blocks; the following block's raw keystream goes to the zero-filled
/// `partial` when given, and the rest is discarded.
#[inline(never)]
fn xor_chunk_wide(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(BLOCKS, input, output, partial);
    let initial_a = input_lanes(state, counter);
    let initial_b = input_lanes(state, counter.wrapping_add(SET_BLOCKS as u64));
    let mut a = initial_a;
    let mut b = initial_b;
    for _ in 0..10 {
        super::salsa20_double_round!(step, a);
        super::salsa20_double_round!(step, b);
    }
    finish_set(a, &initial_a, 0, &mut dest);
    finish_set(b, &initial_b, SET_BLOCKS, &mut dest);
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
        super::salsa20_double_round!(step, x);
    }
    finish_set(x, &initial, 0, &mut dest);
}
