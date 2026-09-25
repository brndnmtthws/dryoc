//! Portable-SIMD Salsa20/20 keystream, four blocks at a time.
//!
//! Lane `i` of every state vector belongs to block `counter + i`, so the
//! Salsa20 rounds are plain lane-wise arithmetic and the blocks only have to
//! be transposed once at the end, right before being XORed into the data.
//! Control flow and memory access are independent of the key and nonce.
//!
//! Wiping: the lane set only flows through registers and inlined helpers, so
//! it lives in registers or compiler spill slots, which are out of Rust's
//! reach and not wiped; a wipe would only force it into stack slots. The
//! keystream goes straight into the caller's buffers, which the driver wipes.

use core::simd::{Simd, simd_swizzle};

use crate::stream::Dest;

type U32x4 = Simd<u32, 4>;

/// Blocks produced per run.
const BLOCKS: usize = 4;

/// The portable-SIMD kernel; always available in this configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Kernel;

/// The kernel the running CPU supports: the portable-SIMD code compiles for
/// every target, so this is always `Some`. Only consulted where this backend
/// is the production one; on AArch64 and x86-64 it is compiled for tests
/// only.
#[cfg(not(dryoc_stream_kernel))]
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    Some(Kernel)
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        vec![Kernel]
    }
}

impl super::Kernel for Kernel {
    #[inline]
    fn blocks(self) -> usize {
        BLOCKS
    }

    /// Only whole chunks go through the lane set (the threshold the earlier
    /// portable-SIMD backend used); the remainder is left to the scalar
    /// block function.
    #[inline]
    fn tail_min(self) -> usize {
        self.chunk()
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
        let mut dest = Dest::new(BLOCKS, input, output, partial);

        let initial = input_lanes(state, counter);
        let mut x = initial;
        for _ in 0..10 {
            double_round(&mut x);
        }
        for (word, init) in x.iter_mut().zip(&initial) {
            *word += *init;
        }
        // `r<i>[block]` holds words `4 * i .. 4 * i + 4` of `block`.
        let r0 = transpose(x[0], x[1], x[2], x[3]);
        let r1 = transpose(x[4], x[5], x[6], x[7]);
        let r2 = transpose(x[8], x[9], x[10], x[11]);
        let r3 = transpose(x[12], x[13], x[14], x[15]);
        for block in 0..BLOCKS {
            xor_block(
                [r0[block], r1[block], r2[block], r3[block]],
                block,
                &mut dest,
            );
        }
    }
}

/// Rotates every lane left by `N` bits.
#[inline(always)]
fn rotl<const N: u32>(x: U32x4) -> U32x4 {
    (x << U32x4::splat(N)) | (x >> U32x4::splat(32 - N))
}

/// One Salsa20 quarter-round step: `x[$b] ^= (x[$a] + x[$c]) <<< $r`.
macro_rules! step {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        $x[$b] ^= rotl::<$r>($x[$a] + $x[$c]);
    };
}

/// One Salsa20 double round (a column round followed by a row round) of the
/// lane set.
#[inline(always)]
fn double_round(x: &mut [U32x4; 16]) {
    super::salsa20_double_round!(step, x);
}

/// The Salsa20 input for blocks `counter .. counter + 4`, one block per lane.
#[inline(always)]
fn input_lanes(state: &[u32; 16], counter: u64) -> [U32x4; 16] {
    let mut lanes = state.map(U32x4::splat);
    let counters = [0, 1, 2, 3].map(|i| counter.wrapping_add(i));
    lanes[8] = U32x4::from(counters.map(|c| c as u32));
    lanes[9] = U32x4::from(counters.map(|c| (c >> 32) as u32));
    lanes
}

/// Transposes the 4x4 word matrix `(a, b, c, d)` so that element `i` of the
/// result holds lane `i` of each input, i.e. four consecutive words of block
/// `i`.
#[inline(always)]
fn transpose(a: U32x4, b: U32x4, c: U32x4, d: U32x4) -> [U32x4; 4] {
    let ab_lo = simd_swizzle!(a, b, [0, 4, 1, 5]);
    let ab_hi = simd_swizzle!(a, b, [2, 6, 3, 7]);
    let cd_lo = simd_swizzle!(c, d, [0, 4, 1, 5]);
    let cd_hi = simd_swizzle!(c, d, [2, 6, 3, 7]);
    [
        simd_swizzle!(ab_lo, cd_lo, [0, 1, 4, 5]),
        simd_swizzle!(ab_lo, cd_lo, [2, 3, 6, 7]),
        simd_swizzle!(ab_hi, cd_hi, [0, 1, 4, 5]),
        simd_swizzle!(ab_hi, cd_hi, [2, 3, 6, 7]),
    ]
}

/// XORs the four 16-byte rows of `keystream` into block `index` of `dest`.
#[inline(always)]
fn xor_block(keystream: [U32x4; 4], index: usize, dest: &mut Dest<'_>) {
    let Some((source, out)) = dest.block(index) else {
        return;
    };
    let source = source.map(|source| source.as_chunks::<16>().0);
    let out = out.as_chunks_mut::<16>().0;
    for (row, keystream) in keystream.into_iter().enumerate() {
        let data = match source {
            Some(source) => load(&source[row]),
            None => load(&out[row]),
        };
        store(&mut out[row], data ^ keystream);
    }
}

/// Loads 16 little-endian bytes as four words.
#[inline(always)]
fn load(bytes: &[u8; 16]) -> U32x4 {
    let words = bytes.as_chunks::<4>().0;
    U32x4::from([words[0], words[1], words[2], words[3]].map(u32::from_le_bytes))
}

/// Stores four words as 16 little-endian bytes.
#[inline(always)]
fn store(bytes: &mut [u8; 16], words: U32x4) {
    for (chunk, word) in bytes
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(words.to_array())
    {
        *chunk = word.to_le_bytes();
    }
}
