//! AVX2 and AVX-512 ChaCha20 keystream, several blocks at a time.
//!
//! Each chunk is a *lane set*: lane `i` of every state vector belongs to
//! block `counter + i`, so the ChaCha20 rounds are plain lane-wise arithmetic
//! (the diagonal round is the column round with permuted register names) and
//! the blocks only have to be transposed once at the end, right before being
//! XORed into the data. Control flow and memory access are independent of the
//! key and nonce.
//!
//! Wiping: the lane sets stay inside each kernel (the finish and XOR helpers
//! are macros; as `#[inline]` functions they were kept out of line and
//! received stack copies of the lane state and input), so they live in
//! registers or compiler spill slots (the AVX2 set does not fit the 16 `ymm`
//! registers), which are out of Rust's reach and not wiped: a wipe would
//! only force them into stack slots. The one addressable copy, the scalar
//! companion block whose words `10..16` are an `asm!` memory operand, is
//! zeroized once per kernel call.

use core::arch::asm;
use core::arch::x86_64::{
    __m256i, _mm256_add_epi32, _mm256_or_si256, _mm256_rol_epi32, _mm256_setr_epi8,
    _mm256_shuffle_epi8, _mm256_slli_epi32, _mm256_srli_epi32, _mm256_xor_si256, _mm512_add_epi32,
    _mm512_rol_epi32, _mm512_xor_si512,
};

use zeroize::Zeroize;

use crate::x86_64::{
    Dest, LANES, LANES512, LaneSet, finish_lanes, finish_lanes512, input_lanes, input_lanes512,
    xor_scalar_words,
};

/// Blocks (including a trailing partial one) a run may hold to be served by
/// [`Kernel::xor_small`](super::Kernel::xor_small): one AVX-512 lane set, or
/// two AVX2 runs.
pub(super) const SMALL_BLOCKS: usize = LANES512;

/// The x86-64 kernel: the [`LaneSet`] variant its runs use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Kernel(LaneSet);

/// The best kernel the running CPU supports.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    LaneSet::detect().map(Kernel)
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        LaneSet::all().into_iter().map(Kernel).collect()
    }
}

impl super::Kernel for Kernel {
    #[inline]
    fn blocks(self) -> usize {
        self.0.blocks()
    }

    /// A run of either lane set costs about two scalar blocks.
    #[inline]
    fn tail_min_blocks(self) -> usize {
        2
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
        let small = LaneSet::fits_ymm(output.len(), partial.is_some());
        match self.0 {
            // SAFETY: a `LaneSet` is only constructed by `LaneSet::detect`
            // (and, in tests, `LaneSet::all`) after `has_x86_feature!`
            // confirmed the features its variant needs; `LaneSet::Avx2`
            // requires `avx2`.
            LaneSet::Avx2 => unsafe { xor_chunk_avx2(state, counter, input, output, partial) },
            // SAFETY: as above; `LaneSet::Avx512Vl` requires `avx512f`,
            // `avx512vl` and `avx2`.
            LaneSet::Avx512Vl if small => unsafe {
                xor_chunk_avx512vl(state, counter, input, output, partial)
            },
            // SAFETY: as above; `LaneSet::Avx512` and `LaneSet::Avx512Vl`
            // require `avx512f`.
            LaneSet::Avx512 | LaneSet::Avx512Vl => unsafe {
                xor_chunk_avx512(state, counter, input, output, partial)
            },
        }
    }

    /// The AVX-512 kernel computes the extra block on the integer ports
    /// alongside the lane set ([`xor_chunk_avx512_with_block`]).
    #[inline]
    fn fuses_extra_block(self) -> bool {
        self.0.fuses_extra_block()
    }

    /// On AVX-512 the extra block's scalar rounds run interleaved with the
    /// lane set's on the otherwise idle integer ports, so it costs about a
    /// third of a dependent scalar block; on AVX2 it is a scalar block after
    /// the run.
    #[inline]
    fn xor_chunk_with_block(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
        (extra_counter, extra): (u64, &mut [u8; 64]),
    ) {
        match self.0 {
            LaneSet::Avx2 => {
                self.xor_chunk(state, counter, input, output, partial);
                crate::stream::xor_scalar_block(
                    state,
                    extra_counter,
                    extra,
                    super::chacha20_soft::block,
                );
            }
            // SAFETY: as for `xor_chunk`; `LaneSet::Avx512` and
            // `LaneSet::Avx512Vl` require `avx512f`.
            LaneSet::Avx512 | LaneSet::Avx512Vl => unsafe {
                xor_chunk_avx512_with_block(
                    state,
                    counter,
                    input,
                    output,
                    partial,
                    extra_counter,
                    extra,
                )
            },
        }
    }
}

/// Byte permutation (per 128-bit half) rotating every 32-bit lane left by 16
/// bits.
#[inline]
#[target_feature(enable = "avx2")]
fn rot16_table() -> __m256i {
    _mm256_setr_epi8(
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9,
        14, 15, 12, 13,
    )
}

/// Byte permutation (per 128-bit half) rotating every 32-bit lane left by 8
/// bits.
#[inline]
#[target_feature(enable = "avx2")]
fn rot8_table() -> __m256i {
    _mm256_setr_epi8(
        3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10,
        15, 12, 13, 14,
    )
}

/// Rotates every lane left by `$r` bits with two shifts and an OR.
macro_rules! rot {
    ($v:expr, $r:literal) => {{
        let v = $v;
        _mm256_or_si256(
            _mm256_slli_epi32::<$r>(v),
            _mm256_srli_epi32::<{ 32 - $r }>(v),
        )
    }};
}

/// One ChaCha20 quarter round over the four vectors `$a, $b, $c, $d` of
/// `$x`, with the byte-permutation tables for the 16- and 8-bit rotations in
/// `$rot16` and `$rot8`.
macro_rules! quarter_round {
    ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal, $rot16:ident, $rot8:ident) => {
        $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256($x[$d], $x[$a]), $rot16);
        $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
        $x[$b] = rot!(_mm256_xor_si256($x[$b], $x[$c]), 12);
        $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256($x[$d], $x[$a]), $rot8);
        $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
        $x[$b] = rot!(_mm256_xor_si256($x[$b], $x[$c]), 7);
    };
}

/// XORs the keystream for blocks `counter .. counter + LANES` into
/// `output`, reading the plaintext/ciphertext from `input` (or from `output`
/// itself when `input` is `None`). `output` holds at most `LANES` whole
/// blocks; the following block's raw keystream goes to the zero-filled
/// `partial` when given, and the rest is discarded, so a short remainder
/// costs one kernel run rather than a run of dependent scalar blocks.
///
/// The lane set fills the 16 `ymm` registers, so the rotation temporaries
/// and the two shuffle tables spill; the four independent columns of each
/// round still keep the vector pipes busy. Kept out of line so its schedule
/// does not change with the inlining context.
#[inline(never)]
#[target_feature(enable = "avx2")]
fn xor_chunk_avx2(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(LANES, input, output, partial);

    let rot16 = rot16_table();
    let rot8 = rot8_table();
    let initial = input_lanes::<12, 13>(state, counter);
    let mut x = initial;
    for _ in 0..10 {
        super::chacha20_double_round!(quarter_round, x, rot16, rot8);
    }
    finish_lanes!(x, &initial, &mut dest);
}

/// One ChaCha20 quarter round over the four `ymm` vectors `$a, $b, $c, $d`
/// of `$x`, with AVX-512VL rotates.
macro_rules! quarter_round_vl {
    ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm256_rol_epi32::<16>(_mm256_xor_si256($x[$d], $x[$a]));
        $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
        $x[$b] = _mm256_rol_epi32::<12>(_mm256_xor_si256($x[$b], $x[$c]));
        $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm256_rol_epi32::<8>(_mm256_xor_si256($x[$d], $x[$a]));
        $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
        $x[$b] = _mm256_rol_epi32::<7>(_mm256_xor_si256($x[$b], $x[$c]));
    };
}

/// [`xor_chunk_avx2`] with AVX-512VL rotates: every rotation is one
/// `vprold` instead of two shifts and an OR or a byte shuffle, and the 32
/// EVEX `ymm` registers hold the lane set without spills. 256-bit
/// operations issue on three ports where 512-bit ones use two, so for a run
/// of at most eight slots this finishes sooner than the 16-lane set.
#[inline(never)]
#[target_feature(enable = "avx2,avx512f,avx512vl")]
fn xor_chunk_avx512vl(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(LANES, input, output, partial);

    let initial = input_lanes::<12, 13>(state, counter);
    let mut x = initial;
    for _ in 0..10 {
        super::chacha20_double_round!(quarter_round_vl, x);
    }
    finish_lanes!(x, &initial, &mut dest);
}

/// One ChaCha20 quarter round over the four vectors `$a, $b, $c, $d` of
/// `$x`, with AVX-512 rotates.
macro_rules! quarter_round512 {
    ($x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $x[$a] = _mm512_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm512_rol_epi32::<16>(_mm512_xor_si512($x[$d], $x[$a]));
        $x[$c] = _mm512_add_epi32($x[$c], $x[$d]);
        $x[$b] = _mm512_rol_epi32::<12>(_mm512_xor_si512($x[$b], $x[$c]));
        $x[$a] = _mm512_add_epi32($x[$a], $x[$b]);
        $x[$d] = _mm512_rol_epi32::<8>(_mm512_xor_si512($x[$d], $x[$a]));
        $x[$c] = _mm512_add_epi32($x[$c], $x[$d]);
        $x[$b] = _mm512_rol_epi32::<7>(_mm512_xor_si512($x[$b], $x[$c]));
    };
}

/// XORs the keystream for blocks `counter .. counter + LANES512` into
/// `output`; see [`xor_chunk_avx2`] for the `output`/`partial` contract.
///
/// One 16-block lane set in 16 of the 32 `zmm` registers, so nothing spills,
/// and each rotation is a single `vprold`: a quarter round is twelve
/// instructions on four independent columns, which keeps both 512-bit pipes
/// busy without a second set.
#[inline(never)]
#[target_feature(enable = "avx512f")]
fn xor_chunk_avx512(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
) {
    let mut dest = Dest::new(LANES512, input, output, partial);

    let initial = input_lanes512::<12, 13>(state, counter);
    let mut x = initial;
    for _ in 0..10 {
        super::chacha20_double_round!(quarter_round512, x);
    }
    finish_lanes512!(x, &initial, &mut dest);
}

/// One scalar ChaCha20 quarter round in the `asm!` template of
/// [`scalar_double_round`]: `$a`, `$b`, `$c` are register operand names, `$d`
/// the byte offset of the fourth word in the memory-resident words at `{p}`,
/// staged through `{t1}` for the quarter round.
macro_rules! scalar_quarter_round_d {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!(
            "mov {t1:e}, dword ptr [{p} + ",
            $d,
            "]\n",
            "add {",
            $a,
            ":e}, {",
            $b,
            ":e}\n",
            "xor {t1:e}, {",
            $a,
            ":e}\n",
            "rol {t1:e}, 16\n",
            "add {",
            $c,
            ":e}, {t1:e}\n",
            "xor {",
            $b,
            ":e}, {",
            $c,
            ":e}\n",
            "rol {",
            $b,
            ":e}, 12\n",
            "add {",
            $a,
            ":e}, {",
            $b,
            ":e}\n",
            "xor {t1:e}, {",
            $a,
            ":e}\n",
            "rol {t1:e}, 8\n",
            "add {",
            $c,
            ":e}, {t1:e}\n",
            "xor {",
            $b,
            ":e}, {",
            $c,
            ":e}\n",
            "rol {",
            $b,
            ":e}, 7\n",
            "mov dword ptr [{p} + ",
            $d,
            "], {t1:e}\n",
        )
    };
}

/// [`scalar_quarter_round_d`] with both the third word (offset `$c`, staged
/// through `{t0}`) and the fourth (offset `$d`, through `{t1}`) in memory.
macro_rules! scalar_quarter_round_cd {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!(
            "mov {t0:e}, dword ptr [{p} + ",
            $c,
            "]\n",
            "mov {t1:e}, dword ptr [{p} + ",
            $d,
            "]\n",
            "add {",
            $a,
            ":e}, {",
            $b,
            ":e}\n",
            "xor {t1:e}, {",
            $a,
            ":e}\n",
            "rol {t1:e}, 16\n",
            "add {t0:e}, {t1:e}\n",
            "xor {",
            $b,
            ":e}, {t0:e}\n",
            "rol {",
            $b,
            ":e}, 12\n",
            "add {",
            $a,
            ":e}, {",
            $b,
            ":e}\n",
            "xor {t1:e}, {",
            $a,
            ":e}\n",
            "rol {t1:e}, 8\n",
            "add {t0:e}, {t1:e}\n",
            "xor {",
            $b,
            ":e}, {t0:e}\n",
            "rol {",
            $b,
            ":e}, 7\n",
            "mov dword ptr [{p} + ",
            $c,
            "], {t0:e}\n",
            "mov dword ptr [{p} + ",
            $d,
            "], {t1:e}\n",
        )
    };
}

/// One scalar ChaCha20 double round on general purpose registers: words
/// `0..10` are register operands and words `10..16` live in memory, each
/// loaded into a temporary for its quarter round and stored back.
///
/// This exists for [`xor_chunk_avx512_with_block`]: written in Rust, the four
/// independent quarter rounds get SLP-vectorised into 128-bit code, which
/// competes with the 512-bit lane set for the same two vector ports; the
/// `add`/`xor`/`rol` here run on the integer ports the lane set leaves idle.
/// Only 13 general purpose registers are allocatable to `asm!` on x86-64, so
/// six words go through memory (loads and stores use the memory ports).
#[inline(always)]
fn scalar_double_round(x: &mut [u32; 16]) {
    let (regs, mem) = x.split_at_mut(10);
    // SAFETY: a `nostack` block whose only memory accesses are 4-byte loads
    // and stores at offsets 0..24 of `mem`, a valid `&mut [u32; 6]` for the
    // whole block (`p` = `mem.as_mut_ptr()`); every written register is a
    // declared `inout`/`out` operand, and the flags are clobbered as Rust
    // assumes by default. Base x86-64 instructions only.
    unsafe {
        asm!(
            // Column round: (0,4,8,12) (1,5,9,13) (2,6,10,14) (3,7,11,15).
            scalar_quarter_round_d!("x0", "x4", "x8", 8),
            scalar_quarter_round_d!("x1", "x5", "x9", 12),
            scalar_quarter_round_cd!("x2", "x6", 0, 16),
            scalar_quarter_round_cd!("x3", "x7", 4, 20),
            // Diagonal round: (0,5,10,15) (1,6,11,12) (2,7,8,13) (3,4,9,14).
            scalar_quarter_round_cd!("x0", "x5", 0, 20),
            scalar_quarter_round_cd!("x1", "x6", 4, 8),
            scalar_quarter_round_d!("x2", "x7", "x8", 12),
            scalar_quarter_round_d!("x3", "x4", "x9", 16),
            x0 = inout(reg) regs[0],
            x1 = inout(reg) regs[1],
            x2 = inout(reg) regs[2],
            x3 = inout(reg) regs[3],
            x4 = inout(reg) regs[4],
            x5 = inout(reg) regs[5],
            x6 = inout(reg) regs[6],
            x7 = inout(reg) regs[7],
            x8 = inout(reg) regs[8],
            x9 = inout(reg) regs[9],
            p = in(reg) mem.as_mut_ptr(),
            t0 = out(reg) _,
            t1 = out(reg) _,
            options(nostack),
        );
    }
}

/// [`xor_chunk_avx512`] plus one unrelated block: the sixteen lanes and,
/// interleaved double round by double round, the scalar block
/// `extra_counter` on the integer ports ([`scalar_double_round`]), whose raw
/// keystream is XORed into the zero-filled `extra`. The lane set keeps both
/// 512-bit ports busy for about 480 cycles while the scalar block's
/// dependency chain is about 360 cycles long, so the extra block adds
/// roughly a third of a dependent scalar block. The extra block is the key
/// block ahead of a message, or the block after a full chunk: the shapes of
/// the AEAD and secretstream constructions.
#[inline(never)]
#[target_feature(enable = "avx512f")]
fn xor_chunk_avx512_with_block(
    state: &[u32; 16],
    counter: u64,
    input: Option<&[u8]>,
    output: &mut [u8],
    partial: Option<&mut [u8; 64]>,
    extra_counter: u64,
    extra: &mut [u8; 64],
) {
    let mut dest = Dest::new(LANES512, input, output, partial);

    let initial = input_lanes512::<12, 13>(state, counter);
    let mut x = initial;
    let scalar_initial = super::chacha20_soft::block_input(state, extra_counter);
    let mut s = scalar_initial;
    for _ in 0..10 {
        super::chacha20_double_round!(quarter_round512, x);
        scalar_double_round(&mut s);
    }
    finish_lanes512!(x, &initial, &mut dest);
    xor_scalar_words(&s, &scalar_initial, extra);
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_prelude::*;

    /// The register-scheduled scalar double round equals the portable one
    /// for random states.
    #[cfg_attr(miri, ignore = "Miri cannot execute inline assembly")]
    #[test]
    fn test_scalar_double_round_matches_portable() {
        let mut rng = crate::utils::test_util::XorShift64::new(0x5eed_1234_abcd_9876);
        for _ in 0..500 {
            let mut x = [0u32; 16];
            for word in &mut x {
                *word = rng.next_u64() as u32;
            }
            let mut expected = x;
            super::super::chacha20_soft::double_round(&mut expected);
            scalar_double_round(&mut x);
            assert_eq!(x, expected);
        }
    }

    /// The fused AVX-512 run equals the AVX-512 run for its lanes (whole
    /// blocks and partial slot) plus the scalar block for the unrelated
    /// extra counter, in place and buffer to buffer, for full and short lane
    /// sets and extra blocks before and after them.
    #[test]
    fn test_avx512_with_block_matches_run_and_scalar_block() {
        if !has_x86_feature!("avx512f") {
            return;
        }
        let mut state = [0u32; 16];
        for (i, word) in state.iter_mut().enumerate() {
            *word = 0x0101_0101u32.wrapping_mul(i as u32 + 3);
        }
        let plaintext: Vec<u8> = (0..LANES512 * 64).map(|i| (i * 13 % 251) as u8).collect();
        for counter in [1u64, 5, u64::from(u32::MAX) - 8, u64::from(u32::MAX) - 16] {
            for whole in [LANES512, LANES512 - 1, 3, 0] {
                for extra_counter in [counter - 1, counter + LANES512 as u64] {
                    let len = whole * 64;
                    let has_partial = whole < LANES512;
                    let mut expected = plaintext[..len].to_vec();
                    let mut expected_partial = [0u8; 64];
                    let mut expected_extra = [0u8; 64];
                    // SAFETY: `avx512f` was detected above.
                    unsafe {
                        xor_chunk_avx512(
                            &state,
                            counter,
                            None,
                            &mut expected,
                            has_partial.then_some(&mut expected_partial),
                        )
                    };
                    super::super::chacha20_soft::block(&state, extra_counter, &mut expected_extra);

                    let mut in_place = plaintext[..len].to_vec();
                    let mut partial = [0u8; 64];
                    let mut extra = [0u8; 64];
                    // SAFETY: `avx512f` was detected above.
                    unsafe {
                        xor_chunk_avx512_with_block(
                            &state,
                            counter,
                            None,
                            &mut in_place,
                            has_partial.then_some(&mut partial),
                            extra_counter,
                            &mut extra,
                        )
                    };
                    let what = format!("counter {counter}, whole {whole}, extra {extra_counter}");
                    assert_eq!(in_place, expected, "in place, {what}");
                    assert_eq!(partial, expected_partial, "partial, {what}");
                    assert_eq!(extra, expected_extra, "extra, {what}");

                    let mut b2b = vec![0u8; len];
                    let mut extra = [0xa5u8; 64];
                    // SAFETY: `avx512f` was detected above.
                    unsafe {
                        xor_chunk_avx512_with_block(
                            &state,
                            counter,
                            Some(&plaintext[..len]),
                            &mut b2b,
                            None,
                            extra_counter,
                            &mut extra,
                        )
                    };
                    assert_eq!(b2b, expected, "b2b, {what}");
                    for (byte, ks) in extra.iter().zip(expected_extra) {
                        assert_eq!(*byte, 0xa5 ^ ks, "extra XOR, {what}");
                    }
                }
            }
        }
    }
}
