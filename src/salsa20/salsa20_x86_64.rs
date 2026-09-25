//! AVX2 and AVX-512 Salsa20/20 keystream, several blocks at a time.
//!
//! Lane `i` of every state vector belongs to block `counter + i`, so the
//! Salsa20 rounds are plain lane-wise arithmetic and the blocks only have to
//! be transposed once at the end, right before being XORed into the data.
//! Control flow and memory access are independent of the key and nonce.
//!
//! Wiping: the lane sets and scalar words stay inside each kernel (the input,
//! transpose, finish and XOR helpers are macros; as `#[inline]` functions they
//! were kept out of line and received stack copies of the lane state and
//! input), so they live in registers or compiler spill slots (the AVX2 set does
//! not fit the 16 `ymm` registers), which are out of Rust's reach and not
//! wiped: a wipe would only force them into stack slots. The one addressable
//! copy, the memory-resident words of the scalar companion block (an `asm!`
//! memory operand), is zeroized once per kernel call.

use core::arch::asm;
use core::arch::x86_64::{
    _mm256_add_epi32, _mm256_or_si256, _mm256_rol_epi32, _mm256_slli_epi32, _mm256_srli_epi32,
    _mm256_xor_si256, _mm512_add_epi32, _mm512_rol_epi32, _mm512_xor_si512,
};

use zeroize::Zeroize;

use crate::x86_64::{
    Dest, LANES, LANES512, LaneSet, finish_lanes, finish_lanes512, input_lanes, input_lanes512,
    xor_scalar_words,
};

/// The x86-64 kernel: the [`LaneSet`] variant its runs use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Kernel(LaneSet);

/// The fastest kernel the running CPU supports, if any.
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
    fn tail_min(self) -> usize {
        2 * 64
    }

    /// Out of line at opt-level `z`, which adds no copy: it only forwards `&`
    /// to the cipher's own state, which `XSalsa20` wipes on drop, and the
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
            // require `avx512f` and `avx2` (`x86_64::has_avx512f`).
            LaneSet::Avx512 | LaneSet::Avx512Vl => unsafe {
                xor_chunk_avx512(state, counter, input, output, partial)
            },
        }
    }

    /// A run costs about two scalar blocks (AVX2 and 16-lane AVX-512), so a
    /// head block plus at least one block of data is worth one staged run;
    /// the AVX-512VL short run is cheaper than two scalar blocks, so any
    /// data is.
    #[inline]
    fn staged_head_min(self) -> usize {
        match self.0 {
            LaneSet::Avx2 | LaneSet::Avx512 => 64,
            LaneSet::Avx512Vl => 1,
        }
    }

    /// The AVX-512 kernel computes the extra block on the integer ports
    /// alongside the lane set ([`xor_chunk_avx512_with_block`]).
    #[inline]
    fn fuses_extra_block(self) -> bool {
        self.0.fuses_extra_block()
    }

    /// Out of line at opt-level `z`, which adds no copy: like
    /// [`xor_chunk`](super::Kernel::xor_chunk) it only forwards `&` to the
    /// cipher's own state and the caller's buffers (`extra` included).
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
                    super::salsa20_soft::block,
                );
            }
            // SAFETY: as for `xor_chunk`; `LaneSet::Avx512` and
            // `LaneSet::Avx512Vl` require `avx512f` and `avx2`.
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

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r` with the
/// rotation computed as two shifts and an OR.
macro_rules! step_avx2 {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        let sum = _mm256_add_epi32($x[$a], $x[$c]);
        $x[$b] = _mm256_xor_si256(
            $x[$b],
            _mm256_or_si256(
                _mm256_slli_epi32::<$r>(sum),
                _mm256_srli_epi32::<{ 32 - $r }>(sum),
            ),
        );
    };
}

/// XORs the keystream for blocks `counter .. counter + LANES` into
/// `output`, reading the plaintext/ciphertext from `input` (or from `output`
/// itself when `input` is `None`). `output` holds at most `LANES` whole
/// blocks; the following block's raw keystream goes to the zero-filled
/// `partial` when given, and the rest is discarded, so a short remainder
/// costs one kernel run rather than a run of dependent scalar blocks.
///
/// The lane set fills the 16 `ymm` registers, so the sum and rotation
/// temporaries spill; the four independent quarter rounds of each round
/// still keep the vector pipes busy. Kept out of line so its schedule does
/// not change with the inlining context.
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

    let initial = input_lanes!(state, counter, 8, 9);
    let mut x = initial;
    for _ in 0..10 {
        super::salsa20_double_round!(step_avx2, x);
    }
    finish_lanes!(x, &initial, &mut dest);
}

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r` on
/// `ymm` vectors with an AVX-512VL rotate.
macro_rules! step_avx512vl {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        $x[$b] = _mm256_xor_si256(
            $x[$b],
            _mm256_rol_epi32::<$r>(_mm256_add_epi32($x[$a], $x[$c])),
        );
    };
}

/// [`xor_chunk_avx2`] with AVX-512VL rotates: every rotation is one
/// `vprold` instead of two shifts and an OR, and the 32 EVEX `ymm`
/// registers hold the lane set without spills. 256-bit operations issue on
/// three ports where 512-bit ones use two, so for a run of at most eight
/// slots this finishes sooner than the 16-lane set.
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

    let initial = input_lanes!(state, counter, 8, 9);
    let mut x = initial;
    for _ in 0..10 {
        super::salsa20_double_round!(step_avx512vl, x);
    }
    finish_lanes!(x, &initial, &mut dest);
}

/// One Salsa20 quarter-round step `x[$b] ^= (x[$a] + x[$c]) <<< $r` with an
/// AVX-512 rotate.
macro_rules! step_avx512 {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        $x[$b] = _mm512_xor_si512(
            $x[$b],
            _mm512_rol_epi32::<$r>(_mm512_add_epi32($x[$a], $x[$c])),
        );
    };
}

/// XORs the keystream for blocks `counter .. counter + LANES512` into
/// `output`; see [`xor_chunk_avx2`] for the `output`/`partial` contract.
///
/// One 16-block lane set in 16 of the 32 `zmm` registers, so nothing spills,
/// and each quarter-round step is `add` + `vprold` + `xor`.
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

    let initial = input_lanes512!(state, counter, 8, 9);
    let mut x = initial;
    for _ in 0..10 {
        super::salsa20_double_round!(step_avx512, x);
    }
    finish_lanes512!(x, &initial, &mut dest);
}

/// One Salsa20 quarter round in the `asm!` template of
/// [`scalar_double_round`]: `$a`..`$d` are the four word operands (register
/// operands or the temporaries holding memory-resident words), each step
/// `x[b] ^= (x[a] + x[c]) <<< r` staged through `{t2}`.
macro_rules! scalar_quarter_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        concat!(
            "mov {t2:e}, ",
            $a,
            "\n",
            "add {t2:e}, ",
            $d,
            "\n",
            "rol {t2:e}, 7\n",
            "xor ",
            $b,
            ", {t2:e}\n",
            "mov {t2:e}, ",
            $b,
            "\n",
            "add {t2:e}, ",
            $a,
            "\n",
            "rol {t2:e}, 9\n",
            "xor ",
            $c,
            ", {t2:e}\n",
            "mov {t2:e}, ",
            $c,
            "\n",
            "add {t2:e}, ",
            $b,
            "\n",
            "rol {t2:e}, 13\n",
            "xor ",
            $d,
            ", {t2:e}\n",
            "mov {t2:e}, ",
            $d,
            "\n",
            "add {t2:e}, ",
            $c,
            "\n",
            "rol {t2:e}, 18\n",
            "xor ",
            $a,
            ", {t2:e}\n",
        )
    };
}

/// Loads the memory-resident word at byte offset `$off` of `{p}` into `$t`.
macro_rules! load_word {
    ($t:expr, $off:expr) => {
        concat!("mov ", $t, ", dword ptr [{p} + ", $off, "]\n")
    };
}

/// Stores `$t` back to the memory-resident word at byte offset `$off`.
macro_rules! store_word {
    ($t:expr, $off:expr) => {
        concat!("mov dword ptr [{p} + ", $off, "], ", $t, "\n")
    };
}

/// Word order of the scalar block state split for [`scalar_double_round`]:
/// these nine Salsa20 words live in registers ...
const REG_WORDS: [usize; 9] = [0, 1, 4, 5, 9, 10, 11, 14, 15];
/// ... and these seven in memory, at 4-byte offsets `0, 4, .., 24`. Every
/// quarter round of the double round touches at most two of them.
const MEM_WORDS: [usize; 7] = [2, 3, 6, 7, 8, 12, 13];

/// One scalar Salsa20 double round on general purpose registers: the words
/// [`REG_WORDS`] are register operands, the words [`MEM_WORDS`] live in
/// memory and are loaded into temporaries for the quarter rounds that use
/// them and stored back.
///
/// This exists for [`xor_chunk_avx512_with_block`]: written in Rust, the
/// four independent quarter rounds get SLP-vectorised into 128-bit code,
/// which competes with the 512-bit lane set for the same two vector ports;
/// the `add`/`xor`/`rol` here run on the integer ports the lane set leaves
/// idle. Only 13 general purpose registers are allocatable to `asm!` on
/// x86-64, so seven words go through memory (loads and stores use the memory
/// ports).
#[inline(always)]
fn scalar_double_round(regs: &mut [u32; 9], mem: &mut [u32; 7]) {
    // SAFETY: a `nostack` block whose only memory accesses are 4-byte loads
    // and stores at offsets 0..28 of `mem`, a valid `&mut [u32; 7]` for the
    // whole block (`p` = `mem.as_mut_ptr()`); every written register is a
    // declared `inout`/`out` operand, and the flags are clobbered as Rust
    // assumes by default. Base x86-64 instructions only.
    unsafe {
        asm!(
            // Column round: (0,4,8,12) (5,9,13,1) (10,14,2,6) (15,3,7,11).
            load_word!("{t0:e}", 16),
            load_word!("{t1:e}", 20),
            scalar_quarter_round!("{x0:e}", "{x4:e}", "{t0:e}", "{t1:e}"),
            store_word!("{t0:e}", 16),
            store_word!("{t1:e}", 20),
            load_word!("{t0:e}", 24),
            scalar_quarter_round!("{x5:e}", "{x9:e}", "{t0:e}", "{x1:e}"),
            store_word!("{t0:e}", 24),
            load_word!("{t0:e}", 0),
            load_word!("{t1:e}", 8),
            scalar_quarter_round!("{x10:e}", "{x14:e}", "{t0:e}", "{t1:e}"),
            store_word!("{t0:e}", 0),
            store_word!("{t1:e}", 8),
            load_word!("{t0:e}", 4),
            load_word!("{t1:e}", 12),
            scalar_quarter_round!("{x15:e}", "{t0:e}", "{t1:e}", "{x11:e}"),
            store_word!("{t0:e}", 4),
            store_word!("{t1:e}", 12),
            // Row round: (0,1,2,3) (5,6,7,4) (10,11,8,9) (15,12,13,14).
            load_word!("{t0:e}", 0),
            load_word!("{t1:e}", 4),
            scalar_quarter_round!("{x0:e}", "{x1:e}", "{t0:e}", "{t1:e}"),
            store_word!("{t0:e}", 0),
            store_word!("{t1:e}", 4),
            load_word!("{t0:e}", 8),
            load_word!("{t1:e}", 12),
            scalar_quarter_round!("{x5:e}", "{t0:e}", "{t1:e}", "{x4:e}"),
            store_word!("{t0:e}", 8),
            store_word!("{t1:e}", 12),
            load_word!("{t0:e}", 16),
            scalar_quarter_round!("{x10:e}", "{x11:e}", "{t0:e}", "{x9:e}"),
            store_word!("{t0:e}", 16),
            load_word!("{t0:e}", 20),
            load_word!("{t1:e}", 24),
            scalar_quarter_round!("{x15:e}", "{t0:e}", "{t1:e}", "{x14:e}"),
            store_word!("{t0:e}", 20),
            store_word!("{t1:e}", 24),
            x0 = inout(reg) regs[0],
            x1 = inout(reg) regs[1],
            x4 = inout(reg) regs[2],
            x5 = inout(reg) regs[3],
            x9 = inout(reg) regs[4],
            x10 = inout(reg) regs[5],
            x11 = inout(reg) regs[6],
            x14 = inout(reg) regs[7],
            x15 = inout(reg) regs[8],
            p = in(reg) mem.as_mut_ptr(),
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            options(nostack),
        );
    }
}

/// Splits a block state into the register and memory words of
/// [`scalar_double_round`]. Spelled out: `array::map` with a closure and
/// index loops are kept out of line at opt-level `z` and `s`, where they
/// would take the key-derived state words through memory.
#[inline(always)]
fn split_words(x: &[u32; 16]) -> ([u32; 9], [u32; 7]) {
    const _: () = assert!(
        matches!(REG_WORDS, [0, 1, 4, 5, 9, 10, 11, 14, 15])
            && matches!(MEM_WORDS, [2, 3, 6, 7, 8, 12, 13])
    );
    (
        [x[0], x[1], x[4], x[5], x[9], x[10], x[11], x[14], x[15]],
        [x[2], x[3], x[6], x[7], x[8], x[12], x[13]],
    )
}

/// Inverse of [`split_words`], spelled out for the same reason.
#[inline(always)]
fn join_words(regs: &[u32; 9], mem: &[u32; 7]) -> [u32; 16] {
    let [r0, r1, r4, r5, r9, r10, r11, r14, r15] = *regs;
    let [m2, m3, m6, m7, m8, m12, m13] = *mem;
    [
        r0, r1, m2, m3, r4, r5, m6, m7, m8, r9, r10, r11, m12, m13, r14, r15,
    ]
}

/// [`xor_chunk_avx512`] plus one unrelated block: the sixteen lanes and,
/// interleaved double round by double round, the scalar block
/// `extra_counter` on the integer ports ([`scalar_double_round`]), whose raw
/// keystream is XORed into the zero-filled `extra`. The lane set keeps both
/// 512-bit ports busy for about 480 cycles while the scalar block's
/// dependency chain is shorter, so the extra block adds a fraction of a
/// dependent scalar block. The extra block is the MAC key block ahead of a
/// secretbox message.
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

    let initial = input_lanes512!(state, counter, 8, 9);
    let mut x = initial;
    let scalar_initial = super::salsa20_soft::block_input(state, extra_counter);
    let (mut regs, mut mem) = split_words(&scalar_initial);
    for _ in 0..10 {
        super::salsa20_double_round!(step_avx512, x);
        scalar_double_round(&mut regs, &mut mem);
    }
    finish_lanes512!(x, &initial, &mut dest);
    let s = join_words(&regs, &mem);
    xor_scalar_words(&s, &scalar_initial, extra);
    mem.zeroize();
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
        let mut rng = crate::utils::test_util::XorShift64::new(0x5a15_a20d_00b1_e000);
        for _ in 0..500 {
            let mut x = [0u32; 16];
            for word in &mut x {
                *word = rng.next_u64() as u32;
            }
            let mut expected = x;
            super::super::salsa20_soft::double_round(&mut expected);
            let (mut regs, mut mem) = split_words(&x);
            scalar_double_round(&mut regs, &mut mem);
            assert_eq!(join_words(&regs, &mem), expected);
        }
    }

    /// The fused AVX-512 run equals the AVX-512 run for its lanes (whole
    /// blocks and partial slot) plus the scalar block for the unrelated
    /// extra counter, in place and buffer to buffer, for full and short lane
    /// sets and extra blocks before and after them.
    #[test]
    fn test_avx512_with_block_matches_run_and_scalar_block() {
        if !crate::x86_64::has_avx512f() {
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
                    // SAFETY: `avx512f` and `avx2` were detected above.
                    unsafe {
                        xor_chunk_avx512(
                            &state,
                            counter,
                            None,
                            &mut expected,
                            has_partial.then_some(&mut expected_partial),
                        )
                    };
                    super::super::salsa20_soft::block(&state, extra_counter, &mut expected_extra);

                    let mut in_place = plaintext[..len].to_vec();
                    let mut partial = [0u8; 64];
                    let mut extra = [0u8; 64];
                    // SAFETY: `avx512f` and `avx2` were detected above.
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
                    // SAFETY: `avx512f` and `avx2` were detected above.
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
