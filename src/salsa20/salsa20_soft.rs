//! Portable scalar Salsa20/20 block function.
//!
//! The double round is spelled out with macros so every state index is a
//! compile-time constant and the 16 words stay in registers; on AArch64 each
//! quarter-round step compiles to `add` + `eor` with a rotated operand.

use zeroize::Zeroize;

/// One Salsa20 quarter-round step: `x[$b] ^= (x[$a] + x[$c]) <<< $r`.
macro_rules! step {
    ($x:ident, $b:literal ^= $a:literal + $c:literal << < $r:literal) => {
        $x[$b] ^= $x[$a].wrapping_add($x[$c]).rotate_left($r);
    };
}

/// One Salsa20 double round (a column round followed by a row round).
#[inline(always)]
pub(super) fn double_round(x: &mut [u32; 16]) {
    super::salsa20_double_round!(step, x);
}

/// The Salsa20 input for block `counter`: `input` with words 8 and 9 replaced
/// by the little-endian halves of the counter.
#[inline(always)]
pub(super) fn block_input(input: &[u32; 16], counter: u64) -> [u32; 16] {
    let mut x = *input;
    x[8] = counter as u32;
    x[9] = (counter >> 32) as u32;
    x
}

/// Computes the Salsa20/20 keystream block for `input` with words 8 and 9
/// replaced by the little-endian halves of `counter`, serialising the result
/// into `out`. The key-bearing working copies are zeroized before returning.
pub(super) fn block(input: &[u32; 16], counter: u64, out: &mut [u8; 64]) {
    let mut initial = block_input(input, counter);
    let mut x = initial;
    for _ in 0..10 {
        double_round(&mut x);
    }
    for ((chunk, word), init) in out.as_chunks_mut::<4>().0.iter_mut().zip(x).zip(initial) {
        *chunk = word.wrapping_add(init).to_le_bytes();
    }
    x.zeroize();
    initial.zeroize();
}
