//! Scalar ChaCha20 block function.
//!
//! The rounds are spelled out with macros so every state index is a
//! compile-time constant and the 16 words stay in registers. On AArch64 the
//! rounds come from the `asm!` block in `chacha20_aarch64`.

use zeroize::Zeroize;

/// One ChaCha20 quarter round over the four words `$a, $b, $c, $d` of `$x`.
#[cfg(any(not(target_arch = "aarch64"), test))]
macro_rules! quarter_round {
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

/// One ChaCha20 double round (a column round followed by a diagonal round).
#[cfg(any(not(target_arch = "aarch64"), test))]
#[inline(always)]
pub(super) fn double_round(x: &mut [u32; 16]) {
    super::chacha20_double_round!(quarter_round, x);
}

/// Applies the 20 ChaCha rounds (10 double rounds) to `x` in place, without
/// the final feed-forward addition.
#[inline]
pub(crate) fn rounds(x: &mut [u32; 16]) {
    #[cfg(target_arch = "aarch64")]
    super::chacha20_aarch64::rounds(x);
    #[cfg(not(target_arch = "aarch64"))]
    for _ in 0..10 {
        double_round(x);
    }
}

/// The ChaCha20 input for block `counter`: `state` with words 12 and 13
/// replaced by the little-endian halves of the counter.
#[inline(always)]
pub(super) fn block_input(state: &[u32; 16], counter: u64) -> [u32; 16] {
    let mut x = *state;
    x[12] = counter as u32;
    x[13] = (counter >> 32) as u32;
    x
}

/// Computes the ChaCha20 keystream block for `state` with words 12 and 13
/// replaced by the little-endian halves of `counter`, serialising the result
/// into `out`. The key-bearing working copies are zeroized before returning.
pub(super) fn block(state: &[u32; 16], counter: u64, out: &mut [u8; 64]) {
    let mut initial = block_input(state, counter);
    let mut x = initial;
    rounds(&mut x);
    for ((chunk, word), init) in out.as_chunks_mut::<4>().0.iter_mut().zip(x).zip(initial) {
        *chunk = word.wrapping_add(init).to_le_bytes();
    }
    x.zeroize();
    initial.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The register-scheduled rounds agree with the portable double rounds.
    #[test]
    fn test_rounds_match_portable() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200 {
            let mut x = [0u32; 16];
            for word in &mut x {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *word = (seed >> 32) as u32;
            }
            let mut expected = x;
            for _ in 0..10 {
                double_round(&mut expected);
            }
            rounds(&mut x);
            assert_eq!(x, expected);
        }
    }
}
