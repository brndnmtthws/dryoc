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
pub(crate) fn block(input: &[u32; 16], counter: u64, out: &mut [u8; 64]) {
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

#[cfg(test)]
mod tests {
    use salsa20::Salsa20;
    use salsa20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

    use super::block;
    use crate::utils::{SIGMA, load_u32_le};

    /// The Salsa20 input words for `key` and `nonce` with a zero counter.
    fn input(key: &[u8; 32], nonce: &[u8; 8]) -> [u32; 16] {
        let word = |bytes: &[u8]| load_u32_le(bytes);
        [
            SIGMA[0],
            word(&key[0..4]),
            word(&key[4..8]),
            word(&key[8..12]),
            word(&key[12..16]),
            SIGMA[1],
            word(&nonce[0..4]),
            word(&nonce[4..8]),
            0,
            0,
            SIGMA[2],
            word(&key[16..20]),
            word(&key[20..24]),
            word(&key[24..28]),
            word(&key[28..32]),
            SIGMA[3],
        ]
    }

    /// The raw keystream block `counter` from RustCrypto's Salsa20/20.
    fn rustcrypto_block(key: &[u8; 32], nonce: &[u8; 8], counter: u64) -> [u8; 64] {
        let mut cipher = Salsa20::new(key.into(), nonce.into());
        cipher.try_seek(u128::from(counter) * 64).unwrap();
        let mut block = [0u8; 64];
        cipher.apply_keystream(&mut block);
        block
    }

    /// ECRYPT Salsa20/20 (256-bit key) set 1, vector 0: key `80 00 .. 00`,
    /// zero IV, the first keystream block.
    #[test]
    fn ecrypt_set1_vector0_block() {
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let expected = hex::decode(concat!(
            "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844",
            "b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117",
        ))
        .unwrap();
        let mut out = [0u8; 64];
        block(&input(&key, &[0u8; 8]), 0, &mut out);
        assert_eq!(out.to_vec(), expected);
    }

    /// Blocks at 0 and 1, either side of the 32-bit carry into word 9, and
    /// the highest block RustCrypto's Salsa20 will produce, against it.
    #[test]
    fn blocks_match_rustcrypto_across_counter_words() {
        let key: [u8; 32] = std::array::from_fn(|i| (i * 7 + 1) as u8);
        let nonce: [u8; 8] = std::array::from_fn(|i| (i * 5 + 3) as u8);
        let input = input(&key, &nonce);
        for counter in [
            0u64,
            1,
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX - 1,
        ] {
            let mut out = [0u8; 64];
            block(&input, counter, &mut out);
            assert_eq!(
                out,
                rustcrypto_block(&key, &nonce, counter),
                "block {counter}"
            );
        }
    }

    /// The last two blocks of the keystream, `u64::MAX - 1` and `u64::MAX`,
    /// against libsodium's `crypto_stream_salsa20_xor_ic`.
    #[cfg(dryoc_native_tests)]
    #[test]
    fn last_blocks_match_libsodium() {
        crate::native_test_util::init();
        let key: [u8; 32] = std::array::from_fn(|i| (i * 7 + 1) as u8);
        let nonce: [u8; 8] = std::array::from_fn(|i| (i * 5 + 3) as u8);
        let mut expected = [0u8; 128];
        // SAFETY: `expected` is valid for its length as both input and
        // output (libsodium permits `c == m`); `nonce` and `key` are
        // exact-size arrays.
        let rc = unsafe {
            libsodium_sys::crypto_stream_salsa20_xor_ic(
                expected.as_mut_ptr(),
                expected.as_ptr(),
                expected.len() as libc::c_ulonglong,
                nonce.as_ptr(),
                u64::MAX - 1,
                key.as_ptr(),
            )
        };
        assert_eq!(rc, 0);

        let input = input(&key, &nonce);
        let mut out = [0u8; 64];
        block(&input, u64::MAX - 1, &mut out);
        assert_eq!(out, expected[..64], "block u64::MAX - 1");
        block(&input, u64::MAX, &mut out);
        assert_eq!(out, expected[64..], "block u64::MAX");
    }
}
