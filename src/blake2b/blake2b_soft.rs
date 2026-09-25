use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    BLOCKBYTES, IV, KEYBYTES, OUTBYTES, PERSONALBYTES, Params, SALTBYTES, blake2b_longhash,
    increment_counter,
};
use crate::error::Error;
use crate::utils::{load_u64_le, zeroize_bytes};

#[derive(Debug)]
pub struct State {
    h: [u64; 8],
    t: [u64; 2],
    f: [u64; 2],
    last_node: u8,
    buf: [u8; BLOCKBYTES],
    buflen: usize,
}

impl Zeroize for State {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.t.zeroize();
        self.f.zeroize();
        self.last_node.zeroize();
        zeroize_bytes(&mut self.buf);
        self.buflen.zeroize();
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for State {}

impl Default for State {
    fn default() -> Self {
        Self {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            last_node: 0,
            buf: [0u8; BLOCKBYTES],
            buflen: 0,
        }
    }
}

/// One BLAKE2b `G` mixing step on four state words with two message words.
#[cfg(any(
    not(all(target_arch = "aarch64", target_endian = "little")),
    miri,
    test
))]
macro_rules! g {
    ($v:ident, $a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $y:expr) => {
        $v[$a] = $v[$a].wrapping_add($v[$b]).wrapping_add($x);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(32);
        $v[$c] = $v[$c].wrapping_add($v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(24);
        $v[$a] = $v[$a].wrapping_add($v[$b]).wrapping_add($y);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(16);
        $v[$c] = $v[$c].wrapping_add($v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(63);
    };
}

/// One full BLAKE2b round; `$s*` are the SIGMA permutation entries for the
/// round, spelled out as literals so every index is a compile-time constant.
#[cfg(any(
    not(all(target_arch = "aarch64", target_endian = "little")),
    miri,
    test
))]
macro_rules! round {
    (
        $v:ident,
        $m:ident,
        $s0:literal,
        $s1:literal,
        $s2:literal,
        $s3:literal,
        $s4:literal,
        $s5:literal,
        $s6:literal,
        $s7:literal,
        $s8:literal,
        $s9:literal,
        $s10:literal,
        $s11:literal,
        $s12:literal,
        $s13:literal,
        $s14:literal,
        $s15:literal
    ) => {
        g!($v, 0, 4, 8, 12, $m[$s0], $m[$s1]);
        g!($v, 1, 5, 9, 13, $m[$s2], $m[$s3]);
        g!($v, 2, 6, 10, 14, $m[$s4], $m[$s5]);
        g!($v, 3, 7, 11, 15, $m[$s6], $m[$s7]);
        g!($v, 0, 5, 10, 15, $m[$s8], $m[$s9]);
        g!($v, 1, 6, 11, 12, $m[$s10], $m[$s11]);
        g!($v, 2, 7, 8, 13, $m[$s12], $m[$s13]);
        g!($v, 3, 4, 9, 14, $m[$s14], $m[$s15]);
    };
}

/// The twelve BLAKE2b rounds over the working state `v` with the message
/// words of `block`.
#[inline]
fn rounds(v: &mut [u64; 16], block: &[u8; BLOCKBYTES]) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    super::blake2b_aarch64::rounds(v, block);
    #[cfg(any(not(all(target_arch = "aarch64", target_endian = "little")), miri))]
    rounds_portable(v, block);
}

#[cfg(any(
    not(all(target_arch = "aarch64", target_endian = "little")),
    miri,
    test
))]
fn rounds_portable(v: &mut [u64; 16], block: &[u8; BLOCKBYTES]) {
    let mut m = [0u64; 16];
    for (word, chunk) in m.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    round!(v, m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    round!(v, m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    round!(v, m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    round!(v, m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    round!(v, m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    round!(v, m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    round!(v, m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    round!(v, m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    round!(v, m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    round!(v, m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    round!(v, m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    round!(v, m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
}

/// Compresses `block` into `sh`, through the runtime-detected x86-64 kernel
/// when there is one, else the portable rounds.
#[inline]
fn compress(sh: &mut [u64; 8], st: &[u64; 2], sf: &[u64; 2], block: &[u8; BLOCKBYTES]) {
    #[cfg(target_arch = "x86_64")]
    if let Some(kernel) = super::blake2b_x86_64::detect() {
        kernel.compress(sh, st, sf, block);
        return;
    }
    compress_portable(sh, st, sf, block);
}

/// One BLAKE2b compression without the x86-64 kernels.
///
/// The working state `v` and the message words only flow through inlined
/// rounds, so they live in registers and compiler spill slots, which are
/// out of Rust's reach and are not wiped.
#[inline]
fn compress_portable(sh: &mut [u64; 8], st: &[u64; 2], sf: &[u64; 2], block: &[u8; BLOCKBYTES]) {
    let mut v = [
        sh[0],
        sh[1],
        sh[2],
        sh[3],
        sh[4],
        sh[5],
        sh[6],
        sh[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        st[0] ^ IV[4],
        st[1] ^ IV[5],
        sf[0] ^ IV[6],
        sf[1] ^ IV[7],
    ];

    rounds(&mut v, block);

    for i in 0..8 {
        sh[i] ^= v[i] ^ v[i + 8];
    }
}

impl State {
    fn init_param(params: &Params) -> Self {
        let mut state = Self::default();
        state.init0();

        let pslice = params.as_bytes();

        for i in 0..8 {
            state.h[i] ^= load_u64_le(&pslice[(8 * i)..(8 * i + 8)]);
        }

        state
    }

    fn init0(&mut self) {
        self.h[..8].copy_from_slice(&IV);
    }

    pub(crate) fn init(
        outlen: u8,
        key: Option<&[u8]>,
        salt: Option<&[u8; SALTBYTES]>,
        personal: Option<&[u8; PERSONALBYTES]>,
    ) -> Result<State, Error> {
        let params = Params::new(outlen, key, salt, personal)?;
        let mut state = Self::init_param(&params);

        if let Some(key) = key {
            // The zero-padded key block, buffered as `update` would buffer a
            // first full block (kept for `finalize` in case it is the last).
            state.buf[..key.len()].copy_from_slice(key);
            state.buflen = BLOCKBYTES;
        }

        // `state` holds the key block in memory (the copy above goes through
        // `memcpy`): move it out and let the local drop (wipe).
        Ok(core::mem::take(&mut state))
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }

        // Fill a partially-filled buffer first. The buffer is only compressed
        // once more input follows it, so a message that ends exactly on a
        // block boundary keeps its final block for `finalize`.
        if self.buflen > 0 {
            let take = BLOCKBYTES - self.buflen;
            if input.len() <= take {
                self.buf[self.buflen..self.buflen + input.len()].copy_from_slice(input);
                self.buflen += input.len();
                return;
            }
            self.buf[self.buflen..].copy_from_slice(&input[..take]);
            input = &input[take..];
            increment_counter(&mut self.t, BLOCKBYTES);
            compress(&mut self.h, &self.t, &self.f, &self.buf);
            self.buflen = 0;
        }

        // Compress every full block except the last one, which may be final.
        while input.len() > BLOCKBYTES {
            let (block, rest) = input.split_first_chunk::<BLOCKBYTES>().unwrap();
            increment_counter(&mut self.t, BLOCKBYTES);
            compress(&mut self.h, &self.t, &self.f, block);
            input = rest;
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buflen = input.len();
    }

    pub(crate) fn finalize(mut self, output: &mut [u8]) -> Result<(), Error> {
        self.finalize_in_place(output)
        // `self` is dropped here, which wipes the whole state.
    }

    /// [`State::finalize`] without consuming `self`, for callers that keep
    /// the state where it is (moving it out leaves unwiped copies) and let it
    /// drop there.
    pub(crate) fn finalize_in_place(&mut self, output: &mut [u8]) -> Result<(), Error> {
        validate_length!(
            1,
            OUTBYTES,
            output.len(),
            crate::ErrorContext::Blake2bOutput
        );

        if self.is_lastblock() {
            return Err(Error::invalid_state(crate::ErrorContext::Blake2b));
        }

        increment_counter(&mut self.t, self.buflen);
        self.set_lastblock();
        self.buf[self.buflen..].fill(0);
        compress(&mut self.h, &self.t, &self.f, &self.buf);

        let mut buffer = [0u8; OUTBYTES];
        buffer[0..8].copy_from_slice(&self.h[0].to_le_bytes());
        buffer[8..16].copy_from_slice(&self.h[1].to_le_bytes());
        buffer[16..24].copy_from_slice(&self.h[2].to_le_bytes());
        buffer[24..32].copy_from_slice(&self.h[3].to_le_bytes());
        buffer[32..40].copy_from_slice(&self.h[4].to_le_bytes());
        buffer[40..48].copy_from_slice(&self.h[5].to_le_bytes());
        buffer[48..56].copy_from_slice(&self.h[6].to_le_bytes());
        buffer[56..64].copy_from_slice(&self.h[7].to_le_bytes());
        output.copy_from_slice(&buffer[..output.len()]);
        zeroize_bytes(&mut buffer);

        Ok(())
    }

    /// Presets the byte counter so a short message drives its low word
    /// across `u64::MAX` (see
    /// `native_tests::test_counter_carry_matches_libsodium`).
    #[cfg(all(test, dryoc_native_tests))]
    pub(crate) fn set_counter(&mut self, t: [u64; 2]) {
        self.t = t;
    }

    fn set_lastnode(&mut self) {
        self.f[1] = -1i64 as u64;
    }

    fn is_lastblock(&self) -> bool {
        self.f[0] != 0
    }

    fn set_lastblock(&mut self) {
        if self.last_node != 0 {
            self.set_lastnode();
        }
        self.f[0] = -1i64 as u64;
    }
}

/// Hashes a message that fits one block in a single compression, without
/// building, buffering through and wiping a `State`.
///
/// `h` is the parameter-block-adjusted IV, `block` the zero-padded final
/// block and `counter` the byte count it stands for (`BLOCKBYTES` for a key
/// block, the message length otherwise). `output` must hold `1..=OUTBYTES`.
fn hash_single_block(
    output: &mut [u8],
    mut h: [u64; 8],
    block: &mut [u8; BLOCKBYTES],
    counter: u64,
) {
    debug_assert!(!output.is_empty() && output.len() <= OUTBYTES);
    let t = [counter, 0];
    let f = [u64::MAX, 0];
    compress(&mut h, &t, &f, block);

    let mut buffer = [0u8; OUTBYTES];
    for (chunk, word) in buffer.as_chunks_mut::<8>().0.iter_mut().zip(&h) {
        *chunk = word.to_le_bytes();
    }
    output.copy_from_slice(&buffer[..output.len()]);
    zeroize_bytes(&mut buffer);
    zeroize_bytes(block);
    h.zeroize();
}

pub fn hash(output: &mut [u8], input: &[u8], key: Option<&[u8]>) -> Result<(), Error> {
    validate_length!(max OUTBYTES, output.len(), crate::ErrorContext::Blake2bOutput);

    if key.is_none() && !output.is_empty() && input.len() <= BLOCKBYTES {
        // Unkeyed message of at most one block. The parameter block is
        // `digest_length | fanout << 16 | depth << 24` in the first word and
        // zero elsewhere (no key, salt or personalization).
        let mut h = IV;
        h[0] ^= (output.len() as u64) | (1 << 16) | (1 << 24);
        let mut block = [0u8; BLOCKBYTES];
        block[..input.len()].copy_from_slice(input);
        hash_single_block(output, h, &mut block, input.len() as u64);
        return Ok(());
    }

    // Work on the state inside `init`'s result: `?` would move it out, and
    // `finalize` by value would move it again, each leaving an unwiped copy
    // of the key block or keyed chaining value. The `Result` drops (wipes)
    // the one copy here.
    let mut state = State::init(output.len() as u8, key, None, None);
    let Ok(inner) = &mut state else {
        return state.map(|_| ());
    };
    inner.update(input);
    inner.finalize_in_place(output)
}

/// Keyed BLAKE2b of the empty message with `salt` and `personal` (the
/// `crypto_kdf` construction): the padded key block is the only block, so this
/// is one compression.
pub(crate) fn hash_key_only(
    output: &mut [u8],
    key: &[u8],
    salt: &[u8; SALTBYTES],
    personal: &[u8; PERSONALBYTES],
) -> Result<(), Error> {
    validate_length!(
        1,
        OUTBYTES,
        output.len(),
        crate::ErrorContext::Blake2bOutput
    );
    validate_length!(1, KEYBYTES, key.len(), crate::ErrorContext::Blake2bKey);
    // Parameter block words: digest_length | key_length << 8 | fanout << 16 |
    // depth << 24, then leaf_length/node_offset/node_depth/inner_length/
    // reserved (all zero), then salt (words 4, 5) and personal (words 6, 7).
    let mut h = IV;
    h[0] ^= (output.len() as u64) | ((key.len() as u64) << 8) | (1 << 16) | (1 << 24);
    h[4] ^= load_u64_le(&salt[..8]);
    h[5] ^= load_u64_le(&salt[8..]);
    h[6] ^= load_u64_le(&personal[..8]);
    h[7] ^= load_u64_le(&personal[8..]);
    let mut block = [0u8; BLOCKBYTES];
    block[..key.len()].copy_from_slice(key);
    hash_single_block(output, h, &mut block, BLOCKBYTES as u64);
    Ok(())
}

blake2b_longhash!();

#[cfg(test)]
mod tests {
    use crate::test_prelude::*;

    #[cfg(feature = "nightly")]
    extern crate test;
    use std::sync::LazyLock;

    use serde::{Deserialize, Serialize};

    use super::*;

    /// The register-scheduled AArch64 rounds agree with the portable rounds
    /// on random states and blocks.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    #[test]
    fn test_rounds_match_portable() {
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        };
        for _ in 0..200 {
            let mut v = [0u64; 16];
            for word in &mut v {
                *word = next();
            }
            let mut block = [0u8; BLOCKBYTES];
            for chunk in block.as_chunks_mut::<8>().0 {
                *chunk = next().to_le_bytes();
            }
            let mut expected = v;
            rounds_portable(&mut expected, &block);
            rounds(&mut v, &block);
            assert_eq!(v, expected);
        }
    }

    /// Every supported x86-64 kernel agrees with the portable compression
    /// on random chaining states, counters, flags and blocks.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_x86_64_compress_matches_portable() {
        let mut seed = 0x1319_8a2e_0370_7344u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        };
        for kernel in super::super::blake2b_x86_64::Kernel::all() {
            for _ in 0..200 {
                let h: [u64; 8] = core::array::from_fn(|_| next());
                let t = [next(), next()];
                let f = [next(), next()];
                let mut block = [0u8; BLOCKBYTES];
                for chunk in block.as_chunks_mut::<8>().0 {
                    *chunk = next().to_le_bytes();
                }
                let mut expected = h;
                compress_portable(&mut expected, &t, &f, &block);
                let mut actual = h;
                kernel.compress(&mut actual, &t, &f, &block);
                assert_eq!(actual, expected, "{kernel:?}");
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestVector {
        hash: String,
        #[serde(rename = "in")]
        in_: String,
        key: String,
        out: String,
    }

    static TEST_VECTORS: LazyLock<Vec<TestVector>> = LazyLock::new(|| {
        serde_json::from_str(include_str!("test-vectors/blake2b-test-vectors.json")).unwrap()
    });

    #[test]
    fn test_vectors() {
        for vector in TEST_VECTORS.iter() {
            let key = if vector.key.is_empty() {
                None
            } else {
                Some(hex::decode(&vector.key).unwrap())
            };
            let mut state = State::init(64, key.as_deref(), None, None).expect("init");
            state.update(hex::decode(&vector.in_).unwrap().as_slice());
            let mut output = [0u8; 64];

            state.finalize(&mut output).ok();

            assert_eq!(vector.out, hex::encode(output));
        }
    }

    /// The one-shot `hash` (single-block fast path for unkeyed messages of at
    /// most one block, buffered `State` otherwise) matches the official
    /// vectors and the `State` path for every output length and every
    /// message length around the block boundary.
    #[test]
    fn test_hash_one_shot_matches_state_path() {
        for vector in TEST_VECTORS.iter().filter(|v| v.key.is_empty()) {
            let input = hex::decode(&vector.in_).unwrap();
            let mut output = [0u8; 64];
            hash(&mut output, &input, None).expect("hash");
            assert_eq!(
                vector.out,
                hex::encode(output),
                "vector len {}",
                input.len()
            );
        }
        let input: Vec<u8> = (0..=255u8)
            .map(|b| b.wrapping_mul(37).wrapping_add(11))
            .collect();
        for len in [0usize, 1, 63, 64, 127, 128, 129, 200, 255, 256] {
            for outlen in [1usize, 16, 31, 32, 33, 48, 63, 64] {
                let mut fast = vec![0u8; outlen];
                hash(&mut fast, &input[..len], None).expect("hash");
                let mut state = State::init(outlen as u8, None, None, None).expect("init");
                state.update(&input[..len]);
                let mut slow = vec![0u8; outlen];
                state.finalize(&mut slow).expect("finalize");
                assert_eq!(fast, slow, "len {len} outlen {outlen}");
            }
        }
        // Output length errors are unchanged.
        assert!(hash(&mut [], b"x", None).is_err());
        assert!(hash(&mut [0u8; 65], b"x", None).is_err());

        // Keyed empty-message hash with salt and personalization (the KDF
        // construction) against the `State` path for every key length.
        let salt: [u8; SALTBYTES] = input[..SALTBYTES].try_into().unwrap();
        let personal: [u8; PERSONALBYTES] = input[16..32].try_into().unwrap();
        for keylen in 1..=KEYBYTES {
            for outlen in [1usize, 16, 32, 64] {
                let key = &input[..keylen];
                let mut fast = vec![0u8; outlen];
                hash_key_only(&mut fast, key, &salt, &personal).expect("keyed");
                let state = State::init(outlen as u8, Some(key), Some(&salt), Some(&personal))
                    .expect("init");
                let mut slow = vec![0u8; outlen];
                state.finalize(&mut slow).expect("finalize");
                assert_eq!(fast, slow, "keylen {keylen} outlen {outlen}");
            }
        }
        assert!(hash_key_only(&mut [0u8; 32], &[], &salt, &personal).is_err());
        assert!(hash_key_only(&mut [0u8; 32], &[0u8; 65], &salt, &personal).is_err());
        assert!(hash_key_only(&mut [], &input[..32], &salt, &personal).is_err());
    }

    #[test]
    fn rejects_key_lengths_that_do_not_fit_in_u8() {
        let key = [0u8; 256];
        let error = State::init(64, Some(&key), None, None).expect_err("key should be rejected");

        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::Blake2bKey,
                actual: 256,
                constraint: crate::LengthConstraint::AtMost(KEYBYTES),
            }
        ));
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn blake2b_bench(b: &mut test::Bencher) {
        use crate::rng::copy_randombytes;
        let mut input = vec![0u8; 694200];
        copy_randombytes(&mut input);

        b.iter(|| {
            let mut state = State::init(64, None, None, None).expect("init");
            state.update(test::black_box(&input));

            let mut output = [0u8; 64];
            state.finalize(&mut output).expect("finalize");
            test::black_box(&output);
        });
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use libc::*;

        use super::*;

        #[repr(C)]
        #[derive(Debug)]
        struct B2state {
            h: [u64; 8],
            t: [u64; 2],
            f: [u64; 2],
            buf: [c_uchar; 256],
            buflen: size_t,
            last_node: u8,
        }

        unsafe extern "C" {
            fn blake2b_init(S: *mut B2state, outlen: c_uchar);
            fn blake2b_init_key(S: *mut B2state, outlen: c_uchar, key: *const u8, keylen: c_uchar);
            fn blake2b_update(S: *mut B2state, input: *const u8, inlen: u64);
            fn blake2b_final(S: *mut B2state, output: *mut u8, outlen: u64);
            #[cfg(feature = "alloc")]
            fn blake2b_long(pout: *mut u8, outlen: u64, input: *const u8, inlen: u64);
        }

        #[test]
        fn test_b2() {
            crate::native_test_util::init();
            use crate::rng::copy_randombytes;

            let mut s = B2state {
                h: [0u64; 8],
                t: [0u64; 2],
                f: [0u64; 2],
                buf: [0u8; 256],
                buflen: 0,
                last_node: 0,
            };

            for i in 0..512 {
                unsafe { blake2b_init(&mut s, 64) };

                let mut state = State::init(64, None, None, None).expect("init");

                let mut block = vec![0u8; i];
                copy_randombytes(&mut block);

                unsafe { blake2b_update(&mut s, block.as_ptr(), block.len() as u64) };

                state.update(&block);

                unsafe { blake2b_update(&mut s, block.as_ptr(), block.len() as u64) };

                state.update(&block);

                let mut output = [0u8; 64];
                let mut so_output = [0u8; 64];

                unsafe { blake2b_final(&mut s, so_output.as_mut_ptr(), so_output.len() as u64) };

                state.finalize(&mut output).ok();

                assert_eq!(output, so_output);
            }
        }

        #[test]
        fn test_b2_key() {
            crate::native_test_util::init();
            use crate::rng::copy_randombytes;

            let mut s = B2state {
                h: [0u64; 8],
                t: [0u64; 2],
                f: [0u64; 2],
                buf: [0u8; 256],
                buflen: 0,
                last_node: 0,
            };

            let mut key = [0u8; 32];
            copy_randombytes(&mut key);
            let mut block = [0u8; 256];
            copy_randombytes(&mut block);

            unsafe { blake2b_init_key(&mut s, 64, &key as *const u8, key.len() as u8) };

            let mut state = State::init(64, Some(&key), None, None).expect("init");

            unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

            state.update(&block);

            unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

            state.update(&block);

            let mut output = [0u8; 64];
            let mut so_output = [0u8; 64];

            unsafe { blake2b_final(&mut s, so_output.as_mut_ptr(), so_output.len() as u64) };

            state.finalize(&mut output).ok();

            assert_eq!(output, so_output);
        }

        #[test]
        #[cfg(feature = "alloc")]
        fn test_blake2b_long() {
            crate::native_test_util::init();
            use crate::rng::copy_randombytes;

            for i in 5..320 {
                let mut input = vec![0u8; i - 5_usize];
                let mut output = vec![0u8; i];
                let mut so_output = output.clone();
                copy_randombytes(&mut input);

                longhash(&mut output, &input).expect("longhash failed");

                unsafe {
                    blake2b_long(
                        so_output.as_mut_ptr(),
                        so_output.len() as u64,
                        input.as_ptr(),
                        input.len() as u64,
                    )
                };

                assert_eq!(output, so_output);
            }
        }

        #[test]
        #[cfg(feature = "alloc")]
        fn test_blake2b_long_rand_length() {
            crate::native_test_util::init();
            use crate::rng::copy_randombytes;

            let random_u32 = || {
                let mut bytes = [0u8; 4];
                copy_randombytes(&mut bytes);
                u32::from_le_bytes(bytes)
            };

            for _ in 0..25 {
                let mut input = vec![0u8; (random_u32() % 1000) as usize];
                let mut output = vec![0u8; (random_u32() % 1000 + 64) as usize];
                let mut so_output = output.clone();
                copy_randombytes(&mut input);

                longhash(&mut output, &input).expect("longhash failed");

                unsafe {
                    blake2b_long(
                        so_output.as_mut_ptr(),
                        so_output.len() as u64,
                        input.as_ptr(),
                        input.len() as u64,
                    )
                };

                assert_eq!(output, so_output);
            }
        }

        /// With the byte counter preset just below `u64::MAX` on both sides,
        /// the blocks that follow carry into the high counter word, which
        /// the compression mixes in (`v[13] ^= t[1]`): a backend that
        /// dropped or mis-carried the high word diverges from libsodium
        /// here and nowhere in the ordinary vectors.
        #[test]
        fn test_counter_carry_matches_libsodium() {
            crate::native_test_util::init();
            let message: Vec<u8> = (0..3 * BLOCKBYTES as u32)
                .map(|i| (i * 31 % 251) as u8)
                .collect();
            for len in [
                BLOCKBYTES + 1,
                2 * BLOCKBYTES,
                2 * BLOCKBYTES + 1,
                3 * BLOCKBYTES,
            ] {
                for t in [[u64::MAX - 64, 0], [u64::MAX - BLOCKBYTES as u64, 0xdead]] {
                    let mut s = B2state {
                        h: [0u64; 8],
                        t: [0u64; 2],
                        f: [0u64; 2],
                        buf: [0u8; 256],
                        buflen: 0,
                        last_node: 0,
                    };
                    unsafe { blake2b_init(&mut s, 64) };
                    s.t = t;
                    unsafe { blake2b_update(&mut s, message.as_ptr(), len as u64) };
                    let mut so_output = [0u8; 64];
                    unsafe { blake2b_final(&mut s, so_output.as_mut_ptr(), 64) };

                    let mut state = State::init(64, None, None, None).expect("init");
                    state.set_counter(t);
                    state.update(&message[..len]);
                    let mut output = [0u8; 64];
                    state.finalize(&mut output).expect("finalize");

                    assert_eq!(output, so_output, "len {len}, t {t:x?}");
                }
            }
        }

        /// libsodium's `crypto_generichash_blake2b` on the same 694,200-byte
        /// input as `blake2b_bench`, so the two rows are directly comparable.
        #[cfg(feature = "nightly")]
        #[bench]
        fn libsodium_blake2b_bench(b: &mut test::Bencher) {
            use crate::rng::copy_randombytes;

            crate::native_test_util::init();

            let mut input = vec![0u8; 694200];
            copy_randombytes(&mut input);
            let mut output = [0u8; 64];

            b.iter(|| {
                // SAFETY: `output` and `input` are valid for the lengths passed
                // and the key pointer is null with a zero length.
                let rc = unsafe {
                    libsodium_sys::crypto_generichash_blake2b(
                        output.as_mut_ptr(),
                        output.len(),
                        test::black_box(input.as_ptr()),
                        input.len() as u64,
                        core::ptr::null(),
                        0,
                    )
                };
                assert_eq!(rc, 0);
                test::black_box(&output);
            });
        }
    }
}
