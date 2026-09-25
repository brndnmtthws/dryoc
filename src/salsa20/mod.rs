//! XSalsa20 stream cipher (Salsa20/20 keyed through HSalsa20), as used by
//! `crypto_secretbox`.
//!
//! Bulk keystream comes from a vector kernel where one is available: the
//! runtime-detected NEON/SVE2 kernels on little-endian AArch64, the
//! runtime-detected AVX2/AVX-512 kernels on x86-64, or the portable-SIMD
//! kernel with `simd_backend` + `nightly` elsewhere. The portable scalar
//! block function handles everything else.

use zeroize::Zeroize;

use crate::classic::crypto_core::crypto_core_hsalsa20;
use crate::stream::{BufferToBuffer, InPlace, Sink};
use crate::utils::{SIGMA, load_u32_le, zeroize_bytes};

mod salsa20_soft;

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
mod salsa20_neon;
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
use salsa20_neon as vector;

#[cfg(target_arch = "x86_64")]
mod salsa20_x86_64;
#[cfg(target_arch = "x86_64")]
use salsa20_x86_64 as vector;

// On AArch64 and x86-64 the target-specific kernels are faster than the
// portable-SIMD lane set, so they are used there even with `simd_backend`;
// the portable kernel is still compiled for tests there so every backend is
// checked against the others.
#[cfg(all(
    feature = "simd_backend",
    feature = "nightly",
    any(test, not(dryoc_stream_kernel))
))]
mod salsa20_simd;
#[cfg(all(
    feature = "simd_backend",
    feature = "nightly",
    not(dryoc_stream_kernel)
))]
use salsa20_simd as vector;

/// One Salsa20 quarter round over the four words `$a, $b, $c, $d` of `$x`,
/// each step `x[b] ^= (x[a] + x[c]) <<< r` spelled out by the backend's
/// `$step` macro so every index is a compile-time constant.
macro_rules! salsa20_quarter_round {
    ($step:ident, $x:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $step!($x, $b ^= $a + $d <<< 7);
        $step!($x, $c ^= $b + $a <<< 9);
        $step!($x, $d ^= $c + $b <<< 13);
        $step!($x, $a ^= $d + $c <<< 18);
    };
}

/// One Salsa20 double round (a column round followed by a row round) of `$x`
/// with the backend's `$step` macro.
macro_rules! salsa20_double_round {
    ($step:ident, $x:ident) => {
        $crate::salsa20::salsa20_quarter_round!($step, $x, 0, 4, 8, 12);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 5, 9, 13, 1);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 10, 14, 2, 6);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 15, 3, 7, 11);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 0, 1, 2, 3);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 5, 6, 7, 4);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 10, 11, 8, 9);
        $crate::salsa20::salsa20_quarter_round!($step, $x, 15, 12, 13, 14);
    };
}
pub(crate) use salsa20_double_round;
pub(crate) use salsa20_quarter_round;

/// A vector kernel producing several keystream blocks per run.
#[cfg(any(
    dryoc_stream_kernel,
    all(feature = "simd_backend", feature = "nightly")
))]
trait Kernel: Copy + core::fmt::Debug {
    /// Blocks produced per run.
    fn blocks(self) -> usize;

    /// Bytes produced per run.
    #[inline]
    fn chunk(self) -> usize {
        self.blocks() * 64
    }

    /// Shortest remainder, in bytes of whole blocks, worth one more kernel
    /// run rather than dependent scalar blocks.
    fn tail_min(self) -> usize;

    /// XORs the keystream for blocks `counter..` into `output`, reading the
    /// plaintext/ciphertext from `input` (or from `output` itself when
    /// `input` is `None`). `output` must hold whole blocks, at most
    /// [`Kernel::chunk`] bytes; when it holds fewer than [`Kernel::blocks`],
    /// the next block's raw keystream is XORed into `partial` if given
    /// (zero-fill it to receive the keystream itself). The whole chunk is
    /// computed regardless, so shorter outputs cost the same time.
    fn xor_chunk(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
    );

    /// Whether [`Kernel::xor_chunk_with_block`] computes the extra block
    /// alongside the lane set rather than after it, which is what makes a
    /// run with a companion block worth choosing over a run and a scalar
    /// block.
    #[inline]
    fn fuses_extra_block(self) -> bool {
        false
    }

    /// Shortest data length, in bytes, for which a head block and the data
    /// (fitting one lane set together) are produced by a single run through
    /// a staging buffer rather than a scalar head block followed by the
    /// data's own run; `usize::MAX` never stages.
    #[inline]
    fn staged_head_min(self) -> usize {
        usize::MAX
    }

    /// [`Kernel::xor_chunk`] plus one unrelated block: the raw keystream of
    /// block `extra_counter` is XORed into the zero-filled `extra` (passed
    /// together as `(extra_counter, extra)`); by default a scalar block after
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
        self.xor_chunk(state, counter, input, output, partial);
        crate::stream::xor_scalar_block(state, extra_counter, extra, salsa20_soft::block);
    }
}

/// XSalsa20 keystream generator with byte-granular continuity across calls.
///
/// The driver helpers (`advance_counter`, `apply_blocks`, `apply_buffered`,
/// `run_chunk(s)`, the scalar block, the slice and `zip` helpers) may be out
/// of line at opt-level `z` and `s`, which adds no copy: they only get `&` or
/// `&mut` to `self`, whose state and keystream `buffer` are wiped on drop,
/// the caller's buffers, and the `staged` scratch, wiped once per call.
pub(crate) struct XSalsa20 {
    /// Salsa20 input words; words 8 and 9 (the block counter) are always zero
    /// here and supplied from `counter` when a block is generated.
    state: [u32; 16],
    /// Index of the next block to generate.
    counter: u64,
    /// Keystream of the most recently generated block.
    buffer: [u8; 64],
    /// Offset of the first unused byte in `buffer` (64 when exhausted).
    pos: usize,
}

impl XSalsa20 {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let mut hsalsa20_input = [0u8; 16];
        hsalsa20_input.copy_from_slice(&nonce[..16]);

        let mut subkey = [0u8; 32];
        crypto_core_hsalsa20(&mut subkey, &hsalsa20_input, key, None);

        let state = [
            SIGMA[0],
            load_u32_le(&subkey[0..4]),
            load_u32_le(&subkey[4..8]),
            load_u32_le(&subkey[8..12]),
            load_u32_le(&subkey[12..16]),
            SIGMA[1],
            load_u32_le(&nonce[16..20]),
            load_u32_le(&nonce[20..24]),
            0,
            0,
            SIGMA[2],
            load_u32_le(&subkey[16..20]),
            load_u32_le(&subkey[20..24]),
            load_u32_le(&subkey[24..28]),
            load_u32_le(&subkey[28..32]),
            SIGMA[3],
        ];

        zeroize_bytes(&mut hsalsa20_input);
        zeroize_bytes(&mut subkey);

        Self {
            state,
            counter: 0,
            buffer: [0u8; 64],
            pos: 64,
        }
    }

    /// XORs the next `data.len()` keystream bytes into `data`.
    pub(crate) fn apply_keystream(&mut self, data: &mut [u8]) {
        self.apply(InPlace(data));
    }

    /// Writes `input` XORed with the next `input.len()` keystream bytes into
    /// `output`. The two slices must have the same length.
    pub(crate) fn apply_keystream_b2b(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert_eq!(input.len(), output.len());
        self.apply(BufferToBuffer { input, output });
    }

    /// On a fresh keystream (no block started), writes the raw keystream of
    /// the current block into the zero-filled `head`, then XORs the keystream
    /// of the following blocks into `data`. Where a kernel computes a scalar
    /// block alongside its lane set, the head block comes for a fraction of
    /// its usual cost; secretbox uses this for its MAC key block.
    pub(crate) fn apply_keystream_with_head(&mut self, head: &mut [u8; 64], data: &mut [u8]) {
        self.apply_with_head(head, InPlace(data));
    }

    /// Buffer-to-buffer variant of
    /// [`apply_keystream_with_head`](Self::apply_keystream_with_head).
    pub(crate) fn apply_keystream_b2b_with_head(
        &mut self,
        head: &mut [u8; 64],
        input: &[u8],
        output: &mut [u8],
    ) {
        debug_assert_eq!(input.len(), output.len());
        self.apply_with_head(head, BufferToBuffer { input, output });
    }

    fn apply_with_head<S: Sink>(&mut self, head: &mut [u8; 64], sink: S) {
        debug_assert_eq!(self.pos, 64, "the head must start a block");
        #[cfg(any(
            dryoc_stream_kernel,
            all(feature = "simd_backend", feature = "nightly")
        ))]
        self.apply_with_head_using(vector::detect(), head, sink);
        #[cfg(not(any(
            dryoc_stream_kernel,
            all(feature = "simd_backend", feature = "nightly")
        )))]
        {
            self.apply_head(head);
            self.apply_scalar(sink);
        }
    }

    /// Writes the raw keystream of the current block into the zero-filled
    /// `head` and advances past it.
    fn apply_head(&mut self, head: &mut [u8; 64]) {
        salsa20_soft::block(&self.state, self.counter, head);
        self.advance_counter(1);
    }

    /// [`apply_with_head`](Self::apply_with_head) with a chosen vector kernel
    /// (`None` for scalar blocks only): the head is the companion block of
    /// the first run when the kernel fuses one and the data spans more than
    /// one block, otherwise a scalar block; the data then follows the normal
    /// driver.
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    fn apply_with_head_using<K: Kernel, S: Sink>(
        &mut self,
        kernel: Option<K>,
        head: &mut [u8; 64],
        mut sink: S,
    ) {
        let Some(kernel) = kernel else {
            self.apply_head(head);
            return self.apply_scalar(sink);
        };
        let len = sink.len();
        // The head takes one slot, the data the rest of the lane set.
        if len >= kernel.staged_head_min() && len.div_ceil(64) < kernel.blocks() {
            return self.apply_with_head_staged(kernel, head, sink);
        }
        // A companion block costs a fraction of a scalar block, but a run
        // costs about two; with a single block of data (whole or partial)
        // two scalar blocks are cheaper than a run with a companion.
        if kernel.fuses_extra_block() && len > 64 {
            let head_counter = self.counter;
            self.advance_counter(1);
            self.run_chunk(kernel, &mut sink, Some((head_counter, head)));
        } else {
            self.apply_head(head);
        }
        self.run_chunks(kernel, &mut sink);
        self.apply_blocks(sink);
    }

    /// The head block and all of `sink` (together at most one lane set, the
    /// data non-empty) in one kernel run: the data is staged behind a zero
    /// block so the kernel sees contiguous whole blocks, and a trailing
    /// partial block is filled through the partial slot into the buffer, as
    /// in [`run_chunk`](Self::run_chunk).
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    fn apply_with_head_staged<K: Kernel, S: Sink>(
        &mut self,
        kernel: K,
        head: &mut [u8; 64],
        mut sink: S,
    ) {
        /// Bytes of the largest lane set (16 blocks).
        const STAGE_BYTES: usize = 16 * 64;
        debug_assert!(kernel.chunk() <= STAGE_BYTES);
        let len = sink.len();
        debug_assert!(len > 0 && 64 + len <= kernel.chunk() + 63);
        let whole = len / 64 * 64;
        let mut staged = [0u8; STAGE_BYTES];
        let (input, output) = sink.take(len);
        staged[64..64 + len].copy_from_slice(input.unwrap_or(&*output));
        let (run, partial_data) = staged[..64 + len].split_at_mut(64 + whole);
        let partial_tail = partial_data.len();
        let partial = (partial_tail > 0).then(|| {
            self.buffer = [0u8; 64];
            &mut self.buffer
        });
        kernel.xor_chunk(&self.state, self.counter, None, run, partial);
        for (byte, ks) in partial_data.iter_mut().zip(&self.buffer) {
            *byte ^= ks;
        }
        head.copy_from_slice(&staged[..64]);
        output.copy_from_slice(&staged[64..64 + len]);
        // Only the written prefix of `staged` ever held keystream.
        zeroize_bytes(&mut staged[..64 + len]);
        self.advance_counter(1 + (whole / 64) as u64);
        if partial_tail > 0 {
            self.advance_counter(1);
            self.pos = partial_tail;
        }
    }

    fn apply<S: Sink>(&mut self, sink: S) {
        #[cfg(any(
            dryoc_stream_kernel,
            all(feature = "simd_backend", feature = "nightly")
        ))]
        self.apply_using(vector::detect(), sink);
        #[cfg(not(any(
            dryoc_stream_kernel,
            all(feature = "simd_backend", feature = "nightly")
        )))]
        self.apply_scalar(sink);
    }

    /// [`apply`](Self::apply) with a chosen vector kernel (`None` for scalar
    /// blocks only): the buffered partial block first, then whole chunks
    /// through the kernel while enough blocks remain, the rest through
    /// scalar blocks.
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    fn apply_using<K: Kernel, S: Sink>(&mut self, kernel: Option<K>, mut sink: S) {
        let Some(kernel) = kernel else {
            return self.apply_scalar(sink);
        };
        self.apply_buffered(&mut sink);
        self.run_chunks(kernel, &mut sink);
        self.apply_blocks(sink);
    }

    /// Whole chunks through the kernel while enough blocks remain (see
    /// [`run_chunk`](Self::run_chunk)); requires the buffer to be exhausted.
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    fn run_chunks<K: Kernel, S: Sink>(&mut self, kernel: K, sink: &mut S) {
        // The kernel's cost is the latency of one block's rounds whatever
        // the number of blocks it is asked for, so even a partly used
        // chunk beats a run of dependent scalar blocks.
        while sink.len() / 64 * 64 >= kernel.tail_min() {
            self.run_chunk(kernel, sink, None);
        }
    }

    /// One kernel run over the front of `sink`: up to a chunk of whole
    /// blocks, and when fewer than a chunk remain also the trailing partial
    /// block, straight into the zero-filled buffer. With `extra`, the run
    /// also produces the raw keystream of that unrelated block (XORed into
    /// its zero-filled buffer). Requires the buffer to be exhausted.
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    fn run_chunk<K: Kernel, S: Sink>(
        &mut self,
        kernel: K,
        sink: &mut S,
        extra: Option<(u64, &mut [u8; 64])>,
    ) {
        debug_assert_eq!(self.pos, 64);
        let chunk = kernel.chunk();
        let len = (sink.len() / 64 * 64).min(chunk);
        let partial_tail = if len < chunk { sink.len() - len } else { 0 };
        let partial = (partial_tail > 0).then(|| {
            self.buffer = [0u8; 64];
            &mut self.buffer
        });
        let (input, output) = sink.take(len);
        match extra {
            Some(extra) => kernel.xor_chunk_with_block(
                &self.state,
                self.counter,
                input,
                output,
                partial,
                extra,
            ),
            None => kernel.xor_chunk(&self.state, self.counter, input, output, partial),
        }
        self.advance_counter((len / 64) as u64);
        if partial_tail > 0 {
            self.advance_counter(1);
            sink.xor(&self.buffer[..partial_tail]);
            self.pos = partial_tail;
        }
    }

    /// The buffered partial block, then whole blocks and a trailing partial
    /// block one scalar block at a time.
    fn apply_scalar<S: Sink>(&mut self, mut sink: S) {
        self.apply_buffered(&mut sink);
        self.apply_blocks(sink);
    }

    /// XORs the unused keystream of the buffered block into the front of
    /// `sink`.
    #[inline]
    fn apply_buffered<S: Sink>(&mut self, sink: &mut S) {
        let buffered = (64 - self.pos).min(sink.len());
        if buffered > 0 {
            sink.xor(&self.buffer[self.pos..self.pos + buffered]);
            self.pos += buffered;
        }
    }

    /// Whole blocks then a trailing partial block (left buffered), one scalar
    /// block at a time; requires the buffer to be exhausted.
    #[inline]
    fn apply_blocks<S: Sink>(&mut self, mut sink: S) {
        debug_assert!(self.pos == 64 || sink.len() == 0);
        while sink.len() >= 64 {
            salsa20_soft::block(&self.state, self.counter, &mut self.buffer);
            self.advance_counter(1);
            sink.xor(&self.buffer);
        }

        let tail = sink.len();
        if tail > 0 {
            salsa20_soft::block(&self.state, self.counter, &mut self.buffer);
            self.advance_counter(1);
            sink.xor(&self.buffer[..tail]);
            self.pos = tail;
        }
    }

    #[inline]
    fn advance_counter(&mut self, blocks: u64) {
        self.counter = self
            .counter
            .checked_add(blocks)
            .expect("XSalsa20 block counter overflow");
    }
}

impl Drop for XSalsa20 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.counter.zeroize();
        zeroize_bytes(&mut self.buffer);
        self.pos.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    use salsa20::{Key as SalsaKey, XNonce, XSalsa20 as RustCryptoXSalsa20};

    use super::*;
    use crate::test_prelude::*;

    /// Keystream for `len` bytes computed one block at a time with the scalar
    /// block function only.
    fn scalar_keystream(state: &[u32; 16], len: usize) -> Vec<u8> {
        scalar_keystream_from(state, 0, len)
    }

    /// Keystream for blocks `start..` (wrapping) of `len` bytes computed one
    /// block at a time with the scalar block function only.
    fn scalar_keystream_from(state: &[u32; 16], start: u64, len: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(len.next_multiple_of(64));
        let mut block = [0u8; 64];
        for i in 0..len.div_ceil(64) as u64 {
            salsa20_soft::block(state, start.wrapping_add(i), &mut block);
            keystream.extend_from_slice(&block);
        }
        keystream.truncate(len);
        keystream
    }

    fn rustcrypto_xor(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) {
        RustCryptoXSalsa20::new(&SalsaKey::from(*key), &XNonce::from(*nonce)).apply_keystream(data);
    }

    /// libsodium `test/default/secretbox.c`: the message follows 32 zero
    /// bytes that become the Poly1305 key, so the expected ciphertext is
    /// keystream bytes 32.. XORed with the message.
    #[test]
    fn test_xsalsa20_libsodium_secretbox_vector() {
        let key: [u8; 32] =
            hex::decode("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = hex::decode("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
            .unwrap()
            .try_into()
            .unwrap();
        let message = hex::decode(concat!(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc",
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31",
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde",
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864",
            "5e0705",
        ))
        .unwrap();
        let expected = hex::decode(concat!(
            "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a",
            "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738",
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da",
            "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74",
            "e355a5",
        ))
        .unwrap();
        assert_eq!(message.len(), 131);
        assert_eq!(expected.len(), 131);

        let mut cipher = XSalsa20::new(&key, &nonce);
        let mut mac_key = [0u8; 32];
        cipher.apply_keystream(&mut mac_key);
        let mut ciphertext = message.clone();
        cipher.apply_keystream(&mut ciphertext);
        assert_eq!(ciphertext, expected);

        let mut cipher = XSalsa20::new(&key, &nonce);
        let mut b2b = [0u8; 32 + 131];
        cipher.apply_keystream_b2b(&[0u8; 32], &mut b2b[..32]);
        cipher.apply_keystream_b2b(&message, &mut b2b[32..]);
        assert_eq!(&b2b[..32], &mac_key);
        assert_eq!(&b2b[32..], &expected);
    }

    #[test]
    fn test_xsalsa20_scalar_blocks_match_rustcrypto_across_counter_words() {
        let key = [0x5au8; 32];
        let nonce = [0xa5u8; 24];
        let mut expected = vec![0u8; 3 * 64];
        rustcrypto_xor(&key, &nonce, &mut expected);

        let cipher = XSalsa20::new(&key, &nonce);
        assert_eq!(scalar_keystream(&cipher.state, 3 * 64), expected);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    mod property_tests {
        use proptest::prelude::*;

        use super::*;

        /// Chunk boundaries that exercise the buffered-prefix, bulk and tail
        /// paths, plus random splits.
        fn chunking_strategy(len: usize) -> impl Strategy<Value = Vec<usize>> {
            prop::collection::vec(0usize..=len.min(700), 0..8).prop_map(move |mut cuts| {
                cuts.push(0);
                cuts.push(len);
                cuts.sort_unstable();
                cuts.dedup();
                cuts
            })
        }

        type Case = ([u8; 32], [u8; 24], Vec<u8>, Vec<usize>, Vec<bool>);

        fn case_strategy() -> impl Strategy<Value = Case> {
            (any::<[u8; 32]>(), any::<[u8; 24]>(), 0usize..=2048).prop_flat_map(
                |(key, nonce, len)| {
                    (
                        Just(key),
                        Just(nonce),
                        prop::collection::vec(any::<u8>(), len),
                        chunking_strategy(len),
                        prop::collection::vec(any::<bool>(), 10),
                    )
                },
            )
        }

        proptest! {
            #![proptest_config(crate::utils::test_util::proptest_config(256))]

            #[test]
            fn test_xsalsa20_chunked_matches_rustcrypto((key, nonce, message, cuts, in_place) in case_strategy()) {
                let mut expected = message.clone();
                rustcrypto_xor(&key, &nonce, &mut expected);

                let mut cipher = XSalsa20::new(&key, &nonce);
                let mut actual = vec![0u8; message.len()];
                for (i, window) in cuts.windows(2).enumerate() {
                    let (start, end) = (window[0], window[1]);
                    if in_place[i % in_place.len()] {
                        actual[start..end].copy_from_slice(&message[start..end]);
                        cipher.apply_keystream(&mut actual[start..end]);
                    } else {
                        cipher.apply_keystream_b2b(&message[start..end], &mut actual[start..end]);
                    }
                }
                prop_assert_eq!(actual, expected);
            }
        }
    }

    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    mod vector_path {
        use super::*;

        /// Every kernel of every compiled backend that the CPU supports.
        /// Every little-endian AArch64 CPU has NEON and the portable-SIMD
        /// kernel always exists, so those builds must visit at least one
        /// kernel; an x86-64 CPU without AVX2 legitimately visits none and
        /// is covered by the scalar path only.
        macro_rules! for_each_kernel {
            (| $kernel:ident | $body:block) => {{
                let mut visited = 0;
                #[cfg(dryoc_stream_kernel)]
                for $kernel in vector::Kernel::all() {
                    visited += 1;
                    $body
                }
                #[cfg(all(feature = "simd_backend", feature = "nightly"))]
                for $kernel in salsa20_simd::Kernel::all() {
                    visited += 1;
                    $body
                }
                let may_be_scalar_only = cfg!(all(
                    target_arch = "x86_64",
                    not(all(feature = "simd_backend", feature = "nightly"))
                ));
                assert!(
                    may_be_scalar_only || visited > 0,
                    "vector path must run on this machine"
                );
            }};
        }

        /// One chunk of a kernel against the scalar block function, at
        /// counters whose lanes straddle the 32-bit boundary (the carry into
        /// word 9), in place and buffer to buffer, clipped to every whole
        /// block count with the partial slot filled.
        fn check_kernel_chunk<K: Kernel>(kernel: K) {
            let cipher = XSalsa20::new(&[0x11u8; 32], &[0x22u8; 24]);
            let counters = [
                0u64,
                1,
                5,
                u32::MAX as u64 - 3,
                u32::MAX as u64 - 1,
                u32::MAX as u64,
                1 << 40,
            ];
            for counter in counters {
                let plaintext: Vec<u8> = (0..kernel.chunk() as u32)
                    .map(|i| (i * 7 % 251) as u8)
                    .collect();
                let mut expected = plaintext.clone();
                let mut block = [0u8; 64];
                for (i, chunk) in expected.as_chunks_mut::<64>().0.iter_mut().enumerate() {
                    salsa20_soft::block(&cipher.state, counter + i as u64, &mut block);
                    for (byte, ks) in chunk.iter_mut().zip(block) {
                        *byte ^= ks;
                    }
                }

                let mut in_place = plaintext.clone();
                kernel.xor_chunk(&cipher.state, counter, None, &mut in_place, None);
                assert_eq!(in_place, expected, "{kernel:?} in place, counter {counter}");

                let mut b2b = vec![0u8; kernel.chunk()];
                kernel.xor_chunk(&cipher.state, counter, Some(&plaintext), &mut b2b, None);
                assert_eq!(b2b, expected, "{kernel:?} b2b, counter {counter}");

                // Clipped to `blocks` whole blocks, with the next block's raw
                // keystream delivered through the zero-filled partial slot.
                for blocks in 0..kernel.blocks() {
                    let len = blocks * 64;
                    let mut clipped = plaintext[..len].to_vec();
                    let mut partial = [0u8; 64];
                    kernel.xor_chunk(
                        &cipher.state,
                        counter,
                        None,
                        &mut clipped,
                        Some(&mut partial),
                    );
                    assert_eq!(
                        clipped,
                        expected[..len],
                        "{kernel:?} clipped to {blocks}, counter {counter}"
                    );
                    let mut block = [0u8; 64];
                    salsa20_soft::block(&cipher.state, counter + blocks as u64, &mut block);
                    assert_eq!(
                        partial, block,
                        "{kernel:?} partial after {blocks}, counter {counter}"
                    );
                }
            }
        }

        #[test]
        fn test_kernel_chunk_matches_scalar_blocks() {
            for_each_kernel!(|kernel| {
                check_kernel_chunk(kernel);
            });
        }

        /// Lengths around the chunk and tail thresholds of `kernel`, plus
        /// fixed ones every kernel sees.
        fn threshold_lens<K: Kernel>(kernel: Option<K>) -> Vec<usize> {
            let mut lens = vec![
                0,
                1,
                31,
                32,
                33,
                63,
                64,
                65,
                127,
                128,
                129,
                1024,
                1024 + 32,
                4096 + 200,
            ];
            if let Some(kernel) = kernel {
                let (chunk, tail_min) = (kernel.chunk(), kernel.tail_min());
                lens.extend([
                    tail_min - 65,
                    tail_min - 64,
                    tail_min - 1,
                    tail_min,
                    tail_min + 32,
                    tail_min + 33,
                    chunk - 1,
                    chunk,
                    chunk + 31,
                    chunk + 32,
                    chunk + 33,
                    chunk + tail_min - 1,
                    chunk + tail_min,
                    chunk + tail_min + 32,
                    2 * chunk + 32,
                ]);
            }
            lens.sort_unstable();
            lens.dedup();
            lens
        }

        /// The driver with `kernel` (or scalar blocks only) against the
        /// scalar keystream: one shot, and split so that a partial block is
        /// left buffered by one call and continued by the next, in place and
        /// buffer to buffer, checking the block counter and buffer position
        /// afterwards.
        fn check_driver<K: Kernel>(kernel: Option<K>) {
            let key = [0x33u8; 32];
            let nonce = [0x44u8; 24];
            for len in threshold_lens(kernel) {
                let total = len + 7;
                let plaintext: Vec<u8> = (0..total as u32).map(|i| (i * 13 % 253) as u8).collect();
                let reference = XSalsa20::new(&key, &nonce);
                let mut expected = plaintext.clone();
                for (byte, ks) in expected
                    .iter_mut()
                    .zip(scalar_keystream(&reference.state, total))
                {
                    *byte ^= ks;
                }
                let cuts = [
                    vec![0, total],
                    vec![0, 32, len, total],
                    vec![0, 1, 63, total],
                ]
                .map(|mut cuts| {
                    cuts.iter_mut().for_each(|cut| *cut = (*cut).min(total));
                    cuts.sort_unstable();
                    cuts.dedup();
                    cuts
                });
                for cuts in &cuts {
                    let mut cipher = XSalsa20::new(&key, &nonce);
                    let mut in_place = plaintext.clone();
                    for window in cuts.windows(2) {
                        cipher.apply_using(kernel, InPlace(&mut in_place[window[0]..window[1]]));
                    }
                    assert_eq!(
                        in_place, expected,
                        "{kernel:?} in place, len {len}, cuts {cuts:?}"
                    );
                    assert_eq!(
                        cipher.counter,
                        total.div_ceil(64) as u64,
                        "{kernel:?} counter, len {len}"
                    );
                    assert_eq!(
                        cipher.pos,
                        if total % 64 == 0 { 64 } else { total % 64 },
                        "{kernel:?} pos, len {len}"
                    );

                    let mut cipher = XSalsa20::new(&key, &nonce);
                    let mut b2b = vec![0u8; total];
                    for window in cuts.windows(2) {
                        cipher.apply_using(
                            kernel,
                            BufferToBuffer {
                                input: &plaintext[window[0]..window[1]],
                                output: &mut b2b[window[0]..window[1]],
                            },
                        );
                    }
                    assert_eq!(b2b, expected, "{kernel:?} b2b, len {len}, cuts {cuts:?}");
                    assert_eq!(
                        cipher.counter,
                        total.div_ceil(64) as u64,
                        "{kernel:?} counter, len {len}"
                    );
                }
            }
        }

        #[test]
        fn test_driver_matches_scalar_keystream_for_every_kernel() {
            check_driver(None::<vector::Kernel>);
            for_each_kernel!(|kernel| {
                check_driver(Some(kernel));
            });
        }

        /// The head-block driver with `kernel` (or scalar blocks only) must
        /// produce the scalar keystream of block 0 as the head and XOR the
        /// keystream from block 1 on into the data, leave the counter and
        /// buffer position where the plain driver would, and continue
        /// correctly through a following call, for lengths around every
        /// kernel threshold (including no data at all), in place and buffer
        /// to buffer.
        fn check_head_driver<K: Kernel>(kernel: Option<K>) {
            let key = [0x55u8; 32];
            let nonce = [0x66u8; 24];
            let mut lens = threshold_lens(kernel);
            lens.extend([
                0,
                1,
                31,
                32,
                33,
                64 * 15 + 32,
                64 * 16,
                64 * 16 + 32,
                64 * 17,
            ]);
            lens.sort_unstable();
            lens.dedup();
            for len in lens {
                let tail = 45;
                let plaintext: Vec<u8> = (0..(len + tail) as u32)
                    .map(|i| (i * 11 % 251) as u8)
                    .collect();
                let reference = XSalsa20::new(&key, &nonce);
                let keystream = scalar_keystream(&reference.state, 64 + len + tail);
                let expected_head: [u8; 64] = keystream[..64].try_into().unwrap();
                let mut expected = plaintext.clone();
                for (byte, ks) in expected.iter_mut().zip(&keystream[64..]) {
                    *byte ^= ks;
                }

                let mut cipher = XSalsa20::new(&key, &nonce);
                let mut head = [0u8; 64];
                let mut in_place = plaintext.clone();
                cipher.apply_with_head_using(kernel, &mut head, InPlace(&mut in_place[..len]));
                assert_eq!(head, expected_head, "{kernel:?} in place head, len {len}");
                assert_eq!(
                    (cipher.counter, cipher.pos),
                    (
                        (64 + len).div_ceil(64) as u64,
                        if len % 64 == 0 { 64 } else { len % 64 }
                    ),
                    "{kernel:?} in place state, len {len}"
                );
                cipher.apply_using(kernel, InPlace(&mut in_place[len..]));
                assert_eq!(in_place, expected, "{kernel:?} in place, len {len}");

                let mut cipher = XSalsa20::new(&key, &nonce);
                let mut head = [0u8; 64];
                let mut b2b = vec![0u8; len + tail];
                cipher.apply_with_head_using(
                    kernel,
                    &mut head,
                    BufferToBuffer {
                        input: &plaintext[..len],
                        output: &mut b2b[..len],
                    },
                );
                assert_eq!(head, expected_head, "{kernel:?} b2b head, len {len}");
                cipher.apply_using(
                    kernel,
                    BufferToBuffer {
                        input: &plaintext[len..],
                        output: &mut b2b[len..],
                    },
                );
                assert_eq!(b2b, expected, "{kernel:?} b2b, len {len}");
            }
        }

        #[test]
        fn test_head_driver_matches_scalar_keystream_for_every_kernel() {
            check_head_driver(None::<vector::Kernel>);
            for_each_kernel!(|kernel| {
                check_head_driver(Some(kernel));
            });
        }

        /// The public entry points pick a kernel on this machine and equal
        /// the driver forced to that kernel, output, counter and buffer
        /// position, across a split that leaves a partial block buffered.
        #[test]
        fn test_default_dispatch_uses_detected_kernel() {
            let kernel = vector::detect();
            #[cfg(not(target_arch = "x86_64"))]
            assert!(kernel.is_some(), "vector path must run on this machine");
            let key = [0x99u8; 32];
            let nonce = [0xaau8; 24];
            for len in [0, 1, 63, 64, 65, 200, 1024 + 32, 4096 + 7] {
                let plaintext: Vec<u8> = (0..len as u32).map(|i| (i * 17 % 251) as u8).collect();
                let split = (len / 3) | 1;
                let split = split.min(len);

                let mut expected = plaintext.clone();
                let mut forced = XSalsa20::new(&key, &nonce);
                forced.apply_using(kernel, InPlace(&mut expected[..split]));
                forced.apply_using(kernel, InPlace(&mut expected[split..]));

                let mut in_place = plaintext.clone();
                let mut cipher = XSalsa20::new(&key, &nonce);
                cipher.apply_keystream(&mut in_place[..split]);
                cipher.apply_keystream(&mut in_place[split..]);
                assert_eq!(in_place, expected, "in place, len {len}");
                assert_eq!(
                    (cipher.counter, cipher.pos),
                    (forced.counter, forced.pos),
                    "len {len}"
                );

                let mut b2b = vec![0u8; len];
                let mut cipher = XSalsa20::new(&key, &nonce);
                cipher.apply_keystream_b2b(&plaintext[..split], &mut b2b[..split]);
                cipher.apply_keystream_b2b(&plaintext[split..], &mut b2b[split..]);
                assert_eq!(b2b, expected, "b2b, len {len}");
                assert_eq!(
                    (cipher.counter, cipher.pos),
                    (forced.counter, forced.pos),
                    "len {len}"
                );
            }
        }

        /// A fresh cipher positioned at block `start` with no block buffered.
        fn cipher_at(key: &[u8; 32], nonce: &[u8; 24], start: u64) -> XSalsa20 {
            let mut cipher = XSalsa20::new(key, nonce);
            cipher.counter = start;
            cipher
        }

        /// Start counters for a kernel of `blocks` per run and a message of
        /// `total_blocks` whose runs cross the 32-bit boundary (the carry
        /// into word 9) inside the second run, inside the first run and at a
        /// run's first lane, plus the starts that end exactly on `u64::MAX`
        /// (the driver refuses to advance past it) and, when the message
        /// fits, one whose second run begins there.
        fn wrap_starts(blocks: u64, total_blocks: u64) -> Vec<u64> {
            let low = u64::from(u32::MAX);
            let mut starts = vec![low - (blocks + 1), low - 1, low, u64::MAX - total_blocks];
            if total_blocks <= blocks + 1 {
                starts.push(u64::MAX - (blocks + 1));
            }
            starts
        }

        /// The driver with `kernel` (or scalar blocks only) from block `start`
        /// against the scalar keystream of blocks `start..`: one shot, and
        /// split so a partial block is buffered by one call and continued
        /// across the wrap by the next, in place and buffer to buffer,
        /// checking the counter and buffer position afterwards.
        fn check_driver_across_wrap<K: Kernel>(kernel: Option<K>, start: u64, len: usize) {
            let key = [0x5au8; 32];
            let nonce = [0x66u8; 24];
            let total = len + 7;
            let plaintext: Vec<u8> = (0..total as u32).map(|i| (i * 13 % 253) as u8).collect();
            let reference = XSalsa20::new(&key, &nonce);
            let expected: Vec<u8> = plaintext
                .iter()
                .zip(scalar_keystream_from(&reference.state, start, total))
                .map(|(byte, ks)| byte ^ ks)
                .collect();
            let end = start + total.div_ceil(64) as u64;
            let end_pos = if total.is_multiple_of(64) {
                64
            } else {
                total % 64
            };
            let cuts = [
                vec![0, total],
                vec![0, 32, len, total],
                vec![0, 1, 63, total],
            ]
            .map(|mut cuts| {
                cuts.iter_mut().for_each(|cut| *cut = (*cut).min(total));
                cuts.sort_unstable();
                cuts.dedup();
                cuts
            });
            for cuts in &cuts {
                let ctx = format!("{kernel:?} from {start:#x}, len {len}, cuts {cuts:?}");
                let mut cipher = cipher_at(&key, &nonce, start);
                let mut in_place = plaintext.clone();
                for window in cuts.windows(2) {
                    cipher.apply_using(kernel, InPlace(&mut in_place[window[0]..window[1]]));
                }
                assert_eq!(in_place, expected, "{ctx}, in place");
                assert_eq!(
                    (cipher.counter, cipher.pos),
                    (end, end_pos),
                    "{ctx}, in place state"
                );

                let mut cipher = cipher_at(&key, &nonce, start);
                let mut b2b = vec![0u8; total];
                for window in cuts.windows(2) {
                    cipher.apply_using(
                        kernel,
                        BufferToBuffer {
                            input: &plaintext[window[0]..window[1]],
                            output: &mut b2b[window[0]..window[1]],
                        },
                    );
                }
                assert_eq!(b2b, expected, "{ctx}, b2b");
                assert_eq!(
                    (cipher.counter, cipher.pos),
                    (end, end_pos),
                    "{ctx}, b2b state"
                );
            }
        }

        /// The head-block driver with `kernel` (or scalar blocks only) from
        /// block `start`: the head is block `start`, the data follows from
        /// `start + 1` across the wrap, and a following call continues from
        /// the buffered position, in place and buffer to buffer.
        fn check_head_driver_across_wrap<K: Kernel>(kernel: Option<K>, start: u64, len: usize) {
            let key = [0x5au8; 32];
            let nonce = [0x66u8; 24];
            let tail = 45;
            let plaintext: Vec<u8> = (0..(len + tail) as u32)
                .map(|i| (i * 11 % 251) as u8)
                .collect();
            let reference = XSalsa20::new(&key, &nonce);
            let keystream = scalar_keystream_from(&reference.state, start, 64 + len + tail);
            let expected_head: [u8; 64] = keystream[..64].try_into().unwrap();
            let expected: Vec<u8> = plaintext
                .iter()
                .zip(&keystream[64..])
                .map(|(byte, ks)| byte ^ ks)
                .collect();
            let after_head = (
                start + (64 + len).div_ceil(64) as u64,
                if len.is_multiple_of(64) { 64 } else { len % 64 },
            );
            let ctx = format!("{kernel:?} from {start:#x}, len {len}");

            let mut cipher = cipher_at(&key, &nonce, start);
            let mut head = [0u8; 64];
            let mut in_place = plaintext.clone();
            cipher.apply_with_head_using(kernel, &mut head, InPlace(&mut in_place[..len]));
            assert_eq!(head, expected_head, "{ctx}, in place head");
            assert_eq!(
                (cipher.counter, cipher.pos),
                after_head,
                "{ctx}, in place state"
            );
            cipher.apply_using(kernel, InPlace(&mut in_place[len..]));
            assert_eq!(in_place, expected, "{ctx}, in place");

            let mut cipher = cipher_at(&key, &nonce, start);
            let mut head = [0u8; 64];
            let mut b2b = vec![0u8; len + tail];
            cipher.apply_with_head_using(
                kernel,
                &mut head,
                BufferToBuffer {
                    input: &plaintext[..len],
                    output: &mut b2b[..len],
                },
            );
            assert_eq!(head, expected_head, "{ctx}, b2b head");
            assert_eq!((cipher.counter, cipher.pos), after_head, "{ctx}, b2b state");
            cipher.apply_using(
                kernel,
                BufferToBuffer {
                    input: &plaintext[len..],
                    output: &mut b2b[len..],
                },
            );
            assert_eq!(b2b, expected, "{ctx}, b2b");
        }

        /// Every kernel (and the scalar path) from every start in
        /// [`wrap_starts`], with and without a head block, over the lengths
        /// around the kernel thresholds up to two chunks and a block.
        #[test]
        fn test_driver_matches_scalar_keystream_across_counter_wraps() {
            fn run<K: Kernel>(kernel: Option<K>) {
                let blocks = kernel.map_or(1, |kernel| kernel.blocks() as u64);
                let chunk = kernel.map_or(64, |kernel| kernel.chunk());
                for len in threshold_lens(kernel)
                    .into_iter()
                    .filter(|&len| len <= 2 * chunk + 65)
                {
                    for start in wrap_starts(blocks, (len + 7).div_ceil(64) as u64) {
                        check_driver_across_wrap(kernel, start, len);
                    }
                    for start in wrap_starts(blocks, (64 + len + 45).div_ceil(64) as u64) {
                        check_head_driver_across_wrap(kernel, start, len);
                    }
                }
            }
            run(None::<vector::Kernel>);
            for_each_kernel!(|kernel| {
                run(Some(kernel));
            });
        }

        /// Every data length from one byte to a chunk and a block, for every
        /// kernel, with and without a head block, from the start that puts
        /// the 32-bit wrap inside the first run and from the one that ends
        /// exactly on `u64::MAX`.
        #[test]
        fn test_driver_every_length_to_a_chunk_across_counter_wraps() {
            fn run<K: Kernel>(kernel: K) {
                // Native tests sweep every byte; Miri keeps both sides of
                // every block and kernel boundary.
                for len in (1..=kernel.chunk() + 64)
                    .filter(|len| !cfg!(miri) || matches!(len % 64, 0 | 1 | 63))
                {
                    for start in [
                        u64::from(u32::MAX) - 1,
                        u64::MAX - (len + 7).div_ceil(64) as u64,
                    ] {
                        check_driver_across_wrap(Some(kernel), start, len);
                    }
                    for start in [
                        u64::from(u32::MAX) - 1,
                        u64::MAX - (64 + len + 45).div_ceil(64) as u64,
                    ] {
                        check_head_driver_across_wrap(Some(kernel), start, len);
                    }
                }
            }
            for_each_kernel!(|kernel| {
                run(kernel);
            });
        }
    }
}
