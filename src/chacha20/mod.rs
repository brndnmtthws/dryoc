//! ChaCha20 stream cipher, in the RFC 8439 (`_ietf`) and original 64-bit
//! counter layouts, as used by the ChaCha20-Poly1305 AEADs and the
//! secretstream construction.
//!
//! Bulk keystream comes from a vector kernel where one is available: the
//! runtime-detected NEON/SVE2 kernels on little-endian AArch64 and the
//! runtime-detected AVX2/AVX-512 kernels on x86-64. The portable scalar block
//! function handles everything else.

use zeroize::Zeroize;

use crate::stream::{BufferToBuffer, InPlace, Sink};
use crate::utils::{load_u32_le, zeroize_bytes};

mod chacha20_soft;

#[cfg(target_arch = "aarch64")]
mod chacha20_aarch64;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod chacha20_neon;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use chacha20_neon as vector;
#[cfg(target_arch = "x86_64")]
mod chacha20_x86_64;
pub(crate) use chacha20_soft::rounds;
#[cfg(target_arch = "x86_64")]
use chacha20_x86_64 as vector;

const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// One ChaCha20 double round (a column round followed by a diagonal round)
/// of `$x`: the eight quarter rounds spelled out with the backend's `$qr`
/// macro so every index is a compile-time constant, with `$extra` (such as
/// rotation tables) passed through to each.
macro_rules! chacha20_double_round {
    ($qr:ident, $x:ident $(, $extra:ident)*) => {
        $qr!($x, 0, 4, 8, 12 $(, $extra)*);
        $qr!($x, 1, 5, 9, 13 $(, $extra)*);
        $qr!($x, 2, 6, 10, 14 $(, $extra)*);
        $qr!($x, 3, 7, 11, 15 $(, $extra)*);
        $qr!($x, 0, 5, 10, 15 $(, $extra)*);
        $qr!($x, 1, 6, 11, 12 $(, $extra)*);
        $qr!($x, 2, 7, 8, 13 $(, $extra)*);
        $qr!($x, 3, 4, 9, 14 $(, $extra)*);
    };
}
pub(crate) use chacha20_double_round;

/// A vector kernel producing several keystream blocks per run.
#[cfg(dryoc_stream_kernel)]
trait Kernel: Copy + std::fmt::Debug {
    /// Blocks produced per run.
    fn blocks(self) -> usize;

    /// Bytes produced per run.
    #[inline]
    fn chunk(self) -> usize {
        self.blocks() * 64
    }

    /// Shortest remainder, in blocks including a trailing partial one, worth
    /// one more kernel run rather than dependent scalar blocks.
    fn tail_min_blocks(self) -> usize;

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
        xor_scalar_block(state, extra_counter, extra);
    }

    /// [`Kernel::xor_chunk`] for runs of at most [`vector::SMALL_BLOCKS`]
    /// blocks (`output` plus `partial`); by default as many runs as the
    /// blocks need, the partial slot filled by the last one.
    #[inline]
    fn xor_small(
        self,
        state: &[u32; 16],
        counter: u64,
        input: Option<&[u8]>,
        mut output: &mut [u8],
        partial: Option<&mut [u8; 64]>,
    ) {
        debug_assert!(output.len() / 64 + usize::from(partial.is_some()) <= vector::SMALL_BLOCKS);
        let chunk = self.chunk();
        let mut input = input;
        let mut counter = counter;
        // Split while the remaining blocks plus the partial slot exceed one
        // run, so the last run always has room for the partial slot. Whole
        // blocks only, so a split always has a full run to take.
        while output.len() + usize::from(partial.is_some()) * 64 > chunk {
            debug_assert!(output.len() >= chunk);
            let (head, rest) = output.split_at_mut(chunk);
            let head_input = match input {
                Some(whole) => {
                    let (head, rest) = whole.split_at(chunk);
                    input = Some(rest);
                    Some(head)
                }
                None => None,
            };
            self.xor_chunk(state, counter, head_input, head, None);
            counter = counter.wrapping_add(self.blocks() as u64);
            output = rest;
        }
        self.xor_chunk(state, counter, input, output, partial);
    }
}

/// XORs the raw keystream of the scalar block `counter` into `extra`.
#[cfg(dryoc_stream_kernel)]
fn xor_scalar_block(state: &[u32; 16], counter: u64, extra: &mut [u8; 64]) {
    let mut block = [0u8; 64];
    chacha20_soft::block(state, counter, &mut block);
    for (byte, ks) in extra.iter_mut().zip(block) {
        *byte ^= ks;
    }
    zeroize_bytes(&mut block);
}

/// ChaCha20 keystream generator positioned at a block boundary.
///
/// Every call to [`apply_keystream`](Self::apply_keystream) or
/// [`apply_keystream_b2b`](Self::apply_keystream_b2b) starts at the current
/// block and advances the counter by `ceil(len / 64)` blocks: a trailing
/// partial block consumes a whole counter step and its unused keystream is
/// discarded, matching libsodium's `_xor_ic` functions when chained. All
/// callers work in whole blocks, so no partial-block continuity is kept.
pub(crate) struct ChaCha20 {
    /// ChaCha20 input words; words 12 and 13 hold the current 64-bit block
    /// counter (low word first). In the IETF layout word 13 is the first
    /// nonce word, which a counter carry would alter exactly as libsodium's
    /// reference implementation does; callers bound message lengths so the
    /// 32-bit counter never wraps and the carry is unobservable there.
    state: [u32; 16],
}

impl ChaCha20 {
    /// RFC 8439 / libsodium `_ietf` layout: word 12 is the block counter and
    /// words 13..16 hold the 96-bit nonce.
    pub(crate) fn ietf(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = Self::keyed(key);
        state[12] = counter;
        state[13] = load_u32_le(&nonce[0..4]);
        state[14] = load_u32_le(&nonce[4..8]);
        state[15] = load_u32_le(&nonce[8..12]);
        Self { state }
    }

    /// Original 64-bit counter layout (libsodium `crypto_stream_chacha20` and
    /// the XChaCha20 inner cipher): words 12 and 13 hold the block counter
    /// and words 14..16 the 64-bit nonce.
    pub(crate) fn legacy(key: &[u8; 32], nonce: &[u8; 8], counter: u64) -> Self {
        let mut state = Self::keyed(key);
        state[12] = counter as u32;
        state[13] = (counter >> 32) as u32;
        state[14] = load_u32_le(&nonce[0..4]);
        state[15] = load_u32_le(&nonce[4..8]);
        Self { state }
    }

    /// The constant and key words; words 12..16 are left zero.
    fn keyed(key: &[u8; 32]) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&SIGMA);
        for (word, bytes) in state[4..12].iter_mut().zip(key.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        state
    }

    /// XORs the keystream from the current block into `data`.
    pub(crate) fn apply_keystream(&mut self, data: &mut [u8]) {
        self.apply(InPlace(data));
    }

    /// Writes `input` XORed with the keystream from the current block into
    /// `output`. The two slices must have the same length.
    pub(crate) fn apply_keystream_b2b(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert_eq!(input.len(), output.len());
        self.apply(BufferToBuffer { input, output });
    }

    /// Vector kernel for this run: the best one the CPU supports.
    #[cfg(dryoc_stream_kernel)]
    #[inline]
    fn kernel() -> Option<vector::Kernel> {
        vector::detect()
    }

    /// Writes the raw keystream of the current block into the zero-filled
    /// `head`, then XORs the keystream of the following blocks into `data`.
    /// When the head and the data together fit one small vector run they
    /// share it, so the AEAD constructions get their Poly1305 key block and a
    /// short message for the price of one run instead of two dependent
    /// scalar blocks.
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
        #[cfg(dryoc_stream_kernel)]
        {
            self.apply_with_head_using(Self::kernel(), head, sink);
        }
        #[cfg(not(dryoc_stream_kernel))]
        {
            self.apply_head(head);
            self.apply_scalar(sink);
        }
    }

    /// [`apply_with_head`](Self::apply_with_head) with a chosen vector kernel
    /// (`None` for scalar blocks only).
    #[cfg(dryoc_stream_kernel)]
    fn apply_with_head_using<S: Sink>(
        &mut self,
        kernel: Option<vector::Kernel>,
        head: &mut [u8; 64],
        sink: S,
    ) {
        let sink = match kernel {
            Some(kernel) => match self.apply_with_head_fused(kernel, head, sink) {
                Ok(()) => return,
                // The head does not fit the lane set beside the data: make
                // it the companion block of the first run when the kernel
                // computes that alongside the run.
                Err(sink) if kernel.fuses_extra_block() => {
                    match self.apply_with_head_companion(kernel, head, sink) {
                        Ok(()) => return,
                        Err(sink) => sink,
                    }
                }
                Err(sink) => sink,
            },
            None => sink,
        };
        self.apply_head(head);
        self.apply_using(kernel, sink);
    }

    /// Produces `head` as the companion block of the first vector run over
    /// `sink` ([`Kernel::xor_chunk_with_block`]), for data too long
    /// to share a lane set with the head: a sink of one lane set (whole
    /// blocks and a trailing partial one) is finished by that run; a longer
    /// one continues through the normal driver. Hands the untouched sink back
    /// when it is empty.
    #[cfg(dryoc_stream_kernel)]
    fn apply_with_head_companion<S: Sink>(
        &mut self,
        kernel: vector::Kernel,
        head: &mut [u8; 64],
        mut sink: S,
    ) -> Result<(), S> {
        if sink.is_empty() {
            return Err(sink);
        }
        let chunk = kernel.chunk();
        let head_counter = self.counter();
        self.advance_counter(1);
        let len = (sink.len() / 64 * 64).min(chunk);
        // As in `apply_using`: a run with spare lanes also produces the
        // keystream of a trailing partial block.
        let partial_tail = if len < chunk { sink.len() - len } else { 0 };
        let mut partial = [0u8; 64];
        let (input, output) = sink.take(len);
        kernel.xor_chunk_with_block(
            &self.state,
            self.counter(),
            input,
            output,
            (partial_tail > 0).then_some(&mut partial),
            (head_counter, head),
        );
        self.advance_counter((len / 64) as u64);
        if partial_tail > 0 {
            self.advance_counter(1);
            sink.xor(&partial[..partial_tail]);
            zeroize_bytes(&mut partial);
        }
        self.apply_using(Some(kernel), sink);
        Ok(())
    }

    /// Writes the raw keystream of the current block into the zero-filled
    /// `head` and advances past it.
    fn apply_head(&mut self, head: &mut [u8; 64]) {
        chacha20_soft::block(&self.state, self.counter(), head);
        self.advance_counter(1);
    }

    /// Produces `head` and all of `sink` in one small vector run when they fit
    /// ([`vector::SMALL_BLOCKS`] blocks including a trailing partial one), the
    /// data staged through a contiguous buffer so the kernel sees plain whole
    /// blocks. Hands the untouched sink back when they do not fit.
    #[cfg(dryoc_stream_kernel)]
    fn apply_with_head_fused<S: Sink>(
        &mut self,
        kernel: vector::Kernel,
        head: &mut [u8; 64],
        mut sink: S,
    ) -> Result<(), S> {
        let blocks = 1 + sink.len().div_ceil(64);
        if sink.is_empty() || blocks > vector::SMALL_BLOCKS {
            return Err(sink);
        }
        let len = sink.len();
        let whole = len / 64 * 64;
        let mut staged = [0u8; vector::SMALL_BLOCKS * 64];
        let (input, output) = sink.take(len);
        staged[64..64 + len].copy_from_slice(input.unwrap_or(&*output));
        // Whole blocks (head included) go through the kernel's output; a
        // partial final block is filled through the partial slot, whose
        // keystream is XORed into the staged data afterwards.
        let (kernel_output, partial_data) = staged[..64 + len].split_at_mut(64 + whole);
        let mut partial = [0u8; 64];
        let has_partial = !partial_data.is_empty();
        kernel.xor_small(
            &self.state,
            self.counter(),
            None,
            kernel_output,
            has_partial.then_some(&mut partial),
        );
        for (byte, ks) in partial_data.iter_mut().zip(&partial) {
            *byte ^= ks;
        }
        head.copy_from_slice(&staged[..64]);
        output.copy_from_slice(&staged[64..64 + len]);
        // Only the written prefix of `staged` ever held keystream.
        zeroize_bytes(&mut staged[..64 + len]);
        if has_partial {
            zeroize_bytes(&mut partial);
        }
        self.advance_counter(blocks as u64);
        Ok(())
    }

    fn apply<S: Sink>(&mut self, sink: S) {
        #[cfg(dryoc_stream_kernel)]
        self.apply_using(Self::kernel(), sink);
        #[cfg(not(dryoc_stream_kernel))]
        self.apply_scalar(sink);
    }

    /// [`apply`](Self::apply) with a chosen vector kernel (`None` for scalar
    /// blocks only): whole chunks through the kernel while enough blocks
    /// remain, the rest through scalar blocks; a full chunk followed by
    /// exactly one more block (whole or partial) takes that block as the
    /// run's companion block when the kernel fuses it.
    #[cfg(dryoc_stream_kernel)]
    fn apply_using<S: Sink>(&mut self, kernel: Option<vector::Kernel>, mut sink: S) {
        if let Some(kernel) = kernel {
            // A kernel run costs about the same whatever the number of blocks
            // it is asked for, so from `tail_min_blocks` on even a partly
            // used chunk beats a run of dependent scalar blocks.
            let chunk = kernel.chunk();
            loop {
                if sink.len().div_ceil(64) < kernel.tail_min_blocks() {
                    break;
                }
                let len = (sink.len() / 64 * 64).min(chunk);
                let companion =
                    kernel.fuses_extra_block() && sink.len() > chunk && sink.len() <= chunk + 64;
                // A final run has spare block slots, so it also produces the
                // keystream of a trailing partial block; with a companion
                // block the tail (up to a whole block) comes from that.
                let partial_tail = if companion {
                    sink.len() - chunk
                } else if len < chunk {
                    sink.len() - len
                } else {
                    0
                };
                let mut partial = [0u8; 64];
                let (input, output) = sink.take(len);
                if companion {
                    kernel.xor_chunk_with_block(
                        &self.state,
                        self.counter(),
                        input,
                        output,
                        None,
                        (self.counter() + kernel.blocks() as u64, &mut partial),
                    );
                } else {
                    kernel.xor_chunk(
                        &self.state,
                        self.counter(),
                        input,
                        output,
                        (partial_tail > 0).then_some(&mut partial),
                    );
                }
                self.advance_counter((len / 64) as u64);
                if partial_tail > 0 {
                    self.advance_counter(1);
                    sink.xor(&partial[..partial_tail]);
                    zeroize_bytes(&mut partial);
                }
            }
        }
        self.apply_scalar(sink);
    }

    /// Whole blocks then a trailing partial block, one scalar block at a time.
    fn apply_scalar<S: Sink>(&mut self, mut sink: S) {
        let mut block = [0u8; 64];
        while sink.len() >= 64 {
            chacha20_soft::block(&self.state, self.counter(), &mut block);
            self.advance_counter(1);
            sink.xor(&block);
        }

        let tail = sink.len();
        if tail > 0 {
            chacha20_soft::block(&self.state, self.counter(), &mut block);
            self.advance_counter(1);
            sink.xor(&block[..tail]);
        }
        zeroize_bytes(&mut block);
    }

    /// The 64-bit block counter held in words 12 and 13.
    #[inline]
    fn counter(&self) -> u64 {
        u64::from(self.state[12]) | (u64::from(self.state[13]) << 32)
    }

    #[inline]
    fn advance_counter(&mut self, blocks: u64) {
        let counter = self
            .counter()
            .checked_add(blocks)
            .expect("ChaCha20 block counter overflow");
        self.state[12] = counter as u32;
        self.state[13] = (counter >> 32) as u32;
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::{ChaCha20 as RustCryptoChaCha20, ChaCha20Legacy};

    use super::*;

    const LENS: [usize; 15] = [
        0, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1023, 1024, 4096, 65536,
    ];

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 8439 section 2.3.2: the block function test vector.
    #[test]
    fn test_rfc8439_block() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
        let expected = hex(concat!(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        ));

        let cipher = ChaCha20::ietf(&key, &nonce, 1);
        let mut block = [0u8; 64];
        chacha20_soft::block(&cipher.state, cipher.counter(), &mut block);
        assert_eq!(block.to_vec(), expected);

        let mut cipher = ChaCha20::ietf(&key, &nonce, 1);
        let mut keystream = [0u8; 64];
        cipher.apply_keystream(&mut keystream);
        assert_eq!(keystream.to_vec(), expected);
        assert_eq!(cipher.counter(), 2 | (0x0900_0000 << 32));
    }

    /// RFC 8439 section 2.4.2: encryption starting at block 1.
    #[test]
    fn test_rfc8439_encryption() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = hex("000000000000004a00000000").try_into().unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
                          tip for the future, sunscreen would be it.";
        let expected = hex(concat!(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
            "5af90bbf74a35be6b40b8eedf2785e42874d",
        ));
        assert_eq!(plaintext.len(), 114);

        let mut cipher = ChaCha20::ietf(&key, &nonce, 1);
        let mut in_place = plaintext.to_vec();
        cipher.apply_keystream(&mut in_place);
        assert_eq!(in_place, expected);
        // The partial second block still consumed a whole counter step.
        assert_eq!(cipher.counter(), 3);

        let mut cipher = ChaCha20::ietf(&key, &nonce, 1);
        let mut b2b = vec![0u8; plaintext.len()];
        cipher.apply_keystream_b2b(plaintext, &mut b2b);
        assert_eq!(b2b, expected);
    }

    fn rustcrypto_ietf(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        let mut cipher = RustCryptoChaCha20::new(key.into(), nonce.into());
        cipher.seek(u64::from(counter) * 64);
        cipher.apply_keystream(data);
    }

    fn rustcrypto_legacy(key: &[u8; 32], nonce: &[u8; 8], counter: u64, data: &mut [u8]) {
        let mut cipher = ChaCha20Legacy::new(key.into(), nonce.into());
        cipher.seek(counter * 64);
        cipher.apply_keystream(data);
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// The legacy layout carries the block counter from word 12 into word
    /// 13, which the IETF layout treats as nonce.
    #[test]
    fn test_legacy_counter_carries_into_word_13() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 8];
        for start in [u64::from(u32::MAX) - 2, u64::from(u32::MAX), (1 << 40) - 1] {
            for len in [1, 64, 65, 3 * 64, 4 * 64 + 5, 9 * 64 - 1] {
                let plaintext = pattern(len);
                let mut expected = plaintext.clone();
                rustcrypto_legacy(&key, &nonce, start, &mut expected);

                let mut cipher = ChaCha20::legacy(&key, &nonce, start);
                let mut actual = plaintext.clone();
                cipher.apply_keystream(&mut actual);
                assert_eq!(actual, expected, "start {start}, len {len}");
                assert_eq!(cipher.counter(), start + len.div_ceil(64) as u64);
            }
        }
    }

    #[test]
    fn test_ietf_matches_rustcrypto_at_every_length() {
        let key: [u8; 32] = std::array::from_fn(|i| (i * 3 + 1) as u8);
        let nonce: [u8; 12] = std::array::from_fn(|i| (i * 5 + 7) as u8);
        let nonce_word = u64::from(load_u32_le(&nonce[0..4])) << 32;
        for len in LENS {
            for counter in [0u32, 1, 7] {
                let plaintext = pattern(len);
                let mut expected = plaintext.clone();
                rustcrypto_ietf(&key, &nonce, counter, &mut expected);

                let mut cipher = ChaCha20::ietf(&key, &nonce, counter);
                let mut actual = plaintext.clone();
                cipher.apply_keystream(&mut actual);
                assert_eq!(actual, expected, "in place, len {len}, counter {counter}");
                assert_eq!(
                    cipher.counter(),
                    nonce_word | (u64::from(counter) + len.div_ceil(64) as u64)
                );

                let mut cipher = ChaCha20::ietf(&key, &nonce, counter);
                let mut actual = vec![0u8; len];
                cipher.apply_keystream_b2b(&plaintext, &mut actual);
                assert_eq!(actual, expected, "b2b, len {len}, counter {counter}");
            }
        }
    }

    /// Chained calls continue at the next block, like libsodium's `_xor_ic`
    /// with an advanced initial counter.
    #[test]
    fn test_chained_calls_advance_by_whole_blocks() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let mut expected = vec![0u8; 32 + 64 + 100 + 4096];
        rustcrypto_ietf(&key, &nonce, 0, &mut expected[..32]);
        rustcrypto_ietf(&key, &nonce, 1, &mut expected[32..96]);
        rustcrypto_ietf(&key, &nonce, 2, &mut expected[96..196]);
        rustcrypto_ietf(&key, &nonce, 4, &mut expected[196..]);

        let mut cipher = ChaCha20::ietf(&key, &nonce, 0);
        let mut actual = vec![0u8; expected.len()];
        cipher.apply_keystream(&mut actual[..32]);
        cipher.apply_keystream(&mut actual[32..96]);
        cipher.apply_keystream(&mut actual[96..196]);
        cipher.apply_keystream(&mut actual[196..]);
        assert_eq!(actual, expected);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    mod libsodium {
        use libc::c_ulonglong;

        use super::*;

        fn sodium_ietf(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
            // SAFETY: the buffers are valid for the given lengths and libsodium
            // permits `c == m`.
            let rc = unsafe {
                libsodium_sys::crypto_stream_chacha20_ietf_xor_ic(
                    data.as_mut_ptr(),
                    data.as_ptr(),
                    data.len() as c_ulonglong,
                    nonce.as_ptr(),
                    counter,
                    key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
        }

        fn sodium_legacy(key: &[u8; 32], nonce: &[u8; 8], counter: u64, data: &mut [u8]) {
            // SAFETY: the buffers are valid for the given lengths and libsodium
            // permits `c == m`.
            let rc = unsafe {
                libsodium_sys::crypto_stream_chacha20_xor_ic(
                    data.as_mut_ptr(),
                    data.as_ptr(),
                    data.len() as c_ulonglong,
                    nonce.as_ptr(),
                    counter,
                    key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
        }

        #[test]
        fn test_matches_libsodium_stream_chacha20() {
            let key: [u8; 32] = std::array::from_fn(|i| (i * 11 + 3) as u8);
            let ietf_nonce: [u8; 12] = std::array::from_fn(|i| (i * 13 + 5) as u8);
            let legacy_nonce: [u8; 8] = std::array::from_fn(|i| (i * 17 + 9) as u8);
            for len in LENS {
                let plaintext = pattern(len);

                let mut expected = plaintext.clone();
                sodium_ietf(&key, &ietf_nonce, 3, &mut expected);
                let mut actual = vec![0u8; len];
                ChaCha20::ietf(&key, &ietf_nonce, 3).apply_keystream_b2b(&plaintext, &mut actual);
                assert_eq!(actual, expected, "ietf, len {len}");

                let counter = u64::from(u32::MAX) - 1;
                let mut expected = plaintext.clone();
                sodium_legacy(&key, &legacy_nonce, counter, &mut expected);
                let mut actual = plaintext.clone();
                ChaCha20::legacy(&key, &legacy_nonce, counter).apply_keystream(&mut actual);
                assert_eq!(actual, expected, "legacy, len {len}");
            }
        }
    }

    #[cfg(dryoc_stream_kernel)]
    mod vector_path {
        use super::*;

        /// Every kernel the CPU supports. Every little-endian AArch64 CPU
        /// has NEON; an x86-64 CPU without AVX2 leaves this empty and the
        /// driver tests below cover the scalar path only.
        fn kernels() -> Vec<vector::Kernel> {
            let kernels = vector::Kernel::all();
            #[cfg(target_arch = "aarch64")]
            assert!(!kernels.is_empty(), "NEON path must run on this machine");
            kernels
        }

        /// Keystream for blocks `counter..` computed with the scalar block
        /// function only, XORed into `data`.
        fn scalar_xor(state: &[u32; 16], counter: u64, data: &mut [u8]) {
            let mut block = [0u8; 64];
            for (i, chunk) in data.chunks_mut(64).enumerate() {
                chacha20_soft::block(state, counter + i as u64, &mut block);
                for (byte, ks) in chunk.iter_mut().zip(block) {
                    *byte ^= ks;
                }
            }
        }

        #[test]
        fn test_kernel_chunk_matches_scalar_blocks() {
            let cipher = ChaCha20::legacy(&[0x11u8; 32], &[0x22u8; 8], 0);
            // Counters whose lanes straddle the 32-bit boundary check the carry
            // into word 13.
            let counters = [
                0u64,
                1,
                5,
                u32::MAX as u64 - 3,
                u32::MAX as u64 - 1,
                u32::MAX as u64,
                1 << 40,
            ];
            for (kernel, counter) in kernels().into_iter().flat_map(|k| counters.map(|c| (k, c))) {
                let plaintext = pattern(kernel.chunk());
                let mut expected = plaintext.clone();
                scalar_xor(&cipher.state, counter, &mut expected);

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
                    chacha20_soft::block(&cipher.state, counter + blocks as u64, &mut block);
                    assert_eq!(
                        partial, block,
                        "{kernel:?} partial after {blocks}, counter {counter}"
                    );
                }
            }
        }

        /// Every kernel the CPU supports plus the scalar-only path, each
        /// driven through the production driver.
        fn drivers() -> Vec<Option<vector::Kernel>> {
            let mut drivers = vec![None];
            drivers.extend(kernels().into_iter().map(Some));
            drivers
        }

        /// Lengths around every kernel's chunk and tail thresholds, so the
        /// bulk, partial-slot and scalar-tail paths are all crossed.
        fn threshold_lens() -> Vec<usize> {
            let mut lens: Vec<usize> = LENS.into();
            lens.extend([31, 127, 128, 200, 1024 + 32]);
            for kernel in kernels() {
                let tail_min = kernel.tail_min_blocks() * 64;
                let chunk = kernel.chunk();
                lens.extend([
                    tail_min - 65,
                    tail_min - 64,
                    tail_min - 63,
                    tail_min - 1,
                    tail_min,
                    tail_min + 32,
                    tail_min + 33,
                    chunk - 65,
                    chunk - 64,
                    chunk - 63,
                    chunk - 1,
                    chunk,
                    chunk + 1,
                    chunk + 31,
                    chunk + 63,
                    chunk + 64,
                    chunk + 65,
                    chunk + tail_min - 65,
                    chunk + tail_min - 1,
                    chunk + tail_min + 32,
                    2 * chunk - 64,
                    2 * chunk + 1,
                    2 * chunk + 32,
                    2 * chunk + 64,
                    2 * chunk + 65,
                ]);
            }
            lens.sort_unstable();
            lens.dedup();
            lens
        }

        /// The driver must XOR exactly the scalar keystream for blocks
        /// `counter..` and advance the counter by `ceil(len / 64)` whichever
        /// kernel it runs (or none), in place and buffer to buffer.
        #[test]
        fn test_driver_matches_scalar_keystream_for_every_kernel() {
            let key = [0x33u8; 32];
            let nonce = [0x44u8; 8];
            let lens = threshold_lens();
            for kernel in drivers() {
                for &len in &lens {
                    let plaintext = pattern(len);
                    let cipher = ChaCha20::legacy(&key, &nonce, 5);
                    let mut expected = plaintext.clone();
                    scalar_xor(&cipher.state, cipher.counter(), &mut expected);
                    let expected_counter = 5 + len.div_ceil(64) as u64;

                    let mut cipher = ChaCha20::legacy(&key, &nonce, 5);
                    let mut actual = plaintext.clone();
                    cipher.apply_using(kernel, InPlace(&mut actual));
                    assert_eq!(actual, expected, "{kernel:?} in place, len {len}");
                    assert_eq!(
                        cipher.counter(),
                        expected_counter,
                        "{kernel:?} counter, len {len}"
                    );

                    let mut cipher = ChaCha20::legacy(&key, &nonce, 5);
                    let mut actual = vec![0u8; len];
                    cipher.apply_using(
                        kernel,
                        BufferToBuffer {
                            input: &plaintext,
                            output: &mut actual,
                        },
                    );
                    assert_eq!(actual, expected, "{kernel:?} b2b, len {len}");
                    assert_eq!(
                        cipher.counter(),
                        expected_counter,
                        "{kernel:?} counter, len {len}"
                    );
                }
            }
        }

        /// The head-block driver must equal the scalar keystream for block
        /// `counter` (the head) followed by the data, for every kernel and
        /// every data length around the fused-run and kernel thresholds
        /// (including no data at all).
        #[test]
        fn test_head_driver_matches_scalar_keystream_for_every_kernel() {
            let key = [0x77u8; 32];
            let nonce = [0x88u8; 8];
            let mut lens = threshold_lens();
            lens.extend(
                (0..vector::SMALL_BLOCKS + 1).flat_map(|b| [b * 64, b * 64 + 1, b * 64 + 63]),
            );
            for kernel in drivers() {
                for &len in &lens {
                    let plaintext = pattern(len);
                    let cipher = ChaCha20::legacy(&key, &nonce, 3);
                    let mut expected_head = [0u8; 64];
                    chacha20_soft::block(&cipher.state, 3, &mut expected_head);
                    let mut expected = plaintext.clone();
                    scalar_xor(&cipher.state, 4, &mut expected);
                    let expected_counter = 4 + len.div_ceil(64) as u64;

                    let mut head = [0u8; 64];
                    let mut in_place = plaintext.clone();
                    let mut cipher = ChaCha20::legacy(&key, &nonce, 3);
                    cipher.apply_with_head_using(kernel, &mut head, InPlace(&mut in_place));
                    assert_eq!(head, expected_head, "{kernel:?} in place head, len {len}");
                    assert_eq!(in_place, expected, "{kernel:?} in place, len {len}");
                    assert_eq!(
                        cipher.counter(),
                        expected_counter,
                        "{kernel:?} counter, len {len}"
                    );

                    let mut head = [0u8; 64];
                    let mut b2b = vec![0u8; len];
                    let mut cipher = ChaCha20::legacy(&key, &nonce, 3);
                    cipher.apply_with_head_using(
                        kernel,
                        &mut head,
                        BufferToBuffer {
                            input: &plaintext,
                            output: &mut b2b,
                        },
                    );
                    assert_eq!(head, expected_head, "{kernel:?} b2b head, len {len}");
                    assert_eq!(b2b, expected, "{kernel:?} b2b, len {len}");
                    assert_eq!(
                        cipher.counter(),
                        expected_counter,
                        "{kernel:?} counter, len {len}"
                    );
                }
            }
        }

        /// The public entry points pick a kernel on this machine and equal
        /// the driver forced to that kernel, output and counter, with and
        /// without a head block, in place and buffer to buffer.
        #[test]
        fn test_default_dispatch_uses_detected_kernel() {
            let kernel = ChaCha20::kernel();
            #[cfg(target_arch = "aarch64")]
            assert!(kernel.is_some(), "NEON path must run on this machine");
            let key = [0x99u8; 32];
            let nonce = [0xaau8; 8];
            for len in [0, 1, 63, 64, 65, 200, 1024 + 32] {
                let plaintext = pattern(len);
                let mut expected_head = [0u8; 64];
                let mut expected = plaintext.clone();
                let mut forced = ChaCha20::legacy(&key, &nonce, 9);
                forced.apply_with_head_using(kernel, &mut expected_head, InPlace(&mut expected));

                let mut head = [0u8; 64];
                let mut in_place = plaintext.clone();
                let mut cipher = ChaCha20::legacy(&key, &nonce, 9);
                cipher.apply_keystream_with_head(&mut head, &mut in_place);
                assert_eq!(
                    (head, &in_place, cipher.counter()),
                    (expected_head, &expected, forced.counter()),
                    "head, len {len}"
                );

                let mut head = [0u8; 64];
                let mut b2b = vec![0u8; len];
                let mut cipher = ChaCha20::legacy(&key, &nonce, 9);
                cipher.apply_keystream_b2b_with_head(&mut head, &plaintext, &mut b2b);
                assert_eq!(
                    (head, &b2b, cipher.counter()),
                    (expected_head, &expected, forced.counter()),
                    "b2b head, len {len}"
                );

                let mut expected = plaintext.clone();
                let mut forced = ChaCha20::legacy(&key, &nonce, 9);
                forced.apply_using(kernel, InPlace(&mut expected));
                let mut in_place = plaintext.clone();
                let mut cipher = ChaCha20::legacy(&key, &nonce, 9);
                cipher.apply_keystream(&mut in_place);
                assert_eq!(
                    (&in_place, cipher.counter()),
                    (&expected, forced.counter()),
                    "len {len}"
                );
                let mut b2b = vec![0u8; len];
                let mut cipher = ChaCha20::legacy(&key, &nonce, 9);
                cipher.apply_keystream_b2b(&plaintext, &mut b2b);
                assert_eq!(
                    (&b2b, cipher.counter()),
                    (&expected, forced.counter()),
                    "b2b, len {len}"
                );
            }
        }
    }
}
