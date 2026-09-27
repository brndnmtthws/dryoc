//! Plumbing shared by the stream ciphers (`chacha20`, `salsa20`): where
//! keystream bytes go, independent of which backend produces them.

// `is_empty`, `take` and `Dest` only have callers in the vector drivers, so
// scalar-only builds see them as dead.
#![cfg_attr(not(dryoc_stream_kernel), allow(dead_code))]

use core::mem;

/// Expands `$body` sixteen times, once per word of a block, with the
/// constant `$i` set to the word's index `0..16`: the feed-forward of the
/// scalar blocks, where the working state is indexed rather than iterated.
/// A `zip` over the block words (or a loop indexing them) takes their
/// addresses: the iterator constructors are out of line at opt-level `z`
/// and `s`, and a loop that is not unrolled keeps the words in a stack
/// array.
#[rustfmt::skip]
macro_rules! each_word {
    ($i:ident, $body:block) => {
        { const $i: usize = 0; $body }
        { const $i: usize = 1; $body }
        { const $i: usize = 2; $body }
        { const $i: usize = 3; $body }
        { const $i: usize = 4; $body }
        { const $i: usize = 5; $body }
        { const $i: usize = 6; $body }
        { const $i: usize = 7; $body }
        { const $i: usize = 8; $body }
        { const $i: usize = 9; $body }
        { const $i: usize = 10; $body }
        { const $i: usize = 11; $body }
        { const $i: usize = 12; $body }
        { const $i: usize = 13; $body }
        { const $i: usize = 14; $body }
        { const $i: usize = 15; $body }
    };
}
pub(crate) use each_word;

/// Destination of keystream bytes: either a buffer XORed in place, or an
/// `input` buffer XORed into a distinct `output` buffer. Each XOR consumes
/// the front of the sink.
///
/// `take` and `xor` (and the slice splits and `zip` inside them) are out of
/// line at opt-level `z`, which adds no copy: they only see the caller's
/// buffers and keystream scratch that the drivers wipe once per call.
pub(crate) trait Sink {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// XORs `keystream` into the next `keystream.len()` bytes; requires
    /// `keystream.len() <= self.len()`.
    fn xor(&mut self, keystream: &[u8]);

    /// Splits off the next `n` bytes as `(input, output)`; `input` is `None`
    /// when the sink is XORed in place. Requires `n <= self.len()`.
    fn take(&mut self, n: usize) -> (Option<&[u8]>, &mut [u8]);
}

pub(crate) struct InPlace<'a>(pub(crate) &'a mut [u8]);

impl Sink for InPlace<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn xor(&mut self, keystream: &[u8]) {
        let (front, rest) = mem::take(&mut self.0).split_at_mut(keystream.len());
        for (byte, ks) in front.iter_mut().zip(keystream) {
            *byte ^= ks;
        }
        self.0 = rest;
    }

    #[inline]
    fn take(&mut self, n: usize) -> (Option<&[u8]>, &mut [u8]) {
        let (front, rest) = mem::take(&mut self.0).split_at_mut(n);
        self.0 = rest;
        (None, front)
    }
}

pub(crate) struct BufferToBuffer<'a> {
    pub(crate) input: &'a [u8],
    pub(crate) output: &'a mut [u8],
}

/// XORs the raw keystream of the scalar block `counter` into `extra`,
/// zeroizing the block copy afterwards. Shared by the ChaCha20 and XSalsa20
/// kernel drivers for companion blocks that no lane set covers. `block` and
/// the `zip` are out of line at opt-level `z` and `s`, which adds no copy:
/// they only get `state` (the cipher's own, wiped on drop), `extra` and the
/// scratch `ks`, which is wiped here.
#[cfg(any(
    dryoc_stream_kernel,
    all(feature = "simd_backend", feature = "nightly")
))]
pub(crate) fn xor_scalar_block(
    state: &[u32; 16],
    counter: u64,
    extra: &mut [u8; 64],
    block: impl Fn(&[u32; 16], u64, &mut [u8; 64]),
) {
    let mut ks = [0u8; 64];
    block(state, counter, &mut ks);
    for (byte, ks_byte) in extra.iter_mut().zip(&ks) {
        *byte ^= *ks_byte;
    }
    crate::utils::zeroize_bytes(&mut ks);
}

impl Sink for BufferToBuffer<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.input.len()
    }

    #[inline]
    fn xor(&mut self, keystream: &[u8]) {
        let (input, input_rest) = self.input.split_at(keystream.len());
        let (output, output_rest) = mem::take(&mut self.output).split_at_mut(keystream.len());
        for ((out, byte), ks) in output.iter_mut().zip(input).zip(keystream) {
            *out = byte ^ ks;
        }
        self.input = input_rest;
        self.output = output_rest;
    }

    #[inline]
    fn take(&mut self, n: usize) -> (Option<&[u8]>, &mut [u8]) {
        let (input, input_rest) = self.input.split_at(n);
        let (output, output_rest) = mem::take(&mut self.output).split_at_mut(n);
        self.input = input_rest;
        self.output = output_rest;
        (Some(input), output)
    }
}

/// Where one kernel run puts its keystream: block `i < output.len()` is
/// XORed into `output[i]` (from `input[i]`, or in place when `input` is
/// `None`); block `output.len()` is XORed into `partial` when given, which
/// the caller zero-fills to receive raw keystream; later blocks are
/// discarded.
pub(crate) struct Dest<'a> {
    input: Option<&'a [[u8; 64]]>,
    output: &'a mut [[u8; 64]],
    partial: Option<&'a mut [u8; 64]>,
}

impl<'a> Dest<'a> {
    /// The destination of one kernel run of at most `max_blocks` blocks:
    /// `output` holds whole blocks (at most `max_blocks` of them), `input`
    /// when given is as long as `output`, and `partial` receives the block
    /// after `output`'s.
    #[inline(always)]
    pub(crate) fn new(
        max_blocks: usize,
        input: Option<&'a [u8]>,
        output: &'a mut [u8],
        partial: Option<&'a mut [u8; 64]>,
    ) -> Self {
        debug_assert!(output.len() <= max_blocks * 64 && output.len().is_multiple_of(64));
        debug_assert!(input.is_none_or(|input| input.len() == output.len()));
        Self {
            input: input.map(|input| input.as_chunks::<64>().0),
            output: output.as_chunks_mut::<64>().0,
            partial,
        }
    }

    /// `(source, destination)` for block `i`, where a `None` source means
    /// XOR in place. The `input.map` closure is out of line at opt-level
    /// `z`, which adds no copy: it only sees the input blocks and `i`.
    #[inline(always)]
    pub(crate) fn block(&mut self, i: usize) -> Option<(Option<&[u8; 64]>, &mut [u8; 64])> {
        if i < self.output.len() {
            Some((self.input.map(|input| &input[i]), &mut self.output[i]))
        } else if i == self.output.len() {
            self.partial.as_deref_mut().map(|partial| (None, partial))
        } else {
            None
        }
    }
}

/// Reference checks shared by the ChaCha20 and Salsa20 kernel tests.
#[cfg(test)]
pub(crate) mod test_util {
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    use crate::test_prelude::*;

    /// A scalar block function: writes keystream block `counter` of `state`.
    pub(crate) type BlockFn = fn(&[u32; 16], u64, &mut [u8; 64]);

    /// XORs the keystream for blocks `counter..` (wrapping), computed one
    /// block at a time with `block`, into `data`.
    pub(crate) fn xor_scalar_blocks(
        block: BlockFn,
        state: &[u32; 16],
        counter: u64,
        data: &mut [u8],
    ) {
        let mut keystream = [0u8; 64];
        for (i, chunk) in data.chunks_mut(64).enumerate() {
            block(state, counter.wrapping_add(i as u64), &mut keystream);
            for (byte, ks) in chunk.iter_mut().zip(keystream) {
                *byte ^= ks;
            }
        }
    }

    /// Checks one kernel run against the scalar block function `block`, at
    /// counters whose lanes straddle the 32-bit boundary (the carry into the
    /// high counter word), in place and buffer to buffer, then clipped to
    /// every whole block count with the next block's raw keystream delivered
    /// through the zero-filled partial slot.
    ///
    /// `xor_chunk(counter, input, output, partial)` is the kernel's
    /// `xor_chunk` over `state`, producing `blocks` blocks per run; `kernel`
    /// names it in failure messages.
    #[cfg(any(
        dryoc_stream_kernel,
        all(feature = "simd_backend", feature = "nightly")
    ))]
    pub(crate) fn check_kernel_chunk(
        kernel: &dyn core::fmt::Debug,
        blocks: usize,
        state: &[u32; 16],
        block: BlockFn,
        xor_chunk: impl Fn(u64, Option<&[u8]>, &mut [u8], Option<&mut [u8; 64]>),
    ) {
        let counters = [
            0u64,
            1,
            5,
            u32::MAX as u64 - 3,
            u32::MAX as u64 - 1,
            u32::MAX as u64,
            1 << 40,
        ];
        let chunk = blocks * 64;
        let plaintext: Vec<u8> = (0..chunk as u32).map(|i| (i * 7 % 251) as u8).collect();
        for counter in counters {
            let mut expected = plaintext.clone();
            xor_scalar_blocks(block, state, counter, &mut expected);

            let mut in_place = plaintext.clone();
            xor_chunk(counter, None, &mut in_place, None);
            assert_eq!(in_place, expected, "{kernel:?} in place, counter {counter}");

            let mut b2b = vec![0u8; chunk];
            xor_chunk(counter, Some(&plaintext), &mut b2b, None);
            assert_eq!(b2b, expected, "{kernel:?} b2b, counter {counter}");

            for whole in 0..blocks {
                let len = whole * 64;
                let mut clipped = plaintext[..len].to_vec();
                let mut partial = [0u8; 64];
                xor_chunk(counter, None, &mut clipped, Some(&mut partial));
                assert_eq!(
                    clipped,
                    expected[..len],
                    "{kernel:?} clipped to {whole}, counter {counter}"
                );
                let mut keystream = [0u8; 64];
                block(state, counter + whole as u64, &mut keystream);
                assert_eq!(
                    partial, keystream,
                    "{kernel:?} partial after {whole}, counter {counter}"
                );
            }
        }
    }
}
