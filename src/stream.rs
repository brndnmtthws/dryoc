//! Plumbing shared by the stream ciphers (`chacha20`, `salsa20`): where
//! keystream bytes go, independent of which backend produces them.

// `is_empty`, `take` and `Dest` only have callers in the vector drivers, so
// scalar-only builds see them as dead.
#![cfg_attr(not(dryoc_stream_kernel), allow(dead_code))]

use std::mem;

/// Destination of keystream bytes: either a buffer XORed in place, or an
/// `input` buffer XORed into a distinct `output` buffer. Each XOR consumes
/// the front of the sink.
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
/// kernel drivers for companion blocks that no lane set covers.
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
    /// XOR in place.
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
