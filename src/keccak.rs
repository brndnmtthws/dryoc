//! Keccak sponge shared by SHA-3, the SHAKE and TurboSHAKE XOFs, and ML-KEM.
//!
//! [`Sponge`] is the FIPS 202 sponge over Keccak-p[1600] with a byte rate
//! `RATE` and `ROUNDS` rounds: 24 for SHA-3 and SHAKE, 12 for TurboSHAKE
//! (RFC 9861). It only absorbs, pads and squeezes; the wrappers decide when
//! padding happens and which domain byte it uses. The permutation comes from
//! the RustCrypto `keccak` crate, which selects the AArch64 SHA3-extension
//! implementation at runtime when the CPU has it.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    CRYPTO_XOF_SHAKE128_BLOCKBYTES, CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD,
    CRYPTO_XOF_SHAKE256_BLOCKBYTES,
};

/// SHAKE128 and TurboSHAKE128 absorb and squeeze 168 bytes per permutation.
pub(crate) const RATE_128: usize = CRYPTO_XOF_SHAKE128_BLOCKBYTES;
/// SHAKE256, TurboSHAKE256 and SHA3-256 absorb 136 bytes per permutation.
pub(crate) const RATE_256: usize = CRYPTO_XOF_SHAKE256_BLOCKBYTES;
/// SHA3-512 absorbs 72 bytes per permutation.
pub(crate) const RATE_512: usize = 72;

/// Keccak-f[1600] rounds, used by SHA-3 and SHAKE.
pub(crate) const ROUNDS_FULL: usize = 24;
/// Keccak-p[1600, 12] rounds, used by TurboSHAKE.
pub(crate) const ROUNDS_TURBO: usize = 12;

/// Domain byte (suffix bits plus the first padding bit) for SHA-3.
pub(crate) const DOMAIN_SHA3: u8 = 0x06;
/// Domain byte for SHAKE, and TurboSHAKE's standard domain.
pub(crate) const DOMAIN_SHAKE: u8 = CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD;

/// A Keccak sponge absorbing or squeezing `RATE` bytes per permutation.
///
/// `offset` is the byte position within the current rate block. The
/// permutation runs lazily, when the next byte would fall past the rate, so
/// absorbing or squeezing an exact multiple of the rate performs no
/// permutation that a later call might not need.
#[derive(Clone)]
pub(crate) struct Sponge<const RATE: usize, const ROUNDS: usize> {
    state: [u64; 25],
    offset: usize,
    keccak: keccak::Keccak,
}

impl<const RATE: usize, const ROUNDS: usize> Sponge<RATE, ROUNDS> {
    pub(crate) fn new() -> Self {
        const { assert!(RATE > 0 && RATE < 200 && RATE.is_multiple_of(8)) };
        Self {
            state: [0; 25],
            offset: 0,
            keccak: keccak::Keccak::new(),
        }
    }

    fn permute(&mut self) {
        let state = &mut self.state;
        self.keccak.with_p1600::<ROUNDS>(|p1600| p1600(state));
        self.offset = 0;
    }

    /// XORs `input` into the rate.
    pub(crate) fn absorb(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.offset == RATE {
                self.permute();
            }
            let take = input.len().min(RATE - self.offset);
            let (chunk, rest) = input.split_at(take);
            xor_into(&mut self.state, self.offset, chunk);
            self.offset += take;
            input = rest;
        }
    }

    /// Appends the `domain` byte and the final padding bit, then permutes, so
    /// the sponge is ready to squeeze. `domain` must be in `0x01..=0x7f`.
    pub(crate) fn pad(&mut self, domain: u8) {
        debug_assert!((0x01..=0x7f).contains(&domain));
        if self.offset == RATE {
            self.permute();
        }
        xor_into(&mut self.state, self.offset, &[domain]);
        xor_into(&mut self.state, RATE - 1, &[0x80]);
        self.permute();
    }

    /// Fills `output` from the rate, permuting between blocks.
    pub(crate) fn squeeze(&mut self, mut output: &mut [u8]) {
        while !output.is_empty() {
            if self.offset == RATE {
                self.permute();
            }
            let take = output.len().min(RATE - self.offset);
            let (chunk, rest) = output.split_at_mut(take);
            extract(&self.state, self.offset, chunk);
            self.offset += take;
            output = rest;
        }
    }
}

impl<const RATE: usize, const ROUNDS: usize> Zeroize for Sponge<RATE, ROUNDS> {
    fn zeroize(&mut self) {
        crate::utils::zeroize_u64s(&mut self.state);
        self.offset.zeroize();
    }
}

impl<const RATE: usize, const ROUNDS: usize> Drop for Sponge<RATE, ROUNDS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const RATE: usize, const ROUNDS: usize> ZeroizeOnDrop for Sponge<RATE, ROUNDS> {}

/// XORs `bytes` into the little-endian lanes of `state`, starting at byte
/// `offset`. Aligned eight-byte runs are XORed one lane at a time.
fn xor_into(state: &mut [u64; 25], offset: usize, bytes: &[u8]) {
    let (head, body) = bytes.split_at(bytes.len().min(offset.wrapping_neg() % 8));
    for (i, &byte) in head.iter().enumerate() {
        xor_byte(state, offset + i, byte);
    }
    let lane = (offset + head.len()) / 8;
    let (words, tail) = body.as_chunks::<8>();
    for (word, chunk) in state[lane..].iter_mut().zip(words) {
        *word ^= u64::from_le_bytes(*chunk);
    }
    let tail_start = (lane + words.len()) * 8;
    for (i, &byte) in tail.iter().enumerate() {
        xor_byte(state, tail_start + i, byte);
    }
}

fn xor_byte(state: &mut [u64; 25], pos: usize, byte: u8) {
    state[pos / 8] ^= u64::from(byte) << (8 * (pos % 8));
}

/// Copies the little-endian bytes of `state` starting at byte `offset` into
/// `output`.
fn extract(state: &[u64; 25], offset: usize, output: &mut [u8]) {
    let head_len = output.len().min(offset.wrapping_neg() % 8);
    let (head, body) = output.split_at_mut(head_len);
    for (i, byte) in head.iter_mut().enumerate() {
        *byte = state_byte(state, offset + i);
    }
    let lane = (offset + head_len) / 8;
    let (words, tail) = body.as_chunks_mut::<8>();
    let tail_start = (lane + words.len()) * 8;
    for (word, chunk) in state[lane..].iter().zip(words) {
        *chunk = word.to_le_bytes();
    }
    for (i, byte) in tail.iter_mut().enumerate() {
        *byte = state_byte(state, tail_start + i);
    }
}

fn state_byte(state: &[u64; 25], pos: usize) -> u8 {
    (state[pos / 8] >> (8 * (pos % 8))) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-at-a-time model of the lane layout: byte `i` of the state is
    /// byte `i % 8` (little-endian) of lane `i / 8`.
    fn state_bytes(state: &[u64; 25]) -> Vec<u8> {
        state.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// `xor_into` and `extract` at every start offset and length within one
    /// rate block agree with a byte-by-byte model, covering the unaligned
    /// head, the lane-wise body and the unaligned tail.
    #[test]
    fn test_lane_io_matches_byte_model() {
        let initial: [u64; 25] =
            std::array::from_fn(|i| 0x0123_4567_89ab_cdefu64.rotate_left(i as u32 * 7));
        for offset in 0..=RATE_128 {
            for len in 0..=(RATE_128 - offset) {
                let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + offset) as u8).collect();
                let mut state = initial;
                xor_into(&mut state, offset, &bytes);
                let mut expected = state_bytes(&initial);
                for (i, byte) in bytes.iter().enumerate() {
                    expected[offset + i] ^= byte;
                }
                assert_eq!(
                    state_bytes(&state),
                    expected,
                    "xor offset {offset} len {len}"
                );

                let mut out = vec![0u8; len];
                extract(&state, offset, &mut out);
                assert_eq!(
                    out,
                    expected[offset..offset + len],
                    "extract offset {offset} len {len}"
                );
            }
        }
    }

    /// Absorbing and squeezing in pieces of every size up to two blocks
    /// matches doing it in one call, so the lazy permutation never skips or
    /// repeats a block.
    #[test]
    fn test_split_absorb_and_squeeze_match_one_call() {
        let input: Vec<u8> = (0..3 * RATE_256 as u32)
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let mut one = Sponge::<RATE_256, ROUNDS_FULL>::new();
        one.absorb(&input);
        one.pad(DOMAIN_SHAKE);
        let mut expected = vec![0u8; 3 * RATE_256];
        one.squeeze(&mut expected);

        for piece in 1..=2 * RATE_256 {
            let mut sponge = Sponge::<RATE_256, ROUNDS_FULL>::new();
            for chunk in input.chunks(piece) {
                sponge.absorb(chunk);
                sponge.absorb(&[]);
            }
            sponge.pad(DOMAIN_SHAKE);
            let mut out = vec![0u8; expected.len()];
            for chunk in out.chunks_mut(piece) {
                sponge.squeeze(chunk);
                sponge.squeeze(&mut []);
            }
            assert_eq!(out, expected, "piece {piece}");
        }
    }

    #[test]
    fn test_zeroize_clears_state() {
        let mut sponge = Sponge::<RATE_128, ROUNDS_TURBO>::new();
        sponge.absorb(b"secret");
        sponge.pad(DOMAIN_SHAKE);
        sponge.zeroize();
        assert_eq!(sponge.state, [0u64; 25]);
        assert_eq!(sponge.offset, 0);
    }
}
