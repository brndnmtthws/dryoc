//! Keccak sponge shared by SHA-3, the SHAKE and TurboSHAKE XOFs, and ML-KEM.
//!
//! [`Sponge`] is the FIPS 202 sponge over Keccak-p[1600] with a byte rate
//! `RATE` and `ROUNDS` rounds: 24 for SHA-3 and SHAKE, 12 for TurboSHAKE
//! (RFC 9861). It only absorbs, pads and squeezes; the wrappers decide when
//! padding happens and which domain byte it uses. The permutation comes from
//! the in-crate SHA3-extension kernel in `keccak_aarch64.rs` when an AArch64
//! CPU has it, and otherwise from the RustCrypto `keccak` crate. [`ParSponge`]
//! runs several independent sponges together: two at a time through the
//! AArch64 kernel, four at a time through the AVX2 kernel in
//! `keccak_x86_64.rs` when an x86-64 CPU has AVX2, and the rest through the
//! crate.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    CRYPTO_XOF_SHAKE128_BLOCKBYTES, CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD,
    CRYPTO_XOF_SHAKE256_BLOCKBYTES,
};

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
mod keccak_aarch64;
#[cfg(target_arch = "x86_64")]
mod keccak_x86_64;

/// The Keccak-f[1600] round constants, from the FIPS 202 `rc` LFSR (`x^8 +
/// x^6 + x^5 + x^4 + 1`): bit `2^j - 1` of constant `i` is output `7 * i +
/// j`. Keccak-p[1600, `ROUNDS`] uses the last `ROUNDS` of them.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    target_arch = "x86_64"
))]
const RC: [u64; 24] = {
    let mut rc = [0u64; 24];
    let mut lfsr: u8 = 1;
    let mut round = 0;
    while round < 24 {
        let mut j = 0;
        while j < 7 {
            if lfsr & 1 == 1 {
                rc[round] |= 1 << ((1 << j) - 1);
            }
            lfsr = if lfsr & 0x80 == 0 {
                lfsr << 1
            } else {
                (lfsr << 1) ^ 0x71
            };
            j += 1;
        }
        round += 1;
    }
    rc
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

    /// Out of line at opt-level `z` and `s` (the `keccak` backend dispatch
    /// and permutation also at `2`), which adds no copy: it and the kernel or
    /// backend get only `&mut self.state`, the sponge's own state, which is
    /// permuted in place and wiped on drop. With the SHA3 extension the
    /// in-crate kernel runs instead of the `keccak` crate's AArch64 backend,
    /// whose single-state path leaves an unwiped `[state, zero]` copy (see
    /// `keccak_aarch64.rs`).
    fn permute(&mut self) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Some(kernel) = keccak_aarch64::detect() {
            kernel.permute1::<ROUNDS>(&mut self.state);
            self.offset = 0;
            return;
        }
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

/// `N` independent Keccak sponges advanced together, so that a backend with
/// a multi-state permutation (the 2-way AArch64 SHA3-extension kernel) runs
/// several of them per call.
///
/// Each lane behaves exactly like its own [`Sponge`]: `absorb`, `pad` and
/// `squeeze` take one input or output per lane, of any lengths, and a lane
/// permutes only when that `Sponge` would. The lanes that need a permutation
/// at the same step share the multi-state calls; see [`permute_lanes`].
pub(crate) struct ParSponge<const RATE: usize, const ROUNDS: usize, const N: usize> {
    states: [[u64; 25]; N],
    offsets: [usize; N],
    keccak: keccak::Keccak,
}

impl<const RATE: usize, const ROUNDS: usize, const N: usize> ParSponge<RATE, ROUNDS, N> {
    pub(crate) fn new() -> Self {
        const { assert!(RATE > 0 && RATE < 200 && RATE.is_multiple_of(8)) };
        Self {
            states: [[0; 25]; N],
            offsets: [0; N],
            keccak: keccak::Keccak::new(),
        }
    }

    /// Permutes the lanes in `selected` and rewinds them to the start of the
    /// rate.
    fn permute(&mut self, selected: [bool; N]) {
        for (offset, _) in self.offsets.iter_mut().zip(selected).filter(|(_, s)| *s) {
            *offset = 0;
        }
        permute_lanes::<ROUNDS, N>(&self.keccak, &mut self.states, selected);
    }

    /// XORs `inputs[i]` into the rate of lane `i`.
    pub(crate) fn absorb(&mut self, mut inputs: [&[u8]; N]) {
        loop {
            self.permute(core::array::from_fn(|i| {
                !inputs[i].is_empty() && self.offsets[i] == RATE
            }));
            let mut done = true;
            for ((state, offset), input) in self
                .states
                .iter_mut()
                .zip(&mut self.offsets)
                .zip(&mut inputs)
            {
                let (chunk, rest) = input.split_at(input.len().min(RATE - *offset));
                xor_into(state, *offset, chunk);
                *offset += chunk.len();
                *input = rest;
                done &= rest.is_empty();
            }
            if done {
                return;
            }
        }
    }

    /// [`Sponge::pad`] on every lane.
    pub(crate) fn pad(&mut self, domain: u8) {
        debug_assert!((0x01..=0x7f).contains(&domain));
        self.permute(self.offsets.map(|offset| offset == RATE));
        for (state, &offset) in self.states.iter_mut().zip(&self.offsets) {
            xor_into(state, offset, &[domain]);
            xor_into(state, RATE - 1, &[0x80]);
        }
        self.permute([true; N]);
    }

    /// Fills `outputs[i]` from the rate of lane `i`, permuting between
    /// blocks; lanes given an empty output are left as they are.
    pub(crate) fn squeeze(&mut self, mut outputs: [&mut [u8]; N]) {
        loop {
            self.permute(core::array::from_fn(|i| {
                !outputs[i].is_empty() && self.offsets[i] == RATE
            }));
            let mut done = true;
            for ((state, offset), output) in
                self.states.iter().zip(&mut self.offsets).zip(&mut outputs)
            {
                let take = output.len().min(RATE - *offset);
                let (chunk, rest) = core::mem::take(output).split_at_mut(take);
                extract(state, *offset, chunk);
                *offset += take;
                *output = rest;
                done &= output.is_empty();
            }
            if done {
                return;
            }
        }
    }
}

impl<const RATE: usize, const ROUNDS: usize, const N: usize> Zeroize
    for ParSponge<RATE, ROUNDS, N>
{
    fn zeroize(&mut self) {
        for state in &mut self.states {
            crate::utils::zeroize_u64s(state);
        }
        self.offsets.zeroize();
    }
}

impl<const RATE: usize, const ROUNDS: usize, const N: usize> Drop for ParSponge<RATE, ROUNDS, N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const RATE: usize, const ROUNDS: usize, const N: usize> ZeroizeOnDrop
    for ParSponge<RATE, ROUNDS, N>
{
}

/// Applies Keccak-p[1600, `ROUNDS`] to each state in `selected`.
///
/// This is the one place multi-state permutations are chosen. On AArch64
/// with the SHA3 extension, the in-crate kernel in `keccak_aarch64.rs`
/// permutes them two at a time (an odd one alone). On x86-64 with AVX2, the
/// in-crate kernel in `keccak_x86_64.rs` permutes them four at a time (three
/// leftover states with a spare one). The rest go to the `keccak` crate's
/// backend one at a time (its soft backend).
fn permute_lanes<const ROUNDS: usize, const N: usize>(
    keccak: &keccak::Keccak,
    states: &mut [[u64; 25]; N],
    selected: [bool; N],
) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    if let Some(kernel) = keccak_aarch64::detect() {
        let mut selected = selected;
        kernel.permute_selected::<ROUNDS, N>(states, &mut selected);
        return;
    }
    #[cfg(target_arch = "x86_64")]
    let selected = {
        let mut selected = selected;
        if let Some(kernel) = keccak_x86_64::detect() {
            kernel.permute_selected::<ROUNDS, N>(states, &mut selected);
        }
        selected
    };
    if selected.contains(&true) {
        keccak.with_backend(PermuteLanes::<ROUNDS, N> { states, selected });
    }
}

/// The [`keccak::BackendClosure`] behind [`permute_lanes`].
struct PermuteLanes<'a, const ROUNDS: usize, const N: usize> {
    states: &'a mut [[u64; 25]; N],
    selected: [bool; N],
}

/// Out of line at opt-level `z` and `s` (as are the backend's permutation
/// closures), which adds no copy: `call_once` gets `&mut` to the sponge
/// states, which are wiped on drop, and the public lane selection; the one
/// staging copy, `par`, is wiped after its group.
impl<const ROUNDS: usize, const N: usize> keccak::BackendClosure for PermuteLanes<'_, ROUNDS, N> {
    fn call_once<B: keccak::Backend>(self) {
        let width = size_of::<keccak::ParState1600<B>>() / size_of::<[u64; 25]>();
        let mut lanes = [0; N];
        let mut count = 0;
        for (lane, _) in self.selected.iter().enumerate().filter(|(_, s)| **s) {
            lanes[count] = lane;
            count += 1;
        }
        for group in lanes[..count].chunks(width) {
            let first = group[0];
            if let [lane] = group {
                B::get_p1600::<ROUNDS>()(&mut self.states[*lane]);
            } else if group.len() == width && group[width - 1] - first == width - 1 {
                // Consecutive lanes are permuted in place.
                let par: &mut keccak::ParState1600<B> = (&mut self.states[first..first + width])
                    .try_into()
                    .expect("group of the backend width");
                B::get_par_p1600::<ROUNDS>()(par);
            } else {
                let mut par = keccak::ParState1600::<B>::default();
                for (state, &lane) in par.iter_mut().zip(group) {
                    *state = self.states[lane];
                }
                B::get_par_p1600::<ROUNDS>()(&mut par);
                for (state, &lane) in par.iter_mut().zip(group) {
                    self.states[lane] = *state;
                    crate::utils::zeroize_u64s(state);
                }
            }
        }
    }
}

/// One-shot 24-round Keccak: absorbs the concatenation of `parts`, pads
/// with `domain` and fills `output`. With [`DOMAIN_SHA3`] and the matching
/// rate this is SHA3-256 or SHA3-512; with [`DOMAIN_SHAKE`] it is SHAKE128
/// or SHAKE256. The output goes straight into the caller's buffer, so a
/// secret result leaves no copy behind.
pub(crate) fn hash<const RATE: usize>(output: &mut [u8], domain: u8, parts: &[&[u8]]) {
    let mut sponge = Sponge::<RATE, ROUNDS_FULL>::new();
    for part in parts {
        sponge.absorb(part);
    }
    sponge.pad(domain);
    sponge.squeeze(output);
}

/// XORs `bytes` into the little-endian lanes of `state`, starting at byte
/// `offset`. Aligned eight-byte runs are XORed one lane at a time.
///
/// Out of line at opt-level `z`, `s` and `2` (as are [`xor_byte`],
/// [`extract`] and [`state_byte`]), which adds no copy: they only get `&` or
/// `&mut` to the sponge's own state, which is wiped on drop.
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
    use crate::test_prelude::*;

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
            core::array::from_fn(|i| 0x0123_4567_89ab_cdefu64.rotate_left(i as u32 * 7));
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

    /// Every lane of a [`ParSponge`] matches its own [`Sponge`] when the
    /// lanes absorb different lengths (empty, around and across rate
    /// boundaries, split over two calls at different points) and squeeze
    /// different multi-block lengths, so lanes permute at different steps,
    /// alone, in consecutive groups and in scattered ones.
    fn check_par_sponge_matches_sponge<const RATE: usize, const ROUNDS: usize, const N: usize>() {
        let lengths = [0, 1, 7, RATE - 1, RATE, RATE + 1, 2 * RATE + 3, 3 * RATE];
        for round in 0..lengths.len() {
            let pick =
                |lane: usize, salt: usize| lengths[(lane * 5 + round + salt) % lengths.len()];
            let inputs: [Vec<u8>; N] = core::array::from_fn(|lane| {
                (0..pick(lane, 0))
                    .map(|i| (i * 7 + lane * 31 + round) as u8)
                    .collect()
            });
            let splits: [usize; N] =
                core::array::from_fn(|lane| inputs[lane].len() * (lane % 3) / 2);
            let squeezes: [[usize; 2]; N] =
                core::array::from_fn(|lane| [pick(lane, 3), pick(lane, 6)]);

            let mut par = ParSponge::<RATE, ROUNDS, N>::new();
            par.absorb(core::array::from_fn(|lane| &inputs[lane][..splits[lane]]));
            par.absorb(core::array::from_fn(|lane| &inputs[lane][splits[lane]..]));
            par.pad(DOMAIN_SHAKE);
            let mut outputs: [[Vec<u8>; 2]; N] =
                core::array::from_fn(|lane| squeezes[lane].map(|len| vec![0; len]));
            for half in 0..2 {
                par.squeeze(outputs.each_mut().map(|o| &mut o[half][..]));
            }

            for lane in 0..N {
                let mut sponge = Sponge::<RATE, ROUNDS>::new();
                sponge.absorb(&inputs[lane]);
                sponge.pad(DOMAIN_SHAKE);
                for (half, output) in outputs[lane].iter().enumerate() {
                    let mut expected = vec![0; output.len()];
                    sponge.squeeze(&mut expected);
                    assert_eq!(
                        output, &expected,
                        "N {N} round {round} lane {lane} half {half}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_par_sponge_matches_sponge() {
        check_par_sponge_matches_sponge::<RATE_128, ROUNDS_FULL, 1>();
        check_par_sponge_matches_sponge::<RATE_256, ROUNDS_FULL, 2>();
        check_par_sponge_matches_sponge::<RATE_128, ROUNDS_TURBO, 3>();
        check_par_sponge_matches_sponge::<RATE_256, ROUNDS_FULL, 4>();
        check_par_sponge_matches_sponge::<RATE_128, ROUNDS_FULL, 9>();
    }

    /// The 4-way x86-64 kernel permutes the selected states like the
    /// `keccak` crate's permutation, with 24 and 12 rounds, in consecutive
    /// and scattered groups of four and in a leftover group of three, and
    /// leaves one or two leftover states selected and untouched.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_x86_64_permute4_matches_scalar() {
        fn check<const ROUNDS: usize>(kernel: keccak_x86_64::Kernel, seed: u64) {
            let mut seed = seed;
            let mut next = move || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            let initial: [[u64; 25]; 9] =
                core::array::from_fn(|_| core::array::from_fn(|_| next()));
            let keccak = keccak::Keccak::new();
            let permuted = initial.map(|mut state| {
                keccak.with_p1600::<ROUNDS>(|p1600| p1600(&mut state));
                state
            });
            // Consecutive and scattered groups of four; one or two leftover
            // lanes stay selected, three run with a spare state.
            let selections: [&[usize]; 5] = [
                &[0, 1, 2, 3],
                &[1, 2, 4, 7, 8],
                &[0, 1, 3, 5, 6, 8],
                &[0, 5, 6],
                &[0, 1, 2, 3, 4, 6, 8],
            ];
            let handled: [&[usize]; 5] = [
                &[0, 1, 2, 3],
                &[1, 2, 4, 7],
                &[0, 1, 3, 5],
                &[0, 5, 6],
                &[0, 1, 2, 3, 4, 6, 8],
            ];
            for (lanes, handled) in selections.into_iter().zip(handled) {
                let mut states = initial;
                let mut selected = [false; 9];
                for &lane in lanes {
                    selected[lane] = true;
                }
                kernel.permute_selected::<ROUNDS, 9>(&mut states, &mut selected);
                for lane in 0..9 {
                    let done = handled.contains(&lane);
                    let expected = if done { permuted[lane] } else { initial[lane] };
                    assert_eq!(
                        states[lane], expected,
                        "{ROUNDS} rounds, {lanes:?}, lane {lane}"
                    );
                    assert_eq!(selected[lane], lanes.contains(&lane) && !done);
                }
            }
        }
        for kernel in keccak_x86_64::Kernel::all() {
            for seed in [0x9e37_79b9_7f4a_7c15, 0x2545_f491_4f6c_dd1d] {
                check::<ROUNDS_FULL>(kernel, seed);
                check::<ROUNDS_TURBO>(kernel, seed);
            }
        }
    }

    /// The AArch64 SHA3-extension kernel permutes like the `keccak` crate,
    /// with 24 and 12 rounds, one state alone and pairs in consecutive and
    /// scattered lanes (an odd leftover alone), and clears every flag.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    #[test]
    fn test_aarch64_sha3_permute_matches_crate() {
        fn check<const ROUNDS: usize>(kernel: keccak_aarch64::Kernel, seed: u64) {
            let mut seed = seed;
            let mut next = move || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            let initial: [[u64; 25]; 7] =
                core::array::from_fn(|_| core::array::from_fn(|_| next()));
            let keccak = keccak::Keccak::new();
            let permuted = initial.map(|mut state| {
                keccak.with_p1600::<ROUNDS>(|p1600| p1600(&mut state));
                state
            });
            let mut one = initial[0];
            kernel.permute1::<ROUNDS>(&mut one);
            assert_eq!(one, permuted[0], "{ROUNDS} rounds, one state");
            let selections: [&[usize]; 4] = [&[0, 1], &[1, 4, 6], &[0, 2, 3, 5, 6], &[3]];
            for lanes in selections {
                let mut states = initial;
                let mut selected = [false; 7];
                for &lane in lanes {
                    selected[lane] = true;
                }
                kernel.permute_selected::<ROUNDS, 7>(&mut states, &mut selected);
                for lane in 0..7 {
                    let expected = if lanes.contains(&lane) {
                        permuted[lane]
                    } else {
                        initial[lane]
                    };
                    assert_eq!(
                        states[lane], expected,
                        "{ROUNDS} rounds, {lanes:?}, lane {lane}"
                    );
                }
                assert_eq!(selected, [false; 7]);
            }
        }
        for kernel in keccak_aarch64::Kernel::all() {
            for seed in [0x9e37_79b9_7f4a_7c15, 0x2545_f491_4f6c_dd1d] {
                check::<ROUNDS_FULL>(kernel, seed);
                check::<ROUNDS_TURBO>(kernel, seed);
            }
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
