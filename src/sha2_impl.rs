//! Shared Merkle–Damgård plumbing for the SHA-2 hashers.
//!
//! [`crate::sha256`] and [`crate::sha512`] differ only in word width, length
//! counter width, block size, initial state and compression function. The
//! buffering, padding and zeroization around those are identical, so each
//! module instantiates them once through [`sha2_hasher!`]; everything is
//! monomorphized per invocation and there is no runtime dispatch.

/// Defines a SHA-2 hasher type and its `impl`s.
///
/// - `$name`: the hasher type; leading attributes (docs) are applied to it.
/// - `$algo`: the algorithm name for the generated method docs.
/// - `$word` / `$word_bytes`: the state word type and its width in bytes; the
///   digest is the state in big-endian words.
/// - `$len` / `$length_bytes`: the message length counter type and its width in
///   bytes, which is also the width of the big-endian bit-length field in the
///   final block.
/// - `$block_bytes`: the block size in bytes.
/// - `$digest_bytes`: the digest size constant.
/// - `$iv`: the initial state, `[$word; 8]`.
/// - `$compress`: `fn(&mut [$word; 8], &[[u8; $block_bytes]])`, compressing
///   whole blocks into the state.
macro_rules! sha2_hasher {
    (
        $(#[$meta:meta])*
        pub struct $name:ident;
        algorithm: $algo:literal,
        word: $word:ty,
        word_bytes: $word_bytes:literal,
        length: $len:ty,
        length_bytes: $length_bytes:literal,
        block_bytes: $block_bytes:expr,
        digest_bytes: $digest_bytes:expr,
        iv: $iv:expr,
        compress: $compress:path,
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            state: [$word; 8],
            buffer: [u8; $block_bytes],
            buflen: usize,
            /// Total bytes absorbed so far.
            len: $len,
        }

        const _: () = {
            assert!(core::mem::size_of::<$word>() == $word_bytes);
            assert!(core::mem::size_of::<$len>() == $length_bytes);
        };

        impl $name {
            #[doc = concat!("Returns a new ", $algo, " hasher instance.")]
            pub fn new() -> Self {
                Self {
                    state: $iv,
                    buffer: [0u8; $block_bytes],
                    buflen: 0,
                    len: 0,
                }
            }

            /// Absorbs exactly `block` (one full block) into this fresh hasher,
            /// for the HMAC key pads: one compression with no buffering.
            ///
            /// The key-equivalent chaining state is compressed in place, so
            /// the only copy is the hasher's own, which is wiped on drop.
            #[inline]
            pub(crate) fn absorb_key_block(&mut self, block: &[u8; $block_bytes]) {
                debug_assert!(self.len == 0 && self.buflen == 0);
                $compress(&mut self.state, core::slice::from_ref(block));
                self.len = $block_bytes as _;
            }

            /// A fresh hasher whose length counter claims `len` bytes were
            /// already absorbed, for exercising the length field of the final
            /// block without feeding that many bytes.
            #[cfg(all(test, feature = "alloc"))]
            pub(crate) fn with_absorbed_len(len: $len) -> Self {
                Self { len, ..Self::new() }
            }

            #[doc = concat!(
                "One-time interface to compute ", $algo, " digest for `input`, copying result\n",
                "into `output`."
            )]
            pub fn compute_into_bytes<
                Input: $crate::types::Bytes + ?Sized,
                Output: $crate::types::MutByteArray<$digest_bytes>,
            >(
                output: &mut Output,
                input: &Input,
            ) {
                let input = input.as_slice();
                // Resolve the output first: it may panic on a short buffer, and no
                // secret-derived state exists yet at that point.
                let output = output.as_mut_array();
                if input.len() < $block_bytes - $length_bytes {
                    // The whole message and its padding fit one block: compress it
                    // directly instead of going through the buffering hasher.
                    let mut block = [0u8; $block_bytes];
                    block[..input.len()].copy_from_slice(input);
                    block[input.len()] = 0x80;
                    block[$block_bytes - $length_bytes..]
                        .copy_from_slice(&((input.len() as $len) * 8).to_be_bytes());
                    let mut state = $iv;
                    $compress(&mut state, core::slice::from_ref(&block));
                    for (chunk, word) in output.as_chunks_mut::<$word_bytes>().0.iter_mut().zip(&state)
                    {
                        *chunk = word.to_be_bytes();
                    }
                    $crate::utils::zeroize_bytes(&mut block);
                    ::zeroize::Zeroize::zeroize(&mut state);
                    return;
                }
                let mut hasher = Self::new();
                hasher.update(input);
                hasher.finalize_into_bytes(output)
            }

            #[doc = concat!("One-time interface to compute ", $algo, " digest for `input`.")]
            pub fn compute<
                Input: $crate::types::Bytes + ?Sized,
                Output: $crate::types::NewByteArray<$digest_bytes>,
            >(
                input: &Input,
            ) -> Output {
                let mut hash = Output::new_byte_array();
                Self::compute_into_bytes(&mut hash, input);
                hash
            }

            #[doc = concat!(
                "Wrapper around [`", stringify!($name), "::compute`], returning a [`Vec`](alloc::vec::Vec). Provided for\n",
                "convenience."
            )]
            #[cfg(feature = "alloc")]
            pub fn compute_to_vec<Input: $crate::types::Bytes + ?Sized>(input: &Input) -> alloc::vec::Vec<u8> {
                Self::compute::<_, $crate::types::StackByteArray<$digest_bytes>>(input).to_vec()
            }

            #[doc = concat!("Updates ", $algo, " hash state with `input`.")]
            pub fn update<Input: $crate::types::Bytes + ?Sized>(&mut self, input: &Input) {
                let mut input = input.as_slice();
                self.len = self.len.wrapping_add(input.len() as $len);

                if self.buflen > 0 {
                    let take = ($block_bytes - self.buflen).min(input.len());
                    self.buffer[self.buflen..self.buflen + take].copy_from_slice(&input[..take]);
                    self.buflen += take;
                    input = &input[take..];
                    if self.buflen < $block_bytes {
                        return;
                    }
                    $compress(&mut self.state, core::slice::from_ref(&self.buffer));
                    // Keep the invariant that bytes at and beyond `buflen` are zero.
                    self.buffer = [0u8; $block_bytes];
                    self.buflen = 0;
                }

                let (blocks, rest) = input.as_chunks::<$block_bytes>();
                $compress(&mut self.state, blocks);
                self.buffer[..rest.len()].copy_from_slice(rest);
                self.buflen = rest.len();
            }

            /// Consumes hasher and return final computed hash.
            pub fn finalize<Output: $crate::types::NewByteArray<$digest_bytes>>(self) -> Output {
                let mut hash = Output::new_byte_array();
                self.finalize_into_bytes(&mut hash);
                hash
            }

            /// Consumes hasher and writes final computed hash into `output`.
            pub fn finalize_into_bytes<Output: $crate::types::MutByteArray<$digest_bytes>>(
                mut self,
                output: &mut Output,
            ) {
                self.finalize_in_place(output.as_mut_array());
            }

            /// [`Self::finalize_into_bytes`] without moving the hasher, for
            /// callers that own it in place (HMAC); the hasher is spent
            /// afterwards and must only be dropped, which wipes it.
            #[inline]
            pub(crate) fn finalize_in_place(&mut self, output: &mut [u8; $digest_bytes]) {
                let bit_len = self.len.wrapping_mul(8).to_be_bytes();
                // Bytes beyond `buflen` are already zero (`new` and `update` keep
                // it so), which avoids a variable-length fill here.
                debug_assert!(self.buffer[self.buflen..].iter().all(|&b| b == 0));
                self.buffer[self.buflen] = 0x80;
                if self.buflen + 1 > $block_bytes - $length_bytes {
                    $compress(&mut self.state, core::slice::from_ref(&self.buffer));
                    self.buffer.fill(0);
                }
                self.buffer[$block_bytes - $length_bytes..].copy_from_slice(&bit_len);
                $compress(&mut self.state, core::slice::from_ref(&self.buffer));

                for (chunk, word) in output.as_chunks_mut::<$word_bytes>().0.iter_mut().zip(&self.state)
                {
                    *chunk = word.to_be_bytes();
                }
            }

            /// Consumes hasher and returns final computed hash as a
            /// [`Vec`](alloc::vec::Vec).
            #[cfg(feature = "alloc")]
            pub fn finalize_to_vec(self) -> alloc::vec::Vec<u8> {
                self.finalize::<$crate::types::StackByteArray<$digest_bytes>>().to_vec()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                ::zeroize::Zeroize::zeroize(&mut self.state);
                $crate::utils::zeroize_bytes(&mut self.buffer);
                ::zeroize::Zeroize::zeroize(&mut self.buflen);
                ::zeroize::Zeroize::zeroize(&mut self.len);
            }
        }
    };
}

pub(crate) use sha2_hasher;

/// The length field both instantiations share, on the inputs where a
/// counter bug would show.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use crate::sha256::Sha256;
    use crate::sha512::Sha512;
    use crate::test_prelude::*;

    const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const SHA512_IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    /// FIPS 180-4 §5.1 padding of `tail` as the end of a message of
    /// `total_bits` bits: `0x80`, zeros, then the big-endian bit length in
    /// the last `L` bytes of the last block (one block when the tail plus
    /// nine (SHA-256) or seventeen (SHA-512) bytes fit, two otherwise).
    fn padded<const B: usize, const L: usize>(tail: &[u8], total_bits: u128) -> Vec<[u8; B]> {
        let blocks = (tail.len() + 1 + L).div_ceil(B);
        let mut out = vec![[0u8; B]; blocks];
        let flat = out.as_flattened_mut();
        flat[..tail.len()].copy_from_slice(tail);
        flat[tail.len()] = 0x80;
        let field = &mut flat[blocks * B - L..];
        field.copy_from_slice(&total_bits.to_be_bytes()[16 - L..]);
        out
    }

    /// Isolates the final-block construction: a hasher claiming `absorbed`
    /// bytes (state still the IV, so this is not a digest of a real long
    /// message) fed `tail` must finalize exactly like compressing the
    /// FIPS-padded tail carrying the bit length of the whole message from the
    /// same IV. Absorbed lengths put the bit count past 2^32 (both) and past
    /// 2^64 (SHA-512's high length word); tails of 0, `B - L - 1` (last byte
    /// that still fits one final block) and `B - L` (forces the second padding
    /// block) bytes, plus a whole block. Real-message digests are covered by
    /// the RustCrypto comparisons in `sha256`/`sha512`.
    #[test]
    fn test_length_field_encodes_total_bits_past_word_boundaries() {
        let tail = |n: usize| -> Vec<u8> { (0..n).map(|i| (i * 7 + 1) as u8).collect() };

        for absorbed in [1u64 << 30, 1u64 << 32, 1u64 << 61] {
            for tail in [tail(0), tail(64 - 8 - 1), tail(64 - 8), tail(64)] {
                let mut hasher = Sha256::with_absorbed_len(absorbed);
                hasher.update(&tail);
                let total_bits = (u128::from(absorbed) + tail.len() as u128) * 8;
                let mut state = SHA256_IV;
                sha2::block_api::compress256(&mut state, &padded::<64, 8>(&tail, total_bits));
                let expected: Vec<u8> = state.iter().flat_map(|w| w.to_be_bytes()).collect();
                assert_eq!(
                    hasher.finalize_to_vec(),
                    expected,
                    "sha256 absorbed {absorbed} tail {}",
                    tail.len()
                );
            }
        }

        for absorbed in [1u128 << 30, 1u128 << 61, 1u128 << 64] {
            for tail in [tail(0), tail(128 - 16 - 1), tail(128 - 16), tail(128)] {
                let mut hasher = Sha512::with_absorbed_len(absorbed);
                hasher.update(&tail);
                let total_bits = (absorbed + tail.len() as u128) * 8;
                let mut state = SHA512_IV;
                sha2::block_api::compress512(&mut state, &padded::<128, 16>(&tail, total_bits));
                let expected: Vec<u8> = state.iter().flat_map(|w| w.to_be_bytes()).collect();
                assert_eq!(
                    hasher.finalize_to_vec(),
                    expected,
                    "sha512 absorbed {absorbed} tail {}",
                    tail.len()
                );
            }
        }
    }
}
