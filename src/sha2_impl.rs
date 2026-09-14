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
            assert!(std::mem::size_of::<$word>() == $word_bytes);
            assert!(std::mem::size_of::<$len>() == $length_bytes);
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

            /// A hasher that has absorbed exactly `block` (one full block), for the
            /// HMAC key pads: one compression with no buffering.
            #[inline]
            pub(crate) fn from_block(block: &[u8; $block_bytes]) -> Self {
                let mut state = $iv;
                $compress(&mut state, std::slice::from_ref(block));
                Self {
                    state,
                    buffer: [0u8; $block_bytes],
                    buflen: 0,
                    len: $block_bytes as _,
                }
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
                    $compress(&mut state, std::slice::from_ref(&block));
                    for (chunk, word) in output.as_chunks_mut::<$word_bytes>().0.iter_mut().zip(state)
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
                "Wrapper around [`", stringify!($name), "::compute`], returning a [`Vec`]. Provided for\n",
                "convenience."
            )]
            pub fn compute_to_vec<Input: $crate::types::Bytes + ?Sized>(input: &Input) -> Vec<u8> {
                Self::compute(input)
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
                    $compress(&mut self.state, std::slice::from_ref(&self.buffer));
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
                let bit_len = self.len.wrapping_mul(8).to_be_bytes();
                // Bytes beyond `buflen` are already zero (`new` and `update` keep
                // it so), which avoids a variable-length fill here.
                debug_assert!(self.buffer[self.buflen..].iter().all(|&b| b == 0));
                self.buffer[self.buflen] = 0x80;
                if self.buflen + 1 > $block_bytes - $length_bytes {
                    $compress(&mut self.state, std::slice::from_ref(&self.buffer));
                    self.buffer.fill(0);
                }
                self.buffer[$block_bytes - $length_bytes..].copy_from_slice(&bit_len);
                $compress(&mut self.state, std::slice::from_ref(&self.buffer));

                let output = output.as_mut_array();
                for (chunk, word) in output.as_chunks_mut::<$word_bytes>().0.iter_mut().zip(self.state)
                {
                    *chunk = word.to_be_bytes();
                }
            }

            /// Consumes hasher and returns final computed hash as a [`Vec`].
            pub fn finalize_to_vec(self) -> Vec<u8> {
                self.finalize()
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
