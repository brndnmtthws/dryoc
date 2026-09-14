/// Increments `bytes` in constant time, representing a large little-endian
/// integer; equivalent to `sodium_increment`.
#[inline]
pub fn increment_bytes(bytes: &mut [u8]) {
    let mut carry: u16 = 1;
    for b in bytes {
        carry += *b as u16;
        *b = (carry & 0xff) as u8;
        carry >>= 8;
    }
}

/// Convenience wrapper for [`increment_bytes`]. Functionally equivalent to
/// `sodium_increment`.
pub fn sodium_increment(bytes: &mut [u8]) {
    increment_bytes(bytes)
}

#[inline]
pub(crate) fn xor_buf(out: &mut [u8], in_: &[u8]) {
    let len = std::cmp::min(out.len(), in_.len());
    for i in 0..len {
        out[i] ^= in_[i];
    }
}

#[inline]
pub(crate) fn load_u64_le(bytes: &[u8]) -> u64 {
    (bytes[0] as u64)
        | ((bytes[1] as u64) << 8)
        | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 24)
        | ((bytes[4] as u64) << 32)
        | ((bytes[5] as u64) << 40)
        | ((bytes[6] as u64) << 48)
        | ((bytes[7] as u64) << 56)
}

#[inline]
pub(crate) fn load_u32_le(bytes: &[u8]) -> u32 {
    (bytes[0] as u32)
        | ((bytes[1] as u32) << 8)
        | ((bytes[2] as u32) << 16)
        | ((bytes[3] as u32) << 24)
}

#[inline]
pub(crate) fn pad16(n: usize) -> usize {
    (0x10 - (n % 16)) & 0xf
}

/// Zeroizes `bytes` with volatile stores like [`zeroize::Zeroize`], but
/// sixteen bytes at a time. The `zeroize` crate issues one volatile store per
/// byte, which dominates the cost of small-message operations whose state
/// buffers are wiped on every call.
pub(crate) fn zeroize_bytes(bytes: &mut [u8]) {
    // SAFETY: `u128` has no bit-validity or padding requirements, so viewing
    // the 16-byte-aligned middle of a `u8` slice as `u128`s is sound;
    // `align_to_mut` returns disjoint views of `bytes`, with the unaligned
    // ends left as bytes.
    let (head, words, tail) = unsafe { bytes.align_to_mut::<u128>() };
    zeroize_wide(head, words, tail);
    zeroize::optimization_barrier(bytes);
}

/// Zeroizes `words` with volatile stores, sixteen bytes at a time where the
/// alignment allows. Used for large secret working buffers (Argon2 memory),
/// where the `zeroize` crate's one store per word is measurable.
pub(crate) fn zeroize_u64s(words: &mut [u64]) {
    // SAFETY: as in `zeroize_bytes`; `u128` has no validity requirements and
    // the three views are disjoint.
    let (head, wide, tail) = unsafe { words.align_to_mut::<u128>() };
    zeroize_wide(head, wide, tail);
    zeroize::optimization_barrier(words);
}

/// Clears the three views of one buffer with volatile stores. Callers follow
/// this with [`zeroize::optimization_barrier`] over the whole buffer, matching
/// what the `zeroize` crate does after its own volatile writes.
#[inline]
fn zeroize_wide<T: zeroize::DefaultIsZeroes>(head: &mut [T], words: &mut [u128], tail: &mut [T]) {
    use zeroize::Zeroize;

    head.zeroize();
    for word in words {
        // SAFETY: `word` is a valid, aligned, exclusively borrowed `u128`.
        unsafe { std::ptr::write_volatile(word, 0) };
    }
    tail.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_u64s_covers_unaligned_ends_and_odd_lengths() {
        let mut buffer = [0xa5a5_a5a5_a5a5_a5a5u64; 19];
        for start in 0..3 {
            for len in [0, 1, 2, 3, 4, 7, 8, 9, 16] {
                buffer.fill(0xa5a5_a5a5_a5a5_a5a5);
                zeroize_u64s(&mut buffer[start..start + len]);
                assert!(
                    buffer[..start].iter().all(|&w| w == 0xa5a5_a5a5_a5a5_a5a5),
                    "{start} {len}"
                );
                assert!(
                    buffer[start..start + len].iter().all(|&w| w == 0),
                    "{start} {len}"
                );
                assert!(
                    buffer[start + len..]
                        .iter()
                        .all(|&w| w == 0xa5a5_a5a5_a5a5_a5a5),
                    "{start} {len}"
                );
            }
        }
    }

    #[test]
    fn test_zeroize_bytes_covers_unaligned_ends_and_odd_lengths() {
        let mut buffer = [0xa5u8; 71];
        for start in 0..9 {
            for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 40, 62] {
                buffer.fill(0xa5);
                zeroize_bytes(&mut buffer[start..start + len]);
                assert!(buffer[..start].iter().all(|&b| b == 0xa5), "{start} {len}");
                assert!(
                    buffer[start..start + len].iter().all(|&b| b == 0),
                    "{start} {len}"
                );
                assert!(
                    buffer[start + len..].iter().all(|&b| b == 0xa5),
                    "{start} {len}"
                );
            }
        }
    }

    #[test]
    fn test_increment_bytes() {
        let mut b = [0];

        increment_bytes(&mut b);
        assert_eq!(b, [1]);
        increment_bytes(&mut b);
        assert_eq!(b, [2]);

        let mut b = [0xff];

        increment_bytes(&mut b);
        assert_eq!(b, [0]);
        increment_bytes(&mut b);
        assert_eq!(b, [1]);

        let mut b = [0xff, 0];

        increment_bytes(&mut b);
        assert_eq!(b, [0, 1]);
        increment_bytes(&mut b);
        assert_eq!(b, [1, 1]);
        increment_bytes(&mut b);
        assert_eq!(b, [2, 1]);
    }

    #[test]
    fn test_xor_buf() {
        let mut a = [0];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([0], a);

        let mut a = [1];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([1], a);

        let mut a = [1, 1, 1];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([1, 1, 1], a);

        let mut a = [1, 1, 1];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([1, 1, 1], a);

        let mut a = [1, 1, 1];
        let b = [0, 1, 1];

        xor_buf(&mut a, &b);
        assert_eq!([1, 0, 0], a);
    }

    #[test]
    fn test_pad16() {
        assert_eq!(pad16(0), 0);
        assert_eq!(pad16(1), 15);
        assert_eq!(pad16(2), 14);
        assert_eq!(pad16(15), 1);
        assert_eq!(pad16(16), 0);
        assert_eq!(pad16(17), 15);
        assert_eq!(pad16(32), 0);
        assert_eq!(pad16(33), 15);
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;

        #[test]
        fn test_sodium_increment() {
            use libsodium_sys::sodium_increment as so_sodium_increment;
            use rand::TryRng;
            use rand::rngs::SysRng;

            use crate::rng::copy_randombytes;

            for _ in 0..20 {
                let rand_usize = (SysRng.try_next_u32().unwrap() % 1000) as usize;
                let mut data = vec![0u8; rand_usize];
                copy_randombytes(&mut data);

                let mut data_copy = data.clone();

                sodium_increment(&mut data);

                unsafe { so_sodium_increment(data_copy.as_mut_ptr(), data_copy.len()) };

                assert_eq!(data, data_copy);
            }
        }
    }
}

/// Helpers shared by the curve and field unit tests.
#[cfg(test)]
pub(crate) mod test_util {
    /// Decodes a 64-character hex string into 32 bytes.
    pub(crate) fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    /// Deterministic xorshift64 generator for reproducible random test inputs.
    pub(crate) struct XorShift64(u64);

    impl XorShift64 {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed)
        }

        pub(crate) fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// Four successive outputs, little-endian, as 32 bytes.
        pub(crate) fn next_bytes32(&mut self) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            bytes
        }
    }
}
