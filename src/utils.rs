use crate::error::{Error, ErrorContext};

/// The ChaCha/Salsa20 "expand 32-byte k" constant, as four little-endian
/// words. Shared by the ChaCha20 and XSalsa20 stream ciphers and the
/// HChaCha20/HSalsa20 defaults in [`crate::classic::crypto_core`].
pub(crate) const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

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

/// Splits `bytes` into a fixed-length prefix and the remainder.
///
/// Returns [`Error::InvalidLength`] with `context` when `bytes` is shorter
/// than `len`. Shared by the Rustaceous `from_bytes` constructors, which all
/// parse an authentication tag, signature, or nonce off one end of a slice.
pub(crate) fn split_prefix(
    bytes: &[u8],
    len: usize,
    context: ErrorContext,
) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < len {
        Err(length_error!(context, bytes.len(), min len))
    } else {
        Ok(bytes.split_at(len))
    }
}

/// Splits `bytes` into the leading remainder and a fixed-length suffix.
///
/// Returns [`Error::InvalidLength`] with `context` when `bytes` is shorter
/// than `len`. See [`split_prefix`].
pub(crate) fn split_suffix(
    bytes: &[u8],
    len: usize,
    context: ErrorContext,
) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < len {
        Err(length_error!(context, bytes.len(), min len))
    } else {
        Ok(bytes.split_at(bytes.len() - len))
    }
}

/// Compares `expected` against `computed` in constant time, returning
/// [`Error::AuthenticationFailed`] on mismatch.
///
/// Shared by the Classic verify paths, which all performed this exact
/// [`subtle::ConstantTimeEq`] comparison inline. Both slices must have the
/// same length; every caller compares fixed-size tags or hashes.
pub(crate) fn verify_ct(expected: &[u8], computed: &[u8]) -> Result<(), Error> {
    use subtle::ConstantTimeEq;

    if expected.ct_eq(computed).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

/// Compares `a` and `b` in constant time, returning `true` when equal.
///
/// Shared by the constant-time [`PartialEq`] impls of the byte-container
/// types. Both slices must have the same length; every caller compares
/// fixed-size values.
pub(crate) fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    a.ct_eq(b).unwrap_u8() == 1
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

    /// `sodium_increment` vectors: little-endian, the carry propagates
    /// through every `0xff` byte, and the all-ones value wraps to zero.
    const INCREMENT_VECTORS: &[(&[u8], &[u8])] = &[
        (&[], &[]),
        (&[0], &[1]),
        (&[1], &[2]),
        (&[0xff], &[0]),
        (&[0xff, 0], &[0, 1]),
        (&[0x00, 0xff], &[0x01, 0xff]),
        (&[0xff, 0xff, 0x00], &[0, 0, 1]),
        (
            &[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0xff; 8],
        ),
        (&[0xff; 8], &[0; 8]),
        (&[0xff; 24], &[0; 24]),
    ];

    #[test]
    fn test_increment_bytes() {
        for (input, expected) in INCREMENT_VECTORS {
            let mut bytes = input.to_vec();
            increment_bytes(&mut bytes);
            assert_eq!(bytes.as_slice(), *expected, "increment of {input:02x?}");
        }

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

            use crate::utils::test_util::XorShift64;

            fn assert_matches_libsodium(input: &[u8]) {
                let mut ours = input.to_vec();
                let mut theirs = input.to_vec();
                sodium_increment(&mut ours);
                // SAFETY: `theirs` is a valid, writable buffer of exactly
                // `theirs.len()` bytes for the duration of the call.
                unsafe { so_sodium_increment(theirs.as_mut_ptr(), theirs.len()) };
                assert_eq!(ours, theirs, "input {input:02x?}");
            }

            for (input, _) in INCREMENT_VECTORS {
                assert_matches_libsodium(input);
            }

            let mut rng = XorShift64::new(0x9e37_79b9_7f4a_7c15);
            for len in 0..=64 {
                let mut data = vec![0u8; len];
                for b in &mut data {
                    *b = rng.next_u64() as u8;
                }
                assert_matches_libsodium(&data);
                assert_matches_libsodium(&vec![0xff; len]);

                // Carry chain that stops at a non-`0xff` final byte.
                if let Some((last, head)) = data.split_last_mut() {
                    head.fill(0xff);
                    *last &= 0x7f;
                    assert_matches_libsodium(&data);
                }
            }
        }
    }
}

/// Helpers shared by the curve, field, and byte-container unit tests.
#[cfg(test)]
pub(crate) mod test_util {
    use crate::error::{Error, ErrorContext, LengthConstraint};

    /// Bounds Miri runs and disables filesystem-backed failure persistence.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn proptest_config(cases: u32) -> proptest::test_runner::Config {
        let mut config = proptest::test_runner::Config::with_cases(cases);
        if cfg!(miri) {
            config.cases = 8;
            config.failure_persistence = None;
        }
        config
    }

    /// Asserts that `result` is `Error::InvalidLength` for a slice of
    /// `actual` bytes where exactly `expected` were required, matching on the
    /// variant rather than its message.
    pub(crate) fn assert_exact_slice_length_error<T>(
        result: Result<T, Error>,
        actual: usize,
        expected: usize,
    ) {
        match result {
            Err(Error::InvalidLength {
                context,
                actual: got,
                constraint,
            }) => {
                assert_eq!(context, ErrorContext::Slice);
                assert_eq!(got, actual);
                assert_eq!(constraint, LengthConstraint::Exact(expected));
            }
            Err(other) => panic!("unexpected error {other:?}"),
            Ok(_) => panic!("length {actual} accepted where exactly {expected} is required"),
        }
    }

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
