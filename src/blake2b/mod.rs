#[cfg(all(feature = "simd_backend", feature = "nightly"))]
pub(crate) mod blake2b_simd;
#[cfg(all(feature = "simd_backend", feature = "nightly"))]
pub(crate) use blake2b_simd::*;

// The soft backend (with its AArch64 rounds) is still compiled for tests of
// the portable-SIMD build so the two are checked against each other.
#[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
pub(crate) mod blake2b_soft;
#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
pub(crate) use blake2b_soft::*;

#[cfg(all(
    any(test, not(all(feature = "simd_backend", feature = "nightly"))),
    target_arch = "aarch64",
    target_endian = "little",
    not(miri)
))]
pub(crate) mod blake2b_aarch64;

// The x86-64 kernels are only reached through the soft backend's `compress`.
#[cfg(all(
    target_arch = "x86_64",
    any(test, not(all(feature = "simd_backend", feature = "nightly")))
))]
pub(crate) mod blake2b_x86_64;

pub(crate) const BLOCKBYTES: usize = 128;
pub(crate) const OUTBYTES: usize = 64;
#[cfg(feature = "alloc")]
pub(crate) const HALFOUTBYTES: usize = OUTBYTES / 2;
pub(crate) const KEYBYTES: usize = 64;
pub(crate) const SALTBYTES: usize = 16;
pub(crate) const PERSONALBYTES: usize = 16;

/// The 64-byte BLAKE2b parameter block, laid out exactly as it is XORed into
/// the IV word by word.
#[repr(C, packed)]
#[allow(dead_code)]
pub(crate) struct Params {
    digest_length: u8,
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: [u8; 4],
    node_offset: [u8; 8],
    node_depth: u8,
    inner_length: u8,
    reserved: [u8; 14],
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
}

const _: () = assert!(size_of::<Params>() == OUTBYTES);

impl Default for Params {
    fn default() -> Self {
        Self {
            digest_length: 0,
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: [0u8; 4],
            node_offset: [0u8; 8],
            node_depth: 0,
            inner_length: 0,
            reserved: [0u8; 14],
            salt: [0u8; SALTBYTES],
            personal: [0u8; PERSONALBYTES],
        }
    }
}

impl Params {
    /// Builds the parameter block for an `outlen`-byte digest with optional
    /// `key`, `salt`, and `personal`, validating lengths per the libsodium
    /// API.
    pub(crate) fn new(
        outlen: u8,
        key: Option<&[u8]>,
        salt: Option<&[u8; SALTBYTES]>,
        personal: Option<&[u8; PERSONALBYTES]>,
    ) -> Result<Self, crate::error::Error> {
        validate_length!(
            1,
            OUTBYTES,
            outlen as usize,
            crate::ErrorContext::Blake2bOutput
        );

        let key_length = key.map_or(0, <[u8]>::len);

        validate_length!(max KEYBYTES, key_length, crate::ErrorContext::Blake2bKey);
        let key_length = key_length as u8;

        let salt = match salt {
            Some(salt) => *salt,
            None => [0u8; SALTBYTES],
        };

        let personal = match personal {
            Some(personal) => *personal,
            None => [0u8; PERSONALBYTES],
        };

        Ok(Params {
            digest_length: outlen,
            key_length,
            salt,
            personal,
            ..Default::default()
        })
    }

    /// The parameter block's object representation, little-endian words of
    /// which are XORed into the IV.
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8; OUTBYTES] {
        // SAFETY: `Params` is `repr(C, packed)` and consists only of `u8`
        // fields and byte arrays, so it has alignment 1, no padding, and every
        // one of its `size_of::<Params>() == OUTBYTES` bytes (checked above at
        // compile time) is initialized parameter data. The returned reference
        // borrows `self`, so it cannot outlive or alias a mutation of it.
        unsafe { &*(self as *const Params as *const [u8; OUTBYTES]) }
    }
}

pub(crate) const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Adds `inc` bytes to the 128-bit block counter.
#[inline]
pub(crate) fn increment_counter(t: &mut [u64; 2], inc: usize) {
    let (lo, carry) = t[0].overflowing_add(inc as u64);
    t[0] = lo;
    t[1] = t[1].wrapping_add(carry as u64);
}

/// Expands the backend's `longhash` (the Argon2 `blake2b_long` variant). It
/// names `State` and `hash` unqualified so each expansion binds statically to
/// the invoking backend's own `State::init`/`update`/`finalize` and `hash`.
macro_rules! blake2b_longhash {
    () => {
        /// Fills `output` (5 bytes or more) with the Argon2 long BLAKE2b:
        /// `H(len ‖ input)` for up to 64 bytes, otherwise a chain of 64-byte
        /// hashes each contributing its first half. Only Argon2, which needs
        /// `alloc`, uses it.
        #[cfg(feature = "alloc")]
        pub fn longhash(output: &mut [u8], input: &[u8]) -> Result<(), Error> {
            use zeroize::Zeroize;

            use crate::blake2b::HALFOUTBYTES;

            assert!(output.len() <= u32::MAX as usize);

            let outlen = output.len() as u32;
            let outlen_bytes = outlen.to_le_bytes();

            let mut state = State::init(
                core::cmp::min(outlen, OUTBYTES as u32) as u8,
                None,
                None,
                None,
            )?;
            state.update(&outlen_bytes);
            state.update(input);

            if outlen as usize <= OUTBYTES {
                state.finalize(output)
            } else {
                let mut in_buffer = [0u8; OUTBYTES];
                let mut out_buffer = [0u8; OUTBYTES];
                let result = (|| {
                    state.finalize(&mut output[..OUTBYTES])?;
                    in_buffer.copy_from_slice(&output[..OUTBYTES]);

                    let outlen = output.len() - HALFOUTBYTES;
                    let chunk_count = if outlen.is_multiple_of(HALFOUTBYTES) {
                        outlen / HALFOUTBYTES - 2
                    } else {
                        outlen / HALFOUTBYTES - 1
                    };
                    let end_offset = chunk_count * HALFOUTBYTES;
                    let (start, end) = output[HALFOUTBYTES..].split_at_mut(end_offset);

                    for chunk in start.as_chunks_mut::<HALFOUTBYTES>().0 {
                        hash(&mut out_buffer, &in_buffer, None)?;

                        chunk.copy_from_slice(&out_buffer[..HALFOUTBYTES]);
                        in_buffer.copy_from_slice(&out_buffer);
                    }
                    hash(end, &in_buffer, None)
                })();
                in_buffer.zeroize();
                out_buffer.zeroize();
                result
            }
        }
    };
}
pub(crate) use blake2b_longhash;

/// The portable-SIMD backend against the soft one (register-scheduled
/// AArch64 rounds where those are compiled in), over every entry point.
#[cfg(all(test, feature = "simd_backend", feature = "nightly"))]
mod tests {
    use super::{blake2b_simd as simd, blake2b_soft as soft};
    use crate::test_prelude::*;

    /// Lengths around the block boundaries, the single-block fast path and a
    /// few longer messages.
    const LENS: [usize; 17] = [
        0, 1, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 257, 383, 384, 1000, 4096,
    ];

    fn message(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// The message hashed through `State` in `cuts` pieces.
    fn chunked<F>(init: F, message: &[u8], cuts: &[usize], outlen: usize) -> Vec<u8>
    where
        F: FnOnce() -> Result<StateEither, crate::error::Error>,
    {
        let mut state = init().unwrap();
        let mut cuts: Vec<usize> = cuts.iter().map(|cut| (*cut).min(message.len())).collect();
        cuts.push(0);
        cuts.push(message.len());
        cuts.sort_unstable();
        cuts.dedup();
        for window in cuts.windows(2) {
            state.update(&message[window[0]..window[1]]);
        }
        let mut out = vec![0u8; outlen];
        state.finalize(&mut out).unwrap();
        out
    }

    /// One `State` of either backend, so the chunked driver is written once.
    enum StateEither {
        Soft(soft::State),
        Simd(simd::State),
    }

    impl StateEither {
        fn update(&mut self, input: &[u8]) {
            match self {
                StateEither::Soft(state) => state.update(input),
                StateEither::Simd(state) => state.update(input),
            }
        }

        fn finalize(self, output: &mut [u8]) -> Result<(), crate::error::Error> {
            match self {
                StateEither::Soft(state) => state.finalize(output),
                StateEither::Simd(state) => state.finalize(output),
            }
        }
    }

    #[test]
    fn test_hash_matches_soft_for_every_length_key_and_outlen() {
        let key: Vec<u8> = (0..64u8).collect();
        for len in LENS {
            let message = message(len);
            for outlen in [1, 16, 31, 32, 33, 48, 63, 64] {
                for key in [None, Some(&key[..1]), Some(&key[..32]), Some(&key[..64])] {
                    let mut expected = vec![0u8; outlen];
                    soft::hash(&mut expected, &message, key).unwrap();
                    let mut actual = vec![0u8; outlen];
                    simd::hash(&mut actual, &message, key).unwrap();
                    assert_eq!(actual, expected, "len {len}, outlen {outlen}, key {key:?}");
                }
            }
        }
    }

    #[test]
    fn test_state_matches_soft_for_every_chunking() {
        let key: Vec<u8> = (0..64u8).collect();
        let salt = [0x5au8; 16];
        let personal = [0xa5u8; 16];
        let cuts: [&[usize]; 4] = [
            &[],
            &[1, 63, 64, 65],
            &[127, 128, 129, 256],
            &[200, 201, 500],
        ];
        for len in LENS {
            let message = message(len);
            for cuts in cuts {
                for (key, salt, personal) in [
                    (None, None, None),
                    (Some(&key[..17]), None, None),
                    (Some(&key[..64]), Some(&salt), Some(&personal)),
                    (None, Some(&salt), Some(&personal)),
                ] {
                    let expected = chunked(
                        || soft::State::init(64, key, salt, personal).map(StateEither::Soft),
                        &message,
                        cuts,
                        64,
                    );
                    let actual = chunked(
                        || simd::State::init(64, key, salt, personal).map(StateEither::Simd),
                        &message,
                        cuts,
                        64,
                    );
                    assert_eq!(actual, expected, "len {len}, cuts {cuts:?}, key {key:?}");
                }
            }
        }
    }

    #[test]
    fn test_hash_key_only_matches_soft() {
        let key: Vec<u8> = (100..164u8).collect();
        let salt = [0x11u8; 16];
        let personal = [0x22u8; 16];
        for key_len in [1, 16, 32, 63, 64] {
            for outlen in [1, 32, 64] {
                let mut expected = vec![0u8; outlen];
                soft::hash_key_only(&mut expected, &key[..key_len], &salt, &personal).unwrap();
                let mut actual = vec![0u8; outlen];
                simd::hash_key_only(&mut actual, &key[..key_len], &salt, &personal).unwrap();
                assert_eq!(actual, expected, "key_len {key_len}, outlen {outlen}");
            }
        }
    }

    /// Output lengths around the 64-byte single-hash case and the 32-byte
    /// chaining steps of the long variant (both the exact multiple and the
    /// remainder branches).
    #[test]
    #[cfg(feature = "alloc")]
    fn test_longhash_matches_soft() {
        let message = message(1000);
        for outlen in [5, 32, 63, 64, 65, 95, 96, 97, 128, 129, 1024, 1025] {
            let mut expected = vec![0u8; outlen];
            soft::longhash(&mut expected, &message).unwrap();
            let mut actual = vec![0u8; outlen];
            simd::longhash(&mut actual, &message).unwrap();
            assert_eq!(actual, expected, "outlen {outlen}");
        }
    }
}

#[cfg(test)]
mod counter_tests {
    use super::increment_counter;

    /// The 128-bit byte counter: the low word wraps and carries exactly one
    /// into the high word, only when it overflows (RFC 7693 §2.3 `t`).
    #[test]
    fn test_increment_counter_carries_into_high_word() {
        let mut t = [u64::MAX - 64, 0];
        increment_counter(&mut t, 64);
        assert_eq!(
            t,
            [u64::MAX, 0],
            "filling the low word exactly does not carry"
        );
        increment_counter(&mut t, 1);
        assert_eq!(t, [0, 1], "one more wraps the low word and carries");
        increment_counter(&mut t, super::BLOCKBYTES);
        assert_eq!(t, [super::BLOCKBYTES as u64, 1]);

        let mut t = [u64::MAX - 64, 7];
        increment_counter(&mut t, super::BLOCKBYTES);
        assert_eq!(t, [63, 8], "a block straddling the wrap carries once");

        let mut t = [u64::MAX, u64::MAX];
        increment_counter(&mut t, 1);
        assert_eq!(t, [0, 0], "the full 128-bit counter wraps silently");
    }
}

/// The selected backend against libsodium's
/// `crypto_generichash_blake2b_salt_personal` over every parameter-block field:
/// output length, key length, salt and personalization, at the block
/// boundaries.
#[cfg(all(test, dryoc_native_tests))]
mod native_tests {
    use super::*;
    use crate::test_prelude::*;

    const LENS: [usize; 5] = [0, 127, 128, 129, 256];
    const OUTLENS: [usize; 6] = [1, 31, 32, 33, 63, 64];
    const KEYLENS: [usize; 4] = [0, 1, 32, 64];

    fn message(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn libsodium(
        outlen: usize,
        message: &[u8],
        key: Option<&[u8]>,
        salt: Option<&[u8; SALTBYTES]>,
        personal: Option<&[u8; PERSONALBYTES]>,
    ) -> Vec<u8> {
        crate::native_test_util::init();
        let mut out = vec![0u8; outlen];
        // SAFETY: every pointer is valid for the length passed alongside it
        // (or null with a zero length for the key; libsodium treats a null
        // salt or personalization as all zeros).
        let rc = unsafe {
            libsodium_sys::crypto_generichash_blake2b_salt_personal(
                out.as_mut_ptr(),
                outlen,
                message.as_ptr(),
                message.len() as u64,
                key.map_or(core::ptr::null(), <[u8]>::as_ptr),
                key.map_or(0, <[u8]>::len),
                salt.map_or(core::ptr::null(), |salt| salt.as_ptr()),
                personal.map_or(core::ptr::null(), |personal| personal.as_ptr()),
            )
        };
        assert_eq!(rc, 0);
        out
    }

    /// `message` through `State`, in one update and cut at `cuts` with an
    /// empty update after every piece.
    fn state_paths(
        outlen: usize,
        message: &[u8],
        key: Option<&[u8]>,
        salt: Option<&[u8; SALTBYTES]>,
        personal: Option<&[u8; PERSONALBYTES]>,
        cuts: &[usize],
    ) -> [Vec<u8>; 2] {
        let mut one = State::init(outlen as u8, key, salt, personal).expect("init");
        one.update(message);
        let mut one_out = vec![0u8; outlen];
        one.finalize(&mut one_out).expect("finalize");

        let mut chunked = State::init(outlen as u8, key, salt, personal).expect("init");
        let mut start = 0;
        for cut in cuts.iter().copied().chain(core::iter::once(message.len())) {
            let cut = cut.min(message.len()).max(start);
            chunked.update(&message[start..cut]);
            chunked.update(&[]);
            start = cut;
        }
        let mut chunked_out = vec![0u8; outlen];
        chunked.finalize(&mut chunked_out).expect("finalize");

        [one_out, chunked_out]
    }

    #[test]
    fn test_parameter_matrix_matches_libsodium() {
        let key: Vec<u8> = (0..KEYBYTES as u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        let salt: [u8; SALTBYTES] = core::array::from_fn(|i| 0xa0 + i as u8);
        let personal: [u8; PERSONALBYTES] = core::array::from_fn(|i| 0x50 + i as u8);

        for len in LENS {
            let message = message(len);
            for outlen in OUTLENS {
                for keylen in KEYLENS {
                    let key = (keylen > 0).then(|| &key[..keylen]);
                    for (salt, personal) in [(None, None), (Some(&salt), Some(&personal))] {
                        let expected = libsodium(outlen, &message, key, salt, personal);
                        let label = format!(
                            "len {len}, outlen {outlen}, keylen {keylen}, salted {}",
                            salt.is_some()
                        );
                        for actual in
                            state_paths(outlen, &message, key, salt, personal, &[1, 128, 129])
                        {
                            assert_eq!(actual, expected, "{label}");
                        }
                        if salt.is_none() {
                            let mut actual = vec![0u8; outlen];
                            hash(&mut actual, &message, key).expect("hash");
                            assert_eq!(actual, expected, "hash, {label}");
                        }
                        if let (0, Some(key), Some(salt), Some(personal)) =
                            (len, key, salt, personal)
                        {
                            let mut actual = vec![0u8; outlen];
                            hash_key_only(&mut actual, key, salt, personal).expect("keyed");
                            assert_eq!(actual, expected, "hash_key_only, {label}");
                        }
                    }
                }
            }
        }
    }
}
