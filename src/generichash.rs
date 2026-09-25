//! # Generic hashing
//!
//! [`GenericHash`] implements libsodium's generic hashing with BLAKE2b. Without
//! a key, it produces a general-purpose cryptographic hash. With a secret key,
//! it acts as a message authentication code (MAC) or pseudorandom function
//! (PRF). Keyed BLAKE2b is not HMAC.
//!
//! # Rustaceous API example, single-part interface
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::generichash::{GenericHash, Key};
//!
//! // The key type must be specified because `None` does not identify it.
//! let hash =
//!     GenericHash::hash_with_defaults_to_vec::<_, Key>(b"hello", None).expect("hash failed");
//!
//! assert_eq!(
//!     general_purpose::STANDARD.encode(&hash),
//!     "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
//! );
//! ```
//!
//! # Rustaceous API example, incremental interface
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::generichash::{GenericHash, Key};
//!
//! // The key type must be specified because `None` does not identify it.
//! let mut hasher = GenericHash::new_with_defaults::<Key>(None).expect("new failed");
//! hasher.update(b"hello");
//! let hash = hasher.finalize_to_vec().expect("finalize failed");
//!
//! assert_eq!(
//!     general_purpose::STANDARD.encode(&hash),
//!     "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
//! );
//! ```

use crate::classic::crypto_generichash::{
    GenericHashState, crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update,
};
use crate::constants::{CRYPTO_GENERICHASH_BYTES, CRYPTO_GENERICHASH_KEYBYTES};
use crate::error::Error;
pub use crate::types::*;

/// Stack-allocated hash output of the recommended output length.
pub type Hash = StackByteArray<CRYPTO_GENERICHASH_BYTES>;
/// Stack-allocated secret key for use with the generic hash algorithm.
pub type Key = StackByteArray<CRYPTO_GENERICHASH_KEYBYTES>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`GenericHash`]
    //!
    //! Protected-memory aliases for generic-hash keys and outputs.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::generichash::GenericHash;
    //! use dryoc::generichash::protected::*;
    //!
    //! // Create a randomly generated key, lock it, protect it as read-only
    //! let key = Key::generate_readonly_locked().expect("generate failed");
    //! let input =
    //!     HeapBytes::from_slice_into_readonly_locked(b"super secret input").expect("input failed");
    //! let hash: Locked<Hash> = GenericHash::hash(&input, Some(&key)).expect("hash failed");
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned secret key for the generic hash algorithm,
    /// for use with protected memory.
    pub type Key = HeapByteArray<CRYPTO_GENERICHASH_KEYBYTES>;
    /// Heap-allocated, page-aligned hash output for the generic hash algorithm,
    /// for use with protected memory.
    pub type Hash = HeapByteArray<CRYPTO_GENERICHASH_BYTES>;
}

/// Provides a generic hash function implementation based on Blake2b. Compatible
/// with libsodium's generic hash.
pub struct GenericHash<const KEY_LENGTH: usize, const OUTPUT_LENGTH: usize> {
    state: GenericHashState,
}

impl<const KEY_LENGTH: usize, const OUTPUT_LENGTH: usize> GenericHash<KEY_LENGTH, OUTPUT_LENGTH> {
    /// Returns a new incremental hasher with an optional secret `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if `OUTPUT_LENGTH` or the length of `key` is outside
    /// the range supported by libsodium's generic hash function.
    pub fn new<Key: ByteArray<KEY_LENGTH>>(key: Option<&Key>) -> Result<Self, Error> {
        Ok(Self {
            state: crypto_generichash_init(key.map(|k| k.as_slice()), OUTPUT_LENGTH)?,
        })
    }

    /// Updates the hasher state from `input`.
    pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
        crypto_generichash_update(&mut self.state, input.as_slice())
    }

    /// Computes and returns the final hash value.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying BLAKE2b finalization rejects the
    /// output. Initialization normally guarantees a valid output length.
    pub fn finalize<Output: NewByteArray<OUTPUT_LENGTH>>(self) -> Result<Output, Error> {
        let mut output = Output::new_byte_array();

        crypto_generichash_final(self.state, output.as_mut_slice())?;

        Ok(output)
    }

    /// Computes and returns the final hash value as a [`Vec`]. Provided for
    /// convenience.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying BLAKE2b finalization rejects the
    /// output. Initialization normally guarantees a valid output length.
    pub fn finalize_to_vec(self) -> Result<Vec<u8>, Error> {
        Ok(self.finalize::<StackByteArray<OUTPUT_LENGTH>>()?.to_vec())
    }

    /// Computes the hash of `input` with an optional secret `key`.
    ///
    /// The output length is determined by `Output`. Providing a key selects
    /// keyed BLAKE2b, which can be used as a MAC or PRF.
    ///
    /// # Errors
    ///
    /// Returns an error if `OUTPUT_LENGTH` or the length of `key` is outside
    /// the range supported by libsodium's generic hash function.
    ///
    /// # Example
    ///
    /// ```
    /// use base64::Engine as _;
    /// use base64::engine::general_purpose;
    /// use dryoc::generichash::{GenericHash, Hash};
    ///
    /// let output: Hash =
    ///     GenericHash::hash(b"hello", Some(b"a very secret key")).expect("hash failed");
    ///
    /// assert_eq!(
    ///     general_purpose::STANDARD.encode(&output),
    ///     "AECDe+XJsB6nOkbCsbS/OPXdzpcRm3AolW/Bg1LFY9A="
    /// );
    /// ```
    pub fn hash<
        Input: Bytes + ?Sized,
        Key: ByteArray<KEY_LENGTH>,
        Output: NewByteArray<OUTPUT_LENGTH>,
    >(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Output, Error> {
        let mut output = Output::new_byte_array();
        crypto_generichash(
            output.as_mut_slice(),
            input.as_slice(),
            key.map(|k| k.as_slice()),
        )?;
        Ok(output)
    }

    /// Convenience wrapper for [`GenericHash::hash`].
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`GenericHash::hash`].
    pub fn hash_to_vec<Input: Bytes, Key: ByteArray<KEY_LENGTH>>(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Vec<u8>, Error> {
        Ok(Self::hash::<_, _, StackByteArray<OUTPUT_LENGTH>>(input, key)?.to_vec())
    }
}

impl GenericHash<CRYPTO_GENERICHASH_KEYBYTES, CRYPTO_GENERICHASH_BYTES> {
    /// Returns an instance of [`GenericHash`] with the default output and key
    /// length parameters.
    ///
    /// # Errors
    ///
    /// The default lengths are valid, so this method does not return an error
    /// for valid [`ByteArray`] implementations. Its return type matches the
    /// generic initialization interface.
    pub fn new_with_defaults<Key: ByteArray<CRYPTO_GENERICHASH_KEYBYTES>>(
        key: Option<&Key>,
    ) -> Result<Self, Error> {
        Ok(Self {
            state: crypto_generichash_init(key.map(|k| k.as_slice()), CRYPTO_GENERICHASH_BYTES)?,
        })
    }

    /// Hashes `input` using `key`, with the default length parameters. Provided
    /// for convenience.
    ///
    /// # Errors
    ///
    /// The default lengths are valid, so this method does not return an error
    /// for valid [`ByteArray`] implementations. Its return type matches the
    /// generic hashing interface.
    pub fn hash_with_defaults<
        Input: Bytes + ?Sized,
        Key: ByteArray<CRYPTO_GENERICHASH_KEYBYTES>,
        Output: NewByteArray<CRYPTO_GENERICHASH_BYTES>,
    >(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Output, Error> {
        Self::hash(input, key)
    }

    /// Hashes `input` using `key`, with the default length parameters,
    /// returning a [`Vec`]. Provided for convenience.
    ///
    /// # Errors
    ///
    /// The default lengths are valid, so this method does not return an error
    /// for valid [`ByteArray`] implementations. Its return type matches the
    /// generic hashing interface.
    pub fn hash_with_defaults_to_vec<
        Input: Bytes + ?Sized,
        Key: ByteArray<CRYPTO_GENERICHASH_KEYBYTES>,
    >(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Vec<u8>, Error> {
        Ok(Self::hash::<_, _, Hash>(input, key)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generichash() {
        use base64::Engine as _;
        use base64::engine::general_purpose;

        let mut hasher = GenericHash::new_with_defaults::<Key>(None).expect("new hash failed");
        hasher.update(b"hello");

        let output: Hash = hasher.finalize().expect("finalize failed");

        assert_eq!(
            general_purpose::STANDARD.encode(&output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );

        let mut hasher = GenericHash::new_with_defaults::<Key>(None).expect("new hash failed");
        hasher.update(b"hello");

        let output = hasher.finalize_to_vec().expect("finalize failed");

        assert_eq!(
            general_purpose::STANDARD.encode(output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );
    }

    #[test]
    fn test_generichash_onetime() {
        use base64::Engine as _;
        use base64::engine::general_purpose;

        let output: Hash =
            GenericHash::hash(b"hello", Some(b"a very secret key")).expect("hash failed");

        assert_eq!(
            general_purpose::STANDARD.encode(&output),
            "AECDe+XJsB6nOkbCsbS/OPXdzpcRm3AolW/Bg1LFY9A="
        );

        let output: Hash =
            GenericHash::hash_with_defaults::<_, Key, _>(b"hello", None).expect("hash failed");

        assert_eq!(
            general_purpose::STANDARD.encode(&output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );

        let output =
            GenericHash::hash_with_defaults_to_vec::<_, Key>(b"hello", None).expect("hash failed");

        assert_eq!(
            general_purpose::STANDARD.encode(output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );
    }
    #[test]
    fn test_generichash_onetime_empty() {
        use base64::Engine as _;
        use base64::engine::general_purpose;

        let output =
            GenericHash::hash_with_defaults_to_vec::<_, Key>(&[], None).expect("hash failed");

        assert_eq!(
            general_purpose::STANDARD.encode(output),
            "DldRwCblQ7Loqy6wYJnaodHl30d3j3eH+qtFzfEv46g="
        );
    }

    #[test]
    fn test_vectors() {
        let test_vec = |input, key, hash| {
            let input = hex::decode(input).expect("decode input");
            let key: [u8; 64] = hex::decode(key)
                .expect("decode key")
                .try_into()
                .expect("64-byte key");
            let expected_hash = hex::decode(hash).expect("decode hash");

            let hash: [u8; 64] =
                GenericHash::<64, 64>::hash(&input, Some(&key)).expect("hash failed");

            assert_eq!(expected_hash, hash);
        };

        test_vec("", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568");
        test_vec("00", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd");
        test_vec("0001", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965");
        test_vec("000102", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1");
        test_vec("00010203", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "beaa5a3d08f3807143cf621d95cd690514d0b49efff9c91d24b59241ec0eefa5f60196d407048bba8d2146828ebcb0488d8842fd56bb4f6df8e19c4b4daab8ac");
        test_vec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfc", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "a6213743568e3b3158b9184301f3690847554c68457cb40fc9a4b8cfd8d4a118c301a07737aeda0f929c68913c5f51c80394f53bff1c3e83b2e40ca97eba9e15");
        test_vec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "d444bfa2362a96df213d070e33fa841f51334e4e76866b8139e8af3bb3398be2dfaddcbc56b9146de9f68118dc5829e74b0c28d7711907b121f9161cb92b69a9");
        test_vec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461");
    }

    use crate::constants::{
        CRYPTO_GENERICHASH_BYTES_MAX, CRYPTO_GENERICHASH_BYTES_MIN,
        CRYPTO_GENERICHASH_KEYBYTES_MAX, CRYPTO_GENERICHASH_KEYBYTES_MIN,
    };

    const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";

    /// libsodium `crypto_generichash` of `FOX` for `(outlen, key = 0..keylen)`.
    /// The unkeyed 64-byte value is the published BLAKE2b-512 digest.
    const FOX_KAT: [(usize, usize, &str); 5] = [
        (16, 0, "249df9a49f517ddcd37f5c897620ec73"),
        (
            64,
            0,
            concat!(
                "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673",
                "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
            ),
        ),
        (16, 16, "fb80e606c7e3d993cbf7117a60f630a0"),
        (
            32,
            32,
            "5d9461aff732d77d0cc98725ea29298c914fd5193b4c08ec9e3ad6b28c3e2faf",
        ),
        (
            64,
            64,
            concat!(
                "1d58d71414d24752db3274afdc483fc0f4c68317c4c2f6a31e09de9437ba02cc",
                "ab8c8585790a52b0d476f7920c0e1397d1aec9e52f3df3feae76f7d6223ce5cf",
            ),
        ),
    ];

    fn sequential_key<const LENGTH: usize>() -> StackByteArray<LENGTH> {
        StackByteArray::from(std::array::from_fn::<u8, LENGTH, _>(|i| i as u8))
    }

    /// Hashes `FOX` one-shot and in three incremental splits, checking both
    /// against `expected`.
    fn assert_fox<const KEY_LENGTH: usize, const OUTPUT_LENGTH: usize>(
        key: Option<&StackByteArray<KEY_LENGTH>>,
        expected: &str,
    ) {
        let expected = hex::decode(expected).expect("hex");
        let output: StackByteArray<OUTPUT_LENGTH> =
            GenericHash::<KEY_LENGTH, OUTPUT_LENGTH>::hash(FOX, key).expect("hash");
        assert_eq!(output.as_slice(), expected.as_slice());
        assert_eq!(
            GenericHash::<KEY_LENGTH, OUTPUT_LENGTH>::hash_to_vec(&FOX, key).expect("hash"),
            expected
        );

        for parts in [
            vec![FOX],
            vec![&FOX[..1], &FOX[1..]],
            vec![&[][..], &FOX[..20], &FOX[20..40], &FOX[40..], &[][..]],
        ] {
            let mut hasher = GenericHash::<KEY_LENGTH, OUTPUT_LENGTH>::new(key).expect("new");
            for part in &parts {
                hasher.update(*part);
            }
            let output: StackByteArray<OUTPUT_LENGTH> = hasher.finalize().expect("finalize");
            assert_eq!(output.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn min_and_max_output_and_key_lengths_match_libsodium_known_answers() {
        assert_fox::<CRYPTO_GENERICHASH_KEYBYTES, 16>(None, FOX_KAT[0].2);
        assert_fox::<CRYPTO_GENERICHASH_KEYBYTES, 64>(None, FOX_KAT[1].2);
        assert_fox::<16, 16>(Some(&sequential_key::<16>()), FOX_KAT[2].2);
        assert_fox::<32, 32>(Some(&sequential_key::<32>()), FOX_KAT[3].2);
        assert_fox::<64, 64>(Some(&sequential_key::<64>()), FOX_KAT[4].2);

        // A key changes the output, and the short digest is not a truncation of
        // the long one.
        let unkeyed16 = hex::decode(FOX_KAT[0].2).expect("hex");
        let keyed16 = hex::decode(FOX_KAT[2].2).expect("hex");
        let unkeyed64 = hex::decode(FOX_KAT[1].2).expect("hex");
        assert_ne!(unkeyed16, keyed16);
        assert_ne!(unkeyed16, &unkeyed64[..16]);
    }

    #[test]
    fn out_of_range_output_and_key_lengths_are_rejected_before_hashing() {
        assert!(matches!(
            GenericHash::<CRYPTO_GENERICHASH_KEYBYTES, { CRYPTO_GENERICHASH_BYTES_MIN - 1 }>::new::<
                Key,
            >(None),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Output,
                actual: 15,
                ..
            })
        ));
        let too_long: Result<StackByteArray<{ CRYPTO_GENERICHASH_BYTES_MAX + 1 }>, Error> =
            GenericHash::<CRYPTO_GENERICHASH_KEYBYTES, { CRYPTO_GENERICHASH_BYTES_MAX + 1 }>::hash::<
                _,
                Key,
                _,
            >(FOX, None);
        assert!(matches!(
            too_long,
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Output,
                actual: 65,
                ..
            })
        ));

        let short_key = sequential_key::<{ CRYPTO_GENERICHASH_KEYBYTES_MIN - 1 }>();
        assert!(matches!(
            GenericHash::<{ CRYPTO_GENERICHASH_KEYBYTES_MIN - 1 }, 32>::new(Some(&short_key)),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Blake2bKey,
                actual: 15,
                ..
            })
        ));
        let long_key = sequential_key::<{ CRYPTO_GENERICHASH_KEYBYTES_MAX + 1 }>();
        let rejected: Result<Hash, Error> =
            GenericHash::<{ CRYPTO_GENERICHASH_KEYBYTES_MAX + 1 }, 32>::hash(FOX, Some(&long_key));
        assert!(matches!(
            rejected,
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Blake2bKey,
                actual: 65,
                ..
            })
        ));

        // Only a supplied key is validated: an unusual key type with no key
        // still hashes, and matches the unkeyed default.
        let unkeyed: Hash = GenericHash::<{ CRYPTO_GENERICHASH_KEYBYTES_MIN - 1 }, 32>::hash(
            FOX,
            None::<&StackByteArray<15>>,
        )
        .expect("unkeyed");
        let default_unkeyed: Hash =
            GenericHash::hash_with_defaults::<_, Key, _>(FOX, None).expect("unkeyed");
        assert_eq!(unkeyed, default_unkeyed);
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_key_input_and_output_match_stack_types() {
        use crate::generichash::protected::*;

        let input = HeapBytes::from_slice_into_readonly_locked(FOX).expect("lock input");
        let key = sequential_key::<CRYPTO_GENERICHASH_KEYBYTES>();
        let locked_key =
            protected::Key::from_slice_into_readonly_locked(key.as_slice()).expect("lock key");
        let expected = hex::decode(FOX_KAT[3].2).expect("hex");

        let hash: Locked<protected::Hash> =
            GenericHash::hash(&input, Some(&locked_key)).expect("hash");
        assert_eq!(hash.as_slice(), expected.as_slice());
        let stack: Hash = GenericHash::hash(FOX, Some(&key)).expect("hash");
        assert_eq!(stack.as_slice(), hash.as_slice());

        let mut hasher = GenericHash::new_with_defaults(Some(&locked_key)).expect("new");
        hasher.update(&input);
        let hash: Locked<protected::Hash> = hasher.finalize().expect("finalize");
        assert_eq!(hash.as_slice(), expected.as_slice());

        let unkeyed: Locked<protected::Hash> =
            GenericHash::hash_with_defaults::<_, protected::Key, _>(&input, None).expect("hash");
        let stack_unkeyed: Hash =
            GenericHash::hash_with_defaults::<_, Key, _>(FOX, None).expect("hash");
        assert_eq!(unkeyed.as_slice(), stack_unkeyed.as_slice());
        assert_ne!(unkeyed.as_slice(), expected.as_slice());
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn keyed_and_unkeyed_hashes_match_libsodium_at_length_bounds() {
        fn sodium_hash(input: &[u8], key: Option<&[u8]>, outlen: usize) -> Vec<u8> {
            crate::native_test_util::init();
            let mut output = vec![0u8; outlen];
            let rc = unsafe {
                libsodium_sys::crypto_generichash(
                    output.as_mut_ptr(),
                    outlen,
                    input.as_ptr(),
                    input.len() as u64,
                    key.map_or(std::ptr::null(), <[u8]>::as_ptr),
                    key.map_or(0, <[u8]>::len),
                )
            };
            assert_eq!(rc, 0);
            output
        }

        for (outlen, keylen, _) in FOX_KAT {
            let key: Vec<u8> = (0..keylen as u8).collect();
            let key = (keylen > 0).then_some(key.as_slice());
            let expected = sodium_hash(FOX, key, outlen);
            let actual = match (keylen, outlen) {
                (0, 16) => GenericHash::<64, 16>::hash_to_vec(&FOX, None::<&StackByteArray<64>>),
                (0, 64) => GenericHash::<64, 64>::hash_to_vec(&FOX, None::<&StackByteArray<64>>),
                (16, 16) => GenericHash::<16, 16>::hash_to_vec(&FOX, Some(&sequential_key::<16>())),
                (32, 32) => GenericHash::<32, 32>::hash_to_vec(&FOX, Some(&sequential_key::<32>())),
                (64, 64) => GenericHash::<64, 64>::hash_to_vec(&FOX, Some(&sequential_key::<64>())),
                _ => unreachable!(),
            }
            .expect("hash");
            assert_eq!(actual, expected);
        }

        // Inputs straddling the 128-byte BLAKE2b block boundary.
        let key = sequential_key::<CRYPTO_GENERICHASH_KEYBYTES>();
        for len in [0, 1, 127, 128, 129, 255, 256, 257] {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let expected = sodium_hash(&input, Some(key.as_slice()), CRYPTO_GENERICHASH_BYTES);
            assert_eq!(
                GenericHash::hash_with_defaults_to_vec(&input, Some(&key)).expect("hash"),
                expected
            );
            let expected = sodium_hash(&input, None, CRYPTO_GENERICHASH_BYTES);
            assert_eq!(
                GenericHash::hash_with_defaults_to_vec::<_, Key>(&input, None).expect("hash"),
                expected
            );
        }
    }
}
