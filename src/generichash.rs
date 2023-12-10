//! # Generic hashing
//!
//! [`GenericHash`] implements libsodium's generic hashing, based on the Blake2b
//! algorithm. Can also be used as an HMAC function, if a key is provided.
//!
//! # Rustaceous API example, one-time interface
//!
//! ```
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::generichash::{GenericHash, Key};
//!
//! // NOTE: The type for `key` param must be specified, the compiler cannot infer it when
//! // we pass `None`.
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
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::generichash::{GenericHash, Key};
//!
//! // The compiler cannot infer the `Key` type, so we pass it below.
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
    crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update, GenericHashState,
};
use crate::constants::{CRYPTO_GENERICHASH_BYTES, CRYPTO_GENERICHASH_KEYBYTES};
use crate::error::Error;
pub use crate::types::*;

/// Stack-allocated hash output of the recommended output length.
pub type Hash = StackByteArray<CRYPTO_GENERICHASH_BYTES>;
/// Stack-allocated secret key for use with the generic hash algorithm.
pub type Key = StackByteArray<CRYPTO_GENERICHASH_KEYBYTES>;

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`GenericHash`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`GenericHash`]. These type aliases are provided for
    //! convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::generichash::protected::*;
    //! use dryoc::generichash::GenericHash;
    //!
    //! // Create a randomly generated key, lock it, protect it as read-only
    //! let key = Key::gen_readonly_locked().expect("gen failed");
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
    /// Returns a new hasher instance, with `key`.
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
    pub fn finalize<Output: NewByteArray<OUTPUT_LENGTH>>(self) -> Result<Output, Error> {
        let mut output = Output::new_byte_array();

        crypto_generichash_final(self.state, output.as_mut_slice())?;

        Ok(output)
    }

    /// Computes and returns the final hash value as a [`Vec`]. Provided for
    /// convenience.
    pub fn finalize_to_vec(self) -> Result<Vec<u8>, Error> {
        self.finalize()
    }

    /// Onet-time interface for the generic hash function. Computes the hash for
    /// `input` with optional `key`. The output length is determined by the type
    /// signature of `Output`.
    ///
    /// # Example
    ///
    /// ```
    /// use base64::engine::general_purpose;
    /// use base64::Engine as _;
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
    pub fn hash_to_vec<Input: Bytes, Key: ByteArray<KEY_LENGTH>>(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Vec<u8>, Error> {
        Self::hash(input, key)
    }
}

impl GenericHash<CRYPTO_GENERICHASH_KEYBYTES, CRYPTO_GENERICHASH_BYTES> {
    /// Returns an instance of [`GenericHash`] with the default output and key
    /// length parameters.
    pub fn new_with_defaults<Key: ByteArray<CRYPTO_GENERICHASH_KEYBYTES>>(
        key: Option<&Key>,
    ) -> Result<Self, Error> {
        Ok(Self {
            state: crypto_generichash_init(key.map(|k| k.as_slice()), CRYPTO_GENERICHASH_BYTES)?,
        })
    }

    /// Hashes `input` using `key`, with the default length parameters. Provided
    /// for convenience.
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
    pub fn hash_with_defaults_to_vec<
        Input: Bytes + ?Sized,
        Key: ByteArray<CRYPTO_GENERICHASH_KEYBYTES>,
    >(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Vec<u8>, Error> {
        Self::hash(input, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generichash() {
        use base64::engine::general_purpose;
        use base64::Engine as _;

        let mut hasher = GenericHash::new_with_defaults::<Key>(None).expect("new hash failed");
        hasher.update(b"hello");

        let output: Vec<u8> = hasher.finalize().expect("finalize failed");

        assert_eq!(
            general_purpose::STANDARD.encode(output),
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
        use base64::engine::general_purpose;
        use base64::Engine as _;

        let output: Hash =
            GenericHash::hash(b"hello", Some(b"a very secret key")).expect("hash failed");

        assert_eq!(
            general_purpose::STANDARD.encode(&output),
            "AECDe+XJsB6nOkbCsbS/OPXdzpcRm3AolW/Bg1LFY9A="
        );

        let output: Vec<u8> =
            GenericHash::hash_with_defaults::<_, Key, _>(b"hello", None).expect("hash failed");

        assert_eq!(
            general_purpose::STANDARD.encode(output),
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
        use base64::engine::general_purpose;
        use base64::Engine as _;

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
            let key = hex::decode(key).expect("decode key");
            let expected_hash = hex::decode(hash).expect("decode hash");

            let hash: Vec<u8> =
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
}
