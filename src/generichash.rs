//! # Generic hashing
//!
//! [`GenericHash`] implements libsodium's generic hashing, based on the Blake2b
//! algorithm.
//!
//! # Rustaceous API example, one-time interface
//!
//! ```
//! use base64::encode;
//! use dryoc::generichash::GenericHash;
//!
//! let hash = GenericHash::hash_with_defaults_to_vec(b"hello", None).expect("hash failed");
//!
//! assert_eq!(
//!     encode(&hash),
//!     "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
//! );
//! ```
//!
//! # Rustaceous API example, incremental interface
//!
//! ```
//! use base64::encode;
//! use dryoc::generichash::GenericHash;
//!
//! let mut hasher = GenericHash::new_with_defaults(None).expect("new failed");
//! hasher.update(b"hello");
//! let hash = hasher.finalize_to_vec().expect("finalize failed");
//!
//! assert_eq!(
//!     encode(&hash),
//!     "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
//! );
//! ```

use crate::constants::{CRYPTO_GENERICHASH_BYTES, CRYPTO_GENERICHASH_KEYBYTES};
use crate::crypto_generichash::{
    crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update, GenericHashState,
};
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
    //! use base64::encode;
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
    pub use crate::types::*;

    /// Heap-allocated, page-aligned secret key for the generic hash algorithm,
    /// for use with protected memory.
    pub type Key = HeapByteArray<CRYPTO_GENERICHASH_KEYBYTES>;
    /// Heap-allocated, page-aligned hash output for the generic hash algorithm,
    /// for use with protected memory.
    pub type Hash = HeapByteArray<CRYPTO_GENERICHASH_BYTES>;
}

/// Provides a generic hash function implementation based on Blake2b. Compatible
/// with libsodium's generic hash.
pub struct GenericHash<const OUTPUT_LENGTH: usize> {
    state: GenericHashState,
}

impl<const OUTPUT_LENGTH: usize> GenericHash<OUTPUT_LENGTH> {
    /// Returns a new hasher instance, with `key`.
    pub fn new<Key: ByteArray<KEY_LENGTH>, const KEY_LENGTH: usize>(
        key: Option<&Key>,
    ) -> Result<Self, Error> {
        Ok(Self {
            state: crypto_generichash_init(key.map(|k| k.as_slice()), OUTPUT_LENGTH)?,
        })
    }

    /// Updates the hasher state from `input`.
    pub fn update<Input: Bytes>(&mut self, input: Input) {
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
    /// use base64::encode;
    /// use dryoc::generichash::{GenericHash, Hash};
    ///
    /// let output: Hash =
    ///     GenericHash::hash(b"hello", Some(b"a very secret key")).expect("hash failed");
    ///
    /// assert_eq!(
    ///     encode(&output),
    ///     "AECDe+XJsB6nOkbCsbS/OPXdzpcRm3AolW/Bg1LFY9A="
    /// );
    /// ```
    pub fn hash<
        Input: Bytes,
        Key: ByteArray<KEY_LENGTH>,
        Output: NewByteArray<OUTPUT_LENGTH>,
        const KEY_LENGTH: usize,
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
    pub fn hash_to_vec<Input: Bytes, Key: ByteArray<KEY_LENGTH>, const KEY_LENGTH: usize>(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Vec<u8>, Error> {
        Self::hash(input, key)
    }
}

impl GenericHash<CRYPTO_GENERICHASH_BYTES> {
    /// Returns an instance of [`GenericHash`] with the default output and key
    /// length parameters.
    pub fn new_with_defaults(key: Option<&Key>) -> Result<Self, Error> {
        Ok(Self {
            state: crypto_generichash_init(key.map(|k| k.as_slice()), CRYPTO_GENERICHASH_BYTES)?,
        })
    }

    /// Hashes `input` using `key`, with the default length parameters. Provided
    /// for convenience.
    pub fn hash_with_defaults<Input: Bytes, Output: NewByteArray<CRYPTO_GENERICHASH_BYTES>>(
        input: &Input,
        key: Option<&Key>,
    ) -> Result<Output, Error> {
        Self::hash(input, key)
    }

    /// Hashes `input` using `key`, with the default length parameters,
    /// returning a [`Vec`]. Provided for convenience.
    pub fn hash_with_defaults_to_vec<Input: Bytes>(
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
        use base64::encode;

        let mut hasher = GenericHash::new_with_defaults(None).expect("new hash failed");
        hasher.update(b"hello");

        let output: Vec<u8> = hasher.finalize().expect("finalize failed");

        assert_eq!(
            encode(&output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );

        let mut hasher = GenericHash::new_with_defaults(None).expect("new hash failed");
        hasher.update(b"hello");

        let output = hasher.finalize_to_vec().expect("finalize failed");

        assert_eq!(
            encode(&output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );
    }

    #[test]
    fn test_generichash_onetime() {
        use base64::encode;

        let output: Hash =
            GenericHash::hash(b"hello", Some(b"a very secret key")).expect("hash failed");

        assert_eq!(
            encode(&output),
            "AECDe+XJsB6nOkbCsbS/OPXdzpcRm3AolW/Bg1LFY9A="
        );

        let output: Vec<u8> = GenericHash::hash_with_defaults(b"hello", None).expect("hash failed");

        assert_eq!(
            encode(&output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );

        let output = GenericHash::hash_with_defaults_to_vec(b"hello", None).expect("hash failed");

        assert_eq!(
            encode(&output),
            "Mk3PAn3UowqTLEQfNlol6GsXPe+kuOWJSCU0cbgbcs8="
        );
    }
}
