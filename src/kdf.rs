//! # Key derivation functions
//!
//! [`Kdf`] implements libsodium's key derivation functions, based on the
//! Blake2b hash function.
//!
//! You should use [`Kdf`] when you want to:
//!
//! * create many subkeys from a main key, without having to risk leaking the
//!   main key
//! * ensure that if a subkey were to become compromised, one could not derive
//!   the main key
//!
//! # Rustaceous API example
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::kdf::*;
//!
//! // Randomly generate a main key and context, using the default stack-allocated
//! // types
//! let key = StackKdf::generate();
//! let subkey_id = 0;
//!
//! let subkey = key
//!     .derive_subkey_to_vec(subkey_id, 32)
//!     .expect("derive failed");
//! println!(
//!     "Subkey {}: {}",
//!     subkey_id,
//!     general_purpose::STANDARD.encode(&subkey)
//! );
//! ```
//!
//! ## Additional resources
//!
//! * See <https://doc.libsodium.org/key_derivation> for additional details on
//!   key derivation

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_kdf::{crypto_kdf_derive_from_key, validate_subkey_length};
use crate::constants::{CRYPTO_KDF_CONTEXTBYTES, CRYPTO_KDF_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key type alias for key derivation with [`Kdf`].
pub type Key = StackByteArray<CRYPTO_KDF_KEYBYTES>;
/// Stack-allocated context type alias for key derivation with [`Kdf`].
pub type Context = StackByteArray<CRYPTO_KDF_CONTEXTBYTES>;

#[cfg_attr(feature = "serde", derive(Zeroize, Clone, Serialize, Deserialize))]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone))]
/// Key derivation implementation based on Blake2b, compatible with libsodium's
/// `crypto_kdf_*` functions.
///
/// The main-key type must implement [`ZeroizeOnDrop`] so keys remain
/// self-wiping after [`Kdf::into_parts`] transfers ownership to the caller.
pub struct Kdf<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> {
    main_key: Key,
    context: Context,
}

impl<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> fmt::Debug for Kdf<Key, Context>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kdf")
            .field("main_key", &"[REDACTED]")
            .field("context", &self.context.as_slice())
            .finish()
    }
}

/// Stack-allocated type alias for [`Kdf`]. Provided for convenience.
pub type StackKdf = Kdf<Key, Context>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`Kdf`]
    //!
    //! Protected-memory aliases for key derivation.
    //!
    //! ## Example
    //!
    //! ```
    //! use base64::Engine as _;
    //! use base64::engine::general_purpose;
    //! use dryoc::kdf::Kdf;
    //! use dryoc::kdf::protected::*;
    //!
    //! // Randomly generate a main key and context, using locked memory
    //! let key: LockedKdf = Kdf::generate();
    //! let subkey_id = 0;
    //!
    //! let subkey: Locked<Key> = key.derive_subkey(subkey_id).expect("derive failed");
    //! println!(
    //!     "Subkey {}: {}",
    //!     subkey_id,
    //!     general_purpose::STANDARD.encode(&subkey)
    //! );
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned key type alias for key derivation with
    /// [`Kdf`].
    pub type Key = HeapByteArray<CRYPTO_KDF_KEYBYTES>;
    /// Heap-allocated, page-aligned context type alias for key derivation with
    /// [`Kdf`].
    pub type Context = HeapByteArray<CRYPTO_KDF_CONTEXTBYTES>;

    /// Locked [`Kdf`], provided as a type alias for convenience.
    pub type LockedKdf = Kdf<Locked<Key>, Locked<Context>>;
}

impl<
    Key: NewByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: NewByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> Kdf<Key, Context>
{
    /// Randomly generates a new pair of main key and context.
    pub fn generate() -> Self {
        Self {
            main_key: Key::generate(),
            context: Context::generate(),
        }
    }

    /// Randomly generates a new pair of main key and context.
    ///
    /// Prefer [`generate`](Self::generate). `gen` is retained for compatibility
    /// with older Rust editions.
    #[deprecated(note = "use generate() instead")]
    pub fn r#gen() -> Self {
        Self::generate()
    }
}

impl<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> Kdf<Key, Context>
{
    /// Derives a subkey for `subkey_id`, returning it.
    ///
    /// # Errors
    ///
    /// Returns an error unless `LENGTH` is between
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MIN`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MIN)
    /// and
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MAX`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MAX),
    /// inclusive.
    pub fn derive_subkey<const LENGTH: usize, Subkey: NewByteArray<LENGTH>>(
        &self,
        subkey_id: u64,
    ) -> Result<Subkey, Error> {
        validate_subkey_length(LENGTH)?;
        let mut subkey = Subkey::new_byte_array();
        crypto_kdf_derive_from_key(
            subkey.as_mut_array(),
            subkey_id,
            self.context.as_array(),
            self.main_key.as_array(),
        )?;
        Ok(subkey)
    }

    /// Derives a subkey for `subkey_id`, returning it as a [`Vec`]. Provided
    /// for convenience.
    ///
    /// # Errors
    ///
    /// Returns an error unless `length` is between
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MIN`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MIN)
    /// and
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MAX`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MAX),
    /// inclusive.
    pub fn derive_subkey_to_vec(&self, subkey_id: u64, length: usize) -> Result<Vec<u8>, Error> {
        validate_subkey_length(length)?;
        let mut subkey = vec![0u8; length];
        crypto_kdf_derive_from_key(
            &mut subkey,
            subkey_id,
            self.context.as_array(),
            self.main_key.as_array(),
        )?;
        Ok(subkey)
    }

    /// Constructs a new instance from `key` and `context`, consuming them both.
    pub fn from_parts(main_key: Key, context: Context) -> Self {
        Self { main_key, context }
    }

    /// Moves the key and context out of this instance, returning them as a
    /// tuple.
    pub fn into_parts(self) -> (Key, Context) {
        (self.main_key, self.context)
    }
}

impl Kdf<Key, Context> {
    /// Randomly generates a new pair of main key and context.
    pub fn generate_with_defaults() -> Self {
        Self {
            main_key: Key::generate(),
            context: Context::generate(),
        }
    }

    /// Randomly generates a new pair of main key and context.
    ///
    /// Prefer [`generate_with_defaults`](Self::generate_with_defaults). This
    /// method is retained for compatibility.
    #[deprecated(note = "use generate_with_defaults() instead")]
    pub fn gen_with_defaults() -> Self {
        Self::generate_with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        let key = StackKdf::generate();

        let short_subkey: StackByteArray<16> = key.derive_subkey(0).expect("derive failed");
        let long_subkey = key.derive_subkey_to_vec(0, 64).expect("derive failed");

        assert_eq!(short_subkey.len(), 16);
        assert_eq!(long_subkey.len(), 64);
        assert!(format!("{key:?}").contains("[REDACTED]"));
        assert!(matches!(
            key.derive_subkey_to_vec(0, usize::MAX),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Subkey,
                actual: usize::MAX,
                ..
            })
        ));

        let invalid_fixed: Result<StackByteArray<15>, Error> = key.derive_subkey(0);
        assert!(invalid_fixed.is_err());
    }
}
