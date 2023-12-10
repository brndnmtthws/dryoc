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
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::kdf::*;
//!
//! // Randomly generate a main key and context, using the default stack-allocated
//! // types
//! let key = Kdf::gen_with_defaults();
//! let subkey_id = 0;
//!
//! let subkey = key.derive_subkey_to_vec(subkey_id).expect("derive failed");
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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::classic::crypto_kdf::crypto_kdf_derive_from_key;
use crate::constants::{CRYPTO_KDF_CONTEXTBYTES, CRYPTO_KDF_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key type alias for key derivation with [`Kdf`].
pub type Key = StackByteArray<CRYPTO_KDF_KEYBYTES>;
/// Stack-allocated context type alias for key derivation with [`Kdf`].
pub type Context = StackByteArray<CRYPTO_KDF_CONTEXTBYTES>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// Key derivation implementation based on Blake2b, compatible with libsodium's
/// `crypto_kdf_*` functions.
pub struct Kdf<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> {
    main_key: Key,
    context: Context,
}

/// Stack-allocated type alias for [`Kdf`]. Provided for convenience.
pub type StackKdf = Kdf<Key, Context>;

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`Kdf`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`Kdf`]. These type aliases are provided for
    //! convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use base64::engine::general_purpose;
    //! use base64::Engine as _;
    //! use dryoc::kdf::protected::*;
    //! use dryoc::kdf::Kdf;
    //!
    //! // Randomly generate a main key and context, using locked memory
    //! let key: LockedKdf = Kdf::gen();
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
    Key: NewByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize,
    Context: NewByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> Kdf<Key, Context>
{
    /// Randomly generates a new pair of main key and context.
    pub fn gen() -> Self {
        Self {
            main_key: Key::gen(),
            context: Context::gen(),
        }
    }
}

impl<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> Kdf<Key, Context>
{
    /// Derives a subkey for `subkey_id`, returning it.
    pub fn derive_subkey<Subkey: NewByteArray<CRYPTO_KDF_KEYBYTES>>(
        &self,
        subkey_id: u64,
    ) -> Result<Subkey, Error> {
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
    pub fn derive_subkey_to_vec(&self, subkey_id: u64) -> Result<Vec<u8>, Error> {
        self.derive_subkey(subkey_id)
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
    pub fn gen_with_defaults() -> Self {
        Self {
            main_key: Key::gen(),
            context: Context::gen(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        let key = StackKdf::gen();

        let _subkey = key.derive_subkey_to_vec(0).expect("derive failed");
    }
}
