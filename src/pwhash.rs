//! # Password hashing functions
//!
//! [`PwHash`] implements libsodium's password hashing functions, based on
//! Argon2.
//!
//! Argon2 provides a configurable memory-hard arbitrary-length hashing function
//! that is well suited for password hashing. You may tune the function
//! according to your preferences to either provide stronger collision
//! resistance, or shorter computation times.
//!
//! You should use [`PwHash`] when you want to:
//!
//! * authenticate with passwords, and store their salted hashes in a database
//! * derive secret keys based on passphrases
//! * hash arbitrary data in a manner that's strongly resistant to collisions
//!
//! # Rustaceous API example
//!
//!
//! ## Additional resources
//!
//! * See <https://libsodium.gitbook.io/doc/password_hashing> for additional
//!   details on password hashing

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm, STR_HASHBYTES};
use crate::constants::{
    CRYPTO_PWHASH_BYTES_MIN, CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, CRYPTO_PWHASH_SALTBYTES, CRYPTO_PWHASH_SALTBYTES_MIN,
};
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::types::*;

/// Heap-allocated salt type alias for password hashing with [`PwHash`]. Salts
/// can be of arbitrary length, but they should be at least
/// [`CRYPTO_PWHASH_SALTBYTES_MIN`] bytes.
pub type Salt = Vec<u8>;
/// Heap-allocated hash type alias for password hashing with [`PwHash`]. Hashes
/// can be of arbitrary length, but they should be at least
/// [`CRYPTO_PWHASH_BYTES_MIN`] bytes.
pub type Hash = Vec<u8>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// Password hash implementation based on Argon2, compatible with libsodium's
/// `crypto_pwhash_*` functions.
pub struct PwHash<Hash: Bytes, Salt: Bytes> {
    hash: Hash,
    salt: Salt,
    algorithm: PasswordHashAlgorithm,
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
}

/// Vec<u8>-based PwHash type alias, provided for convenience.
pub type VecPwHash = PwHash<Hash, Salt>;

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`PwHash`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`PwHash`]. These type aliases are provided for
    //! convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use base64::encode;
    //! use dryoc::PwHash::protected::*;
    //! use dryoc::PwHash::PwHash;
    //!
    //! // Randomly generate a main key and context, using locked memory
    //! let key: LockedPwHash = PwHash::gen();
    //! let subkey_id = 0;
    //!
    //! let subkey: Locked<Key> = key.derive_subkey(subkey_id).expect("derive failed");
    //! println!("Subkey {}: {}", subkey_id, encode(&subkey));
    //! ```
    use super::*;
    pub use crate::protected::*;
    pub use crate::types::*;

    /// Heap-allocated, page-aligned salt type alias for protected password
    /// hashing with [`PwHash`].
    pub type Salt = HeapBytes;
    /// Heap-allocated, page-aligned hash type alias for protected password
    /// hashing with [`PwHash`].
    pub type Hash = HeapBytes;

    /// Locked [`PwHash`], provided as a type alias for convenience.
    pub type LockedPwHash = PwHash<Locked<Hash>, Locked<Salt>>;
}

// impl<Hash: NewBytes + ResizableBytes, Salt: NewBytes + ResizableBytes>
// PwHash<Hash, Salt> {     /// Hashes `password` with a random salt and default
// parameters, returning     /// the hash upon success.
//     pub fn hash<Password: Bytes>(password: &Password) -> Result<Self, Error>
// {         let mut hash = Hash::new_bytes();
//         let mut salt = Salt::new_bytes();

//         hash.resize(STR_HASHBYTES, 0);

//         salt.resize(CRYPTO_PWHASH_SALTBYTES, 0);
//         copy_randombytes(salt.as_mut_slice());

//         crypto_pwhash(
//             hash.as_mut_slice(),
//             password.as_slice(),
//             salt.as_slice(),
//             CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
//             CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
//             crate::classic::crypto_pwhash::PasswordHashAlgorithm::Argon2id13,
//         )?;

//         Ok(Self { hash, salt })
//     }
// }

// impl<Hash: Bytes, Salt: Bytes> PwHash<Hash, Salt> {
//     /// Constructs a new instance from `hash` and `salt`, consuming them
// both.     pub fn from_parts(hash: Hash, salt: Salt) -> Self {
//         Self { hash, salt }
//     }

//     /// Moves the key and context out of this instance, returning them as a
//     /// tuple.
//     pub fn into_parts(self) -> (Hash, Salt) {
//         (self.hash, self.salt)
//     }
// }

impl PwHash<Hash, Salt> {}
