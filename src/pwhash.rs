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
//! If the `serde` feature is enabled, the [`serde::Deserialize`] and
//! [`serde::Serialize`] traits will be implemented for [`PwHash`].
//!
//! ## Rustaceous API example
//!
//! ```
//! use dryoc::pwhash::*;
//!
//! // A strong passphrase
//! let password = b"But, for my own part, it was Greek to me.";
//!
//! // Hash the password, generating a random salt
//! let pwhash = PwHash::hash_with_defaults(password).expect("unable to hash");
//!
//! pwhash.verify(password).expect("verification failed");
//! pwhash
//!     .verify(b"invalid password")
//!     .expect_err("verification should have failed");
//! ```
//!
//! ## Using a custom config, or your own salt
//!
//! ```
//! use dryoc::pwhash::*;
//!
//! // Generate a random salt
//! let mut salt = Salt::default();
//! salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
//! dryoc::rng::copy_randombytes(&mut salt);
//!
//! // A strong passphrase
//! let password = b"What's in a name? That which we call a rose\n
//!                  By any other word would smell as sweet...";
//!
//! // With customized configuration parameters, return type must be explicit
//! let pwhash: VecPwHash = PwHash::hash_with_salt(
//!     password,
//!     salt,
//!     Config::interactive().with_opslimit(1).with_memlimit(8192),
//! )
//! .expect("unable to hash password with salt and custom config");
//!
//! pwhash.verify(password).expect("verification failed");
//! pwhash
//!     .verify(b"invalid password")
//!     .expect_err("verification should have failed");
//! ```
//!
//! ## Deriving a keypair from a passphrase and salt
//!
//! ```
//! use dryoc::keypair::StackKeyPair;
//! use dryoc::pwhash::*;
//!
//! // Generate a random salt
//! let mut salt = Salt::default();
//! salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
//! dryoc::rng::copy_randombytes(&mut salt);
//!
//! // Use a strong passphrase
//! let password = b"Is this a dagger which I see before me, the handle toward my hand?";
//!
//! let keypair: StackKeyPair = PwHash::derive_keypair(password, salt, Config::interactive())
//!     .expect("couldn't derive keypair");
//!
//! // now you can use `keypair` with DryocBox
//! ```
//!
//! ## String-based encoding
//!
//! See [`PwHash::to_string()`] for an example of using the string-based
//! encoding API, compatible with `crypto_pwhash_str*` functions.
//!
//! ## Additional resources
//!
//! * See <https://libsodium.gitbook.io/doc/password_hashing> for additional
//!   details on password hashing
//! * Refer to the [protected] module for details on usage with protected
//!   memory.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::classic::crypto_pwhash;
use crate::constants::*;
use crate::error::Error;
use crate::keypair;
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
/// Password hash configuration parameters. Provides reasonable default
/// values with [`Config::default()`], [`Config::interactive()`],
/// [`Config::moderate()`], and [`Config::sensitive()`].
pub struct Config {
    algorithm: crypto_pwhash::PasswordHashAlgorithm,
    hash_length: usize,
    memlimit: usize,
    opslimit: u64,
    salt_length: usize,
}

impl Config {
    /// Returns this config with `salt_length`.
    #[must_use]
    pub fn with_salt_length(self, salt_length: usize) -> Self {
        Self {
            salt_length,
            ..self
        }
    }

    /// Returns this config with `hash_length`.
    #[must_use]
    pub fn with_hash_length(self, hash_length: usize) -> Self {
        Self {
            hash_length,
            ..self
        }
    }

    /// Returns this config with `memlimit`.
    #[must_use]
    pub fn with_memlimit(self, memlimit: usize) -> Self {
        Self { memlimit, ..self }
    }

    /// Returns this config with `opslimit`.
    #[must_use]
    pub fn with_opslimit(self, opslimit: u64) -> Self {
        Self { opslimit, ..self }
    }

    /// Provides a password hash configuration for interactive hashing.
    pub fn interactive() -> Self {
        Self {
            algorithm: crypto_pwhash::PasswordHashAlgorithm::Argon2id13,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            salt_length: CRYPTO_PWHASH_SALTBYTES,
            hash_length: crypto_pwhash::STR_HASHBYTES,
        }
    }

    /// Provides a password hash configuration for moderate hashing.
    pub fn moderate() -> Self {
        Self {
            algorithm: crypto_pwhash::PasswordHashAlgorithm::Argon2id13,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            salt_length: CRYPTO_PWHASH_SALTBYTES,
            hash_length: crypto_pwhash::STR_HASHBYTES,
        }
    }

    /// Provides a password hash configuration for sensitive hashing.
    pub fn sensitive() -> Self {
        Self {
            algorithm: crypto_pwhash::PasswordHashAlgorithm::Argon2id13,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
            salt_length: CRYPTO_PWHASH_SALTBYTES,
            hash_length: crypto_pwhash::STR_HASHBYTES,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::interactive()
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// Password hash implementation based on Argon2, compatible with libsodium's
/// `crypto_pwhash_*` functions.
pub struct PwHash<Hash: Bytes + Zeroize, Salt: Bytes + Zeroize> {
    hash: Hash,
    salt: Salt,
    config: Config,
}

/// `Vec<u8>`-based PwHash type alias, provided for convenience.
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
    //! use dryoc::pwhash::protected::*;
    //! use dryoc::pwhash::{Config, PwHash};
    //!
    //! let password = HeapBytes::from_slice_into_locked(
    //!     b"The robb'd that smiles, steals something from the thief.",
    //! )
    //! .expect("couldn't lock password");
    //!
    //! let pwhash: LockedPwHash =
    //!     PwHash::hash(&password, Config::interactive()).expect("unable to hash");
    //!
    //! pwhash.verify(&password).expect("verification failed");
    //! pwhash
    //!     .verify(b"invalid password")
    //!     .expect_err("verification should have failed");
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned salt type alias for protected password
    /// hashing with [`PwHash`].
    pub type Salt = HeapBytes;
    /// Heap-allocated, page-aligned hash type alias for protected password
    /// hashing with [`PwHash`].
    pub type Hash = HeapBytes;

    /// Locked [`PwHash`], provided as a type alias for convenience.
    pub type LockedPwHash = PwHash<Locked<Hash>, Locked<Salt>>;
}

impl<Hash: NewBytes + ResizableBytes + Zeroize, Salt: NewBytes + ResizableBytes + Zeroize>
    PwHash<Hash, Salt>
{
    /// Hashes `password` with a random salt and `config`, returning
    /// the hash, salt, and config upon success.
    pub fn hash<Password: Bytes>(password: &Password, config: Config) -> Result<Self, Error> {
        let mut hash = Hash::new_bytes();
        let mut salt = Salt::new_bytes();

        hash.resize(config.hash_length, 0);

        salt.resize(config.salt_length, 0);
        copy_randombytes(salt.as_mut_slice());

        crypto_pwhash::crypto_pwhash(
            hash.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            config.opslimit,
            config.memlimit,
            config.algorithm.clone(),
        )?;

        Ok(Self { hash, salt, config })
    }

    /// Hashes `password` with a random salt and a default configuration
    /// suitable for interactive hashing, returning the hash, salt, and config
    /// upon success.
    pub fn hash_interactive<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash(password, Config::interactive())
    }

    /// Hashes `password` with a random salt and a default configuration
    /// suitable for moderate hashing, returning the hash, salt, and config upon
    /// success.
    pub fn hash_moderate<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash(password, Config::moderate())
    }

    /// Hashes `password` with a random salt and a default configuration
    /// suitable for sensitive hashing, returning the hash, salt, and config
    /// upon success.
    pub fn hash_sensitive<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash(password, Config::sensitive())
    }

    /// Returns a string-encoded representation of this hash, salt, and config,
    /// suitable for storage in a database.
    ///
    /// It's recommended that you use the Serde support instead of this
    /// function, however this function is provided for compatiblity reasons.
    ///
    /// The string returned is compatible with libsodium's `crypto_pwhash_str`,
    /// `crypto_pwhash_str_verify`, and `crypto_pwhash_str_needs_rehash`
    /// functions, but _only_ when the hash and salt length values match those
    /// supported by libsodium. This implementation supports variable-length
    /// salts and hashes, but libsodium's does not.
    ///
    /// ## Example
    ///
    /// ```
    /// use dryoc::pwhash::*;
    ///
    /// let password = b"Come what come may, time and the hour runs through the roughest day.";
    ///
    /// let pwhash = PwHash::hash_with_defaults(password).expect("unable to hash");
    /// let pw_string = pwhash.to_string();
    ///
    /// let parsed_pwhash =
    ///     PwHash::from_string_with_defaults(&pw_string).expect("couldn't parse hashed password");
    ///
    /// parsed_pwhash.verify(password).expect("verification failed");
    /// parsed_pwhash
    ///     .verify(b"invalid password")
    ///     .expect_err("verification should have failed");
    /// ```
    #[cfg(any(feature = "base64", all(doc, not(doctest))))]
    #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let (t_cost, m_cost) =
            crypto_pwhash::convert_costs(self.config.opslimit, self.config.memlimit);

        crypto_pwhash::pwhash_to_string(t_cost, m_cost, self.salt.as_slice(), self.hash.as_slice())
    }
}

impl<Hash: NewBytes + ResizableBytes + Zeroize, Salt: Bytes + Clone + Zeroize> PwHash<Hash, Salt> {
    /// Verifies that this hash, salt, and config is valid for `password`.
    pub fn verify<Password: Bytes>(&self, password: &Password) -> Result<(), Error> {
        let computed = Self::hash_with_salt(password, self.salt.clone(), self.config.clone())?;

        if self
            .hash
            .as_slice()
            .ct_eq(computed.hash.as_slice())
            .unwrap_u8()
            == 1
        {
            Ok(())
        } else {
            Err(dryoc_error!("hashes do not match"))
        }
    }

    /// Hashes `password` with `salt` and `config`, returning
    /// the hash, salt, and config upon success.
    pub fn hash_with_salt<Password: Bytes>(
        password: &Password,
        salt: Salt,
        config: Config,
    ) -> Result<Self, Error> {
        let mut hash = Hash::new_bytes();

        hash.resize(config.hash_length, 0);

        crypto_pwhash::crypto_pwhash(
            hash.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            config.opslimit,
            config.memlimit,
            config.algorithm.clone(),
        )?;

        Ok(Self { hash, salt, config })
    }
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
impl<Hash: Bytes + From<Vec<u8>> + Zeroize, Salt: Bytes + From<Vec<u8>> + Zeroize>
    PwHash<Hash, Salt>
{
    /// Creates a new password hash instance by parsing `hashed_password`.
    /// Compatible with libsodium's `crypto_pwhash_str*` functions, and supports
    /// variable-length encoding for the hash and salt.
    ///
    /// It's recommended that you use the Serde support instead of this
    /// function, however this function is provided for compatiblity reasons.
    pub fn from_string(hashed_password: &str) -> Result<Self, Error> {
        let parsed_pwhash = crypto_pwhash::Pwhash::parse_encoded_pwhash(hashed_password)?;

        let opslimit = parsed_pwhash.t_cost.unwrap() as u64;
        let memlimit = 1024 * (parsed_pwhash.m_cost.unwrap() as usize);
        let hash_length = parsed_pwhash.pwhash.as_ref().unwrap().len();
        let salt_length = parsed_pwhash.salt.as_ref().unwrap().len();
        let algorithm = parsed_pwhash.type_.unwrap();

        Ok(Self {
            hash: parsed_pwhash.pwhash.unwrap().into(),
            salt: parsed_pwhash.salt.unwrap().into(),
            config: Config {
                algorithm,
                hash_length,
                memlimit,
                opslimit,
                salt_length,
            },
        })
    }
}

impl<Hash: Bytes + Zeroize, Salt: Bytes + Zeroize> PwHash<Hash, Salt> {
    /// Constructs a new instance from `hash`, `salt`, and `config`, consuming
    /// them.
    pub fn from_parts(hash: Hash, salt: Salt, config: Config) -> Self {
        Self { hash, salt, config }
    }

    /// Moves the hash, salt, and config out of this instance, returning them as
    /// a tuple.
    pub fn into_parts(self) -> (Hash, Salt, Config) {
        (self.hash, self.salt, self.config)
    }
}

impl<Salt: Bytes + Zeroize> PwHash<Hash, Salt> {
    /// Derives a keypair from `password` and `salt`, using `config`.
    pub fn derive_keypair<
        Password: Bytes + Zeroize,
        PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
        SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
    >(
        password: &Password,
        salt: Salt,
        config: Config,
    ) -> Result<keypair::KeyPair<PublicKey, SecretKey>, Error> {
        let mut secret_key = SecretKey::new_byte_array();

        crypto_pwhash::crypto_pwhash(
            secret_key.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            config.opslimit,
            config.memlimit,
            config.algorithm,
        )?;

        Ok(keypair::KeyPair::<PublicKey, SecretKey>::from_secret_key(
            secret_key,
        ))
    }
}

impl PwHash<Hash, Salt> {
    /// Hashes `password` using default (interactive) config parameters,
    /// returning the `Vec<u8>`-based hash and salt, with config, upon success.
    ///
    /// This function provides reasonable defaults, and is provided for
    /// convenience.
    pub fn hash_with_defaults<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash_interactive(password)
    }

    #[cfg(any(feature = "base64", all(doc, not(doctest))))]
    #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
    /// Parses the `hashed_password` string, returning a new hash instance upon
    /// success. Wraps [`PwHash::from_string`], provided for convenience.
    pub fn from_string_with_defaults(hashed_password: &str) -> Result<Self, Error> {
        Self::from_string(hashed_password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pwhash() {
        let password = b"super secrit password";

        let pwhash = PwHash::hash_with_defaults(password).expect("unable to hash");

        pwhash.verify(password).expect("verification failed");
        pwhash
            .verify(b"invalid password")
            .expect_err("verification should have failed");
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_pwhash_str() {
        let password = b"super secrit password";

        let pwhash = PwHash::hash_with_defaults(password).expect("unable to hash");
        let pw_string = pwhash.to_string();

        let parsed_pwhash =
            PwHash::from_string_with_defaults(&pw_string).expect("couldn't parse hashed password");

        parsed_pwhash.verify(password).expect("verification failed");
        parsed_pwhash
            .verify(b"invalid password")
            .expect_err("verification should have failed");
    }

    #[test]
    #[cfg(feature = "nightly")]
    fn test_protected() {
        use crate::pwhash::protected::*;

        let password =
            HeapBytes::from_slice_into_locked(b"juicy password").expect("couldn't lock password");

        let pwhash: LockedPwHash =
            PwHash::hash(&password, Config::interactive()).expect("unable to hash");

        pwhash.verify(&password).expect("verification failed");
        pwhash
            .verify(b"invalid password")
            .expect_err("verification should have failed");
    }
}
