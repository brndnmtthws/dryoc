//! # Password hashing functions
//!
//! [`PwHash`] implements libsodium's password hashing functions, based on
//! Argon2.
//!
//! Argon2 is a memory-hard password hashing function. Its work and memory
//! settings make each password guess more expensive, which slows offline
//! guessing if a password database is stolen. These settings do not compensate
//! for weak passwords, so applications should still encourage long, unique
//! passwords.
//!
//! You should use [`PwHash`] when you want to:
//!
//! * authenticate with passwords, and store their salted hashes in a database
//! * derive secret keys based on passphrases
//!
//! Use a general-purpose hash such as [`crate::generichash`] or
//! [`crate::sha256`] for arbitrary data. Password hashing is deliberately much
//! more expensive.
//!
//! If the `serde` feature is enabled, the `serde::Deserialize` and
//! `serde::Serialize` traits will be implemented for [`PwHash`].
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
//! // Start with a preset, then increase its work factor if your deployment can
//! // tolerate the extra time. Benchmark the result on the slowest target.
//! let mut config = Config::interactive()
//!     .with_opslimit(dryoc::constants::CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE + 1);
//! # // Keep this doctest fast; these minimums are not a production recommendation.
//! # config = config
//! #     .with_opslimit(dryoc::constants::CRYPTO_PWHASH_OPSLIMIT_MIN)
//! #     .with_memlimit(dryoc::constants::CRYPTO_PWHASH_MEMLIMIT_MIN);
//!
//! // With customized configuration parameters, the return type must be explicit.
//! let pwhash: VecPwHash = PwHash::hash_with_salt(password, salt, config)
//!     .expect("unable to hash password with salt and custom config");
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
//! See [`PwHash::to_encoded_string()`] for an example of using the string-based
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
use zeroize::Zeroize;

use crate::classic::crypto_pwhash;
pub use crate::classic::crypto_pwhash::PasswordHashAlgorithm;
use crate::constants::*;
use crate::error::Error;
use crate::keypair;
use crate::rng::copy_randombytes;
use crate::types::*;

/// Heap-allocated salt type alias for password hashing with [`PwHash`].
///
/// Newly generated salts contain exactly [`CRYPTO_PWHASH_SALTBYTES`] bytes.
/// Parsed Argon2 strings may contain other valid Argon2 salt lengths. Each
/// stored password hash needs a unique, unpredictable salt;
/// [`PwHash::hash`] generates one automatically.
pub type Salt = Vec<u8>;
/// Heap-allocated hash type alias for password hashing with [`PwHash`].
///
/// Hashes must contain at least [`CRYPTO_PWHASH_BYTES_MIN`] bytes.
pub type Hash = Vec<u8>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// Password hash configuration parameters.
///
/// [`Config::interactive`] is the default and is suitable for online
/// authentication. [`Config::moderate`] and [`Config::sensitive`] spend more
/// time and memory per password guess. Benchmark the chosen preset on the
/// slowest supported system, and account for the number of concurrent hashes
/// when setting memory limits.
pub struct Config {
    algorithm: PasswordHashAlgorithm,
    hash_length: usize,
    memlimit: usize,
    opslimit: u64,
    parallelism: u32,
}

impl Config {
    /// Selects the password-hashing algorithm.
    ///
    /// The preset resource limits target Argon2id. When selecting Argon2i,
    /// choose limits that satisfy the corresponding `CRYPTO_PWHASH_ARGON2I_*`
    /// constants.
    #[must_use]
    pub fn with_algorithm(self, algorithm: PasswordHashAlgorithm) -> Self {
        Self { algorithm, ..self }
    }

    /// Sets the hash output length in bytes.
    ///
    /// The length must be between [`CRYPTO_PWHASH_BYTES_MIN`] and
    /// [`CRYPTO_PWHASH_BYTES_MAX`], inclusive. Invalid values are reported when
    /// the config is used to hash a password.
    #[must_use]
    pub fn with_hash_length(self, hash_length: usize) -> Self {
        Self {
            hash_length,
            ..self
        }
    }

    /// Sets the approximate memory cost in bytes.
    ///
    /// More memory makes parallel guessing more expensive, but every
    /// concurrent hash also consumes that memory. The value must be between
    /// [`CRYPTO_PWHASH_MEMLIMIT_MIN`] and [`CRYPTO_PWHASH_MEMLIMIT_MAX`],
    /// inclusive.
    #[must_use]
    pub fn with_memlimit(self, memlimit: usize) -> Self {
        Self { memlimit, ..self }
    }

    /// Sets the computation cost.
    ///
    /// Larger values take longer and make each password guess more expensive.
    /// The supported range depends on the selected algorithm. See the
    /// `CRYPTO_PWHASH_ARGON2I_OPSLIMIT_*` and
    /// `CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_*` constants.
    #[must_use]
    pub fn with_opslimit(self, opslimit: u64) -> Self {
        Self { opslimit, ..self }
    }

    /// Returns libsodium's interactive password hashing configuration.
    ///
    /// This is the default preset for online operations where users wait for
    /// the result.
    pub fn interactive() -> Self {
        Self {
            algorithm: PasswordHashAlgorithm::Argon2id13,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            parallelism: 1,
            hash_length: crypto_pwhash::STR_HASHBYTES,
        }
    }

    /// Returns libsodium's moderate password hashing configuration.
    ///
    /// This preset uses more time and memory than [`Config::interactive`].
    pub fn moderate() -> Self {
        Self {
            algorithm: PasswordHashAlgorithm::Argon2id13,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            parallelism: 1,
            hash_length: crypto_pwhash::STR_HASHBYTES,
        }
    }

    /// Returns libsodium's sensitive password hashing configuration.
    ///
    /// This preset has the highest resource requirements. Use it only when the
    /// deployment can tolerate its latency and memory use.
    pub fn sensitive() -> Self {
        Self {
            algorithm: PasswordHashAlgorithm::Argon2id13,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
            parallelism: 1,
            hash_length: crypto_pwhash::STR_HASHBYTES,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::interactive()
    }
}

fn validate_direct_config(
    config: &Config,
    output_len: usize,
    password_len: usize,
    salt_len: usize,
) -> Result<(), Error> {
    if config.parallelism != 1 {
        return Err(Error::InvalidValue {
            context: crate::ErrorContext::PasswordHashParallelism,
            actual: config.parallelism as u64,
            constraint: crate::ValueConstraint::Between { min: 1, max: 1 },
        });
    }
    crypto_pwhash::validate_pwhash_parameters(
        output_len,
        password_len,
        salt_len,
        config.opslimit,
        config.memlimit,
        config.algorithm,
    )
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

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`PwHash`]
    //!
    //! Protected-memory aliases for password hashes and salts.
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
    ///
    /// # Errors
    ///
    /// Returns an error if a work limit, memory limit, hash length, or password
    /// length is outside the supported range, or if the
    /// underlying Argon2 operation fails.
    pub fn hash<Password: Bytes>(password: &Password, config: Config) -> Result<Self, Error> {
        validate_direct_config(
            &config,
            config.hash_length,
            password.len(),
            CRYPTO_PWHASH_SALTBYTES,
        )?;

        let mut hash = Hash::new_bytes();
        let mut salt = Salt::new_bytes();

        hash.resize(config.hash_length, 0);

        salt.resize(CRYPTO_PWHASH_SALTBYTES, 0);
        copy_randombytes(salt.as_mut_slice());

        crypto_pwhash::crypto_pwhash(
            hash.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            config.opslimit,
            config.memlimit,
            config.algorithm,
        )?;

        Ok(Self { hash, salt, config })
    }

    /// Hashes `password` with a random salt and a default configuration
    /// suitable for interactive hashing, returning the hash, salt, and config
    /// upon success.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PwHash::hash`].
    pub fn hash_interactive<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash(password, Config::interactive())
    }

    /// Hashes `password` with a random salt and a default configuration
    /// suitable for moderate hashing, returning the hash, salt, and config upon
    /// success.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PwHash::hash`].
    pub fn hash_moderate<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash(password, Config::moderate())
    }

    /// Hashes `password` with a random salt and a default configuration
    /// suitable for sensitive hashing, returning the hash, salt, and config
    /// upon success.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PwHash::hash`].
    pub fn hash_sensitive<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash(password, Config::sensitive())
    }
}

impl<Hash: NewBytes + ResizableBytes + Zeroize, Salt: Bytes + Zeroize> PwHash<Hash, Salt> {
    /// Hashes `password` with `salt` and `config`, returning
    /// the hash, salt, and config upon success.
    ///
    /// The caller must provide a unique, unpredictable salt for each password.
    /// Prefer [`PwHash::hash`] unless an existing salt must be reused.
    ///
    /// # Errors
    ///
    /// Returns an error if a work limit, memory limit, hash length, salt
    /// length, or password length is outside the supported range, or if the
    /// underlying Argon2 operation fails.
    pub fn hash_with_salt<Password: Bytes>(
        password: &Password,
        salt: Salt,
        config: Config,
    ) -> Result<Self, Error> {
        validate_direct_config(&config, config.hash_length, password.len(), salt.len())?;

        let mut hash = Hash::new_bytes();

        hash.resize(config.hash_length, 0);

        crypto_pwhash::crypto_pwhash(
            hash.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            config.opslimit,
            config.memlimit,
            config.algorithm,
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
    /// Compatible with libsodium's `crypto_pwhash_str*` functions, including
    /// valid Argon2 strings with non-default salt lengths or parallelism.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is malformed, uses an unsupported
    /// algorithm or version, omits a required field, or contains an invalid
    /// encoded value.
    pub fn from_string(hashed_password: &str) -> Result<Self, Error> {
        let parsed_pwhash = crypto_pwhash::Pwhash::parse_encoded_pwhash(hashed_password)?;

        let opslimit = parsed_pwhash.t_cost.ok_or(Error::missing_data(
            crate::ErrorContext::PasswordHashTimeCost,
        ))? as u64;
        let encoded_memlimit = parsed_pwhash.m_cost.ok_or(Error::missing_data(
            crate::ErrorContext::PasswordHashMemoryCost,
        ))?;
        let memlimit =
            1024usize
                .checked_mul(encoded_memlimit as usize)
                .ok_or(Error::InvalidValue {
                    context: crate::ErrorContext::PasswordHashMemoryCost,
                    actual: encoded_memlimit as u64,
                    constraint: crate::ValueConstraint::Between {
                        min: 0,
                        max: (usize::MAX / 1024) as u64,
                    },
                })?;
        let hash = parsed_pwhash
            .pwhash
            .ok_or(Error::missing_data(crate::ErrorContext::PasswordHash))?;
        let salt = parsed_pwhash
            .salt
            .ok_or(Error::missing_data(crate::ErrorContext::PasswordHashSalt))?;
        let algorithm = parsed_pwhash.type_.ok_or(Error::missing_data(
            crate::ErrorContext::PasswordHashAlgorithm,
        ))?;
        let parallelism = parsed_pwhash.parallelism.ok_or(Error::missing_data(
            crate::ErrorContext::PasswordHashParallelism,
        ))?;
        let hash_length = hash.len();

        Ok(Self {
            hash: hash.into(),
            salt: salt.into(),
            config: Config {
                algorithm,
                hash_length,
                memlimit,
                opslimit,
                parallelism,
            },
        })
    }
}

impl<Hash: Bytes + Zeroize, Salt: Bytes + Zeroize> PwHash<Hash, Salt> {
    /// Returns a string-encoded representation of this hash, salt, and config,
    /// suitable for storage in a database.
    ///
    /// The string returned is compatible with libsodium's `crypto_pwhash_str`,
    /// `crypto_pwhash_str_verify`, and `crypto_pwhash_str_needs_rehash`
    /// functions when the hash length matches libsodium's string format. The
    /// lower-level hashing API also supports variable-length hash output.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored parameters are invalid or the resulting
    /// string would not fit libsodium's password-hash string format.
    ///
    /// ## Example
    ///
    /// ```
    /// use dryoc::pwhash::*;
    ///
    /// let password = b"Come what come may, time and the hour runs through the roughest day.";
    ///
    /// let pwhash = PwHash::hash_with_defaults(password).expect("unable to hash");
    /// let pw_string = pwhash.to_encoded_string().expect("unable to encode hash");
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
    pub fn to_encoded_string(&self) -> Result<String, Error> {
        let (t_cost, m_cost) =
            crypto_pwhash::convert_costs_checked(self.config.opslimit, self.config.memlimit)?;
        crate::argon2::validate_argon2_pwhash_parameters(
            self.hash.len(),
            self.salt.len(),
            t_cost,
            m_cost,
            self.config.parallelism,
        )?;

        let encoded_len = crypto_pwhash::pwhash_string_len(
            self.config.algorithm,
            t_cost,
            m_cost,
            self.config.parallelism,
            self.salt.len(),
            self.hash.len(),
        )
        .ok_or(Error::arithmetic_overflow(
            crate::ErrorContext::PasswordHash,
        ))?;
        if encoded_len >= CRYPTO_PWHASH_STRBYTES {
            return Err(length_error!(
                crate::ErrorContext::PasswordHash,
                encoded_len,
                max CRYPTO_PWHASH_STRBYTES - 1
            ));
        }
        let encoded = crypto_pwhash::pwhash_to_string(
            self.config.algorithm,
            t_cost,
            m_cost,
            self.config.parallelism,
            self.salt.as_slice(),
            self.hash.as_slice(),
        );
        debug_assert_eq!(encoded.len(), encoded_len);
        Ok(encoded)
    }

    /// Verifies `password` against this hash using its salt and configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the password does not match, if the stored salt or
    /// configuration is invalid, or if the underlying Argon2 operation fails.
    pub fn verify<Password: Bytes>(&self, password: &Password) -> Result<(), Error> {
        let (t_cost, m_cost) =
            crypto_pwhash::convert_costs_checked(self.config.opslimit, self.config.memlimit)?;
        crypto_pwhash::verify_pwhash_parts(
            self.hash.as_slice(),
            password.as_slice(),
            self.salt.as_slice(),
            t_cost,
            m_cost,
            self.config.parallelism,
            self.config.algorithm,
        )
    }

    /// Constructs a new instance from `hash`, `salt`, and `config`, consuming
    /// them.
    ///
    /// This function does not validate the parts. Invalid values are reported
    /// when an operation such as [`PwHash::verify`] or
    /// [`PwHash::to_encoded_string`] uses them.
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
    ///
    /// The same password and salt derive the same keypair. Store the salt, keep
    /// it unique per derived key, and do not treat it as secret.
    ///
    /// # Errors
    ///
    /// Returns an error if a work limit, memory limit, salt length, or password
    /// length is outside the supported range, or if the underlying Argon2
    /// operation fails.
    pub fn derive_keypair<
        Password: Bytes + Zeroize,
        PublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
        SecretKey: NewByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
    >(
        password: &Password,
        salt: Salt,
        config: Config,
    ) -> Result<keypair::KeyPair<PublicKey, SecretKey>, Error> {
        validate_direct_config(
            &config,
            CRYPTO_BOX_SECRETKEYBYTES,
            password.len(),
            salt.len(),
        )?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the password length is unsupported or the
    /// underlying Argon2 operation fails.
    pub fn hash_with_defaults<Password: Bytes>(password: &Password) -> Result<Self, Error> {
        Self::hash_interactive(password)
    }

    #[cfg(any(feature = "base64", all(doc, not(doctest))))]
    #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
    /// Parses the `hashed_password` string, returning a new hash instance upon
    /// success. Wraps [`PwHash::from_string`], provided for convenience.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is malformed, uses an unsupported
    /// algorithm or version, omits a required field, or contains an invalid
    /// encoded value.
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

    #[test]
    fn test_pwhash_uses_random_salt() {
        let password = b"super secrit password";

        let pwhash1 = PwHash::hash_with_defaults(password).expect("unable to hash");
        let pwhash2 = PwHash::hash_with_defaults(password).expect("unable to hash");

        assert_ne!(pwhash1.salt.as_slice(), pwhash2.salt.as_slice());

        pwhash1.verify(password).expect("verification failed");
        pwhash2.verify(password).expect("verification failed");
    }

    #[test]
    fn test_pwhash_validates_output_length_before_allocation() {
        let config = Config::interactive().with_hash_length(usize::MAX);
        assert!(matches!(
            VecPwHash::hash(b"password", config),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Output,
                actual: usize::MAX,
                ..
            })
        ));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_pwhash_serde_roundtrip_preserves_verification() {
        let password = b"serde password";
        let config = Config::interactive()
            .with_opslimit(CRYPTO_PWHASH_OPSLIMIT_MIN)
            .with_memlimit(CRYPTO_PWHASH_MEMLIMIT_MIN);
        let pwhash = VecPwHash::hash(password, config).expect("unable to hash");

        let json = serde_json::to_string(&pwhash).expect("unable to serialize password hash");
        let decoded: VecPwHash =
            serde_json::from_str(&json).expect("unable to deserialize password hash");

        decoded.verify(password).expect("verification failed");
        decoded
            .verify(b"wrong password")
            .expect_err("wrong password should not verify");

        #[cfg(feature = "base64")]
        decoded
            .to_encoded_string()
            .expect("unable to encode deserialized password hash");
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_pwhash_str() {
        let password = b"super secrit password";

        let pwhash = PwHash::hash_with_defaults(password).expect("unable to hash");
        let pw_string = pwhash
            .to_encoded_string()
            .expect("couldn't encode password hash");

        let parsed_pwhash =
            PwHash::from_string_with_defaults(&pw_string).expect("couldn't parse hashed password");

        parsed_pwhash.verify(password).expect("verification failed");
        parsed_pwhash
            .verify(b"invalid password")
            .expect_err("verification should have failed");

        let argon2i = concat!(
            "$argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$",
            "TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M",
        );
        let parsed_argon2i =
            VecPwHash::from_string(argon2i).expect("valid Argon2i string should parse");
        parsed_argon2i
            .verify(b"password")
            .expect("valid Argon2i string should verify");
        assert_eq!(
            parsed_argon2i
                .to_encoded_string()
                .expect("couldn't re-encode hash"),
            argon2i
        );

        let oversized_encoding = VecPwHash::from_parts(
            vec![0u8; 64],
            vec![0u8; CRYPTO_PWHASH_SALTBYTES],
            Config::interactive().with_hash_length(64),
        );
        assert!(oversized_encoding.to_encoded_string().is_err());

        let _argon2i_config = Config::interactive()
            .with_algorithm(PasswordHashAlgorithm::Argon2i13)
            .with_opslimit(CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE)
            .with_memlimit(CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE);
    }

    #[test]
    #[cfg(all(feature = "protected", any(unix, windows)))]
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
