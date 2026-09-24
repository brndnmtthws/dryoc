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
//! If the `serde` feature is enabled, the
//! [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) and
//! [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) traits will be
//! implemented for [`PwHash`].
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
//! * See the [libsodium documentation](https://doc.libsodium.org/password_hashing)
//!   for more about password hashing
//! * See the [`protected`] module for examples that keep passwords and keys in
//!   protected memory

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
        Self::preset(
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
    }

    /// Returns libsodium's moderate password hashing configuration.
    ///
    /// This preset uses more time and memory than [`Config::interactive`].
    pub fn moderate() -> Self {
        Self::preset(
            CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        )
    }

    /// Returns libsodium's sensitive password hashing configuration.
    ///
    /// This preset has the highest resource requirements. Use it only when the
    /// deployment can tolerate its latency and memory use.
    pub fn sensitive() -> Self {
        Self::preset(
            CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
        )
    }

    /// Returns the Argon2id13 configuration with the given resource limits,
    /// shared by the three libsodium presets.
    const fn preset(opslimit: u64, memlimit: usize) -> Self {
        Self {
            algorithm: PasswordHashAlgorithm::Argon2id13,
            opslimit,
            memlimit,
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

/// Runs Argon2 over `password` and `salt` into `output` per `config`.
fn argon2_into(
    output: &mut [u8],
    password: &[u8],
    salt: &[u8],
    config: &Config,
) -> Result<(), Error> {
    crypto_pwhash::crypto_pwhash(
        output,
        password,
        salt,
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

        argon2_into(
            hash.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            &config,
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

        argon2_into(
            hash.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            &config,
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

        argon2_into(
            secret_key.as_mut_slice(),
            password.as_slice(),
            salt.as_slice(),
            &config,
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

    /// libsodium `crypto_pwhash` outputs for password `"password"`, salt
    /// `"0123456789abcdef"`, 32 output bytes, and the minimum cost of each
    /// algorithm (Argon2id: opslimit 1; Argon2i: opslimit 3; both 8 KiB).
    const PASSWORD: &[u8; 8] = b"password";
    const SALT: &[u8; CRYPTO_PWHASH_SALTBYTES] = b"0123456789abcdef";
    const ARGON2ID_MIN_HASH: &str =
        "771338d819573c67116b39e1788ae8e04b0eb0cf9dfbbfe2e6d746cf3e464fc7";
    /// `crypto_scalarmult_base` of `ARGON2ID_MIN_HASH`.
    const ARGON2ID_MIN_PUBLIC_KEY: &str =
        "4a4673d64ae26efee17c8432ffd40f6358ef58f533bc318a5968555d19d1d66f";
    const ARGON2I_MIN_HASH: &str =
        "edb3a9e12a39f7528d38ddcc001fd6dfa0c2858bdf8f7910c8c2c74889ab902b";
    /// libsodium `test/default/pwhash_argon2id.c` string vector for
    /// `"password"`.
    #[cfg(feature = "base64")]
    const LIBSODIUM_ARGON2ID_STR: &str = concat!(
        "$argon2id$v=19$m=256,t=3,p=1$MDEyMzQ1Njc$",
        "G5ajKFCoUzaXRLdz7UJb5wGkb2Xt+X5/GQjUYtS2+TE",
    );

    fn argon2id_min() -> Config {
        Config::interactive()
            .with_opslimit(CRYPTO_PWHASH_OPSLIMIT_MIN)
            .with_memlimit(CRYPTO_PWHASH_MEMLIMIT_MIN)
    }

    fn argon2i_min() -> Config {
        Config::interactive()
            .with_algorithm(PasswordHashAlgorithm::Argon2i13)
            .with_opslimit(CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN)
            .with_memlimit(CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN)
    }

    fn classic_hash(config: &Config) -> Vec<u8> {
        let mut output = vec![0u8; config.hash_length];
        crypto_pwhash::crypto_pwhash(
            &mut output,
            PASSWORD,
            SALT,
            config.opslimit,
            config.memlimit,
            config.algorithm,
        )
        .expect("classic pwhash");
        output
    }

    #[test]
    fn hash_with_salt_matches_libsodium_argon2id_and_classic() {
        let expected = hex::decode(ARGON2ID_MIN_HASH).expect("hex");
        let pwhash: VecPwHash =
            PwHash::hash_with_salt(PASSWORD, SALT.to_vec(), argon2id_min()).expect("hash");
        assert_eq!(pwhash.hash, expected);
        assert_eq!(pwhash.salt, SALT);
        assert_eq!(classic_hash(&argon2id_min()), expected);

        pwhash.verify(PASSWORD).expect("verify failed");
        assert!(pwhash.verify(b"Password").is_err());
        assert!(pwhash.verify(b"").is_err());

        let (hash, salt, config) = pwhash.into_parts();
        assert_eq!(hash, expected);
        let rebuilt = VecPwHash::from_parts(hash, salt, config);
        rebuilt.verify(PASSWORD).expect("verify failed");

        // A different salt or cost is a different hash.
        let mut other_salt = *SALT;
        other_salt[0] ^= 1;
        let other: VecPwHash =
            PwHash::hash_with_salt(PASSWORD, other_salt.to_vec(), argon2id_min()).expect("hash");
        assert_ne!(other.hash, expected);
        let costlier: VecPwHash = PwHash::hash_with_salt(
            PASSWORD,
            SALT.to_vec(),
            argon2id_min().with_opslimit(CRYPTO_PWHASH_OPSLIMIT_MIN + 1),
        )
        .expect("hash");
        assert_ne!(costlier.hash, expected);
        assert!(costlier.verify(PASSWORD).is_ok());
    }

    #[test]
    fn argon2i_configuration_matches_libsodium_and_classic() {
        let expected = hex::decode(ARGON2I_MIN_HASH).expect("hex");
        let pwhash: VecPwHash =
            PwHash::hash_with_salt(PASSWORD, SALT.to_vec(), argon2i_min()).expect("hash");
        assert_eq!(pwhash.hash, expected);
        assert_eq!(classic_hash(&argon2i_min()), expected);
        assert_ne!(pwhash.hash, hex::decode(ARGON2ID_MIN_HASH).expect("hex"));
        pwhash.verify(PASSWORD).expect("verify failed");
        assert!(pwhash.verify(b"password ").is_err());

        // Argon2i has a higher minimum opslimit than Argon2id.
        let below_min = argon2i_min().with_opslimit(CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN - 1);
        assert!(matches!(
            VecPwHash::hash_with_salt(PASSWORD, SALT.to_vec(), below_min),
            Err(Error::InvalidValue {
                context: crate::ErrorContext::OperationsLimit,
                ..
            })
        ));
        let derived: Result<keypair::StackKeyPair, Error> = PwHash::derive_keypair(
            PASSWORD,
            SALT.to_vec(),
            argon2i_min().with_opslimit(CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN - 1),
        );
        assert!(derived.is_err());

        #[cfg(feature = "base64")]
        {
            let encoded = pwhash.to_encoded_string().expect("encode");
            assert!(encoded.starts_with("$argon2i$v=19$m=8,t=3,p=1$"));
            let parsed = VecPwHash::from_string(&encoded).expect("parse");
            assert_eq!(parsed.hash, expected);
            assert_eq!(parsed.salt, SALT);
            parsed.verify(PASSWORD).expect("verify failed");
            assert_eq!(parsed.to_encoded_string().expect("encode"), encoded);
            crypto_pwhash::crypto_pwhash_str_verify(&encoded, PASSWORD).expect("classic verify");
        }
    }

    #[test]
    fn derive_keypair_is_the_scalar_base_multiple_of_the_argon2_output() {
        use crate::classic::crypto_core::crypto_scalarmult_base;

        let secret_key = hex::decode(ARGON2ID_MIN_HASH).expect("hex");
        let public_key = hex::decode(ARGON2ID_MIN_PUBLIC_KEY).expect("hex");

        let keypair: keypair::StackKeyPair =
            PwHash::derive_keypair(PASSWORD, SALT.to_vec(), argon2id_min()).expect("derive");
        assert_eq!(keypair.secret_key.as_slice(), secret_key.as_slice());
        assert_eq!(keypair.public_key.as_slice(), public_key.as_slice());

        // The classic composition: `crypto_pwhash` into the secret key, then
        // `crypto_scalarmult_base` (i.e. `KeyPair::from_secret_key`).
        let mut classic_secret = [0u8; CRYPTO_BOX_SECRETKEYBYTES];
        crypto_pwhash::crypto_pwhash(
            &mut classic_secret,
            PASSWORD,
            SALT,
            CRYPTO_PWHASH_OPSLIMIT_MIN,
            CRYPTO_PWHASH_MEMLIMIT_MIN,
            PasswordHashAlgorithm::Argon2id13,
        )
        .expect("classic pwhash");
        let mut classic_public = [0u8; CRYPTO_BOX_PUBLICKEYBYTES];
        crypto_scalarmult_base(&mut classic_public, &classic_secret);
        assert_eq!(keypair.secret_key.as_array(), &classic_secret);
        assert_eq!(keypair.public_key.as_array(), &classic_public);
        assert_eq!(
            keypair::StackKeyPair::from_secret_key(keypair.secret_key.clone()),
            keypair
        );

        // Same password with a different salt derives a different keypair, and
        // the salt length is validated.
        let mut other_salt = *SALT;
        other_salt[15] ^= 1;
        let other: keypair::StackKeyPair =
            PwHash::derive_keypair(PASSWORD, other_salt.to_vec(), argon2id_min()).expect("derive");
        assert_ne!(other, keypair);
        let short_salt: Result<keypair::StackKeyPair, Error> =
            PwHash::derive_keypair(PASSWORD, SALT[..8].to_vec(), argon2id_min());
        assert!(matches!(
            short_salt,
            Err(Error::InvalidLength {
                context: crate::ErrorContext::PasswordHashSalt,
                actual: 8,
                ..
            })
        ));
    }

    #[cfg(feature = "base64")]
    #[test]
    fn libsodium_string_vector_parses_verifies_and_reencodes() {
        let parsed = VecPwHash::from_string(LIBSODIUM_ARGON2ID_STR).expect("parse");
        assert_eq!(parsed.salt, b"01234567");
        assert_eq!(parsed.hash.len(), 32);
        assert_eq!(parsed.config.opslimit, 3);
        assert_eq!(parsed.config.memlimit, 256 * 1024);
        assert_eq!(parsed.config.parallelism, 1);
        assert_eq!(parsed.config.algorithm, PasswordHashAlgorithm::Argon2id13);
        parsed.verify(PASSWORD).expect("verify failed");
        assert!(parsed.verify(b"passwore").is_err());
        assert_eq!(
            parsed.to_encoded_string().expect("encode"),
            LIBSODIUM_ARGON2ID_STR
        );

        // The direct hashing API requires libsodium's fixed salt length, so
        // the parsed 8-byte salt only works through `verify`.
        let (hash, salt, config) = parsed.into_parts();
        assert_eq!(salt.len(), 8);
        assert!(matches!(
            VecPwHash::hash_with_salt(PASSWORD, salt.clone(), config.clone()),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::PasswordHashSalt,
                actual: 8,
                ..
            })
        ));
        VecPwHash::from_parts(hash, salt, config)
            .verify(PASSWORD)
            .expect("verify failed");
    }

    #[cfg(feature = "base64")]
    #[test]
    fn from_string_rejects_malformed_encodings() {
        let (prefix, rest) = LIBSODIUM_ARGON2ID_STR.split_at("$argon2id$v=19$".len());
        let (params, salt_and_hash) = rest.split_at("m=256,t=3,p=1".len());
        let (salt, hash) = salt_and_hash[1..].split_once('$').expect("salt and hash");

        let malformed = [
            String::new(),
            "$".to_string(),
            "$argon2id$".to_string(),
            LIBSODIUM_ARGON2ID_STR.trim_start_matches('$').to_string(),
            format!("{prefix}{params}${salt}"),
            format!("{prefix}{params}$${hash}"),
            format!("{prefix}{params}${salt}$"),
            format!("{prefix}{params}${salt}${hash}$extra"),
            format!("{prefix}{params}${salt}$!{}", &hash[1..]),
            format!("{prefix}{params}$!{}${hash}", &salt[1..]),
            format!("{prefix}t=3,p=1${salt}${hash}"),
            format!("{prefix}m=256,p=1${salt}${hash}"),
            format!("{prefix}m=256,t=3${salt}${hash}"),
            format!("{prefix}m=256,t=3,p=0${salt}${hash}"),
            format!("{prefix}m=256,t=0,p=1${salt}${hash}"),
            format!("{prefix}m=0256,t=3,p=1${salt}${hash}"),
            format!("$argon2id$v=18${params}${salt}${hash}"),
            format!("$argon2id${params}${salt}${hash}"),
            format!("$argon2d$v=19${params}${salt}${hash}"),
            format!("$scrypt$v=19${params}${salt}${hash}"),
        ];
        for input in &malformed {
            assert!(
                VecPwHash::from_string(input).is_err(),
                "accepted malformed string {input:?}"
            );
            assert!(PwHash::from_string_with_defaults(input).is_err());
        }

        // The unmodified vector still parses, so the rejections above are not
        // an artifact of the reconstruction.
        assert_eq!(
            format!("{prefix}{params}${salt}${hash}"),
            LIBSODIUM_ARGON2ID_STR
        );
        PwHash::from_string_with_defaults(LIBSODIUM_ARGON2ID_STR).expect("valid string");
    }

    #[cfg(feature = "base64")]
    #[test]
    fn encoded_string_reports_rehash_only_when_the_limits_change() {
        use crate::classic::crypto_pwhash::crypto_pwhash_str_needs_rehash;

        let config = argon2id_min();
        let pwhash: VecPwHash =
            PwHash::hash_with_salt(PASSWORD, SALT.to_vec(), config.clone()).expect("hash");
        let encoded = pwhash.to_encoded_string().expect("encode");

        assert!(
            !crypto_pwhash_str_needs_rehash(&encoded, config.opslimit, config.memlimit)
                .expect("rehash check")
        );
        assert!(
            crypto_pwhash_str_needs_rehash(&encoded, config.opslimit + 1, config.memlimit)
                .expect("rehash check")
        );
        assert!(
            crypto_pwhash_str_needs_rehash(&encoded, config.opslimit, config.memlimit * 2)
                .expect("rehash check")
        );

        // A wider hash still fits libsodium's string format and round-trips
        // with its length intact.
        let wide: VecPwHash =
            PwHash::hash_with_salt(PASSWORD, SALT.to_vec(), config.with_hash_length(48))
                .expect("hash");
        assert_eq!(wide.hash.len(), 48);
        let encoded = wide.to_encoded_string().expect("encode");
        assert_ne!(encoded, pwhash.to_encoded_string().expect("encode"));
        let parsed = VecPwHash::from_string(&encoded).expect("parse");
        assert_eq!(parsed.hash, wide.hash);
        parsed.verify(PASSWORD).expect("verify failed");
        crypto_pwhash::crypto_pwhash_str_verify(&encoded, PASSWORD).expect("classic verify");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn config_serde_round_trip_reproduces_the_hash() {
        let expected = hex::decode(ARGON2I_MIN_HASH).expect("hex");
        let config = argon2i_min();
        let json = serde_json::to_string(&config).expect("serialize");
        let decoded: Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.algorithm, PasswordHashAlgorithm::Argon2i13);
        assert_eq!(decoded.opslimit, config.opslimit);
        assert_eq!(decoded.memlimit, config.memlimit);
        assert_eq!(decoded.parallelism, config.parallelism);
        assert_eq!(decoded.hash_length, config.hash_length);

        let pwhash: VecPwHash =
            PwHash::hash_with_salt(PASSWORD, SALT.to_vec(), decoded.clone()).expect("hash");
        assert_eq!(pwhash.hash, expected);
        VecPwHash::from_parts(expected, SALT.to_vec(), decoded)
            .verify(PASSWORD)
            .expect("verify failed");

        // Dropping the algorithm field changes the result: an Argon2id config
        // with the same limits does not verify the Argon2i hash.
        let argon2id = argon2i_min().with_algorithm(PasswordHashAlgorithm::Argon2id13);
        assert!(
            VecPwHash::from_parts(
                hex::decode(ARGON2I_MIN_HASH).expect("hex"),
                SALT.to_vec(),
                argon2id
            )
            .verify(PASSWORD)
            .is_err()
        );
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn hash_with_salt_matches_libsodium_for_both_algorithms() {
        crate::native_test_util::init();
        for config in [argon2id_min(), argon2i_min()] {
            let pwhash: VecPwHash =
                PwHash::hash_with_salt(PASSWORD, SALT.to_vec(), config.clone()).expect("hash");
            let mut sodium = vec![0u8; config.hash_length];
            let rc = unsafe {
                libsodium_sys::crypto_pwhash(
                    sodium.as_mut_ptr(),
                    config.hash_length as u64,
                    PASSWORD.as_ptr().cast(),
                    PASSWORD.len() as u64,
                    SALT.as_ptr(),
                    config.opslimit,
                    config.memlimit,
                    config.algorithm as i32,
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(pwhash.hash, sodium);
        }
    }

    #[test]
    fn test_pwhash_uses_random_salt() {
        let password = b"super secrit password";

        // Production-cost Argon2 is too expensive to interpret. Salt
        // generation and verification exercise the same path at minimum cost.
        let hash = || {
            if cfg!(miri) {
                VecPwHash::hash(password, argon2id_min())
            } else {
                PwHash::hash_with_defaults(password)
            }
            .expect("unable to hash")
        };
        let pwhash1 = hash();
        let pwhash2 = hash();

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

        let config = if cfg!(miri) {
            argon2id_min()
        } else {
            Config::interactive()
        };
        let pwhash = VecPwHash::hash(password, config).expect("unable to hash");
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
        // Miri checks multi-lane Argon2i with the smaller RFC vector in
        // argon2::tests; retain parsing and re-encoding this 4 MiB vector.
        #[cfg(not(miri))]
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
