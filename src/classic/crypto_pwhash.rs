//! # Password hashing
//!
//! Implements libsodium's `crypto_pwhash_*` functions. This implementation
//! currently only supports Argon2i and Argon2id algorithms, and does not
//! support scrypt.
//!
//! To use the string-based functions, the `base64` crate feature must be
//! enabled.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/password_hashing/default_phf).
//!
//! ## Classic API example, key derivation
//!
//! ```
//! use base64::{Engine as _, engine::general_purpose};
//! use dryoc::classic::crypto_pwhash::*;
//! use dryoc::rng::copy_randombytes;
//! use dryoc::constants::{CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
//!     CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_SALTBYTES};
//!
//! let mut key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
//!
//! // Randomly generate a salt
//! let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
//! copy_randombytes(&mut salt);
//!
//! // Create a really good password
//! let password = b"It is by riding a bicycle that you learn the contours of a country best, since you have to sweat up the hills and coast down them.";
//!
//! crypto_pwhash(
//!     &mut key,
//!     password,
//!     &salt,
//!     CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
//!     CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
//!     PasswordHashAlgorithm::Argon2id13,
//! )
//! .expect("pwhash failed");
//!
//! // now `key` can be used as a secret key
//! println!("key = {}", general_purpose::STANDARD_NO_PAD.encode(&key));
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "base64")]
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(feature = "base64")]
use crate::argon2::ARGON2_VERSION_NUMBER;
use crate::argon2::{self, argon2_hash};
use crate::constants::*;
use crate::error::Error;

pub(crate) const STR_HASHBYTES: usize = 32;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// Password hash algorithm implementations.
pub enum PasswordHashAlgorithm {
    /// Argon2i version 0x13 (v19)
    Argon2i13  = 1,
    /// Argon2id version 0x13 (v19)
    Argon2id13 = 2,
}

impl From<u32> for PasswordHashAlgorithm {
    fn from(num: u32) -> Self {
        // a bit clunky but it gets the job done
        match num {
            num if num == PasswordHashAlgorithm::Argon2i13 as u32 => {
                PasswordHashAlgorithm::Argon2i13
            }
            num if num == PasswordHashAlgorithm::Argon2id13 as u32 => {
                PasswordHashAlgorithm::Argon2id13
            }
            _ => panic!("invalid password hash algorithm type: {}", num),
        }
    }
}

impl From<PasswordHashAlgorithm> for argon2::Argon2Type {
    fn from(algo: PasswordHashAlgorithm) -> Self {
        match algo {
            PasswordHashAlgorithm::Argon2i13 => argon2::Argon2Type::Argon2i,
            PasswordHashAlgorithm::Argon2id13 => argon2::Argon2Type::Argon2id,
        }
    }
}

/// Hashes `password` with `salt`, placing the resulting hash into `output`.
///
/// * `opslimit` specifies the number of iterations to use in the underlying
///   algorithm
/// * `memlimit` specifies the maximum amount of memory to use, in bytes
///
/// Generally speaking, you want to set `opslimit` and `memlimit` sufficiently
/// large such that it's hard for someone to brute-force a password.
///
/// For your convenience, the following constants are defined which can be used
/// with `opslimit` and `memlimit`:
/// * [`CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE`] and
///   [`CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE`] for interactive operations
/// * [`CRYPTO_PWHASH_OPSLIMIT_MODERATE`] and
///   [`CRYPTO_PWHASH_MEMLIMIT_MODERATE`] for typical operations, such as
///   server-side password hashing
/// * [`CRYPTO_PWHASH_OPSLIMIT_SENSITIVE`] and
///   [`CRYPTO_PWHASH_MEMLIMIT_SENSITIVE`] for sensitive operations
///
/// Compatible with libsodium's `crypto_pwhash`.
pub fn crypto_pwhash(
    output: &mut [u8],
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
    algorithm: PasswordHashAlgorithm,
) -> Result<(), Error> {
    validate!(
        CRYPTO_PWHASH_OPSLIMIT_MIN,
        CRYPTO_PWHASH_OPSLIMIT_MAX,
        opslimit,
        "opslimit"
    );
    validate!(
        CRYPTO_PWHASH_MEMLIMIT_MIN,
        CRYPTO_PWHASH_MEMLIMIT_MAX,
        memlimit,
        "memlimit"
    );

    let (t_cost, m_cost) = convert_costs(opslimit, memlimit);

    argon2_hash(
        t_cost,
        m_cost,
        1,
        password,
        salt,
        None,
        None,
        output,
        algorithm.into(),
    )
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub(crate) fn pwhash_to_string(t_cost: u32, m_cost: u32, salt: &[u8], hash: &[u8]) -> String {
    use base64::engine::general_purpose;
    use base64::Engine as _;

    format!(
        "$argon2id$v={}$m={},t={},p=1${}${}",
        argon2::ARGON2_VERSION_NUMBER,
        m_cost,
        t_cost,
        general_purpose::STANDARD_NO_PAD.encode(salt),
        general_purpose::STANDARD_NO_PAD.encode(hash),
    )
}

pub(crate) fn convert_costs(opslimit: u64, memlimit: usize) -> (u32, u32) {
    (opslimit as u32, (memlimit / 1024) as u32)
}

/// Wrapper for [`crypto_pwhash`] that returns a string encoding of a hashed
/// password with a random salt, suitable for use with password hash storage
/// (i.e., in a database). Can be used to verify a password using
/// [`crypto_pwhash_str_verify`].
///
/// Compatible with libsodium's `crypto_pwhash_str`.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str(password: &[u8], opslimit: u64, memlimit: usize) -> Result<String, Error> {
    validate!(
        CRYPTO_PWHASH_OPSLIMIT_MIN,
        CRYPTO_PWHASH_OPSLIMIT_MAX,
        opslimit,
        "opslimit"
    );
    validate!(
        CRYPTO_PWHASH_MEMLIMIT_MIN,
        CRYPTO_PWHASH_MEMLIMIT_MAX,
        memlimit,
        "memlimit"
    );

    let salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    let mut hash = [0u8; STR_HASHBYTES];

    let (t_cost, m_cost) = convert_costs(opslimit, memlimit);

    argon2_hash(
        t_cost,
        m_cost,
        1,
        password,
        &salt,
        None,
        None,
        &mut hash,
        argon2::Argon2Type::Argon2id,
    )?;

    let pw = pwhash_to_string(t_cost, m_cost, &salt, &hash);

    Ok(pw)
}

#[cfg(feature = "base64")]
#[derive(Default)]
pub(crate) struct Pwhash {
    pub(crate) pwhash: Option<Vec<u8>>,
    pub(crate) salt: Option<Vec<u8>>,
    pub(crate) type_: Option<PasswordHashAlgorithm>,
    pub(crate) t_cost: Option<u32>,
    pub(crate) m_cost: Option<u32>,
    pub(crate) parallelism: Option<u32>,
    pub(crate) version: Option<u32>,
}

#[cfg(feature = "base64")]
impl Pwhash {
    pub(crate) fn parse_encoded_pwhash(hashed_password: &str) -> Result<Self, Error> {
        use base64::Engine;
        let mut pwhash = Pwhash::default();
        let base64_engine = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::NO_PAD,
        );

        for s in hashed_password.split('$') {
            if s.is_empty() {
                // skip
            } else if s.starts_with("argon2") {
                match s {
                    "argon2i" => pwhash.type_ = Some(PasswordHashAlgorithm::Argon2i13),
                    "argon2id" => pwhash.type_ = Some(PasswordHashAlgorithm::Argon2id13),
                    _ => return Err(dryoc_error!(format!("invalid type: {}", s))),
                }
            } else if let Some(stripped) = s.strip_prefix("v=") {
                pwhash.version = Some(
                    stripped
                        .parse::<u32>()
                        .map_err(|_| dryoc_error!("unable to decode password hash version"))?,
                );
            } else if s.contains("m=") && s.contains("t=") && s.contains("p=") {
                for p in s.split(',') {
                    if let Some(m_cost) = p.strip_prefix("m=") {
                        pwhash.m_cost = Some(m_cost.parse::<u32>().map_err(|_| {
                            dryoc_error!("unable to decode password hash parameter m_cost")
                        })?);
                    } else if let Some(t_cost) = p.strip_prefix("t=") {
                        pwhash.t_cost = Some(t_cost.parse::<u32>().map_err(|_| {
                            dryoc_error!("unable to decode password hash parameter t_cost")
                        })?);
                    } else if let Some(parallelism) = p.strip_prefix("p=") {
                        pwhash.parallelism = Some(parallelism.parse::<u32>().map_err(|_| {
                            dryoc_error!("unable to decode password hash parameter t_cost")
                        })?);
                    }
                }
            } else if pwhash.salt.is_none() {
                pwhash.salt = base64_engine.decode(s).ok();
            } else if pwhash.pwhash.is_none() {
                pwhash.pwhash = base64_engine.decode(s).ok();
            }
        }

        // Check if version is supported
        if pwhash.version.is_none() || pwhash.version.unwrap() != ARGON2_VERSION_NUMBER {
            Err(dryoc_error!("unsupported password hash"))
        // Verify correct value for parallism
        } else if pwhash.parallelism.is_none() || pwhash.parallelism.unwrap() != 1 {
            Err(dryoc_error!("parallelism missing or invalid"))
        // Check for missing fields
        } else if pwhash.pwhash.is_none() || pwhash.pwhash.as_ref().unwrap().is_empty() {
            Err(dryoc_error!("password hash missing"))
        } else if pwhash.salt.is_none() || pwhash.salt.as_ref().unwrap().is_empty() {
            Err(dryoc_error!("password salt missing"))
        } else if pwhash.type_.is_none() {
            Err(dryoc_error!("algorithm type missing"))
        } else if pwhash.m_cost.is_none() {
            Err(dryoc_error!("m_cost missing"))
        } else if pwhash.t_cost.is_none() {
            Err(dryoc_error!("t_cost missing"))
        } else {
            Ok(pwhash)
        }
    }
}

/// Verifies that `hashed_password` is valid for `password`, assuming the hashed
/// password was encoded using `crypto_pwhash_str`.
///
/// Compatible with libsodium's `crypto_pwhash_str_verify`.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str_verify(hashed_password: &str, password: &[u8]) -> Result<(), Error> {
    let mut hash = [0u8; STR_HASHBYTES];

    let pwhash = Pwhash::parse_encoded_pwhash(hashed_password)?;

    argon2_hash(
        pwhash.t_cost.unwrap(),
        pwhash.m_cost.unwrap(),
        pwhash.parallelism.unwrap(),
        password,
        pwhash.salt.unwrap().as_ref(),
        None,
        None,
        &mut hash,
        pwhash.type_.unwrap().into(),
    )?;

    if hash.ct_eq(pwhash.pwhash.unwrap().as_ref()).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("password hashes do not match"))
    }
}

/// Checks if the parameters for `hashed_password` match those passed to the
/// function. Returns `false` if the parameters match, and `true` if the
/// parameters are mismatched (requiring a rehash).
///
/// Compatible with libsodium's `crypto_pwhash_str_needs_rehash`.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str_needs_rehash(
    hashed_password: &str,
    opslimit: u64,
    memlimit: usize,
) -> Result<bool, Error> {
    let pwhash = Pwhash::parse_encoded_pwhash(hashed_password)?;

    let (t_cost, m_cost) = convert_costs(opslimit, memlimit);

    if t_cost != pwhash.t_cost.unwrap() || m_cost != pwhash.m_cost.unwrap() {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_pwhash() {
        use sodiumoxide::crypto::pwhash;

        use crate::rng::copy_randombytes;

        let mut hash = [0u8; 32];
        let mut so_hash = [0u8; 32];
        let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];

        copy_randombytes(&mut salt);

        let password = b"donkey kong";

        crypto_pwhash(
            &mut hash,
            password,
            &salt,
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            PasswordHashAlgorithm::Argon2id13,
        )
        .expect("pwhash failed");

        let _ = pwhash::argon2id13::derive_key(
            &mut so_hash,
            password,
            &pwhash::argon2id13::Salt::from_slice(&salt).expect("salt failed"),
            pwhash::argon2id13::OPSLIMIT_INTERACTIVE,
            pwhash::argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .expect("so pwhash failed");

        assert_eq!(hash, so_hash);
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_crypto_pwhash_str() {
        use sodiumoxide::crypto::pwhash;

        let password = b"donkey kong";

        let pwhash = crypto_pwhash_str(
            password,
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
        .expect("pwhash failed");

        let mut pwhash_bytes = [0u8; CRYPTO_PWHASH_STRBYTES];
        pwhash_bytes[..pwhash.len()].copy_from_slice(pwhash.as_bytes());

        assert!(pwhash::argon2id13::pwhash_verify(
            &pwhash::argon2id13::HashedPassword::from_slice(&pwhash_bytes)
                .expect("hashed password failed"),
            password,
        ));
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_crypto_pwhash_str_verify() {
        use sodiumoxide::crypto::pwhash;

        let password = b"donkey kong";

        let pwhash = pwhash::argon2id13::pwhash(
            password,
            pwhash::argon2id13::OPSLIMIT_INTERACTIVE,
            pwhash::argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .expect("so pwhash failed");

        let pw_str = std::str::from_utf8(&pwhash.0)
            .expect("from ut8 failed")
            .trim_end_matches('\x00');

        crypto_pwhash_str_verify(pw_str, password).expect("verify failed");
        crypto_pwhash_str_verify(pw_str, b"invalid password")
            .expect_err("verify should have failed");

        // should be false
        assert!(
            !crypto_pwhash_str_needs_rehash(
                pw_str,
                CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            )
            .expect("verify rehash failed")
        );

        // should be true
        assert!(
            crypto_pwhash_str_needs_rehash(
                pw_str,
                CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE + 1,
                CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            )
            .expect("verify rehash failed")
        );
    }
}
