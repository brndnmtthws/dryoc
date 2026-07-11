//! # Password hashing
//!
//! Implements libsodium's `crypto_pwhash_*` functions. This implementation
//! currently only supports Argon2i and Argon2id algorithms, and does not
//! support scrypt.
//!
//! String-based functions are enabled by default. They can be disabled by
//! building without default features, and re-enabled with the `base64` feature.
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
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "base64")]
use crate::argon2::ARGON2_VERSION_NUMBER;
use crate::argon2::{self, argon2_hash};
use crate::constants::*;
use crate::error::Error;

pub(crate) const STR_HASHBYTES: usize = 32;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)
)]
#[cfg_attr(
    not(feature = "serde"),
    derive(Zeroize, Clone, Copy, Debug, Eq, PartialEq)
)]
/// Password hash algorithm implementations.
pub enum PasswordHashAlgorithm {
    /// Argon2i version 0x13 (v19)
    Argon2i13  = 1,
    /// Argon2id version 0x13 (v19)
    Argon2id13 = 2,
}

impl TryFrom<u32> for PasswordHashAlgorithm {
    type Error = Error;

    fn try_from(num: u32) -> Result<Self, Self::Error> {
        match num {
            num if num == PasswordHashAlgorithm::Argon2i13 as u32 => {
                Ok(PasswordHashAlgorithm::Argon2i13)
            }
            num if num == PasswordHashAlgorithm::Argon2id13 as u32 => {
                Ok(PasswordHashAlgorithm::Argon2id13)
            }
            _ => Err(Error::InvalidValue {
                context: crate::ErrorContext::PasswordHashAlgorithm,
                actual: num as u64,
                constraint: crate::ValueConstraint::Between {
                    min: PasswordHashAlgorithm::Argon2i13 as u64,
                    max: PasswordHashAlgorithm::Argon2id13 as u64,
                },
            }),
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
///
/// # Errors
///
/// Returns an error if the cost parameters, salt length, or output length are
/// invalid, or if Argon2 cannot hash the password with the requested settings.
pub fn crypto_pwhash(
    output: &mut [u8],
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
    algorithm: PasswordHashAlgorithm,
) -> Result<(), Error> {
    validate_pwhash_parameters(
        output.len(),
        password.len(),
        salt.len(),
        opslimit,
        memlimit,
        algorithm,
    )?;

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

pub(crate) fn validate_pwhash_parameters(
    output_len: usize,
    password_len: usize,
    salt_len: usize,
    opslimit: u64,
    memlimit: usize,
    algorithm: PasswordHashAlgorithm,
) -> Result<(), Error> {
    let (
        bytes_min,
        bytes_max,
        password_max,
        opslimit_min,
        opslimit_max,
        memlimit_min,
        memlimit_max,
    ) = match algorithm {
        PasswordHashAlgorithm::Argon2i13 => (
            CRYPTO_PWHASH_ARGON2I_BYTES_MIN,
            CRYPTO_PWHASH_ARGON2I_BYTES_MAX,
            CRYPTO_PWHASH_ARGON2I_PASSWD_MAX,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MAX,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MAX,
        ),
        PasswordHashAlgorithm::Argon2id13 => (
            CRYPTO_PWHASH_ARGON2ID_BYTES_MIN,
            CRYPTO_PWHASH_ARGON2ID_BYTES_MAX,
            CRYPTO_PWHASH_ARGON2ID_PASSWD_MAX,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MAX,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX,
        ),
    };

    validate_length!(
        bytes_min,
        bytes_max,
        output_len,
        crate::ErrorContext::Output
    );
    validate_length!(
        CRYPTO_PWHASH_PASSWD_MIN,
        password_max,
        password_len,
        crate::ErrorContext::Password
    );
    validate_length!(
        exact CRYPTO_PWHASH_SALTBYTES,
        salt_len,
        crate::ErrorContext::PasswordHashSalt
    );
    validate_value!(
        opslimit_min,
        opslimit_max,
        opslimit,
        crate::ErrorContext::OperationsLimit
    );
    validate_value!(
        memlimit_min,
        memlimit_max,
        memlimit,
        crate::ErrorContext::MemoryLimit
    );

    Ok(())
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub(crate) fn pwhash_to_string(
    algorithm: PasswordHashAlgorithm,
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    salt: &[u8],
    hash: &[u8],
) -> String {
    let algorithm_name = pwhash_algorithm_name(algorithm);
    format!(
        "${algorithm_name}$v={}$m={},t={},p={parallelism}${}${}",
        argon2::ARGON2_VERSION_NUMBER,
        m_cost,
        t_cost,
        base64_no_pad_encode(salt),
        base64_no_pad_encode(hash),
    )
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
pub(crate) fn pwhash_string_len(
    algorithm: PasswordHashAlgorithm,
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    salt_len: usize,
    hash_len: usize,
) -> Option<usize> {
    let salt_len = base64_no_pad_encoded_len(salt_len)?;
    let hash_len = base64_no_pad_encoded_len(hash_len)?;
    1usize
        .checked_add(pwhash_algorithm_name(algorithm).len())?
        .checked_add(3 + decimal_len(ARGON2_VERSION_NUMBER))?
        .checked_add(3 + decimal_len(m_cost))?
        .checked_add(3 + decimal_len(t_cost))?
        .checked_add(3 + decimal_len(parallelism))?
        .checked_add(1)?
        .checked_add(salt_len)?
        .checked_add(1)?
        .checked_add(hash_len)
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
const fn pwhash_algorithm_name(algorithm: PasswordHashAlgorithm) -> &'static str {
    match algorithm {
        PasswordHashAlgorithm::Argon2i13 => "argon2i",
        PasswordHashAlgorithm::Argon2id13 => "argon2id",
    }
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
const fn decimal_len(value: u32) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
const fn base64_no_pad_encoded_len(input_len: usize) -> Option<usize> {
    let remainder_len = match input_len % 3 {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    match (input_len / 3).checked_mul(4) {
        Some(full_len) => full_len.checked_add(remainder_len),
        None => None,
    }
}

#[cfg(any(feature = "base64", all(doc, not(doctest))))]
fn base64_no_pad_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    let (chunks, rem) = input.as_chunks::<3>();

    for chunk in chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        output.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        output.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        output.push(ALPHABET[(n & 0x3f) as usize] as char);
    }

    if rem.len() == 1 {
        let n = (rem[0] as u32) << 16;
        output.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
    } else if rem.len() == 2 {
        let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        output.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        output.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
    }

    output
}

#[cfg(feature = "base64")]
fn base64_no_pad_decode(input: &str) -> Option<Vec<u8>> {
    fn decode_byte(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let input = input.as_bytes();
    if input.len() % 4 == 1 || input.contains(&b'=') {
        return None;
    }

    let mut output = Vec::with_capacity(input.len() / 4 * 3 + 2);
    let (chunks, rem) = input.as_chunks::<4>();

    for chunk in chunks {
        let n = ((decode_byte(chunk[0])? as u32) << 18)
            | ((decode_byte(chunk[1])? as u32) << 12)
            | ((decode_byte(chunk[2])? as u32) << 6)
            | decode_byte(chunk[3])? as u32;
        output.push((n >> 16) as u8);
        output.push((n >> 8) as u8);
        output.push(n as u8);
    }

    if rem.len() == 2 {
        let second = decode_byte(rem[1])?;
        if second & 0x0f != 0 {
            return None;
        }
        let n = ((decode_byte(rem[0])? as u32) << 18) | ((second as u32) << 12);
        output.push((n >> 16) as u8);
    } else if rem.len() == 3 {
        let third = decode_byte(rem[2])?;
        if third & 0x03 != 0 {
            return None;
        }
        let n = ((decode_byte(rem[0])? as u32) << 18)
            | ((decode_byte(rem[1])? as u32) << 12)
            | ((third as u32) << 6);
        output.push((n >> 16) as u8);
        output.push((n >> 8) as u8);
    }

    Some(output)
}

pub(crate) fn convert_costs(opslimit: u64, memlimit: usize) -> (u32, u32) {
    (opslimit as u32, (memlimit / 1024) as u32)
}

pub(crate) fn convert_costs_checked(opslimit: u64, memlimit: usize) -> Result<(u32, u32), Error> {
    let t_cost = u32::try_from(opslimit).map_err(|_| Error::InvalidValue {
        context: crate::ErrorContext::OperationsLimit,
        actual: opslimit,
        constraint: crate::ValueConstraint::Between {
            min: 0,
            max: u32::MAX as u64,
        },
    })?;
    let m_cost = u32::try_from(memlimit / 1024).map_err(|_| Error::InvalidValue {
        context: crate::ErrorContext::MemoryLimit,
        actual: memlimit as u64,
        constraint: crate::ValueConstraint::Between {
            min: 0,
            max: (u32::MAX as u64) * 1024 + 1023,
        },
    })?;
    Ok((t_cost, m_cost))
}

/// Hash a password string with a random salt.
///
/// This function provides a wrapper for [`crypto_pwhash`] that returns a string
/// encoding of a hashed password with a random salt, suitable for use with
/// password hash storage (i.e., in a database). Can be used to verify a
/// password using [`crypto_pwhash_str_verify`].
///
/// Compatible with libsodium's `crypto_pwhash_str`.
///
/// # Errors
///
/// Returns an error if the password or resource limits are unsupported, or if
/// Argon2 cannot hash the password.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str(password: &[u8], opslimit: u64, memlimit: usize) -> Result<String, Error> {
    crypto_pwhash_str_alg(
        password,
        opslimit,
        memlimit,
        PasswordHashAlgorithm::Argon2id13,
    )
}

/// Hashes a password with a random salt and the selected algorithm, returning
/// a database-safe encoded string.
///
/// Compatible with libsodium's `crypto_pwhash_str_alg`.
///
/// # Errors
///
/// Returns an error if the password or resource limits are unsupported, or if
/// Argon2 cannot hash the password.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str_alg(
    password: &[u8],
    opslimit: u64,
    memlimit: usize,
    algorithm: PasswordHashAlgorithm,
) -> Result<String, Error> {
    validate_pwhash_parameters(
        STR_HASHBYTES,
        password.len(),
        CRYPTO_PWHASH_SALTBYTES,
        opslimit,
        memlimit,
        algorithm,
    )?;

    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    let mut hash = [0u8; STR_HASHBYTES];
    crate::rng::copy_randombytes(&mut salt);

    let (t_cost, m_cost) = convert_costs(opslimit, memlimit);

    crypto_pwhash(&mut hash, password, &salt, opslimit, memlimit, algorithm)?;

    let pw = pwhash_to_string(algorithm, t_cost, m_cost, 1, &salt, &hash);

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
}

#[cfg(feature = "base64")]
impl Pwhash {
    pub(crate) fn parse_encoded_pwhash(hashed_password: &str) -> Result<Self, Error> {
        if hashed_password.len() >= CRYPTO_PWHASH_STRBYTES {
            return Err(length_error!(
                crate::ErrorContext::PasswordHash,
                hashed_password.len(),
                max CRYPTO_PWHASH_STRBYTES - 1
            ));
        }

        let encoded = hashed_password
            .strip_prefix('$')
            .ok_or_else(|| Error::invalid_encoding(crate::ErrorContext::PasswordHash))?;
        let mut fields = encoded.split('$');

        let algorithm = match fields.next().filter(|field| !field.is_empty()) {
            Some("argon2i") => PasswordHashAlgorithm::Argon2i13,
            Some("argon2id") => PasswordHashAlgorithm::Argon2id13,
            Some(field) if field.starts_with("v=") => {
                return Err(Error::missing_data(
                    crate::ErrorContext::PasswordHashAlgorithm,
                ));
            }
            Some(_) => {
                return Err(Error::invalid_encoding(
                    crate::ErrorContext::PasswordHashAlgorithm,
                ));
            }
            None => {
                return Err(Error::missing_data(
                    crate::ErrorContext::PasswordHashAlgorithm,
                ));
            }
        };

        let version = fields
            .next()
            .ok_or(Error::missing_data(
                crate::ErrorContext::PasswordHashVersion,
            ))?
            .strip_prefix("v=")
            .ok_or(Error::invalid_encoding(
                crate::ErrorContext::PasswordHashVersion,
            ))?;
        let version =
            parse_minimal_pwhash_decimal(version, crate::ErrorContext::PasswordHashVersion)?;
        if version != ARGON2_VERSION_NUMBER {
            return Err(Error::invalid_encoding(
                crate::ErrorContext::PasswordHashVersion,
            ));
        }

        let parameters = fields.next().ok_or(Error::missing_data(
            crate::ErrorContext::PasswordHashMemoryCost,
        ))?;
        let mut parameters = parameters.split(',');
        let m_cost = parse_pwhash_parameter(
            parameters.next(),
            "m=",
            crate::ErrorContext::PasswordHashMemoryCost,
        )?;
        let t_cost = parse_pwhash_parameter(
            parameters.next(),
            "t=",
            crate::ErrorContext::PasswordHashTimeCost,
        )?;
        let parallelism = parse_pwhash_parameter(
            parameters.next(),
            "p=",
            crate::ErrorContext::PasswordHashParallelism,
        )?;
        if parameters.next().is_some() {
            return Err(Error::invalid_encoding(crate::ErrorContext::PasswordHash));
        }

        let salt = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or(Error::missing_data(crate::ErrorContext::PasswordHashSalt))?;
        let salt = base64_no_pad_decode(salt).ok_or(Error::invalid_encoding(
            crate::ErrorContext::PasswordHashSalt,
        ))?;

        let pwhash = fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or(Error::missing_data(crate::ErrorContext::PasswordHash))?;
        let pwhash = base64_no_pad_decode(pwhash)
            .ok_or(Error::invalid_encoding(crate::ErrorContext::PasswordHash))?;

        if fields.next().is_some() {
            return Err(Error::invalid_encoding(crate::ErrorContext::PasswordHash));
        }

        crate::argon2::validate_argon2_pwhash_parameters(
            pwhash.len(),
            salt.len(),
            t_cost,
            m_cost,
            parallelism,
        )?;

        Ok(Self {
            pwhash: Some(pwhash),
            salt: Some(salt),
            type_: Some(algorithm),
            t_cost: Some(t_cost),
            m_cost: Some(m_cost),
            parallelism: Some(parallelism),
        })
    }
}

#[cfg(feature = "base64")]
fn parse_pwhash_parameter(
    parameter: Option<&str>,
    prefix: &str,
    context: crate::ErrorContext,
) -> Result<u32, Error> {
    let value = parameter
        .ok_or(Error::missing_data(context))?
        .strip_prefix(prefix)
        .ok_or(Error::invalid_encoding(context))?;
    parse_minimal_pwhash_decimal(value, context)
}

#[cfg(feature = "base64")]
fn parse_minimal_pwhash_decimal(value: &str, context: crate::ErrorContext) -> Result<u32, Error> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(Error::invalid_encoding(context));
    }
    value
        .parse::<u32>()
        .map_err(|_| Error::invalid_encoding(context))
}

/// Verifies that `hashed_password` is valid for `password`, assuming the hashed
/// password was encoded using `crypto_pwhash_str`.
///
/// Compatible with libsodium's `crypto_pwhash_str_verify`.
///
/// # Errors
///
/// Returns an error if `hashed_password` is malformed, uses unsupported
/// parameters, or does not match `password`.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str_verify(hashed_password: &str, password: &[u8]) -> Result<(), Error> {
    let pwhash = Pwhash::parse_encoded_pwhash(hashed_password)?;
    let t_cost = pwhash.t_cost.ok_or(Error::missing_data(
        crate::ErrorContext::PasswordHashTimeCost,
    ))?;
    let m_cost = pwhash.m_cost.ok_or(Error::missing_data(
        crate::ErrorContext::PasswordHashMemoryCost,
    ))?;
    let parallelism = pwhash.parallelism.ok_or(Error::missing_data(
        crate::ErrorContext::PasswordHashParallelism,
    ))?;
    let salt = pwhash
        .salt
        .ok_or(Error::missing_data(crate::ErrorContext::PasswordHashSalt))?;
    let algorithm = pwhash.type_.ok_or(Error::missing_data(
        crate::ErrorContext::PasswordHashAlgorithm,
    ))?;
    let expected_hash = pwhash
        .pwhash
        .ok_or(Error::missing_data(crate::ErrorContext::PasswordHash))?;

    verify_pwhash_parts(
        &expected_hash,
        password,
        &salt,
        t_cost,
        m_cost,
        parallelism,
        algorithm,
    )
}

pub(crate) fn verify_pwhash_parts(
    expected_hash: &[u8],
    password: &[u8],
    salt: &[u8],
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    algorithm: PasswordHashAlgorithm,
) -> Result<(), Error> {
    let mut hash = Zeroizing::new(vec![0u8; expected_hash.len()]);
    argon2_hash(
        t_cost,
        m_cost,
        parallelism,
        password,
        salt,
        None,
        None,
        &mut hash,
        algorithm.into(),
    )?;

    if hash.as_slice().ct_eq(expected_hash).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

/// Checks if the parameters for `hashed_password` match those passed to the
/// function. Returns `false` if the parameters match, and `true` if the
/// parameters are mismatched (requiring a rehash).
///
/// Compatible with libsodium's `crypto_pwhash_str_needs_rehash`.
///
/// # Errors
///
/// Returns an error if `hashed_password` is malformed or uses unsupported
/// parameters.
#[cfg(any(feature = "base64", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "base64")))]
pub fn crypto_pwhash_str_needs_rehash(
    hashed_password: &str,
    opslimit: u64,
    memlimit: usize,
) -> Result<bool, Error> {
    let (t_cost, m_cost) = convert_costs_checked(opslimit, memlimit)?;
    let pwhash = Pwhash::parse_encoded_pwhash(hashed_password)?;
    let parsed_t_cost = pwhash.t_cost.ok_or(Error::missing_data(
        crate::ErrorContext::PasswordHashTimeCost,
    ))?;
    let parsed_m_cost = pwhash.m_cost.ok_or(Error::missing_data(
        crate::ErrorContext::PasswordHashMemoryCost,
    ))?;

    if t_cost != parsed_t_cost || m_cost != parsed_m_cost {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(all(test, dryoc_native_tests))]
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
    fn test_base64_no_pad_matches_base64_crate() {
        use base64::Engine as _;
        use base64::engine::general_purpose;

        for len in 0..128 {
            let input: Vec<u8> = (0..len).map(|i| (i * 31 + len) as u8).collect();
            let encoded = base64_no_pad_encode(&input);
            assert_eq!(encoded, general_purpose::STANDARD_NO_PAD.encode(&input));
            assert_eq!(
                base64_no_pad_decode(&encoded).as_deref(),
                Some(input.as_slice())
            );
        }

        assert_eq!(base64_no_pad_decode("A"), None);
        assert_eq!(base64_no_pad_decode("AA="), None);
        assert_eq!(base64_no_pad_decode("A/"), None);
        assert_eq!(base64_no_pad_decode("AA/"), None);

        let salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
        let hash = [0u8; STR_HASHBYTES];
        let encoded = pwhash_to_string(
            PasswordHashAlgorithm::Argon2id13,
            2,
            65_536,
            1,
            &salt,
            &hash,
        );
        assert_eq!(
            pwhash_string_len(
                PasswordHashAlgorithm::Argon2id13,
                2,
                65_536,
                1,
                salt.len(),
                hash.len(),
            ),
            Some(encoded.len())
        );

        assert_eq!(
            pwhash_string_len(
                PasswordHashAlgorithm::Argon2id13,
                2,
                65_536,
                1,
                usize::MAX,
                0
            ),
            None,
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            pwhash_string_len(
                PasswordHashAlgorithm::Argon2id13,
                2,
                65_536,
                1,
                3_221_225_471,
                0,
            ),
            None,
        );
    }

    #[cfg(feature = "base64")]
    #[test]
    fn malformed_password_hash_fields_have_structured_errors() {
        const SALT: &str = "AAAAAAAAAAA";
        const HASH: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let cases = [
            (
                format!("$argon2wat$v=19$m=65536,t=2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashAlgorithm,
            ),
            (
                format!("$argon2id$v=nope$m=65536,t=2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashVersion,
            ),
            (
                format!("$argon2id$v=19$m=nope,t=2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashMemoryCost,
            ),
            (
                format!("$argon2id$v=19$m=65536,t=nope,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashTimeCost,
            ),
            (
                format!("$argon2id$v=19$m=65536,t=2,p=nope${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashParallelism,
            ),
            (
                format!("$argon2id$v=19$m=65536,t=2,p=1$A${HASH}"),
                crate::ErrorContext::PasswordHashSalt,
            ),
            (
                format!("$argon2id$v=19$m=65536,t=2,p=1${SALT}$A"),
                crate::ErrorContext::PasswordHash,
            ),
            (
                format!("$argon2id$v=18$m=65536,t=2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashVersion,
            ),
            (
                format!("$argon2id$v=019$m=65536,t=2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashVersion,
            ),
            (
                format!("$argon2id$v=19$m=065536,t=2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashMemoryCost,
            ),
            (
                format!("$argon2id$v=19$m=65536,t=+2,p=1${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashTimeCost,
            ),
            (
                format!("$argon2id$v=19$m=65536,t=2,p=01${SALT}${HASH}"),
                crate::ErrorContext::PasswordHashParallelism,
            ),
        ];

        for (encoded, expected_context) in cases {
            let error = match Pwhash::parse_encoded_pwhash(&encoded) {
                Ok(_) => panic!("the malformed field should be rejected"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                Error::InvalidEncoding { context } if context == expected_context
            ));
        }

        let missing_hash = format!("$argon2id$v=19$m=65536,t=2,p=1${SALT}");
        assert!(matches!(
            Pwhash::parse_encoded_pwhash(&missing_hash),
            Err(Error::MissingData {
                context: crate::ErrorContext::PasswordHash,
            })
        ));

        let missing_algorithm = format!("$v=19$m=65536,t=2,p=1${SALT}${HASH}");
        assert!(matches!(
            Pwhash::parse_encoded_pwhash(&missing_algorithm),
            Err(Error::MissingData {
                context: crate::ErrorContext::PasswordHashAlgorithm,
            })
        ));
    }

    #[test]
    fn password_hashing_reports_invalid_resource_limits() {
        let mut output = [0u8; CRYPTO_PWHASH_BYTES_MIN];
        let salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
        let password = b"password";

        for (opslimit, memlimit, expected_context) in [
            (
                CRYPTO_PWHASH_OPSLIMIT_MIN - 1,
                CRYPTO_PWHASH_MEMLIMIT_MIN,
                crate::ErrorContext::OperationsLimit,
            ),
            (
                CRYPTO_PWHASH_OPSLIMIT_MIN,
                CRYPTO_PWHASH_MEMLIMIT_MIN - 1,
                crate::ErrorContext::MemoryLimit,
            ),
        ] {
            let error = crypto_pwhash(
                &mut output,
                password,
                &salt,
                opslimit,
                memlimit,
                PasswordHashAlgorithm::Argon2id13,
            )
            .expect_err("invalid resource limits should fail");
            assert!(matches!(
                error,
                Error::InvalidValue { context, .. } if context == expected_context
            ));

            #[cfg(feature = "base64")]
            {
                let error = crypto_pwhash_str(password, opslimit, memlimit)
                    .expect_err("invalid resource limits should fail");
                assert!(matches!(
                    error,
                    Error::InvalidValue { context, .. } if context == expected_context
                ));
            }
        }
    }

    #[test]
    fn password_hashing_enforces_classic_parameter_contract() {
        let mut output = [0u8; CRYPTO_PWHASH_BYTES_MIN];
        let salt = [0u8; CRYPTO_PWHASH_SALTBYTES];

        for opslimit in 1..CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN {
            assert!(matches!(
                crypto_pwhash(
                    &mut output,
                    b"password",
                    &salt,
                    opslimit,
                    CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN,
                    PasswordHashAlgorithm::Argon2i13,
                ),
                Err(Error::InvalidValue {
                    context: crate::ErrorContext::OperationsLimit,
                    ..
                })
            ));
        }

        assert!(matches!(
            crypto_pwhash(
                &mut output,
                b"password",
                &salt[..CRYPTO_PWHASH_SALTBYTES - 1],
                CRYPTO_PWHASH_OPSLIMIT_MIN,
                CRYPTO_PWHASH_MEMLIMIT_MIN,
                PasswordHashAlgorithm::Argon2id13,
            ),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::PasswordHashSalt,
                constraint: crate::LengthConstraint::Exact(CRYPTO_PWHASH_SALTBYTES),
                ..
            })
        ));

        assert!(PasswordHashAlgorithm::try_from(0).is_err());
        assert_eq!(
            PasswordHashAlgorithm::try_from(CRYPTO_PWHASH_ALG_ARGON2ID13 as u32)
                .expect("valid algorithm"),
            PasswordHashAlgorithm::Argon2id13
        );
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
        let pwhash2 = crypto_pwhash_str(
            password,
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
        .expect("pwhash failed");

        let parsed = Pwhash::parse_encoded_pwhash(&pwhash).expect("couldn't parse pwhash");
        let parsed2 = Pwhash::parse_encoded_pwhash(&pwhash2).expect("couldn't parse pwhash");

        assert_ne!(
            parsed.salt.as_ref().expect("missing salt"),
            &vec![0u8; CRYPTO_PWHASH_SALTBYTES]
        );
        assert_ne!(parsed.salt, parsed2.salt);

        let mut pwhash_bytes = [0u8; CRYPTO_PWHASH_STRBYTES];
        pwhash_bytes[..pwhash.len()].copy_from_slice(pwhash.as_bytes());

        assert!(pwhash::argon2id13::pwhash_verify(
            &pwhash::argon2id13::HashedPassword::from_slice(&pwhash_bytes)
                .expect("hashed password failed"),
            password,
        ));

        let argon2i = crypto_pwhash_str_alg(
            password,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE,
            PasswordHashAlgorithm::Argon2i13,
        )
        .expect("argon2i pwhash failed");
        assert!(argon2i.starts_with(CRYPTO_PWHASH_ARGON2I_STRPREFIX));
        crypto_pwhash_str_verify(&argon2i, password).expect("argon2i verify failed");
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

        for encoded in [
            concat!(
                "$argon2id$v=19$m=256,t=3,p=1$MDEyMzQ1Njc$",
                "G5ajKFCoUzaXRLdz7UJb5wGkb2Xt+X5/GQjUYtS2+TE",
            ),
            concat!(
                "$argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$",
                "TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M",
            ),
        ] {
            crypto_pwhash_str_verify(encoded, b"password")
                .expect("valid libsodium Argon2 vector should verify");
        }

        assert!(crypto_pwhash_str_verify(&format!("{pw_str}$garbage"), password).is_err());
        assert!(crypto_pwhash_str_verify(pw_str.trim_start_matches('$'), password).is_err());
        for invalid_parallelism in ["0", "4294967295"] {
            let malformed = pw_str.replace(",p=1", &format!(",p={invalid_parallelism}"));
            assert!(crypto_pwhash_str_verify(&malformed, password).is_err());
            assert!(
                crypto_pwhash_str_needs_rehash(
                    &malformed,
                    CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                    CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                )
                .is_err()
            );
        }

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

        assert!(
            crypto_pwhash_str_needs_rehash(pw_str, 0, 0,)
                .expect("zero costs are a valid rehash comparison")
        );

        assert!(matches!(
            crypto_pwhash_str_needs_rehash(pw_str, u32::MAX as u64 + 1, 0),
            Err(Error::InvalidValue {
                context: crate::ErrorContext::OperationsLimit,
                ..
            })
        ));
    }
}
