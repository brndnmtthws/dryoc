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
    format!(
        "$argon2id$v={}$m={},t={},p=1${}${}",
        argon2::ARGON2_VERSION_NUMBER,
        m_cost,
        t_cost,
        base64_no_pad_encode(salt),
        base64_no_pad_encode(hash),
    )
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

/// Hash a password string with a random salt.
///
/// This function provides a wrapper for [`crypto_pwhash`] that returns a string
/// encoding of a hashed password with a random salt, suitable for use with
/// password hash storage (i.e., in a database). Can be used to verify a
/// password using [`crypto_pwhash_str_verify`].
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

    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    let mut hash = [0u8; STR_HASHBYTES];
    crate::rng::copy_randombytes(&mut salt);

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
        let mut pwhash = Pwhash::default();

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
                pwhash.salt = base64_no_pad_decode(s);
            } else if pwhash.pwhash.is_none() {
                pwhash.pwhash = base64_no_pad_decode(s);
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
