//! Native half of `dryoc.pwhash` (Argon2 password hashing, libsodium's
//! `crypto_pwhash`). Presets and defaults live in the Python module.

use dryoc::classic::crypto_pwhash::PasswordHashAlgorithm;
use dryoc::constants::{
    CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN,
    CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MODERATE, CRYPTO_PWHASH_ARGON2I_MEMLIMIT_SENSITIVE,
    CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE, CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN,
    CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MODERATE, CRYPTO_PWHASH_ARGON2I_OPSLIMIT_SENSITIVE,
    CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN,
    CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE, CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE,
    CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE, CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN,
    CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE, CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE,
    CRYPTO_PWHASH_BYTES_MAX, CRYPTO_PWHASH_BYTES_MIN, CRYPTO_PWHASH_SALTBYTES,
};
use dryoc::pwhash::{Config, VecPwHash};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use zeroize::Zeroizing;

use crate::util::{Buf, OrRaise, Password, secret_bytes};

fn config(opslimit: u64, memlimit: usize, algorithm: u32) -> PyResult<Config> {
    let algorithm = PasswordHashAlgorithm::try_from(algorithm).or_raise()?;
    Ok(Config::default()
        .with_algorithm(algorithm)
        .with_opslimit(opslimit)
        .with_memlimit(memlimit))
}

/// Hashes `password` with a random salt into libsodium's `$argon2id$...`
/// string format. Always runs detached from the interpreter.
#[pyfunction]
pub fn hash_password(
    py: Python<'_>,
    password: Password<'_>,
    opslimit: u64,
    memlimit: usize,
    algorithm: u32,
) -> PyResult<String> {
    let config = config(opslimit, memlimit, algorithm)?;
    let password = password.as_slice();
    py.detach(|| VecPwHash::hash(&password, config)?.to_encoded_string())
        .or_raise()
}

/// Checks `password` against an encoded hash. Raises `CryptoError` on a
/// mismatch and `InvalidInputError` if `encoded` is malformed.
#[pyfunction]
pub fn verify_password(py: Python<'_>, encoded: &str, password: Password<'_>) -> PyResult<()> {
    let password = password.as_slice();
    py.detach(|| VecPwHash::from_string(encoded)?.verify(&password))
        .or_raise()
}

/// Derives `length` raw key bytes from `password` and `salt`.
#[pyfunction]
pub fn derive_key<'py>(
    py: Python<'py>,
    password: Password<'py>,
    salt: Buf<'py>,
    length: usize,
    opslimit: u64,
    memlimit: usize,
    algorithm: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let config = config(opslimit, memlimit, algorithm)?.with_hash_length(length);
    let password = password.as_slice();
    let salt = salt.as_slice().to_vec();
    let key = py
        .detach(|| {
            let (hash, _, _) = VecPwHash::hash_with_salt(&password, salt, config)?.into_parts();
            Ok::<_, dryoc::Error>(Zeroizing::new(hash))
        })
        .or_raise()?;
    Ok(secret_bytes(py, key))
}

/// Returns libsodium's preset and limit constants for the Python module.
pub fn constants(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let constants = PyDict::new(py);
    constants.set_item("SALT_SIZE", CRYPTO_PWHASH_SALTBYTES)?;
    constants.set_item("MIN_KEY_SIZE", CRYPTO_PWHASH_BYTES_MIN)?;
    constants.set_item("MAX_KEY_SIZE", CRYPTO_PWHASH_BYTES_MAX)?;
    let argon2i = PasswordHashAlgorithm::Argon2i13 as u32;
    let argon2id = PasswordHashAlgorithm::Argon2id13 as u32;
    let presets = [
        (
            argon2i,
            "min",
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN,
        ),
        (
            argon2i,
            "interactive",
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE,
        ),
        (
            argon2i,
            "moderate",
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MODERATE,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MODERATE,
        ),
        (
            argon2i,
            "sensitive",
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_SENSITIVE,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_SENSITIVE,
        ),
        (
            argon2id,
            "min",
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN,
        ),
        (
            argon2id,
            "interactive",
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE,
        ),
        (
            argon2id,
            "moderate",
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE,
        ),
        (
            argon2id,
            "sensitive",
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE,
        ),
    ];
    let limits = PyDict::new(py);
    for (algorithm, level, opslimit, memlimit) in presets {
        limits.set_item((algorithm, level), (opslimit, memlimit))?;
    }
    constants.set_item("LIMITS", limits)?;
    Ok(constants)
}
