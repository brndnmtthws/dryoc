//! Native extension module behind the `dryoc` Python package.
//!
//! Classes are registered under private, module-prefixed attribute names (for
//! example `secretbox_SecretBox`) and re-exported by the public Python
//! modules, whose names they carry in `__module__`.
//!
//! The module declares free-threading support (`gil_used = false`): it has no
//! `unsafe` code and no global mutable state besides `PyOnceLock` caches,
//! every class is immutable to PyO3 (`frozen`), and the mutable state of
//! hashers, MACs, streams and `Ed25519ph` sits behind `util::Locked`, a mutex
//! that serializes concurrent calls on one object without deadlocking with the
//! GIL.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod aead;
mod hash;
mod kdf;
mod kem;
mod kx;
mod mac;
mod public_box;
mod pwhash;
mod secretbox;
mod secretstream;
mod sign;
mod util;

fn add<T: pyo3::PyTypeInfo>(module: &Bound<'_, PyModule>, name: &str) -> PyResult<()> {
    module.add(name, module.py().get_type::<T>())
}

/// Returns `size` cryptographically secure random bytes from the operating
/// system.
#[pyfunction]
fn random_bytes(py: Python<'_>, size: usize) -> PyResult<Bound<'_, PyBytes>> {
    PyBytes::new_with(py, size, |buffer| {
        util::maybe_detach(py, size, || dryoc::rng::copy_randombytes(buffer));
        Ok(())
    })
}

#[pymodule(gil_used = false)]
fn _dryoc(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;

    add::<secretbox::SecretBox>(m, "secretbox_SecretBox")?;

    add::<aead::XChaCha20Poly1305>(m, "aead_XChaCha20Poly1305")?;
    add::<aead::ChaCha20Poly1305>(m, "aead_ChaCha20Poly1305")?;

    add::<public_box::PublicKey>(m, "box_PublicKey")?;
    add::<public_box::SecretKey>(m, "box_SecretKey")?;
    add::<public_box::KeyPair>(m, "box_KeyPair")?;
    add::<public_box::PublicBox>(m, "box_Box")?;
    add::<public_box::SealedBox>(m, "box_SealedBox")?;

    add::<kem::xwing::PublicKey>(m, "xwing_PublicKey")?;
    add::<kem::xwing::SecretKey>(m, "xwing_SecretKey")?;
    add::<kem::xwing::KeyPair>(m, "xwing_KeyPair")?;
    add::<kem::mlkem768::PublicKey>(m, "mlkem768_PublicKey")?;
    add::<kem::mlkem768::SecretKey>(m, "mlkem768_SecretKey")?;
    add::<kem::mlkem768::KeyPair>(m, "mlkem768_KeyPair")?;
    add::<kem::sealedbox::SealedBox>(m, "sealedbox_SealedBox")?;

    add::<secretstream::Key>(m, "secretstream_Key")?;
    add::<secretstream::Encryptor>(m, "secretstream_Encryptor")?;
    add::<secretstream::Decryptor>(m, "secretstream_Decryptor")?;

    add::<hash::Sha256>(m, "hash_Sha256")?;
    add::<hash::Sha512>(m, "hash_Sha512")?;
    add::<hash::Sha3_256>(m, "hash_Sha3_256")?;
    add::<hash::Sha3_512>(m, "hash_Sha3_512")?;
    add::<hash::Blake2b>(m, "hash_Blake2b")?;
    add::<hash::Shake128>(m, "hash_Shake128")?;
    add::<hash::Shake256>(m, "hash_Shake256")?;
    add::<hash::TurboShake128>(m, "hash_TurboShake128")?;
    add::<hash::TurboShake256>(m, "hash_TurboShake256")?;
    add::<hash::Shake128Reader>(m, "hash_Shake128Reader")?;
    add::<hash::Shake256Reader>(m, "hash_Shake256Reader")?;
    add::<hash::TurboShake128Reader>(m, "hash_TurboShake128Reader")?;
    add::<hash::TurboShake256Reader>(m, "hash_TurboShake256Reader")?;
    m.add("hash_sha256", wrap_pyfunction!(hash::sha256, m)?)?;
    m.add("hash_sha512", wrap_pyfunction!(hash::sha512, m)?)?;
    m.add("hash_sha3_256", wrap_pyfunction!(hash::sha3_256, m)?)?;
    m.add("hash_sha3_512", wrap_pyfunction!(hash::sha3_512, m)?)?;
    m.add("hash_blake2b", wrap_pyfunction!(hash::blake2b, m)?)?;
    m.add("hash_shake128", wrap_pyfunction!(hash::shake128, m)?)?;
    m.add("hash_shake256", wrap_pyfunction!(hash::shake256, m)?)?;
    m.add(
        "hash_turboshake128",
        wrap_pyfunction!(hash::turboshake128, m)?,
    )?;
    m.add(
        "hash_turboshake256",
        wrap_pyfunction!(hash::turboshake256, m)?,
    )?;

    add::<mac::HmacSha256>(m, "mac_HmacSha256")?;
    add::<mac::HmacSha512>(m, "mac_HmacSha512")?;
    add::<mac::HmacSha512256>(m, "mac_HmacSha512256")?;
    add::<mac::Poly1305>(m, "mac_Poly1305")?;
    m.add("mac_hmac_sha256", wrap_pyfunction!(mac::hmac_sha256, m)?)?;
    m.add("mac_hmac_sha512", wrap_pyfunction!(mac::hmac_sha512, m)?)?;
    m.add(
        "mac_hmac_sha512256",
        wrap_pyfunction!(mac::hmac_sha512256, m)?,
    )?;
    m.add("mac_poly1305", wrap_pyfunction!(mac::poly1305, m)?)?;

    add::<kdf::Kdf>(m, "kdf_Kdf")?;
    add::<kdf::HkdfSha256>(m, "kdf_HkdfSha256")?;
    add::<kdf::HkdfSha512>(m, "kdf_HkdfSha512")?;
    m.add("kdf_hkdf_sha256", wrap_pyfunction!(kdf::hkdf_sha256, m)?)?;
    m.add("kdf_hkdf_sha512", wrap_pyfunction!(kdf::hkdf_sha512, m)?)?;

    add::<kx::SessionKeys>(m, "kx_SessionKeys")?;
    m.add(
        "kx_client_session_keys",
        wrap_pyfunction!(kx::client_session_keys, m)?,
    )?;
    m.add(
        "kx_server_session_keys",
        wrap_pyfunction!(kx::server_session_keys, m)?,
    )?;

    add::<sign::SigningKey>(m, "sign_SigningKey")?;
    add::<sign::VerifyKey>(m, "sign_VerifyKey")?;
    add::<sign::Ed25519ph>(m, "sign_Ed25519ph")?;

    m.add(
        "pwhash_hash_password",
        wrap_pyfunction!(pwhash::hash_password, m)?,
    )?;
    m.add(
        "pwhash_verify_password",
        wrap_pyfunction!(pwhash::verify_password, m)?,
    )?;
    m.add(
        "pwhash_derive_key",
        wrap_pyfunction!(pwhash::derive_key, m)?,
    )?;
    m.add("pwhash_constants", pwhash::constants(m.py())?)?;

    Ok(())
}
