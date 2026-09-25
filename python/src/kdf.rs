//! `dryoc.kdf`: libsodium's BLAKE2b subkey derivation and HKDF (RFC 5869).

use dryoc::constants::{
    CRYPTO_KDF_BLAKE2B_BYTES_MAX, CRYPTO_KDF_BLAKE2B_BYTES_MIN, CRYPTO_KDF_CONTEXTBYTES,
    CRYPTO_KDF_HKDF_SHA256_BYTES_MAX, CRYPTO_KDF_HKDF_SHA256_KEYBYTES,
    CRYPTO_KDF_HKDF_SHA512_BYTES_MAX, CRYPTO_KDF_HKDF_SHA512_KEYBYTES, CRYPTO_KDF_KEYBYTES,
};
use dryoc::kdf::{Context, Key, StackKdf};
use dryoc::types::NewByteArray;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use zeroize::Zeroizing;

use crate::util::{Buf, OrRaise, fixed, secret_bytes, secret_key_class};

/// Derives many independent subkeys from one master key (libsodium's
/// `crypto_kdf`, BLAKE2b-based).
///
/// Each subkey is identified by a numeric `subkey_id` and the 8-byte
/// `context`, a constant describing its purpose in your application (for
/// example `b"Sessions"`).
#[pyclass(frozen, name = "Kdf", module = "dryoc.kdf")]
pub struct Kdf {
    key: Key,
    context: Context,
}

#[pymethods]
impl Kdf {
    /// Length of the context in bytes.
    #[classattr]
    const CONTEXT_SIZE: usize = CRYPTO_KDF_CONTEXTBYTES;
    /// Length of the master key in bytes.
    #[classattr]
    const KEY_SIZE: usize = CRYPTO_KDF_KEYBYTES;
    /// Longest subkey `derive` produces.
    #[classattr]
    const MAX_SUBKEY_SIZE: usize = CRYPTO_KDF_BLAKE2B_BYTES_MAX;
    /// Shortest subkey `derive` produces.
    #[classattr]
    const MIN_SUBKEY_SIZE: usize = CRYPTO_KDF_BLAKE2B_BYTES_MIN;
    /// Master keys are secrets and are not hashable.
    #[classattr]
    const __hash__: Option<Py<PyAny>> = None;

    /// Creates a KDF from a 32-byte master `key` and an 8-byte `context`.
    #[new]
    fn py_new(key: Buf<'_>, context: Buf<'_>) -> PyResult<Self> {
        let key: Key = fixed(key.as_slice(), "master key")?;
        let context: Context = fixed(context.as_slice(), "context")?;
        Ok(Self { key, context })
    }

    /// Creates a KDF with a new random master key for `context`.
    #[classmethod]
    fn generate(_cls: &Bound<'_, PyType>, context: Buf<'_>) -> PyResult<Self> {
        let context: Context = fixed(context.as_slice(), "context")?;
        Ok(Self {
            key: Key::generate(),
            context,
        })
    }

    /// The context this KDF derives subkeys for.
    #[getter]
    fn context<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.context.as_ref())
    }

    /// Derives the subkey numbered `subkey_id` (0 to 2**64 - 1), `length`
    /// bytes long (16 to 64).
    #[pyo3(signature = (subkey_id, length = 32))]
    fn derive<'py>(
        &self,
        py: Python<'py>,
        subkey_id: u64,
        length: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let subkey = StackKdf::from_parts(self.key.clone(), self.context.clone())
            .derive_subkey_to_vec(subkey_id, length)
            .map(Zeroizing::new)
            .or_raise()?;
        Ok(secret_bytes(py, subkey))
    }

    /// Exports the master key. Handle the result as a secret.
    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.key.as_ref())
    }

    /// Compares master key and context in constant time.
    fn __eq__(&self, other: &Bound<'_, Self>) -> bool {
        use subtle::ConstantTimeEq;
        let other = other.get();
        let key: &[u8] = self.key.as_ref();
        let context: &[u8] = self.context.as_ref();
        bool::from(key.ct_eq(other.key.as_ref()) & context.ct_eq(other.context.as_ref()))
    }

    fn __repr__(&self) -> String {
        format!(
            "Kdf(<redacted>, context={:?})",
            DisplayBytes(self.context.as_ref())
        )
    }
}

/// Formats bytes like a Python `bytes` literal.
struct DisplayBytes<'a>(&'a [u8]);

impl core::fmt::Debug for DisplayBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("b'")?;
        for &byte in self.0 {
            match byte {
                b'\\' => f.write_str("\\\\")?,
                b'\'' => f.write_str("\\'")?,
                0x20..=0x7e => write!(f, "{}", byte as char)?,
                _ => write!(f, "\\x{byte:02x}")?,
            }
        }
        f.write_str("'")
    }
}

macro_rules! hkdf_class {
    (
        $(#[$meta:meta])*
        $rust:ident, $inner:ty, $name:literal,
        prk: $prk_bytes:expr, max: $max:expr, oneshot: $oneshot:ident, $display:literal
    ) => {
        secret_key_class! {
            $(#[$meta])*
            $rust, $name, "dryoc.kdf", SIZE = $prk_bytes, "pseudorandom key"
            {
                /// Longest output `expand` produces.
                #[classattr]
                const MAX_OUTPUT_SIZE: usize = $max;

                /// HKDF-Extract: condenses input keying material `ikm` (and an
                /// optional, ideally random, `salt`) into a pseudorandom key.
                #[classmethod]
                #[pyo3(signature = (ikm, *, salt = None))]
                fn extract(
                    _cls: &Bound<'_, PyType>,
                    ikm: Buf<'_>,
                    salt: Option<Buf<'_>>,
                ) -> Self {
                    let salt = salt.as_ref().map(Buf::as_slice);
                    Self {
                        key: <$inner>::extract(salt, ikm.as_slice()).into_prk(),
                    }
                }

                /// HKDF-Expand: derives `length` bytes bound to `info`.
                #[pyo3(signature = (info = None, length = 32))]
                fn expand<'py>(
                    &self,
                    py: Python<'py>,
                    info: Option<Buf<'py>>,
                    length: usize,
                ) -> PyResult<Bound<'py, PyBytes>> {
                    let info = info.as_ref().map(Buf::as_slice).unwrap_or_default();
                    let output = <$inner>::from_prk(self.key.clone())
                        .expand_to_vec(length, info)
                        .map(Zeroizing::new)
                        .or_raise()?;
                    Ok(secret_bytes(py, output))
                }
            }
        }

        #[doc = concat!(
            "One-shot ", $display, ": extract from `ikm` and `salt`, then expand ",
            "`length` bytes bound to `info`."
        )]
        #[pyfunction]
        #[pyo3(signature = (ikm, *, salt = None, info = None, length = 32))]
        pub fn $oneshot<'py>(
            py: Python<'py>,
            ikm: Buf<'py>,
            salt: Option<Buf<'py>>,
            info: Option<Buf<'py>>,
            length: usize,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let salt = salt.as_ref().map(Buf::as_slice);
            let info = info.as_ref().map(Buf::as_slice).unwrap_or_default();
            let output = <$inner>::extract_and_expand_to_vec(length, salt, ikm.as_slice(), info)
                .map(Zeroizing::new)
                .or_raise()?;
            Ok(secret_bytes(py, output))
        }
    };
}

hkdf_class! {
    /// An HKDF-SHA-256 (RFC 5869) pseudorandom key, ready to expand.
    ///
    /// Create it with `extract()`, or from an existing 32-byte PRK.
    HkdfSha256, dryoc::hkdf::HkdfSha256, "HkdfSha256",
    prk: CRYPTO_KDF_HKDF_SHA256_KEYBYTES, max: CRYPTO_KDF_HKDF_SHA256_BYTES_MAX,
    oneshot: hkdf_sha256, "HKDF-SHA-256"
}

hkdf_class! {
    /// An HKDF-SHA-512 (RFC 5869) pseudorandom key, ready to expand.
    ///
    /// Create it with `extract()`, or from an existing 64-byte PRK.
    HkdfSha512, dryoc::hkdf::HkdfSha512, "HkdfSha512",
    prk: CRYPTO_KDF_HKDF_SHA512_KEYBYTES, max: CRYPTO_KDF_HKDF_SHA512_BYTES_MAX,
    oneshot: hkdf_sha512, "HKDF-SHA-512"
}
