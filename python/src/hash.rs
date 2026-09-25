//! `dryoc.hash`: SHA-2, SHA-3, BLAKE2b and SHAKE/TurboSHAKE following the
//! `hashlib` protocol, plus one-shot functions.

use dryoc::classic::crypto_generichash::{
    GenericHashState, crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update,
};
use dryoc::constants::{
    CRYPTO_GENERICHASH_BYTES, CRYPTO_GENERICHASH_BYTES_MAX, CRYPTO_GENERICHASH_KEYBYTES_MAX,
    CRYPTO_XOF_SHAKE128_BLOCKBYTES, CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD,
    CRYPTO_XOF_SHAKE256_BLOCKBYTES, CRYPTO_XOF_SHAKE256_DOMAIN_STANDARD,
    CRYPTO_XOF_TURBOSHAKE128_BLOCKBYTES, CRYPTO_XOF_TURBOSHAKE128_DOMAIN_STANDARD,
    CRYPTO_XOF_TURBOSHAKE256_BLOCKBYTES, CRYPTO_XOF_TURBOSHAKE256_DOMAIN_STANDARD,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

use crate::util::{Buf, InvalidInputError, Locked, OrRaise, maybe_detach};

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0xf)] as char);
    }
    out
}

/// Defines a fixed-output `hashlib`-style hasher over a Clone dryoc hasher.
macro_rules! fixed_hasher {
    (
        $(#[$meta:meta])*
        $rust:ident, $inner:path, $name:literal, $hashlib_name:literal,
        digest: $digest:expr, block: $block:expr,
        oneshot: $oneshot:ident
    ) => {
        $(#[$meta])*
        #[pyclass(frozen, name = $name, module = "dryoc.hash")]
        pub struct $rust {
            state: Locked<$inner>,
        }

        #[pymethods]
        impl $rust {
            /// Digest length in bytes.
            #[classattr]
            #[pyo3(name = "digest_size")]
            const DIGEST_SIZE: usize = $digest;

            /// Internal block length in bytes.
            #[classattr]
            #[pyo3(name = "block_size")]
            const BLOCK_SIZE: usize = $block;

            /// The algorithm's `hashlib` name.
            #[classattr]
            #[pyo3(name = "name")]
            const NAME: &'static str = $hashlib_name;

            /// Starts a new hash, optionally absorbing `data`.
            #[new]
            #[pyo3(signature = (data = None))]
            fn py_new(py: Python<'_>, data: Option<Buf<'_>>) -> PyResult<Self> {
                let hasher = Self {
                    state: Locked::new(<$inner>::new()),
                };
                if let Some(data) = data {
                    hasher.absorb(py, data.as_slice())?;
                }
                Ok(hasher)
            }

            /// Absorbs more `data`.
            fn update(&self, py: Python<'_>, data: Buf<'_>) -> PyResult<()> {
                self.absorb(py, data.as_slice())
            }

            /// Returns the digest of everything absorbed so far. The hasher can
            /// keep absorbing afterwards.
            fn digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new(py, &self.snapshot(py)?.finalize_to_vec()))
            }

            /// Returns `digest()` as a lowercase hexadecimal string.
            fn hexdigest(&self, py: Python<'_>) -> PyResult<String> {
                Ok(to_hex(&self.snapshot(py)?.finalize_to_vec()))
            }

            /// Returns an independent copy of the hasher.
            fn copy(&self, py: Python<'_>) -> PyResult<Self> {
                Ok(Self {
                    state: Locked::new(self.snapshot(py)?),
                })
            }

            fn __repr__(&self) -> &'static str {
                concat!("<dryoc.hash.", $name, " object>")
            }
        }

        impl $rust {
            fn absorb(&self, py: Python<'_>, data: &[u8]) -> PyResult<()> {
                let mut state = self.state.lock(py)?;
                let state = &mut *state;
                maybe_detach(py, data.len(), || state.update(data));
                Ok(())
            }

            fn snapshot(&self, py: Python<'_>) -> PyResult<$inner> {
                Ok(self.state.lock(py)?.clone())
            }
        }

        #[doc = concat!("Returns the ", $hashlib_name, " digest of `data`.")]
        #[pyfunction]
        pub fn $oneshot<'py>(py: Python<'py>, data: Buf<'py>) -> Bound<'py, PyBytes> {
            let data = data.as_slice();
            let digest = maybe_detach(py, data.len(), || <$inner>::compute_to_vec(data));
            PyBytes::new(py, &digest)
        }
    };
}

fixed_hasher! {
    /// Incremental SHA-256 (FIPS 180-4) with the `hashlib` interface.
    Sha256, dryoc::sha256::Sha256, "Sha256", "sha256",
    digest: dryoc::constants::CRYPTO_HASH_SHA256_BYTES, block: 64,
    oneshot: sha256
}

fixed_hasher! {
    /// Incremental SHA-512 (FIPS 180-4) with the `hashlib` interface.
    Sha512, dryoc::sha512::Sha512, "Sha512", "sha512",
    digest: dryoc::constants::CRYPTO_HASH_SHA512_BYTES, block: 128,
    oneshot: sha512
}

fixed_hasher! {
    /// Incremental SHA3-256 (FIPS 202) with the `hashlib` interface.
    Sha3_256, dryoc::sha3::Sha3256, "Sha3_256", "sha3_256",
    digest: dryoc::constants::CRYPTO_HASH_SHA3256_BYTES, block: 136,
    oneshot: sha3_256
}

fixed_hasher! {
    /// Incremental SHA3-512 (FIPS 202) with the `hashlib` interface.
    Sha3_512, dryoc::sha3::Sha3512, "Sha3_512", "sha3_512",
    digest: dryoc::constants::CRYPTO_HASH_SHA3512_BYTES, block: 72,
    oneshot: sha3_512
}

const BLAKE2B_BLOCK: usize = 128;

// The signatures spell the default digest size as a literal so it shows in
// `help()` and the text signature.
const _: () = assert!(CRYPTO_GENERICHASH_BYTES == 32);

fn blake2b_init(digest_size: usize, key: Option<&[u8]>) -> PyResult<GenericHashState> {
    if !(1..=CRYPTO_GENERICHASH_BYTES_MAX).contains(&digest_size) {
        return Err(InvalidInputError::new_err(format!(
            "digest_size must be between 1 and {CRYPTO_GENERICHASH_BYTES_MAX}, got {digest_size}"
        )));
    }
    if let Some(key) = key
        && key.len() > CRYPTO_GENERICHASH_KEYBYTES_MAX
    {
        return Err(InvalidInputError::new_err(format!(
            "key must be at most {CRYPTO_GENERICHASH_KEYBYTES_MAX} bytes long, got {}",
            key.len()
        )));
    }
    crypto_generichash_init(key, digest_size).or_raise()
}

/// Incremental BLAKE2b (libsodium's `crypto_generichash`) with the `hashlib`
/// interface.
///
/// `digest_size` defaults to 32 bytes as in libsodium, not 64 as in
/// `hashlib.blake2b`. An optional `key` (up to 64 bytes, 32 recommended) makes
/// it a MAC.
#[pyclass(frozen, name = "Blake2b", module = "dryoc.hash")]
pub struct Blake2b {
    state: Locked<GenericHashState>,
    digest_size: usize,
}

impl Blake2b {
    fn absorb(&self, py: Python<'_>, data: &[u8]) -> PyResult<()> {
        let mut state = self.state.lock(py)?;
        let state = &mut *state;
        maybe_detach(py, data.len(), || crypto_generichash_update(state, data));
        Ok(())
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<GenericHashState> {
        Ok(self.state.lock(py)?.clone())
    }

    fn finish(&self, py: Python<'_>) -> PyResult<Zeroizing<Vec<u8>>> {
        let mut digest = Zeroizing::new(vec![0u8; self.digest_size]);
        crypto_generichash_final(self.snapshot(py)?, &mut digest).or_raise()?;
        Ok(digest)
    }
}

#[pymethods]
impl Blake2b {
    /// Internal block length in bytes.
    #[classattr]
    #[pyo3(name = "block_size")]
    const BLOCK_SIZE: usize = BLAKE2B_BLOCK;
    /// Largest supported `digest_size`.
    #[classattr]
    const MAX_DIGEST_SIZE: usize = CRYPTO_GENERICHASH_BYTES_MAX;
    /// Largest supported key length.
    #[classattr]
    const MAX_KEY_SIZE: usize = CRYPTO_GENERICHASH_KEYBYTES_MAX;
    /// The algorithm's `hashlib` name.
    #[classattr]
    #[pyo3(name = "name")]
    const NAME: &'static str = "blake2b";

    /// Starts a new hash, optionally absorbing `data`.
    #[new]
    #[pyo3(signature = (data = None, *, digest_size = 32, key = None))]
    fn py_new(
        py: Python<'_>,
        data: Option<Buf<'_>>,
        digest_size: usize,
        key: Option<Buf<'_>>,
    ) -> PyResult<Self> {
        let hasher = Self {
            state: Locked::new(blake2b_init(digest_size, key.as_ref().map(Buf::as_slice))?),
            digest_size,
        };
        if let Some(data) = data {
            hasher.absorb(py, data.as_slice())?;
        }
        Ok(hasher)
    }

    /// Digest length in bytes.
    #[getter]
    fn digest_size(&self) -> usize {
        self.digest_size
    }

    /// Absorbs more `data`.
    fn update(&self, py: Python<'_>, data: Buf<'_>) -> PyResult<()> {
        self.absorb(py, data.as_slice())
    }

    /// Returns the digest of everything absorbed so far. The hasher can keep
    /// absorbing afterwards.
    fn digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.finish(py)?))
    }

    /// Returns `digest()` as a lowercase hexadecimal string.
    fn hexdigest(&self, py: Python<'_>) -> PyResult<String> {
        Ok(to_hex(&self.finish(py)?))
    }

    /// Returns an independent copy of the hasher.
    fn copy(&self, py: Python<'_>) -> PyResult<Self> {
        Ok(Self {
            state: Locked::new(self.snapshot(py)?),
            digest_size: self.digest_size,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "<dryoc.hash.Blake2b object, digest_size={}>",
            self.digest_size
        )
    }
}

/// Returns the BLAKE2b digest of `data` (libsodium's `crypto_generichash`).
///
/// `digest_size` defaults to 32 bytes; `key` (up to 64 bytes) makes it a MAC.
#[pyfunction]
#[pyo3(signature = (data, *, digest_size = 32, key = None))]
pub fn blake2b<'py>(
    py: Python<'py>,
    data: Buf<'py>,
    digest_size: usize,
    key: Option<Buf<'py>>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate the parameters with the same messages as the class.
    let key = key.as_ref().map(Buf::as_slice);
    blake2b_init(digest_size, key)?;
    let data = data.as_slice();
    let mut digest = Zeroizing::new(vec![0u8; digest_size]);
    let output = &mut *digest;
    maybe_detach(py, data.len(), || crypto_generichash(output, data, key)).or_raise()?;
    Ok(PyBytes::new(py, &digest))
}

/// Allocates `length` bytes on the Python heap (raising `MemoryError` rather
/// than aborting when that fails) and fills them with `fill`.
fn new_filled<'py, F>(py: Python<'py>, length: usize, fill: F) -> PyResult<Bound<'py, PyBytes>>
where
    F: FnOnce(&mut [u8]) + Send,
{
    PyBytes::new_with(py, length, |buffer| {
        maybe_detach(py, length, || fill(buffer));
        Ok(())
    })
}

/// Defines a `hashlib`-style extendable-output function and its reader.
macro_rules! xof_hasher {
    (
        $(#[$meta:meta])*
        $rust:ident, $inner:path, $reader:ident, $inner_reader:path,
        $name:literal, $reader_name:literal, $hashlib_name:literal,
        block: $block:expr,
        oneshot: $oneshot:ident,
        domain: $domain:expr
    ) => {
        $(#[$meta])*
        #[pyclass(frozen, name = $name, module = "dryoc.hash")]
        pub struct $rust {
            state: Locked<$inner>,
        }

        impl $rust {
            fn absorb(&self, py: Python<'_>, data: &[u8]) -> PyResult<()> {
                let mut state = self.state.lock(py)?;
                let state = &mut *state;
                maybe_detach(py, data.len(), || state.update(data));
                Ok(())
            }

            fn snapshot(&self, py: Python<'_>) -> PyResult<$inner> {
                Ok(self.state.lock(py)?.clone())
            }
        }

        #[pymethods]
        impl $rust {
            /// Always 0: the output length is chosen per call.
            #[classattr]
            #[pyo3(name = "digest_size")]
            const DIGEST_SIZE: usize = 0;

            /// Sponge rate in bytes.
            #[classattr]
            #[pyo3(name = "block_size")]
            const BLOCK_SIZE: usize = $block;

            /// The algorithm's name.
            #[classattr]
            #[pyo3(name = "name")]
            const NAME: &'static str = $hashlib_name;

            /// Starts a new hash, optionally absorbing `data`. `domain` is the
            /// domain-separation byte (0x01 to 0x7f); the default is the
            /// standard one, and others give unrelated outputs.
            #[new]
            #[pyo3(signature = (data = None, *, domain = 0x1f))]
            fn py_new(py: Python<'_>, data: Option<Buf<'_>>, domain: u8) -> PyResult<Self> {
                let hasher = Self {
                    state: Locked::new(<$inner>::with_domain(domain).or_raise()?),
                };
                if let Some(data) = data {
                    hasher.absorb(py, data.as_slice())?;
                }
                Ok(hasher)
            }

            /// Absorbs more `data`.
            fn update(&self, py: Python<'_>, data: Buf<'_>) -> PyResult<()> {
                self.absorb(py, data.as_slice())
            }

            /// Returns the first `length` output bytes for everything absorbed so
            /// far. The hasher can keep absorbing afterwards.
            fn digest<'py>(&self, py: Python<'py>, length: usize) -> PyResult<Bound<'py, PyBytes>> {
                let mut reader = self.snapshot(py)?.finalize();
                new_filled(py, length, move |buffer| reader.squeeze(buffer))
            }

            /// Returns `digest(length)` as a lowercase hexadecimal string.
            fn hexdigest<'py>(&self, py: Python<'py>, length: usize) -> PyResult<Bound<'py, PyAny>> {
                self.digest(py, length)?.call_method0("hex")
            }

            /// Returns an independent copy of the hasher.
            fn copy(&self, py: Python<'_>) -> PyResult<Self> {
                Ok(Self {
                    state: Locked::new(self.snapshot(py)?),
                })
            }

            /// Returns a reader that streams the output for everything absorbed
            /// so far: successive `read` calls continue the same output. The
            /// hasher can keep absorbing afterwards.
            fn reader(&self, py: Python<'_>) -> PyResult<$reader> {
                Ok($reader {
                    state: Locked::new(self.snapshot(py)?.finalize()),
                })
            }

            fn __repr__(&self) -> &'static str {
                concat!("<dryoc.hash.", $name, " object>")
            }
        }

        #[doc = concat!("Streaming output of a finished `", $name, "`.")]
        #[pyclass(frozen, name = $reader_name, module = "dryoc.hash")]
        pub struct $reader {
            state: Locked<$inner_reader>,
        }

        #[pymethods]
        impl $reader {
            /// Returns the next `length` output bytes.
            fn read<'py>(&self, py: Python<'py>, length: usize) -> PyResult<Bound<'py, PyBytes>> {
                let mut state = self.state.lock(py)?;
                let state = &mut *state;
                new_filled(py, length, move |buffer| state.squeeze(buffer))
            }

            fn __repr__(&self) -> &'static str {
                concat!("<dryoc.hash.", $reader_name, " object>")
            }
        }

        // The signatures spell the standard domain as a literal so it shows in
        // `help()` and the text signature.
        const _: () = assert!($domain == 0x1f);

        xof_hasher!(@oneshot $oneshot, $inner, $hashlib_name, $domain);
    };

    (@oneshot $oneshot:ident, $inner:path, $hashlib_name:literal, $standard:expr) => {
        #[doc = concat!(
            "Returns `length` bytes of ", $hashlib_name, " output for `data` with the ",
            "domain-separation byte `domain`."
        )]
        #[pyfunction]
        #[pyo3(signature = (data, length, *, domain = 0x1f))]
        pub fn $oneshot<'py>(
            py: Python<'py>,
            data: Buf<'py>,
            length: usize,
            domain: u8,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let mut state = <$inner>::with_domain(domain).or_raise()?;
            let data = data.as_slice();
            maybe_detach(py, data.len(), || state.update(data));
            let mut reader = state.finalize();
            new_filled(py, length, move |buffer| reader.squeeze(buffer))
        }
    };
}

xof_hasher! {
    /// Incremental SHAKE128 (FIPS 202), like `hashlib.shake_128`.
    Shake128, dryoc::xof::Shake128, Shake128Reader, dryoc::xof::Shake128Reader,
    "Shake128", "Shake128Reader", "shake_128",
    block: CRYPTO_XOF_SHAKE128_BLOCKBYTES,
    oneshot: shake128,
    domain: CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD
}

xof_hasher! {
    /// Incremental SHAKE256 (FIPS 202), like `hashlib.shake_256`.
    Shake256, dryoc::xof::Shake256, Shake256Reader, dryoc::xof::Shake256Reader,
    "Shake256", "Shake256Reader", "shake_256",
    block: CRYPTO_XOF_SHAKE256_BLOCKBYTES,
    oneshot: shake256,
    domain: CRYPTO_XOF_SHAKE256_DOMAIN_STANDARD
}

xof_hasher! {
    /// Incremental TurboSHAKE128 (RFC 9861): SHAKE128's sponge with 12 rounds.
    TurboShake128, dryoc::xof::TurboShake128, TurboShake128Reader,
    dryoc::xof::TurboShake128Reader,
    "TurboShake128", "TurboShake128Reader", "turboshake128",
    block: CRYPTO_XOF_TURBOSHAKE128_BLOCKBYTES,
    oneshot: turboshake128,
    domain: CRYPTO_XOF_TURBOSHAKE128_DOMAIN_STANDARD
}

xof_hasher! {
    /// Incremental TurboSHAKE256 (RFC 9861): SHAKE256's sponge with 12 rounds.
    TurboShake256, dryoc::xof::TurboShake256, TurboShake256Reader,
    dryoc::xof::TurboShake256Reader,
    "TurboShake256", "TurboShake256Reader", "turboshake256",
    block: CRYPTO_XOF_TURBOSHAKE256_BLOCKBYTES,
    oneshot: turboshake256,
    domain: CRYPTO_XOF_TURBOSHAKE256_DOMAIN_STANDARD
}
