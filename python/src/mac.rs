//! `dryoc.mac`: HMAC-SHA-2 and Poly1305 message authentication.

use dryoc::constants::{
    CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA256_KEYBYTES, CRYPTO_AUTH_HMACSHA512_BYTES,
    CRYPTO_AUTH_HMACSHA512_KEYBYTES, CRYPTO_AUTH_HMACSHA512256_BYTES,
    CRYPTO_AUTH_HMACSHA512256_KEYBYTES, CRYPTO_ONETIMEAUTH_BYTES, CRYPTO_ONETIMEAUTH_KEYBYTES,
};
use dryoc::types::{NewByteArray, StackByteArray};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use subtle::ConstantTimeEq;

use crate::util::{Buf, CryptoError, DryocError, Locked, fixed, maybe_detach};

/// A MAC that is absorbing (`running`) or finalized (`tag`).
struct MacState<Inner, const TAG_BYTES: usize> {
    running: Option<Inner>,
    tag: Option<StackByteArray<TAG_BYTES>>,
}

fn finished() -> PyErr {
    DryocError::new_err(
        "the MAC is already finalized; create a new object to authenticate more data",
    )
}

/// Defines a single-use `hmac`-style authenticator. `digest()`, `hexdigest()`
/// and `verify()` finalize it; further `update()` calls raise `DryocError`.
macro_rules! mac_class {
    (
        $(#[$meta:meta])*
        $rust:ident, $inner:ty, $name:literal, $display:literal,
        key: $key_bytes:expr, tag: $tag_bytes:expr, block: $block:expr,
        update: |$state:ident, $data:ident| $update:expr,
        oneshot: $oneshot:ident
    ) => {
        $(#[$meta])*
        #[pyclass(frozen, name = $name, module = "dryoc.mac")]
        pub struct $rust {
            state: Locked<MacState<$inner, { $tag_bytes }>>,
        }

        impl $rust {
            fn absorb(&self, py: Python<'_>, data: &[u8]) -> PyResult<()> {
                let mut guard = self.state.lock(py)?;
                let $state = guard.running.as_mut().ok_or_else(finished)?;
                let $data = data;
                maybe_detach(py, data.len(), || $update);
                Ok(())
            }

            fn finish(&self, py: Python<'_>) -> PyResult<StackByteArray<{ $tag_bytes }>> {
                let mut guard = self.state.lock(py)?;
                if let Some(state) = guard.running.take() {
                    guard.tag = Some(state.finalize());
                }
                Ok(guard.tag.clone().expect("a finalized MAC keeps its tag"))
            }
        }

        #[pymethods]
        impl $rust {
            /// Length of the key in bytes.
            #[classattr]
            const KEY_SIZE: usize = $key_bytes;

            /// Length of the tag in bytes.
            #[classattr]
            #[pyo3(name = "digest_size")]
            const DIGEST_SIZE: usize = $tag_bytes;

            /// Internal block length in bytes.
            #[classattr]
            #[pyo3(name = "block_size")]
            const BLOCK_SIZE: usize = $block;

            /// The algorithm's name.
            #[classattr]
            #[pyo3(name = "name")]
            const NAME: &'static str = $display;

            /// Returns a new random key.
            #[classmethod]
            fn generate_key<'py>(_cls: &Bound<'py, PyType>, py: Python<'py>) -> Bound<'py, PyBytes> {
                let key = StackByteArray::<{ $key_bytes }>::generate();
                PyBytes::new(py, key.as_ref())
            }

            /// Starts authenticating under `key`, optionally absorbing `data`.
            #[new]
            #[pyo3(signature = (key, data = None))]
            fn py_new(py: Python<'_>, key: Buf<'_>, data: Option<Buf<'_>>) -> PyResult<Self> {
                let key: StackByteArray<{ $key_bytes }> = fixed(key.as_slice(), "key")?;
                let mac = Self {
                    state: Locked::new(MacState {
                        running: Some(<$inner>::new(key)),
                        tag: None,
                    }),
                };
                if let Some(data) = data {
                    mac.absorb(py, data.as_slice())?;
                }
                Ok(mac)
            }

            /// Absorbs more `data`. Raises `DryocError` once finalized.
            fn update(&self, py: Python<'_>, data: Buf<'_>) -> PyResult<()> {
                self.absorb(py, data.as_slice())
            }

            /// Finalizes (on the first call) and returns the tag.
            fn digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new(py, self.finish(py)?.as_ref()))
            }

            /// Returns `digest()` as a lowercase hexadecimal string.
            fn hexdigest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
                self.digest(py)?.call_method0("hex")
            }

            /// Finalizes (on the first call) and checks `tag` in constant time.
            ///
            /// Raises `CryptoError` if it does not match.
            fn verify(&self, py: Python<'_>, tag: Buf<'_>) -> PyResult<()> {
                let computed = self.finish(py)?;
                let computed: &[u8] = computed.as_ref();
                if bool::from(computed.ct_eq(tag.as_slice())) {
                    Ok(())
                } else {
                    Err(CryptoError::new_err(concat!($display, " tag verification failed")))
                }
            }

            fn __repr__(&self) -> &'static str {
                concat!("<dryoc.mac.", $name, " object>")
            }
        }

        #[doc = concat!("Returns the ", $display, " tag of `data` under `key`.")]
        #[pyfunction]
        pub fn $oneshot<'py>(
            py: Python<'py>,
            key: Buf<'py>,
            data: Buf<'py>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            $rust::py_new(py, key, Some(data))?.digest(py)
        }
    };
}

mac_class! {
    /// HMAC-SHA-256 (RFC 2104 / FIPS 198-1) with a 32-byte key.
    HmacSha256, dryoc::hmac::HmacSha256, "HmacSha256", "hmac-sha256",
    key: CRYPTO_AUTH_HMACSHA256_KEYBYTES, tag: CRYPTO_AUTH_HMACSHA256_BYTES, block: 64,
    update: |state, data| state.update(data),
    oneshot: hmac_sha256
}

mac_class! {
    /// HMAC-SHA-512 (RFC 2104 / FIPS 198-1) with a 32-byte key.
    HmacSha512, dryoc::hmac::HmacSha512, "HmacSha512", "hmac-sha512",
    key: CRYPTO_AUTH_HMACSHA512_KEYBYTES, tag: CRYPTO_AUTH_HMACSHA512_BYTES, block: 128,
    update: |state, data| state.update(data),
    oneshot: hmac_sha512
}

mac_class! {
    /// HMAC-SHA-512-256: HMAC-SHA-512 truncated to 32 bytes, libsodium's
    /// default `crypto_auth` MAC.
    HmacSha512256, dryoc::hmac::HmacSha512256, "HmacSha512256", "hmac-sha512-256",
    key: CRYPTO_AUTH_HMACSHA512256_KEYBYTES, tag: CRYPTO_AUTH_HMACSHA512256_BYTES, block: 128,
    update: |state, data| state.update(data),
    oneshot: hmac_sha512256
}

mac_class! {
    /// Poly1305 one-time authenticator (libsodium's `crypto_onetimeauth`).
    ///
    /// A Poly1305 key must authenticate only ONE message; reusing it lets an
    /// attacker forge tags. Use an HMAC unless you derive a fresh key per
    /// message.
    Poly1305, dryoc::onetimeauth::OnetimeAuth, "Poly1305", "poly1305",
    key: CRYPTO_ONETIMEAUTH_KEYBYTES, tag: CRYPTO_ONETIMEAUTH_BYTES, block: 16,
    update: |state, data| state.update(&data),
    oneshot: poly1305
}
