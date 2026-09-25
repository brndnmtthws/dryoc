//! `dryoc.kx`: libsodium's `crypto_kx` key exchange.

use dryoc::kx::{SessionKey, StackSession};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyIterator, PyTuple};

use crate::public_box::{KeyPair, PublicKey};
use crate::util::OrRaise;

/// A pair of session keys from `client_session_keys` or
/// `server_session_keys`.
///
/// Decrypt what the peer sends with `rx` and encrypt what you send with `tx`;
/// `rx, tx = keys` unpacks both. The keys are wiped when the object is freed,
/// compare in constant time, are not hashable, and never appear in the repr.
#[pyclass(frozen, name = "SessionKeys", module = "dryoc.kx")]
pub struct SessionKeys {
    rx: SessionKey,
    tx: SessionKey,
}

impl From<StackSession> for SessionKeys {
    fn from(session: StackSession) -> Self {
        let (rx, tx) = session.into_parts();
        Self { rx, tx }
    }
}

#[pymethods]
impl SessionKeys {
    /// Session keys are secrets and are not hashable.
    #[classattr]
    const __hash__: Option<Py<PyAny>> = None;

    /// Key for receiving (decrypting) data from the peer. Handle it as a
    /// secret.
    #[getter]
    fn rx<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.rx.as_ref())
    }

    /// Key for transmitting (encrypting) data to the peer. Handle it as a
    /// secret.
    #[getter]
    fn tx<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.tx.as_ref())
    }

    /// Iterates over `(rx, tx)`, so the keys unpack like a pair.
    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyIterator>> {
        PyTuple::new(py, [self.rx(py), self.tx(py)])?.try_iter()
    }

    /// Compares both keys in constant time.
    fn __eq__(&self, other: &Bound<'_, Self>) -> bool {
        use subtle::ConstantTimeEq;
        let other = other.get();
        let rx: &[u8] = self.rx.as_ref();
        let tx: &[u8] = self.tx.as_ref();
        bool::from(rx.ct_eq(other.rx.as_ref()) & tx.ct_eq(other.tx.as_ref()))
    }

    fn __repr__(&self) -> &'static str {
        "SessionKeys(rx=<redacted>, tx=<redacted>)"
    }
}

/// Computes the client's session keys for talking to the server with
/// `server_public_key`.
///
/// Returns `SessionKeys`: decrypt with `rx`, encrypt with `tx`. The server's
/// `tx` equals the client's `rx` and vice versa. Raises `InvalidInputError` if
/// `server_public_key` is a low-order point.
#[pyfunction]
pub fn client_session_keys(
    client: &Bound<'_, KeyPair>,
    server_public_key: &Bound<'_, PublicKey>,
) -> PyResult<SessionKeys> {
    StackSession::new_client_with_defaults(&client.get().pair, &server_public_key.get().key)
        .map(SessionKeys::from)
        .or_raise()
}

/// Computes the server's session keys for talking to the client with
/// `client_public_key`.
///
/// Returns `SessionKeys`: decrypt with `rx`, encrypt with `tx`. Raises
/// `InvalidInputError` if `client_public_key` is a low-order point.
#[pyfunction]
pub fn server_session_keys(
    server: &Bound<'_, KeyPair>,
    client_public_key: &Bound<'_, PublicKey>,
) -> PyResult<SessionKeys> {
    StackSession::new_server_with_defaults(&server.get().pair, &client_public_key.get().key)
        .map(SessionKeys::from)
        .or_raise()
}
