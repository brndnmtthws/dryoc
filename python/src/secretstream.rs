//! `dryoc.secretstream`: libsodium's `crypto_secretstream_xchacha20poly1305`.

use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
};
use dryoc::dryocstream::{DryocStream, Header, Pull, Push, Tag};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyType};
use zeroize::Zeroizing;

use crate::util::{
    Buf, CryptoError, DryocError, InvalidInputError, Locked, OrRaise, fixed, maybe_detach,
    opt_slice, python_type, secret_bytes, secret_key_class,
};

secret_key_class! {
    /// A secret key for an encrypted stream.
    Key, "Key", "dryoc.secretstream", SIZE = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    "secretstream key" {}
}

static TAG: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn to_tag(bits: u8) -> PyResult<Tag> {
    Tag::from_bits(bits).ok_or_else(|| {
        InvalidInputError::new_err(format!(
            "invalid secretstream tag {bits:#04x}: use a dryoc.secretstream.Tag member"
        ))
    })
}

fn tag_object<'py>(py: Python<'py>, tag: Tag) -> PyResult<Bound<'py, PyAny>> {
    python_type(py, &TAG, "dryoc._types", "Tag")?.call1((tag.bits(),))
}

fn closed() -> PyErr {
    DryocError::new_err("the stream is closed")
}

/// Encrypts an ordered sequence of messages.
///
/// Send `header` to the receiver before the ciphertexts. Mark the last message
/// with `Tag.FINAL`; after it, the encryptor refuses further messages. Used as
/// a context manager, it wipes its state on exit and raises `DryocError` if the
/// block finished without a `Tag.FINAL` message.
#[pyclass(frozen, name = "Encryptor", module = "dryoc.secretstream")]
pub struct Encryptor {
    state: Locked<StreamState<Push>>,
    header: Header,
}

/// A stream's state (`None` once closed, which wipes it) and whether its
/// `Tag.FINAL` message has been processed.
struct StreamState<M> {
    stream: Option<DryocStream<M>>,
    finished: bool,
}

impl<M> StreamState<M> {
    fn new(stream: DryocStream<M>) -> Locked<Self> {
        Locked::new(Self {
            stream: Some(stream),
            finished: false,
        })
    }

    fn describe(&self) -> &'static str {
        if self.finished {
            "finished"
        } else if self.stream.is_none() {
            "closed"
        } else {
            "open"
        }
    }

    /// Wipes the state (a no-op if already closed), returning whether the
    /// stream never reached `Tag.FINAL`. Whether it was closed before does not
    /// matter: an early `close()` inside a `with` block must not hide a
    /// truncated stream from `__exit__`.
    fn close(&mut self) -> bool {
        self.stream = None;
        !self.finished
    }
}

impl StreamState<Push> {
    fn stream(&mut self) -> PyResult<&mut DryocStream<Push>> {
        if self.finished {
            return Err(DryocError::new_err(
                "the stream is finished: no messages may follow Tag.FINAL",
            ));
        }
        self.stream.as_mut().ok_or_else(closed)
    }
}

impl StreamState<Pull> {
    fn stream(&mut self) -> PyResult<&mut DryocStream<Pull>> {
        if self.finished {
            return Err(CryptoError::new_err(
                "unexpected data after the Tag.FINAL message",
            ));
        }
        self.stream.as_mut().ok_or_else(closed)
    }
}

#[pymethods]
impl Encryptor {
    /// Length of the stream header in bytes.
    #[classattr]
    const HEADER_SIZE: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
    /// Bytes each ciphertext adds to its message.
    #[classattr]
    const OVERHEAD: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /// Starts a new stream under `key` with a fresh random header.
    #[new]
    fn py_new(key: &Bound<'_, Key>) -> Self {
        let (stream, header) = DryocStream::init_push(&key.get().key);
        Self {
            state: StreamState::new(stream),
            header,
        }
    }

    /// The public stream header. The receiver needs it to decrypt.
    #[getter]
    fn header<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.header.as_ref())
    }

    /// Whether a `Tag.FINAL` message has been pushed.
    #[getter]
    fn finished(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.state.lock(py)?.finished)
    }

    /// Encrypts the next `message`, returning its ciphertext.
    ///
    /// `tag` marks the message; `Tag.FINAL` ends the stream. `associated_data`
    /// is authenticated but not encrypted, and must be passed again to `pull`.
    #[pyo3(signature = (message, *, tag = 0, associated_data = None))]
    fn push<'py>(
        &self,
        py: Python<'py>,
        message: Buf<'py>,
        tag: u8,
        associated_data: Option<Buf<'py>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let tag = to_tag(tag)?;
        let mut state = self.state.lock(py)?;
        let stream = state.stream()?;
        let message = message.as_slice();
        let aad = opt_slice(&associated_data);
        let ciphertext = maybe_detach(py, message.len(), || {
            stream.push_to_vec(&message, aad.as_ref(), tag)
        })
        .or_raise()?;
        if tag == Tag::FINAL {
            state.finished = true;
        }
        Ok(PyBytes::new(py, &ciphertext))
    }

    /// Derives a new key for the following messages without sending a
    /// message. The receiver must call `rekey()` at the same point.
    fn rekey(&self, py: Python<'_>) -> PyResult<()> {
        self.state.lock(py)?.stream()?.rekey();
        Ok(())
    }

    /// Wipes the stream state. Further `push` calls raise `DryocError`.
    ///
    /// Closing never raises, even if no `Tag.FINAL` message was pushed; check
    /// `finished` first, or use the encryptor as a context manager, whose exit
    /// raises for an unfinished stream even after an explicit `close()`.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        self.state.lock(py)?.close();
        Ok(())
    }

    fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    #[pyo3(signature = (exc_type, _exc_value, _traceback))]
    fn __exit__(
        &self,
        py: Python<'_>,
        exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        let unfinished = self.state.lock(py)?.close();
        if exc_type.is_none() && unfinished {
            return Err(DryocError::new_err(
                "the stream was closed without a Tag.FINAL message; the receiver will treat it as \
                 truncated",
            ));
        }
        Ok(false)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("Encryptor(<{}>)", self.state.lock(py)?.describe()))
    }
}

/// Decrypts and authenticates a stream produced by `Encryptor`.
///
/// Messages must be pulled in the order they were pushed; a modified,
/// reordered, duplicated or dropped message raises `CryptoError`. Truncation
/// is only detectable through `Tag.FINAL`: check `finished`, or use the
/// decryptor as a context manager, which wipes its state on exit and raises
/// `CryptoError` if the block finished before a `Tag.FINAL` message arrived.
#[pyclass(frozen, name = "Decryptor", module = "dryoc.secretstream")]
pub struct Decryptor {
    state: Locked<StreamState<Pull>>,
}

#[pymethods]
impl Decryptor {
    /// Length of the stream header in bytes.
    #[classattr]
    const HEADER_SIZE: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
    /// Bytes each ciphertext adds to its message.
    #[classattr]
    const OVERHEAD: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /// Starts decrypting the stream identified by `header` under `key`.
    #[new]
    fn py_new(key: &Bound<'_, Key>, header: Buf<'_>) -> PyResult<Self> {
        let header: Header = fixed(header.as_slice(), "header")?;
        Ok(Self {
            state: StreamState::new(DryocStream::init_pull(&key.get().key, &header)),
        })
    }

    /// Whether the `Tag.FINAL` message has been pulled.
    #[getter]
    fn finished(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.state.lock(py)?.finished)
    }

    /// Decrypts the next `ciphertext`, returning `(message, tag)`.
    ///
    /// Raises `CryptoError` if the ciphertext is not the next authentic
    /// message of this stream (the stream state is left unchanged), or if it
    /// follows the `Tag.FINAL` message.
    #[pyo3(signature = (ciphertext, *, associated_data = None))]
    fn pull<'py>(
        &self,
        py: Python<'py>,
        ciphertext: Buf<'py>,
        associated_data: Option<Buf<'py>>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyAny>)> {
        let mut state = self.state.lock(py)?;
        let stream = state.stream()?;
        let ciphertext = ciphertext.as_slice();
        let aad = opt_slice(&associated_data);
        let (message, tag) = maybe_detach(py, ciphertext.len(), || {
            stream
                .pull_to_vec(&ciphertext, aad.as_ref())
                .map(|(message, tag)| (Zeroizing::new(message), tag))
        })
        .or_raise()?;
        if tag == Tag::FINAL {
            state.finished = true;
        }
        drop(state);
        Ok((secret_bytes(py, message), tag_object(py, tag)?))
    }

    /// Derives a new key at the point where the sender called `rekey()`.
    fn rekey(&self, py: Python<'_>) -> PyResult<()> {
        self.state.lock(py)?.stream()?.rekey();
        Ok(())
    }

    /// Wipes the stream state. Further `pull` calls raise `DryocError`.
    ///
    /// Closing never raises, even before the `Tag.FINAL` message arrived; the
    /// caller must then check `finished` to detect truncation. Used as a
    /// context manager, the decryptor's exit raises `CryptoError` for an
    /// unfinished stream even after an explicit `close()`.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        self.state.lock(py)?.close();
        Ok(())
    }

    fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    #[pyo3(signature = (exc_type, _exc_value, _traceback))]
    fn __exit__(
        &self,
        py: Python<'_>,
        exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        let unfinished = self.state.lock(py)?.close();
        if exc_type.is_none() && unfinished {
            return Err(CryptoError::new_err(
                "the stream ended without a Tag.FINAL message; it may have been truncated",
            ));
        }
        Ok(false)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("Decryptor(<{}>)", self.state.lock(py)?.describe()))
    }
}
