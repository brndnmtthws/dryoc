//! Shared argument conversion, error mapping and key-class helpers.

use dryoc::types::StackByteArray;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyTypeError;
use pyo3::intern;
use pyo3::marker::Ungil;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyByteArray, PyBytes, PyMemoryView, PySlice, PyString, PyType};
use zeroize::Zeroizing;

pyo3::import_exception!(dryoc.exceptions, DryocError);
pyo3::import_exception!(dryoc.exceptions, CryptoError);
pyo3::import_exception!(dryoc.exceptions, InvalidInputError);

/// Inputs at least this long are processed with the thread detached from the
/// interpreter (the GIL released), matching `hashlib`'s threshold.
pub(crate) const DETACH_THRESHOLD: usize = 2048;

/// Maps a dryoc error onto the Python exception hierarchy.
pub(crate) fn map_err(error: dryoc::Error) -> PyErr {
    use dryoc::Error;

    let message = error.to_string();
    match error {
        Error::AuthenticationFailed => CryptoError::new_err(message),
        Error::InvalidLength { .. }
        | Error::InvalidValue { .. }
        | Error::InvalidEncoding { .. }
        | Error::InvalidKey { .. }
        | Error::MissingData { .. } => InvalidInputError::new_err(message),
        _ => DryocError::new_err(message),
    }
}

/// `Result` extension converting dryoc errors to Python exceptions.
pub(crate) trait OrRaise<T> {
    fn or_raise(self) -> PyResult<T>;
}

impl<T> OrRaise<T> for Result<T, dryoc::Error> {
    fn or_raise(self) -> PyResult<T> {
        self.map_err(map_err)
    }
}

/// Runs `f` detached from the interpreter when `len` is large enough for the
/// work to outweigh the cost of releasing and reacquiring the GIL.
///
/// Every input the closure reads is either an immutable `bytes` object or a
/// private copy made while attached, so no other thread can mutate it.
pub(crate) fn maybe_detach<T, F>(py: Python<'_>, len: usize, f: F) -> T
where
    F: Ungil + FnOnce() -> T,
    T: Ungil,
{
    if len >= DETACH_THRESHOLD {
        py.detach(f)
    } else {
        f()
    }
}

/// A bytes-like argument.
///
/// Extraction takes the first route that applies:
///
/// 1. `bytes` is immutable and borrowed without copying.
/// 2. An exact `bytearray` is copied once with `PyByteArray::to_vec`, which
///    holds the object's critical section on free-threaded builds. Its own
///    methods (`ba[:] = ...`, `extend`, ...) write under that lock, so the copy
///    is a snapshot of one state rather than a torn mix of bytes from a
///    concurrent write; a buffer export only stops resizing, not writes.
///    Subclasses take the buffer routes because they may override `__buffer__`
///    (PEP 688) and export bytes other than their storage.
/// 3. A buffer with a byte format (`B` or `c`: `memoryview` slices of bytes,
///    `bytearray` subclasses, ...) is copied once through `PyBuffer<u8>`, at
///    any strides.
/// 4. A C-contiguous buffer of any other format (`array.array('I')`,
///    `memoryview.cast('I')`, ctypes arrays, ...) is viewed as bytes with
///    `memoryview.cast('B')` and copied once the same way.
/// 5. Anything `cast` rejects, i.e. a non-C-contiguous buffer of a non-byte
///    format (`memoryview(array.array('I'))[::2]`, a sliced numpy `int32`
///    array, ...) or an empty one with a zero in its shape, is copied through a
///    `bytearray` temporary that is wiped afterwards. PyO3 0.29 offers no safe
///    C-order copy of an untyped buffer (`PyBuffer<T>` only copies formats
///    matching `T`), so this is the one route that needs neither `unsafe` nor
///    refusing the input.
///
/// Every route yields the raw item bytes in C order, as
/// `bytes(memoryview(obj))` does. Copies are taken while attached into a
/// private buffer that is wiped when dropped, so they cannot change while the
/// GIL is released.
///
/// Routes 3 to 5 copy without a lock: the buffer protocol has none, and writes
/// through a `memoryview` (of a `bytearray` or anything else), to an
/// `array.array` or to a numpy array do not take one either. Mutating such a
/// buffer from another thread during a call is the caller's race, as with
/// `hashlib`, and may make the call see a mix of old and new bytes.
pub(crate) enum Buf<'py> {
    Bytes(Bound<'py, PyBytes>),
    Owned(Zeroizing<Vec<u8>>),
}

impl Buf<'_> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Buf::Bytes(bytes) => bytes.as_bytes(),
            Buf::Owned(bytes) => bytes,
        }
    }
}

fn not_bytes_like(obj: &Bound<'_, PyAny>) -> PyErr {
    let name = obj
        .get_type()
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|_| "object".into());
    if obj.is_instance_of::<PyString>() {
        PyTypeError::new_err("expected a bytes-like object, got 'str' (encode it first)")
    } else {
        PyTypeError::new_err(format!("expected a bytes-like object, got '{name}'"))
    }
}

/// Copies a buffer-protocol object (routes 3 to 5 of [`Buf`]) into a
/// wiped-on-drop vector.
fn copy_buffer(obj: &Bound<'_, PyAny>) -> PyResult<Zeroizing<Vec<u8>>> {
    let py = obj.py();
    // Re-exporting through a memoryview fills in the shape and strides that
    // `PyBuffer` requires and some exporters (ctypes) leave out.
    let view = PyMemoryView::from(obj).map_err(|_| not_bytes_like(obj))?;
    // Fails for non-byte formats, and for 0-dimensional buffers (no shape),
    // which are C-contiguous and take the `cast` route instead.
    let bytes = if let Ok(bytes) = PyBuffer::<u8>::get(&view) {
        bytes
    } else if let Ok(cast) = view.call_method1(intern!(py, "cast"), (intern!(py, "B"),)) {
        PyBuffer::<u8>::get(&cast)?
    } else {
        return copy_through_temporary(&view);
    };
    let mut copy = Zeroizing::new(vec![0; bytes.len_bytes()]);
    bytes.copy_to_slice(py, &mut copy)?;
    Ok(copy)
}

/// Copies a buffer of any format and layout in C order through a `bytearray`
/// (route 5 of [`Buf`]), then overwrites the temporary.
fn copy_through_temporary(view: &Bound<'_, PyMemoryView>) -> PyResult<Zeroizing<Vec<u8>>> {
    let py = view.py();
    let temporary = PyByteArray::from(view.as_any())?;
    let copy = Zeroizing::new(temporary.to_vec());
    // Overwrite the temporary in place (same length, so no reallocation).
    let zeros = PyBytes::new_with(py, copy.len(), |_| Ok(()))?;
    temporary.set_item(PySlice::full(py), zeros)?;
    Ok(copy)
}

impl<'a, 'py> FromPyObject<'a, 'py> for Buf<'py> {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = obj.cast::<PyBytes>() {
            return Ok(Buf::Bytes(bytes.to_owned()));
        }
        if let Ok(bytearray) = obj.cast_exact::<PyByteArray>() {
            return Ok(Buf::Owned(Zeroizing::new(bytearray.to_vec())));
        }
        let obj = obj.to_owned();
        if obj.is_instance_of::<PyString>() {
            return Err(not_bytes_like(&obj));
        }
        Ok(Buf::Owned(copy_buffer(&obj)?))
    }
}

/// A password: a `str` (encoded as UTF-8) or any bytes-like object.
pub(crate) struct Password<'py>(Buf<'py>);

impl Password<'_> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<'a, 'py> FromPyObject<'a, 'py> for Password<'py> {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(text) = obj.cast::<PyString>() {
            let utf8 = text.to_str()?;
            return Ok(Password(Buf::Owned(Zeroizing::new(
                utf8.as_bytes().to_vec(),
            ))));
        }
        Ok(Password(obj.extract()?))
    }
}

/// Copies `data` into a fixed-size array, raising `InvalidInputError` with the
/// expected length otherwise.
pub(crate) fn fixed<const N: usize>(data: &[u8], what: &str) -> PyResult<StackByteArray<N>> {
    StackByteArray::<N>::try_from(data).map_err(|_| {
        InvalidInputError::new_err(format!(
            "{what} must be exactly {N} bytes long, got {}",
            data.len()
        ))
    })
}

/// Returns an optional associated-data argument as a slice.
pub(crate) fn opt_slice<'a>(data: &'a Option<Buf<'_>>) -> Option<&'a [u8]> {
    data.as_ref().map(Buf::as_slice)
}

/// Copies secret output into a new `bytes` object; the Rust copy is wiped when
/// the argument is dropped.
pub(crate) fn secret_bytes<'py>(py: Python<'py>, data: Zeroizing<Vec<u8>>) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &data)
}

/// Looks up (once) a class defined in the pure-Python part of the package.
pub(crate) fn python_type<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyType>>,
    module: &str,
    name: &str,
) -> PyResult<&'py Bound<'py, PyType>> {
    cell.import(py, module, name)
}

/// Formats up to 32 bytes of `data` as hex, eliding the rest.
pub(crate) fn short_hex(data: &[u8]) -> String {
    use core::fmt::Write;

    const SHOWN: usize = 32;
    let mut out = String::with_capacity(2 * SHOWN.min(data.len()) + 3);
    for byte in data.iter().take(SHOWN) {
        let _ = write!(out, "{byte:02x}");
    }
    if data.len() > SHOWN {
        out.push_str("...");
    }
    out
}

/// Defines a frozen class holding one fixed-size secret, with constant-time
/// equality, no hashing, a redacted repr, and explicit `bytes()` export.
macro_rules! secret_key_class {
    (
        $(#[$meta:meta])*
        $rust:ident, $name:literal, $module:literal, $size:ident = $len:expr, $what:literal
        { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[pyo3::pyclass(frozen, name = $name, module = $module)]
        pub struct $rust {
            pub(crate) key: dryoc::types::StackByteArray<{ $len }>,
        }

        #[pyo3::pymethods]
        impl $rust {
            /// Length of the key in bytes.
            #[classattr]
            const $size: usize = $len;

            /// Secrets are not hashable.
            #[classattr]
            const __hash__: Option<pyo3::Py<pyo3::PyAny>> = None;

            #[new]
            fn py_new(key: crate::util::Buf<'_>) -> pyo3::PyResult<Self> {
                Ok(Self {
                    key: crate::util::fixed(key.as_slice(), $what)?,
                })
            }

            /// Creates the key from its raw bytes.
            #[classmethod]
            fn from_bytes(
                _cls: &pyo3::Bound<'_, pyo3::types::PyType>,
                key: crate::util::Buf<'_>,
            ) -> pyo3::PyResult<Self> {
                Self::py_new(key)
            }

            /// Generates a new random key.
            #[classmethod]
            fn generate(_cls: &pyo3::Bound<'_, pyo3::types::PyType>) -> Self {
                use dryoc::types::NewByteArray;
                Self {
                    key: dryoc::types::StackByteArray::generate(),
                }
            }

            /// Exports the raw key bytes. Handle the result as a secret.
            fn __bytes__<'py>(
                &self,
                py: pyo3::Python<'py>,
            ) -> pyo3::Bound<'py, pyo3::types::PyBytes> {
                pyo3::types::PyBytes::new(py, self.key.as_ref())
            }

            /// Compares two keys in constant time.
            fn __eq__(&self, other: &pyo3::Bound<'_, Self>) -> bool {
                use subtle::ConstantTimeEq;
                let this: &[u8] = self.key.as_ref();
                let that: &[u8] = other.get().key.as_ref();
                this.ct_eq(that).into()
            }

            fn __repr__(&self) -> String {
                concat!($name, "(<redacted>)").to_string()
            }

            $($body)*
        }
    };
}

/// Defines a frozen class holding one fixed-size public value, with ordinary
/// equality, hashing, and a hex repr.
macro_rules! public_key_class {
    (
        $(#[$meta:meta])*
        $rust:ident, $name:literal, $module:literal, $size:ident = $len:expr, $what:literal
        { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[pyo3::pyclass(frozen, name = $name, module = $module)]
        pub struct $rust {
            pub(crate) key: dryoc::types::StackByteArray<{ $len }>,
        }

        #[pyo3::pymethods]
        impl $rust {
            /// Length of the key in bytes.
            #[classattr]
            const $size: usize = $len;

            #[new]
            fn py_new(key: crate::util::Buf<'_>) -> pyo3::PyResult<Self> {
                Ok(Self {
                    key: crate::util::fixed(key.as_slice(), $what)?,
                })
            }

            /// Creates the key from its raw bytes.
            #[classmethod]
            fn from_bytes(
                _cls: &pyo3::Bound<'_, pyo3::types::PyType>,
                key: crate::util::Buf<'_>,
            ) -> pyo3::PyResult<Self> {
                Self::py_new(key)
            }

            /// Returns the raw key bytes.
            fn __bytes__<'py>(
                &self,
                py: pyo3::Python<'py>,
            ) -> pyo3::Bound<'py, pyo3::types::PyBytes> {
                pyo3::types::PyBytes::new(py, self.key.as_ref())
            }

            fn __eq__(&self, other: &pyo3::Bound<'_, Self>) -> bool {
                self.key == other.get().key
            }

            fn __hash__(&self) -> u64 {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                let bytes: &[u8] = self.key.as_ref();
                bytes.hash(&mut hasher);
                hasher.finish()
            }

            fn __repr__(&self) -> String {
                format!(
                    concat!($name, "('{}')"),
                    crate::util::short_hex(self.key.as_ref())
                )
            }

            $($body)*
        }
    };
}

pub(crate) use public_key_class;
pub(crate) use secret_key_class;

static ENCRYPTED_MESSAGE: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// Builds a `dryoc.EncryptedMessage(ciphertext, nonce)` named tuple.
pub(crate) fn encrypted_message<'py>(
    py: Python<'py>,
    nonce: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyAny>> {
    python_type(py, &ENCRYPTED_MESSAGE, "dryoc._types", "EncryptedMessage")?
        .call1((PyBytes::new(py, ciphertext), PyBytes::new(py, nonce)))
}

/// Mutable state of a Python object.
///
/// Calls on one object from several threads are serialized, as `hashlib`
/// does, instead of failing with PyO3's "Already borrowed" error. Waiting for
/// the lock detaches from the interpreter, so a thread that holds it while
/// detached (hashing a large buffer) cannot deadlock with one that holds the
/// GIL.
pub(crate) struct Locked<T>(std::sync::Mutex<T>);

impl<T> Locked<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    pub(crate) fn lock(&self, py: Python<'_>) -> PyResult<std::sync::MutexGuard<'_, T>> {
        use pyo3::sync::MutexExt;

        self.0.lock_py_attached(py).map_err(|_| {
            DryocError::new_err("this object is unusable after an earlier internal error")
        })
    }
}
