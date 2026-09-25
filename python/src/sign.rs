//! `dryoc.sign`: Ed25519 and Ed25519ph signatures (libsodium's `crypto_sign`).

use dryoc::classic::crypto_sign::{crypto_sign_detached, crypto_sign_verify_detached};
use dryoc::constants::{
    CRYPTO_SIGN_BYTES, CRYPTO_SIGN_PUBLICKEYBYTES, CRYPTO_SIGN_SECRETKEYBYTES,
    CRYPTO_SIGN_SEEDBYTES,
};
use dryoc::sign::{
    IncrementalSigner, PublicKey, SecretKey, Seed, Signature, SigningKeyPair, VecSignedMessage,
};
use dryoc::types::NewByteArray;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};

use crate::util::{
    Buf, CryptoError, DryocError, Locked, OrRaise, fixed, maybe_detach, public_key_class,
};

type StackSigningKeyPair = SigningKeyPair<PublicKey, SecretKey>;

/// Every verification failure, including a malformed signature or public
/// key, is reported as `CryptoError`.
fn verification_failed(error: dryoc::Error) -> PyErr {
    CryptoError::new_err(format!("signature verification failed: {error}"))
}

public_key_class! {
    /// An Ed25519 public key, used to verify signatures.
    VerifyKey, "VerifyKey", "dryoc.sign", SIZE = CRYPTO_SIGN_PUBLICKEYBYTES, "verify key"
    {
        /// Checks a detached Ed25519 `signature` over `message`.
        ///
        /// Raises `CryptoError` if the signature is invalid.
        fn verify(&self, py: Python<'_>, signature: Buf<'_>, message: Buf<'_>) -> PyResult<()> {
            let signature: Signature = fixed(signature.as_slice(), "signature")?;
            let message = message.as_slice();
            maybe_detach(py, message.len(), || {
                crypto_sign_verify_detached(signature.as_ref(), message, self.key.as_ref())
            })
            .map_err(verification_failed)
        }

        /// Checks a combined `signature || message` (libsodium's `crypto_sign`
        /// format) and returns the message.
        ///
        /// Raises `CryptoError` if the signature is invalid.
        fn verify_combined<'py>(
            &self,
            py: Python<'py>,
            signed_message: Buf<'py>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let bytes = signed_message.as_slice();
            let signed = VecSignedMessage::from_bytes(bytes).or_raise()?;
            maybe_detach(py, bytes.len(), || signed.verify(&self.key))
                .map_err(verification_failed)?;
            let (_, message) = signed.into_parts();
            Ok(PyBytes::new(py, &message))
        }
    }
}

/// An Ed25519 signing key.
///
/// Its raw form (`bytes(key)`, 64 bytes) is libsodium's secret key: the
/// 32-byte seed followed by the public key. The repr never shows it.
#[pyclass(frozen, name = "SigningKey", module = "dryoc.sign")]
pub struct SigningKey {
    pair: StackSigningKeyPair,
}

#[pymethods]
impl SigningKey {
    /// Length of a seed in bytes.
    #[classattr]
    const SEED_SIZE: usize = CRYPTO_SIGN_SEEDBYTES;
    /// Length of a signature in bytes.
    #[classattr]
    const SIGNATURE_SIZE: usize = CRYPTO_SIGN_BYTES;
    /// Length of the raw (libsodium) secret key in bytes.
    #[classattr]
    const SIZE: usize = CRYPTO_SIGN_SECRETKEYBYTES;
    /// Signing keys are secrets and are not hashable.
    #[classattr]
    const __hash__: Option<Py<PyAny>> = None;

    /// Loads a 64-byte libsodium secret key. The public half is recomputed
    /// from the seed.
    #[new]
    fn py_new(secret_key: Buf<'_>) -> PyResult<Self> {
        let secret_key: SecretKey = fixed(secret_key.as_slice(), "signing key")?;
        Ok(Self {
            pair: StackSigningKeyPair::from_secret_key(secret_key),
        })
    }

    /// Loads a 64-byte libsodium secret key. The public half is recomputed
    /// from the seed.
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, PyType>, secret_key: Buf<'_>) -> PyResult<Self> {
        Self::py_new(secret_key)
    }

    /// Deterministically derives a signing key from a 32-byte `seed`.
    #[classmethod]
    fn from_seed(_cls: &Bound<'_, PyType>, seed: Buf<'_>) -> PyResult<Self> {
        let seed: Seed = fixed(seed.as_slice(), "seed")?;
        Ok(Self {
            pair: StackSigningKeyPair::from_seed(&seed),
        })
    }

    /// Generates a new random signing key.
    #[classmethod]
    fn generate(_cls: &Bound<'_, PyType>) -> Self {
        Self {
            pair: StackSigningKeyPair::generate(),
        }
    }

    /// The matching public key.
    #[getter]
    fn verify_key(&self) -> VerifyKey {
        VerifyKey {
            key: self.pair.public_key.clone(),
        }
    }

    /// Exports the 32-byte seed. Handle the result as a secret.
    fn to_seed<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let seed: Seed = self.pair.to_seed();
        PyBytes::new(py, seed.as_ref())
    }

    /// Returns the 64-byte detached Ed25519 signature of `message`.
    fn sign<'py>(&self, py: Python<'py>, message: Buf<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let message = message.as_slice();
        let mut signature = Signature::new_byte_array();
        let output = &mut signature;
        maybe_detach(py, message.len(), || {
            crypto_sign_detached(output.as_mut(), message, self.pair.secret_key.as_ref())
        })
        .or_raise()?;
        Ok(PyBytes::new(py, signature.as_ref()))
    }

    /// Returns `signature || message` (libsodium's `crypto_sign` format).
    fn sign_combined<'py>(
        &self,
        py: Python<'py>,
        message: Buf<'py>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let message = message.as_slice();
        let signed = maybe_detach(py, message.len(), || {
            self.pair
                .sign::<Signature, _>(message.to_vec())
                .map(|signed| signed.to_vec())
        })
        .or_raise()?;
        Ok(PyBytes::new(py, &signed))
    }

    /// Exports the 64-byte libsodium secret key. Handle it as a secret.
    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.pair.secret_key.as_ref())
    }

    /// Compares two signing keys in constant time.
    fn __eq__(&self, other: &Bound<'_, Self>) -> bool {
        self.pair == other.get().pair
    }

    fn __repr__(&self) -> String {
        format!(
            "SigningKey(verify_key=VerifyKey('{}'), <redacted>)",
            crate::util::short_hex(self.pair.public_key.as_ref())
        )
    }
}

/// Incremental Ed25519ph (pre-hashed Ed25519, RFC 8032) for messages too
/// large to hold in memory.
///
/// Ed25519ph signatures differ from Ed25519 ones: verify them with
/// `Ed25519ph`, not `VerifyKey.verify`. An instance produces or checks one
/// signature; afterwards it raises `DryocError`.
#[pyclass(frozen, name = "Ed25519ph", module = "dryoc.sign")]
pub struct Ed25519ph {
    state: Locked<Option<IncrementalSigner>>,
}

fn used() -> PyErr {
    DryocError::new_err("this Ed25519ph object was already used to sign or verify")
}

impl Ed25519ph {
    fn take(&self, py: Python<'_>) -> PyResult<IncrementalSigner> {
        self.state.lock(py)?.take().ok_or_else(used)
    }

    fn absorb(&self, py: Python<'_>, data: &[u8]) -> PyResult<()> {
        let mut guard = self.state.lock(py)?;
        let state = guard.as_mut().ok_or_else(used)?;
        maybe_detach(py, data.len(), || state.update(&data));
        Ok(())
    }
}

#[pymethods]
impl Ed25519ph {
    /// Starts a new message, optionally absorbing `data`.
    #[new]
    #[pyo3(signature = (data = None))]
    fn py_new(py: Python<'_>, data: Option<Buf<'_>>) -> PyResult<Self> {
        let signer = Self {
            state: Locked::new(Some(IncrementalSigner::new())),
        };
        if let Some(data) = data {
            signer.absorb(py, data.as_slice())?;
        }
        Ok(signer)
    }

    /// Absorbs the next part of the message.
    fn update(&self, py: Python<'_>, data: Buf<'_>) -> PyResult<()> {
        self.absorb(py, data.as_slice())
    }

    /// Signs the absorbed message, returning a 64-byte signature.
    fn sign<'py>(
        &self,
        py: Python<'py>,
        signing_key: &Bound<'py, SigningKey>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let signature: Signature = self
            .take(py)?
            .finalize(&signing_key.get().pair.secret_key)
            .or_raise()?;
        Ok(PyBytes::new(py, signature.as_ref()))
    }

    /// Checks `signature` over the absorbed message.
    ///
    /// Raises `CryptoError` if the signature is invalid.
    fn verify(
        &self,
        py: Python<'_>,
        signature: Buf<'_>,
        verify_key: &Bound<'_, VerifyKey>,
    ) -> PyResult<()> {
        let signature: Signature = fixed(signature.as_slice(), "signature")?;
        self.take(py)?
            .verify(&signature, &verify_key.get().key)
            .map_err(verification_failed)
    }

    fn __repr__(&self) -> &'static str {
        "<dryoc.sign.Ed25519ph object>"
    }
}
