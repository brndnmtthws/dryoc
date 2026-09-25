//! `dryoc.box`: X25519-XSalsa20-Poly1305 public-key authenticated encryption
//! (libsodium's `crypto_box`), anonymous sealed boxes (`crypto_box_seal`),
//! and the X25519 key pairs shared with `dryoc.kx`.

use dryoc::constants::{
    CRYPTO_BOX_MACBYTES, CRYPTO_BOX_NONCEBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES,
    CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_BOX_SEEDBYTES,
};
use dryoc::dryocbox::{DryocBox, Nonce, VecBox};
use dryoc::keypair::StackKeyPair;
use dryoc::precalc::PrecalcSecretKey;
use dryoc::types::{NewByteArray, StackByteArray};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use zeroize::Zeroizing;

use crate::util::{
    Buf, OrRaise, encrypted_message, fixed, maybe_detach, public_key_class, secret_bytes,
    secret_key_class,
};

public_key_class! {
    /// An X25519 public key, used with `Box`, `SealedBox` and `dryoc.kx`.
    PublicKey, "PublicKey", "dryoc.box", SIZE = CRYPTO_BOX_PUBLICKEYBYTES, "public key" {}
}

secret_key_class! {
    /// An X25519 secret key. Most code uses a `KeyPair` instead.
    SecretKey, "SecretKey", "dryoc.box", SIZE = CRYPTO_BOX_SECRETKEYBYTES, "secret key"
    {
        /// The public key matching this secret key.
        #[getter]
        fn public_key(&self) -> PublicKey {
            PublicKey {
                key: StackKeyPair::from_secret_key(self.key.clone()).public_key.clone(),
            }
        }
    }
}

/// An X25519 key pair for `Box`, `SealedBox` and `dryoc.kx`.
///
/// Create one with `generate()`, `from_seed()` or `from_secret_key()`. The
/// repr never shows the secret key; export it deliberately with
/// `bytes(pair.secret_key)`.
#[pyclass(frozen, name = "KeyPair", module = "dryoc.box")]
pub struct KeyPair {
    pub(crate) pair: StackKeyPair,
}

impl KeyPair {
    fn from_secret(key: &StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>) -> Self {
        Self {
            pair: StackKeyPair::from_secret_key(key.clone()),
        }
    }
}

/// A secret-key argument: a `KeyPair` or a `SecretKey`.
#[derive(FromPyObject)]
pub(crate) enum SecretArg<'py> {
    Pair(Bound<'py, KeyPair>),
    Key(Bound<'py, SecretKey>),
}

impl SecretArg<'_> {
    pub(crate) fn key_pair(&self) -> KeyPairRef<'_> {
        match self {
            SecretArg::Pair(pair) => KeyPairRef::Borrowed(&pair.get().pair),
            SecretArg::Key(key) => KeyPairRef::Owned(KeyPair::from_secret(&key.get().key).pair),
        }
    }
}

/// A key pair borrowed from a `KeyPair` or derived from a `SecretKey`.
pub(crate) enum KeyPairRef<'a> {
    Borrowed(&'a StackKeyPair),
    Owned(StackKeyPair),
}

impl core::ops::Deref for KeyPairRef<'_> {
    type Target = StackKeyPair;

    fn deref(&self) -> &StackKeyPair {
        match self {
            KeyPairRef::Borrowed(pair) => pair,
            KeyPairRef::Owned(pair) => pair,
        }
    }
}

#[pymethods]
impl KeyPair {
    /// Length of a seed accepted by `from_seed` in bytes.
    #[classattr]
    const SEED_SIZE: usize = CRYPTO_BOX_SEEDBYTES;
    /// Key pairs hold secrets and are not hashable.
    #[classattr]
    const __hash__: Option<Py<PyAny>> = None;

    /// Generates a new random key pair.
    #[classmethod]
    fn generate(_cls: &Bound<'_, PyType>) -> Self {
        Self {
            pair: StackKeyPair::generate(),
        }
    }

    /// Deterministically derives a key pair from a 32-byte `seed`
    /// (libsodium's `crypto_box_seed_keypair`).
    #[classmethod]
    fn from_seed(_cls: &Bound<'_, PyType>, seed: Buf<'_>) -> PyResult<Self> {
        let seed: StackByteArray<CRYPTO_BOX_SEEDBYTES> = fixed(seed.as_slice(), "seed")?;
        Ok(Self {
            pair: StackKeyPair::from_seed(&seed),
        })
    }

    /// Rebuilds a key pair from a secret key (a `SecretKey` or its 32 raw
    /// bytes), deriving the public key.
    #[classmethod]
    fn from_secret_key(_cls: &Bound<'_, PyType>, secret_key: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(key) = secret_key.cast::<SecretKey>() {
            return Ok(Self::from_secret(&key.get().key));
        }
        let bytes: Buf<'_> = secret_key.extract()?;
        Ok(Self::from_secret(&fixed(bytes.as_slice(), "secret key")?))
    }

    /// The public key; share it freely.
    #[getter]
    fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.pair.public_key.clone(),
        }
    }

    /// The secret key; keep it private.
    #[getter]
    fn secret_key(&self) -> SecretKey {
        SecretKey {
            key: self.pair.secret_key.clone(),
        }
    }

    /// Compares two key pairs in constant time.
    fn __eq__(&self, other: &Bound<'_, Self>) -> bool {
        use subtle::ConstantTimeEq;
        let other = &other.get().pair;
        let public: &[u8] = self.pair.public_key.as_ref();
        let secret: &[u8] = self.pair.secret_key.as_ref();
        bool::from(
            public.ct_eq(other.public_key.as_ref()) & secret.ct_eq(other.secret_key.as_ref()),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "KeyPair(public_key=PublicKey('{}'), secret_key=<redacted>)",
            crate::util::short_hex(self.pair.public_key.as_ref())
        )
    }
}

/// Authenticated encryption between two parties (libsodium's `crypto_box`).
///
/// `Box(my_secret, their_public_key)` precomputes the shared key once, so
/// repeated messages are cheap. Both directions share one nonce space: a nonce
/// must never repeat for the same pair of keys. The random nonces `encrypt`
/// generates by default satisfy that.
#[pyclass(frozen, name = "Box", module = "dryoc.box")]
pub struct PublicBox {
    shared: PrecalcSecretKey<StackByteArray<32>>,
}

#[pymethods]
impl PublicBox {
    /// Length of the authentication tag added to each message.
    #[classattr]
    const MAC_SIZE: usize = CRYPTO_BOX_MACBYTES;
    /// Length of a nonce in bytes.
    #[classattr]
    const NONCE_SIZE: usize = CRYPTO_BOX_NONCEBYTES;
    /// Boxes hold a shared secret and are not hashable.
    #[classattr]
    const __hash__: Option<Py<PyAny>> = None;

    /// Creates a box from your secret key (`KeyPair` or `SecretKey`) and the
    /// other party's `PublicKey`.
    ///
    /// Raises `InvalidInputError` if `public_key` is a low-order point.
    #[new]
    fn py_new(secret_key: SecretArg<'_>, public_key: &Bound<'_, PublicKey>) -> PyResult<Self> {
        let pair = secret_key.key_pair();
        let shared =
            PrecalcSecretKey::precalculate(&public_key.get().key, &pair.secret_key).or_raise()?;
        Ok(Self { shared })
    }

    /// Encrypts `plaintext`, returning `EncryptedMessage(ciphertext, nonce)`.
    ///
    /// A random nonce is generated when `nonce` is omitted. The ciphertext is
    /// libsodium's `crypto_box_easy` format (tag then encrypted data).
    #[pyo3(signature = (plaintext, nonce = None))]
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        plaintext: Buf<'py>,
        nonce: Option<Buf<'py>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let nonce: Nonce = match nonce {
            Some(nonce) => fixed(nonce.as_slice(), "nonce")?,
            None => Nonce::generate(),
        };
        let message = plaintext.as_slice();
        let ciphertext = maybe_detach(py, message.len(), || {
            DryocBox::precalc_encrypt_to_vecbox(message, &nonce, &self.shared)
                .map(|sealed| sealed.to_vec())
        })
        .or_raise()?;
        encrypted_message(py, nonce.as_ref(), &ciphertext)
    }

    /// Decrypts and authenticates `ciphertext` produced with `nonce`.
    ///
    /// Raises `CryptoError` if the keys, nonce or ciphertext are wrong.
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        ciphertext: Buf<'py>,
        nonce: Buf<'py>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let nonce: Nonce = fixed(nonce.as_slice(), "nonce")?;
        let ciphertext = ciphertext.as_slice();
        let plaintext = maybe_detach(py, ciphertext.len(), || {
            VecBox::from_bytes(ciphertext)
                .and_then(|sealed| sealed.precalc_decrypt_to_vec(&nonce, &self.shared))
                .map(Zeroizing::new)
        })
        .or_raise()?;
        Ok(secret_bytes(py, plaintext))
    }

    fn __repr__(&self) -> &'static str {
        "Box(<redacted>)"
    }
}

/// Anonymous public-key encryption (libsodium's `crypto_box_seal`).
///
/// Anyone with the recipient's `PublicKey` can encrypt; only the holder of the
/// `KeyPair` can decrypt. The sender stays anonymous and cannot decrypt their
/// own message. For confidentiality against future quantum computers, use
/// `dryoc.sealedbox.SealedBox` instead.
#[pyclass(frozen, name = "SealedBox", module = "dryoc.box")]
pub struct SealedBox {
    public_key: StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
    pair: Option<StackKeyPair>,
}

#[pymethods]
impl SealedBox {
    /// Bytes a sealed box adds to the plaintext.
    #[classattr]
    const OVERHEAD: usize = CRYPTO_BOX_SEALBYTES;
    /// Sealed boxes may hold a secret key and are not hashable.
    #[classattr]
    const __hash__: Option<Py<PyAny>> = None;

    /// Creates a sealed box for a recipient.
    ///
    /// Pass the recipient's `PublicKey` to encrypt only, or the recipient's
    /// `KeyPair` (or `SecretKey`) to also decrypt.
    #[new]
    fn py_new(recipient: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(public_key) = recipient.cast::<PublicKey>() {
            return Ok(Self {
                public_key: public_key.get().key.clone(),
                pair: None,
            });
        }
        let secret: SecretArg<'_> = recipient.extract().map_err(|_| {
            PyTypeError::new_err("recipient must be a dryoc.box PublicKey, KeyPair or SecretKey")
        })?;
        let pair = secret.key_pair().clone();
        Ok(Self {
            public_key: pair.public_key.clone(),
            pair: Some(pair),
        })
    }

    /// Encrypts `plaintext` for the recipient, returning
    /// `ephemeral_public_key || tag || ciphertext`.
    fn encrypt<'py>(&self, py: Python<'py>, plaintext: Buf<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let message = plaintext.as_slice();
        let sealed = maybe_detach(py, message.len(), || {
            DryocBox::seal_to_vecbox(message, &self.public_key).map(|sealed| sealed.to_vec())
        })
        .or_raise()?;
        Ok(PyBytes::new(py, &sealed))
    }

    /// Decrypts a sealed box. Requires the recipient's key pair.
    ///
    /// Raises `CryptoError` if the box was modified or is for another key.
    fn decrypt<'py>(&self, py: Python<'py>, ciphertext: Buf<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let pair = self.pair.as_ref().ok_or_else(|| {
            PyTypeError::new_err(
                "this SealedBox was created from a PublicKey and cannot decrypt; create it from \
                 the recipient's KeyPair",
            )
        })?;
        let ciphertext = ciphertext.as_slice();
        let plaintext = maybe_detach(py, ciphertext.len(), || {
            VecBox::from_sealed_bytes(ciphertext)
                .and_then(|sealed| sealed.unseal_to_vec(pair))
                .map(Zeroizing::new)
        })
        .or_raise()?;
        Ok(secret_bytes(py, plaintext))
    }

    /// The recipient's public key.
    #[getter]
    fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.public_key.clone(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SealedBox(PublicKey('{}'){})",
            crate::util::short_hex(self.public_key.as_ref()),
            if self.pair.is_some() {
                ", <secret key>"
            } else {
                ""
            }
        )
    }
}
