//! `dryoc.kem.xwing` and `dryoc.kem.mlkem768`: post-quantum key encapsulation,
//! and `dryoc.sealedbox`: post-quantum sealed boxes built on X-Wing.

macro_rules! kem_classes {
    (
        algorithm:
        $algo:literal,rust:
        $rust:ident,module:
        $module:literal,public_key_bytes:
        $pk_bytes:expr,secret_key_bytes:
        $sk_bytes:expr,ciphertext_bytes:
        $ct_bytes:expr,shared_secret_bytes:
        $ss_bytes:expr,seed_bytes:
        $seed_bytes:expr,classes:
        ($public_key:ident, $secret_key:ident, $key_pair:ident) $(,)?
    ) => {
        use dryoc::kem::$rust::{Ciphertext, Seed, SharedSecret, StackKeyPair};
        use pyo3::prelude::*;
        use pyo3::types::{PyBytes, PyType};

        use crate::util::{Buf, OrRaise, fixed, public_key_class};

        public_key_class! {
            #[doc = concat!("An ", $algo, " public key.")]
            $public_key, "PublicKey", $module, SIZE = $pk_bytes, "public key"
            {
                /// Length of a ciphertext produced by `encapsulate` in bytes.
                #[classattr]
                const CIPHERTEXT_SIZE: usize = $ct_bytes;

                /// Length of the shared secret in bytes.
                #[classattr]
                const SHARED_SECRET_SIZE: usize = $ss_bytes;

                /// Creates a fresh random shared secret for this key's owner.
                ///
                /// Returns `(ciphertext, shared_secret)`: send the ciphertext to the
                /// key's owner, who recovers the same secret with
                /// `KeyPair.decapsulate`. Pass the secret through a KDF before
                /// using it as a key.
                fn encapsulate<'py>(
                    &self,
                    py: Python<'py>,
                ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
                    let (ciphertext, shared_secret): (Ciphertext, SharedSecret) =
                        dryoc::kem::$rust::encapsulate(&self.key).or_raise()?;
                    Ok((
                        PyBytes::new(py, ciphertext.as_ref()),
                        PyBytes::new(py, shared_secret.as_ref()),
                    ))
                }
            }
        }

        #[doc = concat!("An ", $algo, " secret key. Most code uses a `KeyPair` instead.")]
        ///
        /// Generate keys with `KeyPair.generate()`; this class only wraps
        /// existing key bytes.
        #[pyclass(frozen, name = "SecretKey", module = $module)]
        pub struct $secret_key {
            pub(crate) key: dryoc::types::StackByteArray<{ $sk_bytes }>,
        }

        #[pymethods]
        impl $secret_key {
            /// Length of the key in bytes.
            #[classattr]
            const SIZE: usize = $sk_bytes;
            /// Secrets are not hashable.
            #[classattr]
            const __hash__: Option<Py<PyAny>> = None;

            #[new]
            fn py_new(key: Buf<'_>) -> PyResult<Self> {
                Ok(Self {
                    key: fixed(key.as_slice(), "secret key")?,
                })
            }

            /// Wraps existing secret key bytes.
            #[classmethod]
            fn from_bytes(_cls: &Bound<'_, PyType>, key: Buf<'_>) -> PyResult<Self> {
                Self::py_new(key)
            }

            /// Exports the raw key bytes. Handle the result as a secret.
            fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, self.key.as_ref())
            }

            /// Compares two keys in constant time.
            fn __eq__(&self, other: &Bound<'_, Self>) -> bool {
                use subtle::ConstantTimeEq;
                let this: &[u8] = self.key.as_ref();
                this.ct_eq(other.get().key.as_ref()).into()
            }

            fn __repr__(&self) -> &'static str {
                "SecretKey(<redacted>)"
            }
        }

        #[doc = concat!("An ", $algo, " key pair.")]
        ///
        /// Create one with `generate()`, `from_seed()` or `from_secret_key()`.
        /// The repr never shows the secret key; export it deliberately with
        /// `bytes(pair.secret_key)`.
        #[pyclass(frozen, name = "KeyPair", module = $module)]
        pub struct $key_pair {
            pub(crate) pair: StackKeyPair,
        }

        #[pymethods]
        impl $key_pair {
            /// Length of a seed accepted by `from_seed` in bytes.
            #[classattr]
            const SEED_SIZE: usize = $seed_bytes;
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

            /// Deterministically derives a key pair from `seed`.
            #[classmethod]
            fn from_seed(_cls: &Bound<'_, PyType>, seed: Buf<'_>) -> PyResult<Self> {
                let seed: Seed = fixed(seed.as_slice(), "seed")?;
                Ok(Self {
                    pair: StackKeyPair::from_seed(&seed),
                })
            }

            /// Rebuilds a key pair from a secret key (a `SecretKey` or its raw
            /// bytes), deriving the public key.
            #[classmethod]
            fn from_secret_key(
                _cls: &Bound<'_, PyType>,
                secret_key: &Bound<'_, PyAny>,
            ) -> PyResult<Self> {
                let key = match secret_key.cast::<$secret_key>() {
                    Ok(key) => key.get().key.clone(),
                    Err(_) => {
                        let bytes: Buf<'_> = secret_key.extract()?;
                        fixed(bytes.as_slice(), "secret key")?
                    }
                };
                Ok(Self {
                    pair: StackKeyPair::from_secret_key(key),
                })
            }

            /// The public key; share it freely.
            #[getter]
            fn public_key(&self) -> $public_key {
                $public_key {
                    key: self.pair.public_key.clone(),
                }
            }

            /// The secret key; keep it private.
            #[getter]
            fn secret_key(&self) -> $secret_key {
                $secret_key {
                    key: self.pair.secret_key.clone(),
                }
            }

            /// Recovers the shared secret from a `ciphertext` made by
            /// `PublicKey.encapsulate`.
            ///
            /// A modified ciphertext does not raise: ML-KEM's implicit rejection
            /// returns an unrelated secret instead, so the mismatch surfaces when
            /// the derived key fails to authenticate.
            fn decapsulate<'py>(
                &self,
                py: Python<'py>,
                ciphertext: Buf<'py>,
            ) -> PyResult<Bound<'py, PyBytes>> {
                let ciphertext: Ciphertext = fixed(ciphertext.as_slice(), "ciphertext")?;
                let shared_secret: SharedSecret = self.pair.decapsulate(&ciphertext).or_raise()?;
                Ok(PyBytes::new(py, shared_secret.as_ref()))
            }

            /// Compares two key pairs in constant time.
            fn __eq__(&self, other: &Bound<'_, Self>) -> bool {
                use subtle::ConstantTimeEq;
                let other = &other.get().pair;
                let public: &[u8] = self.pair.public_key.as_ref();
                let secret: &[u8] = self.pair.secret_key.as_ref();
                bool::from(
                    public.ct_eq(other.public_key.as_ref())
                        & secret.ct_eq(other.secret_key.as_ref()),
                )
            }

            fn __repr__(&self) -> String {
                format!(
                    "KeyPair(public_key=PublicKey('{}'), secret_key=<redacted>)",
                    crate::util::short_hex(self.pair.public_key.as_ref())
                )
            }
        }
    };
}

pub mod xwing {
    use dryoc::constants::{
        CRYPTO_KEM_XWING_CIPHERTEXTBYTES, CRYPTO_KEM_XWING_PUBLICKEYBYTES,
        CRYPTO_KEM_XWING_SECRETKEYBYTES, CRYPTO_KEM_XWING_SEEDBYTES,
        CRYPTO_KEM_XWING_SHAREDSECRETBYTES,
    };

    kem_classes! {
        algorithm: "X-Wing (ML-KEM-768 + X25519)",
        rust: xwing,
        module: "dryoc.kem.xwing",
        public_key_bytes: CRYPTO_KEM_XWING_PUBLICKEYBYTES,
        secret_key_bytes: CRYPTO_KEM_XWING_SECRETKEYBYTES,
        ciphertext_bytes: CRYPTO_KEM_XWING_CIPHERTEXTBYTES,
        shared_secret_bytes: CRYPTO_KEM_XWING_SHAREDSECRETBYTES,
        seed_bytes: CRYPTO_KEM_XWING_SEEDBYTES,
        classes: (PublicKey, SecretKey, KeyPair),
    }
}

pub mod mlkem768 {
    use dryoc::constants::{
        CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES,
        CRYPTO_KEM_MLKEM768_SECRETKEYBYTES, CRYPTO_KEM_MLKEM768_SEEDBYTES,
        CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
    };

    kem_classes! {
        algorithm: "ML-KEM-768 (FIPS 203)",
        rust: mlkem768,
        module: "dryoc.kem.mlkem768",
        public_key_bytes: CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES,
        secret_key_bytes: CRYPTO_KEM_MLKEM768_SECRETKEYBYTES,
        ciphertext_bytes: CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES,
        shared_secret_bytes: CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
        seed_bytes: CRYPTO_KEM_MLKEM768_SEEDBYTES,
        classes: (PublicKey, SecretKey, KeyPair),
    }
}

pub mod sealedbox {
    use dryoc::dryocsealedbox::{DryocSealedBox, SEALBYTES, VecBox};
    use dryoc::kem::xwing::StackKeyPair;
    use dryoc::types::StackByteArray;
    use pyo3::exceptions::PyTypeError;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;
    use zeroize::Zeroizing;

    use super::xwing::{KeyPair, PublicKey, SecretKey};
    use crate::util::{Buf, OrRaise, maybe_detach, secret_bytes};

    /// Anonymous post-quantum public-key encryption: an HPKE (RFC 9180) sealed
    /// box using X-Wing, HKDF-SHA256 and ChaCha20-Poly1305.
    ///
    /// Anyone with the recipient's `dryoc.kem.xwing.PublicKey` can encrypt;
    /// only the holder of the matching `KeyPair` can decrypt. Recorded boxes
    /// stay confidential even if X25519 is later broken.
    #[pyclass(frozen, name = "SealedBox", module = "dryoc.sealedbox")]
    pub struct SealedBox {
        public_key: StackByteArray<{ dryoc::constants::CRYPTO_KEM_XWING_PUBLICKEYBYTES }>,
        pair: Option<StackKeyPair>,
    }

    #[pymethods]
    impl SealedBox {
        /// Bytes a sealed box adds to the plaintext.
        #[classattr]
        const OVERHEAD: usize = SEALBYTES;
        /// Sealed boxes may hold a secret key and are not hashable.
        #[classattr]
        const __hash__: Option<Py<PyAny>> = None;

        /// Creates a sealed box for a recipient.
        ///
        /// Pass the recipient's X-Wing `PublicKey` to encrypt only, or the
        /// recipient's `KeyPair` (or `SecretKey`) to also decrypt.
        #[new]
        fn py_new(recipient: &Bound<'_, PyAny>) -> PyResult<Self> {
            if let Ok(public_key) = recipient.cast::<PublicKey>() {
                return Ok(Self {
                    public_key: public_key.get().key.clone(),
                    pair: None,
                });
            }
            let pair = if let Ok(pair) = recipient.cast::<KeyPair>() {
                pair.get().pair.clone()
            } else if let Ok(key) = recipient.cast::<SecretKey>() {
                StackKeyPair::from_secret_key(key.get().key.clone())
            } else {
                return Err(PyTypeError::new_err(
                    "recipient must be a dryoc.kem.xwing PublicKey, KeyPair or SecretKey",
                ));
            };
            Ok(Self {
                public_key: pair.public_key.clone(),
                pair: Some(pair),
            })
        }

        /// Encrypts `plaintext` for the recipient, returning
        /// `encapsulated_key || ciphertext || tag`.
        fn encrypt<'py>(
            &self,
            py: Python<'py>,
            plaintext: Buf<'py>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let message = plaintext.as_slice();
            let sealed = maybe_detach(py, message.len(), || {
                DryocSealedBox::seal_to_vecbox(message, &self.public_key)
                    .map(|sealed| sealed.to_vec())
            })
            .or_raise()?;
            Ok(PyBytes::new(py, &sealed))
        }

        /// Decrypts a sealed box. Requires the recipient's key pair.
        ///
        /// Raises `CryptoError` if the box was modified or is for another key.
        fn decrypt<'py>(
            &self,
            py: Python<'py>,
            ciphertext: Buf<'py>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let pair = self.pair.as_ref().ok_or_else(|| {
                PyTypeError::new_err(
                    "this SealedBox was created from a PublicKey and cannot decrypt; create it \
                     from the recipient's KeyPair",
                )
            })?;
            let ciphertext = ciphertext.as_slice();
            let plaintext = maybe_detach(py, ciphertext.len(), || {
                VecBox::from_bytes(ciphertext)
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
}
