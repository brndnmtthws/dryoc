//! `dryoc.aead`: ChaCha20-Poly1305 authenticated encryption with associated
//! data.

use dryoc::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
};
use dryoc::dryocaead::{self, chacha20poly1305_ietf};
use dryoc::types::NewByteArray;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

use crate::util::{
    Buf, OrRaise, encrypted_message, fixed, maybe_detach, opt_slice, secret_bytes, secret_key_class,
};

secret_key_class! {
    /// A key for XChaCha20-Poly1305-IETF (libsodium's
    /// `crypto_aead_xchacha20poly1305_ietf`).
    ///
    /// Its 192-bit nonces are safe to generate at random, so `encrypt` and
    /// `seal` do so by default.
    XChaCha20Poly1305, "XChaCha20Poly1305", "dryoc.aead",
    KEY_SIZE = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, "XChaCha20-Poly1305 key"
    {
        /// Length of a nonce in bytes.
        #[classattr]
        const NONCE_SIZE: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        /// Length of the authentication tag appended to each ciphertext.
        #[classattr]
        const TAG_SIZE: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

        /// Encrypts `plaintext`, returning `EncryptedMessage(ciphertext, nonce)`.
        ///
        /// The ciphertext is libsodium's format (encrypted data then tag). A
        /// random nonce is generated when `nonce` is omitted. `associated_data`
        /// is authenticated but not encrypted, and must be passed again to
        /// `decrypt`.
        #[pyo3(signature = (plaintext, nonce = None, *, associated_data = None))]
        fn encrypt<'py>(
            &self,
            py: Python<'py>,
            plaintext: Buf<'py>,
            nonce: Option<Buf<'py>>,
            associated_data: Option<Buf<'py>>,
        ) -> PyResult<Bound<'py, PyAny>> {
            let nonce: dryocaead::Nonce = match nonce {
                Some(nonce) => fixed(nonce.as_slice(), "nonce")?,
                None => dryocaead::Nonce::generate(),
            };
            let message = plaintext.as_slice();
            let aad = opt_slice(&associated_data);
            let ciphertext = maybe_detach(py, message.len(), || {
                dryocaead::DryocAead::encrypt_to_vecbox(message, aad, &nonce, &self.key)
                    .map(dryocaead::VecBox::into_vec)
            })
            .or_raise()?;
            encrypted_message(py, nonce.as_ref(), &ciphertext)
        }

        /// Decrypts and authenticates `ciphertext` produced with `nonce`.
        ///
        /// Raises `CryptoError` if the key, nonce, ciphertext or associated data
        /// is wrong.
        #[pyo3(signature = (ciphertext, nonce, *, associated_data = None))]
        fn decrypt<'py>(
            &self,
            py: Python<'py>,
            ciphertext: Buf<'py>,
            nonce: Buf<'py>,
            associated_data: Option<Buf<'py>>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let nonce: dryocaead::Nonce = fixed(nonce.as_slice(), "nonce")?;
            let ciphertext = ciphertext.as_slice();
            let aad = opt_slice(&associated_data);
            let plaintext = maybe_detach(py, ciphertext.len(), || {
                dryocaead::VecBox::from_bytes(ciphertext)
                    .and_then(|sealed| sealed.decrypt_to_vec(aad, &nonce, &self.key))
                    .map(Zeroizing::new)
            })
            .or_raise()?;
            Ok(secret_bytes(py, plaintext))
        }

        /// Encrypts `plaintext` under a fresh random nonce and returns the
        /// self-contained envelope `nonce || ciphertext || tag`.
        #[pyo3(signature = (plaintext, *, associated_data = None))]
        fn seal<'py>(
            &self,
            py: Python<'py>,
            plaintext: Buf<'py>,
            associated_data: Option<Buf<'py>>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let message = plaintext.as_slice();
            let aad = opt_slice(&associated_data);
            let envelope = maybe_detach(py, message.len(), || {
                dryocaead::DryocAeadEnvelope::seal_to_vec(message, aad, &self.key)
                    .map(dryocaead::VecEnvelope::into_vec)
            })
            .or_raise()?;
            Ok(PyBytes::new(py, &envelope))
        }

        /// Opens an envelope produced by `seal`, returning the plaintext.
        ///
        /// Raises `CryptoError` if the envelope was modified or the key or
        /// associated data is wrong.
        #[pyo3(signature = (envelope, *, associated_data = None))]
        fn open<'py>(
            &self,
            py: Python<'py>,
            envelope: Buf<'py>,
            associated_data: Option<Buf<'py>>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let envelope = envelope.as_slice();
            let aad = opt_slice(&associated_data);
            let plaintext = maybe_detach(py, envelope.len(), || {
                dryocaead::VecEnvelope::from_bytes(envelope)
                    .and_then(|sealed| sealed.open_to_vec(aad, &self.key))
                    .map(Zeroizing::new)
            })
            .or_raise()?;
            Ok(secret_bytes(py, plaintext))
        }
    }
}

secret_key_class! {
    /// A key for ChaCha20-Poly1305-IETF (RFC 8439, libsodium's
    /// `crypto_aead_chacha20poly1305_ietf`).
    ///
    /// Its 96-bit nonces are too short to pick at random safely, so every call
    /// takes an explicit nonce, which must never repeat under one key. Prefer
    /// `XChaCha20Poly1305` unless a protocol requires this variant.
    ChaCha20Poly1305, "ChaCha20Poly1305", "dryoc.aead",
    KEY_SIZE = CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES, "ChaCha20-Poly1305 key"
    {
        /// Length of a nonce in bytes.
        #[classattr]
        const NONCE_SIZE: usize = CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;

        /// Length of the authentication tag appended to each ciphertext.
        #[classattr]
        const TAG_SIZE: usize = CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;

        /// Encrypts `plaintext` with `nonce`, returning
        /// `EncryptedMessage(ciphertext, nonce)`.
        ///
        /// The ciphertext is the encrypted data followed by the tag.
        #[pyo3(signature = (plaintext, nonce, *, associated_data = None))]
        fn encrypt<'py>(
            &self,
            py: Python<'py>,
            plaintext: Buf<'py>,
            nonce: Buf<'py>,
            associated_data: Option<Buf<'py>>,
        ) -> PyResult<Bound<'py, PyAny>> {
            let nonce: chacha20poly1305_ietf::Nonce = fixed(nonce.as_slice(), "nonce")?;
            let message = plaintext.as_slice();
            let aad = opt_slice(&associated_data);
            let ciphertext = maybe_detach(py, message.len(), || {
                chacha20poly1305_ietf::DryocAead::encrypt_to_vecbox(message, aad, &nonce, &self.key)
                    .map(chacha20poly1305_ietf::VecBox::into_vec)
            })
            .or_raise()?;
            encrypted_message(py, nonce.as_ref(), &ciphertext)
        }

        /// Decrypts and authenticates `ciphertext` produced with `nonce`.
        ///
        /// Raises `CryptoError` if the key, nonce, ciphertext or associated data
        /// is wrong.
        #[pyo3(signature = (ciphertext, nonce, *, associated_data = None))]
        fn decrypt<'py>(
            &self,
            py: Python<'py>,
            ciphertext: Buf<'py>,
            nonce: Buf<'py>,
            associated_data: Option<Buf<'py>>,
        ) -> PyResult<Bound<'py, PyBytes>> {
            let nonce: chacha20poly1305_ietf::Nonce = fixed(nonce.as_slice(), "nonce")?;
            let ciphertext = ciphertext.as_slice();
            let aad = opt_slice(&associated_data);
            let plaintext = maybe_detach(py, ciphertext.len(), || {
                chacha20poly1305_ietf::VecBox::from_bytes(ciphertext)
                    .and_then(|sealed| sealed.decrypt_to_vec(aad, &nonce, &self.key))
                    .map(Zeroizing::new)
            })
            .or_raise()?;
            Ok(secret_bytes(py, plaintext))
        }
    }
}
