//! `dryoc.secretbox`: XSalsa20-Poly1305 secret-key authenticated encryption.

use dryoc::constants::{
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use dryoc::dryocsecretbox::{DryocSecretBox, Nonce, VecBox};
use dryoc::types::NewByteArray;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

use crate::util::{
    Buf, OrRaise, encrypted_message, fixed, maybe_detach, secret_bytes, secret_key_class,
};

secret_key_class! {
    /// A secret key for XSalsa20-Poly1305 authenticated encryption
    /// (libsodium's `crypto_secretbox`).
    SecretBox, "SecretBox", "dryoc.secretbox", KEY_SIZE = CRYPTO_SECRETBOX_KEYBYTES, "secretbox key"
    {
        /// Length of a nonce in bytes.
        #[classattr]
        const NONCE_SIZE: usize = CRYPTO_SECRETBOX_NONCEBYTES;

        /// Length of the authentication tag added to each message.
        #[classattr]
        const MAC_SIZE: usize = CRYPTO_SECRETBOX_MACBYTES;

        /// Encrypts `plaintext`, returning `EncryptedMessage(ciphertext, nonce)`.
        ///
        /// A random nonce is generated when `nonce` is omitted. The ciphertext is
        /// libsodium's `crypto_secretbox_easy` format (tag then encrypted data).
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
            let sealed = maybe_detach(py, message.len(), || {
                DryocSecretBox::encrypt_to_vecbox(message, &nonce, &self.key).into_vec()
            });
            encrypted_message(py, nonce.as_ref(), &sealed)
        }

        /// Decrypts and authenticates `ciphertext` produced with `nonce`.
        ///
        /// Raises `CryptoError` if the key, nonce or ciphertext is wrong.
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
                    .and_then(|sealed| sealed.decrypt_to_vec(&nonce, &self.key))
                    .map(Zeroizing::new)
            })
            .or_raise()?;
            Ok(secret_bytes(py, plaintext))
        }
    }
}
