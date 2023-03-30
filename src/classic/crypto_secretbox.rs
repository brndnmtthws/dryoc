//! # Authenticated encryption functions
//!
//! Implements libsodium's secret-key authenticated crypto boxes.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox).
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_secretbox::{
//!     crypto_secretbox_easy, crypto_secretbox_keygen, crypto_secretbox_open_easy, Key, Nonce,
//! };
//! use dryoc::constants::{CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES};
//! use dryoc::rng::randombytes_buf;
//! use dryoc::types::*;
//!
//! let key: Key = crypto_secretbox_keygen();
//! let nonce = Nonce::gen();
//!
//! let message = "I Love Doge!";
//!
//! // Encrypt
//! let mut ciphertext = vec![0u8; message.len() + CRYPTO_SECRETBOX_MACBYTES];
//! crypto_secretbox_easy(&mut ciphertext, message.as_bytes(), &nonce, &key)
//!     .expect("encrypt failed");
//!
//! // Decrypt
//! let mut decrypted = vec![0u8; ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES];
//! crypto_secretbox_open_easy(&mut decrypted, &ciphertext, &nonce, &key).expect("decrypt failed");
//!
//! assert_eq!(decrypted, message.as_bytes());
//! ```

use crate::classic::crypto_secretbox_impl::*;
use crate::constants::{
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::types::*;

/// Secret box message authentication code.
pub type Mac = [u8; CRYPTO_SECRETBOX_MACBYTES];
/// Nonce for secret key authenticated boxes.
pub type Nonce = [u8; CRYPTO_SECRETBOX_NONCEBYTES];
/// Key (or secret) for secret key authenticated boxes.
pub type Key = [u8; CRYPTO_SECRETBOX_KEYBYTES];

/// In-place variant of [`crypto_secretbox_keygen`]
pub fn crypto_secretbox_keygen_inplace(key: &mut Key) {
    copy_randombytes(key)
}

/// Generates a random key using
/// [`copy_randombytes`](crate::rng::copy_randombytes).
pub fn crypto_secretbox_keygen() -> Key {
    Key::gen()
}

/// Detached version of [`crypto_secretbox_easy`].
///
/// Compatible with libsodium's `crypto_secretbox_detached`.
pub fn crypto_secretbox_detached(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) {
    ciphertext[..message.len()].copy_from_slice(message);
    crypto_secretbox_detached_inplace(ciphertext, mac, nonce, key);
}

/// Detached version of [`crypto_secretbox_open_easy`].
///
/// Compatible with libsodium's `crypto_secretbox_open_detached`.
pub fn crypto_secretbox_open_detached(
    message: &mut [u8],
    mac: &Mac,
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let c_len = ciphertext.len();
    message[..c_len].copy_from_slice(ciphertext);
    crypto_secretbox_open_detached_inplace(message, mac, nonce, key)
}

/// Encrypts `message` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_easy`.
pub fn crypto_secretbox_easy(
    ciphertext: &mut [u8],
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let mut mac = Mac::default();
    crypto_secretbox_detached(
        &mut ciphertext[CRYPTO_SECRETBOX_MACBYTES..],
        &mut mac,
        message,
        nonce,
        key,
    );

    ciphertext[..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(&mac);

    Ok(())
}

/// Decrypts `ciphertext` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_open_easy`.
pub fn crypto_secretbox_open_easy(
    message: &mut [u8],
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    if ciphertext.len() < CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        let (mac, ciphertext) = ciphertext.split_at(CRYPTO_SECRETBOX_MACBYTES);
        let mac = mac.as_array();
        crypto_secretbox_open_detached(message, mac, ciphertext, nonce, key)
    }
}

/// Encrypts `message` with `nonce` and `key` in-place, without allocating
/// additional memory for the ciphertext.
pub fn crypto_secretbox_easy_inplace(
    data: &mut [u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    data.rotate_right(CRYPTO_SECRETBOX_MACBYTES);
    let (mac, data) = data.split_at_mut(CRYPTO_SECRETBOX_MACBYTES);
    let mac = mac.as_mut_array();

    crypto_secretbox_detached_inplace(data, mac, nonce, key);

    Ok(())
}

/// Decrypts `ciphertext` with `nonce` and `key` in-place, without allocating
/// additional memory for the message.
pub fn crypto_secretbox_open_easy_inplace(
    ciphertext: &mut [u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    if ciphertext.len() < CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        let (mac, data) = ciphertext.split_at_mut(CRYPTO_SECRETBOX_MACBYTES);
        let mac = mac.as_array();

        crypto_secretbox_open_detached_inplace(data, mac, nonce, key)?;

        ciphertext.rotate_left(CRYPTO_SECRETBOX_MACBYTES);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_secretbox_easy() {
        for i in 0..20 {
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            let key: Key = crypto_secretbox_keygen();
            let nonce = Nonce::gen();

            let words = vec!["love Doge".to_string(); i];
            let message = words.join(" <3 ");

            let mut ciphertext = vec![0u8; message.len() + CRYPTO_SECRETBOX_MACBYTES];
            crypto_secretbox_easy(&mut ciphertext, message.as_bytes(), &nonce, &key)
                .expect("encrypt failed");
            let so_ciphertext = secretbox::seal(
                message.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&key).unwrap(),
            );
            assert_eq!(
                general_purpose::STANDARD.encode(&ciphertext),
                general_purpose::STANDARD.encode(&so_ciphertext)
            );

            let mut decrypted = vec![0u8; message.len()];
            crypto_secretbox_open_easy(&mut decrypted, &ciphertext, &nonce, &key)
                .expect("decrypt failed");
            let so_decrypted = secretbox::open(
                &ciphertext,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&key).unwrap(),
            )
            .unwrap();

            assert_eq!(decrypted, message.as_bytes());
            assert_eq!(decrypted, so_decrypted);
        }
    }

    #[test]
    fn test_crypto_secretbox_easy_inplace() {
        for i in 0..20 {
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            let key = crypto_secretbox_keygen();
            let nonce = Nonce::gen();

            let words = vec!["love Doge".to_string(); i];
            let message: Vec<u8> = words.join(" <3 ").into();
            let message_copy = message.clone();

            let mut ciphertext = message.clone();
            ciphertext.resize(message.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
            crypto_secretbox_easy_inplace(&mut ciphertext, &nonce, &key).expect("encrypt failed");
            let so_ciphertext = secretbox::seal(
                &message_copy,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&key).unwrap(),
            );
            assert_eq!(
                general_purpose::STANDARD.encode(&ciphertext),
                general_purpose::STANDARD.encode(&so_ciphertext)
            );

            let mut decrypted = ciphertext.clone();
            crypto_secretbox_open_easy_inplace(&mut decrypted, &nonce, &key)
                .expect("decrypt failed");
            decrypted.resize(ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES, 0);
            let so_decrypted = secretbox::open(
                &ciphertext,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&key).unwrap(),
            )
            .expect("decrypt failed");

            assert_eq!(&decrypted, &message_copy);
            assert_eq!(decrypted, so_decrypted);
        }
    }
}
