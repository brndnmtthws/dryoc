//! # Authenticated encryption
//!
//! Implements libsodium's secret-key authenticated crypto boxes.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox).
//!
//! # Basic usage
//!
//! ```
//! use dryoc::rng::randombytes_buf;
//! use dryoc::crypto_secretbox::{crypto_secretbox_keygen, crypto_secretbox_easy, crypto_secretbox_open_easy};
//! use dryoc::constants::CRYPTO_SECRETBOX_NONCEBYTES;
//!
//! let key = crypto_secretbox_keygen();
//! let nonce = randombytes_buf(CRYPTO_SECRETBOX_NONCEBYTES);
//!
//! let message = "I Love Doge!";
//!
//! // Encrypt
//! let ciphertext = crypto_secretbox_easy(message.as_bytes(), &nonce, &key).unwrap();
//!
//! // Decrypt
//! let decrypted = crypto_secretbox_open_easy(&ciphertext, &nonce, &key).unwrap();
//!
//! assert_eq!(decrypted, message.as_bytes());
//! ```

use crate::constants::*;
use crate::crypto_secretbox_impl::*;
use crate::error::Error;
use crate::rng::*;
use crate::types::*;

/// Generates a random key using [randombytes_buf]
pub fn crypto_secretbox_keygen() -> SecretboxKey {
    let mut key: SecretboxKey = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
    let random_bytes = randombytes_buf(CRYPTO_SECRETBOX_KEYBYTES);
    key.copy_from_slice(&random_bytes);
    key
}

/// Detached version of [crypto_secretbox_easy]
pub fn crypto_secretbox_detached(message: &Input, nonce: &Nonce, key: &SecretboxKey) -> CryptoBox {
    let mut cryptobox = CryptoBox::with_data(message);

    crypto_secretbox_detached_inplace(&mut cryptobox, nonce, key);

    cryptobox
}

/// Detached version of [crypto_secretbox_open_easy]
pub fn crypto_secretbox_open_detached(
    mac: &Mac,
    ciphertext: &Input,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    let mut cryptobox = CryptoBox::with_data_and_mac(mac, ciphertext);

    crypto_secretbox_open_detached_inplace(&mut cryptobox, nonce, key)?;

    Ok(cryptobox.data)
}

/// Encrypts `message` with `nonce` and `key`
pub fn crypto_secretbox_easy(
    message: &Input,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    let cryptobox = crypto_secretbox_detached(message, nonce, key);
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(&cryptobox.mac);
    ciphertext.extend(cryptobox.data);
    Ok(ciphertext)
}

/// Decrypts `ciphertext` with `nonce` and `key`
pub fn crypto_secretbox_open_easy(
    ciphertext: &Input,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    if ciphertext.len() < CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        let mut mac: Mac = [0u8; CRYPTO_SECRETBOX_MACBYTES];
        mac.copy_from_slice(&ciphertext[0..CRYPTO_SECRETBOX_MACBYTES]);

        crypto_secretbox_open_detached(&mac, &ciphertext[CRYPTO_SECRETBOX_MACBYTES..], nonce, key)
    }
}

/// Encrypts `message` with `nonce` and `key` in-place, without allocating
/// additional memory for the ciphertext
pub fn crypto_secretbox_easy_inplace(
    message: Vec<u8>,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    let mut cryptobox = CryptoBox::from_data(message);

    crypto_secretbox_detached_inplace(&mut cryptobox, nonce, key);

    let mut ciphertext = cryptobox.data;
    // Resize to prepend mac
    ciphertext.resize(ciphertext.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
    // Rotate everything to the right
    ciphertext.rotate_right(CRYPTO_SECRETBOX_MACBYTES);
    // Copy mac into ciphertext
    ciphertext[..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(&cryptobox.mac);

    Ok(ciphertext)
}

/// Decrypts `ciphertext` with `nonce` and `key` in-place, without allocating
/// additional memory for the message
pub fn crypto_secretbox_open_easy_inplace(
    ciphertext: Vec<u8>,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    if ciphertext.len() < CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        let mut mac: Mac = [0u8; CRYPTO_SECRETBOX_MACBYTES];
        mac.copy_from_slice(&ciphertext[0..CRYPTO_SECRETBOX_MACBYTES]);

        let mut cryptobox = CryptoBox::from_data_and_mac(mac, ciphertext);

        cryptobox.data.rotate_left(CRYPTO_SECRETBOX_MACBYTES);
        cryptobox
            .data
            .resize(cryptobox.data.len() - CRYPTO_SECRETBOX_MACBYTES, 0);

        crypto_secretbox_open_detached_inplace(&mut cryptobox, nonce, key)?;

        Ok(cryptobox.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_secretbox_easy() {
        for i in 0..20 {
            use base64::encode;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key, Nonce};

            let key = crypto_secretbox_keygen();
            let nonce = randombytes_buf(CRYPTO_SECRETBOX_NONCEBYTES);

            let words = vec!["love Doge".to_string(); i];
            let message = words.join(" <3 ");

            let ciphertext = crypto_secretbox_easy(message.as_bytes(), &nonce, &key).unwrap();
            let so_ciphertext = secretbox::seal(
                message.as_bytes(),
                &Nonce::from_slice(&nonce).unwrap(),
                &Key::from_slice(&key).unwrap(),
            );
            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let decrypted = crypto_secretbox_open_easy(&ciphertext, &nonce, &key).unwrap();
            let so_decrypted = secretbox::open(
                &ciphertext,
                &Nonce::from_slice(&nonce).unwrap(),
                &Key::from_slice(&key).unwrap(),
            )
            .unwrap();

            assert_eq!(decrypted, message.as_bytes());
            assert_eq!(decrypted, so_decrypted);
        }
    }

    #[test]
    fn test_crypto_secretbox_easy_inplace() {
        for i in 0..20 {
            use base64::encode;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key, Nonce};

            let key = crypto_secretbox_keygen();
            let nonce = randombytes_buf(CRYPTO_SECRETBOX_NONCEBYTES);

            let words = vec!["love Doge".to_string(); i];
            let message: Vec<u8> = words.join(" <3 ").into();
            let message_copy = message.clone();

            let ciphertext = crypto_secretbox_easy_inplace(message, &nonce, &key).unwrap();
            let so_ciphertext = secretbox::seal(
                &message_copy,
                &Nonce::from_slice(&nonce).unwrap(),
                &Key::from_slice(&key).unwrap(),
            );
            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let ciphertext_copy = ciphertext.clone();
            let decrypted = crypto_secretbox_open_easy_inplace(ciphertext, &nonce, &key).unwrap();
            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &Nonce::from_slice(&nonce).unwrap(),
                &Key::from_slice(&key).unwrap(),
            )
            .unwrap();

            assert_eq!(&decrypted, &message_copy);
            assert_eq!(decrypted, so_decrypted);
        }
    }
}
