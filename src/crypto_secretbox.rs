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
use crate::error::Error;
use crate::rng::*;
use crate::types::*;

use generic_array::GenericArray;
use poly1305::{universal_hash::NewUniversalHash, Poly1305};
use salsa20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    XSalsa20,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Generates a random key using [randombytes_buf]
pub fn crypto_secretbox_keygen() -> SecretboxKey {
    let mut key: SecretboxKey = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
    let random_bytes = randombytes_buf(CRYPTO_SECRETBOX_KEYBYTES);
    key.copy_from_slice(&random_bytes);
    key
}

/// Detached version of [crypto_secretbox_easy]
pub fn crypto_secretbox_detached(message: &Input, nonce: &Nonce, key: &SecretboxKey) -> CryptoBox {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(message);

    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut *mac_key);

    let mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    cipher.apply_keystream(data.as_mut_slice());

    let mac: [u8; CRYPTO_SECRETBOX_MACBYTES] =
        mac.compute_unpadded(data.as_slice()).into_bytes().into();

    CryptoBox { mac, data }
}

/// Detached version of [crypto_secretbox_open_easy]
pub fn crypto_secretbox_open_detached(
    cryptobox: &CryptoBox,
    nonce: &Nonce,
    key: &Input,
) -> Result<Output, Error> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(&cryptobox.data);

    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut *mac_key);

    let mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    let mac: [u8; CRYPTO_SECRETBOX_MACBYTES] =
        mac.compute_unpadded(buffer.as_slice()).into_bytes().into();

    cipher.apply_keystream(buffer.as_mut_slice());

    if mac.ct_eq(&cryptobox.mac).unwrap_u8() == 1 {
        Ok(buffer)
    } else {
        Err(dryoc_error!("decryption error (authentication failure)"))
    }
}

/// Encrypts `message` with `nonce` and `key`
pub fn crypto_secretbox_easy(
    message: &Input,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    if message.len() > CRYPTO_SECRETBOX_MESSAGEBYTES_MAX {
        Err(dryoc_error!(format!(
            "Message length {} exceeds max message length {}",
            message.len(),
            CRYPTO_SECRETBOX_MESSAGEBYTES_MAX
        )))
    } else {
        let cryptobox = crypto_secretbox_detached(message, nonce, key);
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&cryptobox.mac);
        ciphertext.extend(cryptobox.data);
        Ok(ciphertext)
    }
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
        let mut cryptobox = CryptoBox {
            mac: [0; CRYPTO_SECRETBOX_MACBYTES],
            data: Vec::new(),
        };
        cryptobox
            .mac
            .copy_from_slice(&ciphertext[0..CRYPTO_SECRETBOX_MACBYTES]);
        cryptobox
            .data
            .extend_from_slice(&ciphertext[CRYPTO_SECRETBOX_MACBYTES..]);

        crypto_secretbox_open_detached(&cryptobox, nonce, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::*;

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
}
