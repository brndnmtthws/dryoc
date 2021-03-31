/*!
# Authenticated encryption functions

Implements libsodium's secret-key authenticated crypto boxes.

For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox).

# Classic API example

```
use dryoc::rng::randombytes_buf;
use dryoc::crypto_secretbox::{Nonce, crypto_secretbox_keygen, crypto_secretbox_easy, crypto_secretbox_open_easy, Key};
use dryoc::constants::CRYPTO_SECRETBOX_NONCEBYTES;
use dryoc::types::*;

let key: Key = crypto_secretbox_keygen();
let nonce = Nonce::gen();

let message = "I Love Doge!";

// Encrypt
let ciphertext = crypto_secretbox_easy(message.as_bytes(), &nonce, &key).unwrap();

// Decrypt
let decrypted = crypto_secretbox_open_easy(&ciphertext, &nonce, &key).unwrap();

assert_eq!(decrypted, message.as_bytes());
```
*/

use crate::constants::{
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use crate::crypto_secretbox_impl::*;
use crate::dryocsecretbox::DryocSecretBox;
use crate::error::Error;
use crate::types::*;

/// Container for crypto secret box message authentication code.
pub type Mac = StackByteArray<CRYPTO_SECRETBOX_MACBYTES>;
/// A nonce for secret key authenticated boxes.
pub type Nonce = StackByteArray<CRYPTO_SECRETBOX_NONCEBYTES>;
/// A secret for secret key authenticated boxes.
pub type Key = StackByteArray<CRYPTO_SECRETBOX_KEYBYTES>;

/// Generates a random key using [crate::rng::copy_randombytes].
pub fn crypto_secretbox_keygen<K>() -> K
where
    K: NewByteArray<CRYPTO_SECRETBOX_KEYBYTES>,
{
    K::gen()
}

/// Detached version of [crypto_secretbox_easy].
///
/// Compatible with libsodium's `crypto_secretbox_detached`.
pub fn crypto_secretbox_detached(message: &InputBase, nonce: &Nonce, key: &Key) -> DryocSecretBox {
    let mut dryocsecretbox = DryocSecretBox::with_data(message);

    crypto_secretbox_detached_inplace(
        &mut dryocsecretbox.tag,
        &mut dryocsecretbox.data,
        nonce,
        key,
    );

    dryocsecretbox
}

/// Detached version of [crypto_secretbox_open_easy].
///
/// Compatible with libsodium's `crypto_secretbox_open_detached`.
pub fn crypto_secretbox_open_detached(
    mac: &Mac,
    ciphertext: &InputBase,
    nonce: &Nonce,
    key: &Key,
) -> Result<OutputBase, Error> {
    let mut dryocsecretbox = DryocSecretBox::with_data_and_mac(mac, ciphertext);

    crypto_secretbox_open_detached_inplace(
        &dryocsecretbox.tag,
        &mut dryocsecretbox.data,
        nonce,
        key,
    )?;

    Ok(dryocsecretbox.data)
}

/// Encrypts `message` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_easy`.
pub fn crypto_secretbox_easy(
    message: &InputBase,
    nonce: &Nonce,
    key: &Key,
) -> Result<OutputBase, Error> {
    let dryocsecretbox = crypto_secretbox_detached(message, nonce, key);
    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(dryocsecretbox.tag.as_slice());
    ciphertext.extend(dryocsecretbox.data);
    Ok(ciphertext)
}

/// Decrypts `ciphertext` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_open_easy`.
pub fn crypto_secretbox_open_easy(
    ciphertext: &InputBase,
    nonce: &Nonce,
    key: &Key,
) -> Result<OutputBase, Error> {
    if ciphertext.len() < CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        use std::convert::TryInto;
        let mac: Mac = ciphertext[0..CRYPTO_SECRETBOX_MACBYTES].try_into()?;

        crypto_secretbox_open_detached(&mac, &ciphertext[CRYPTO_SECRETBOX_MACBYTES..], nonce, key)
    }
}

/// Encrypts `message` with `nonce` and `key` in-place, without allocating
/// additional memory for the ciphertext.
pub fn crypto_secretbox_easy_inplace(
    message: Vec<u8>,
    nonce: &Nonce,
    key: &Key,
) -> Result<OutputBase, Error> {
    let mut dryocsecretbox = DryocSecretBox::from_data(message);

    crypto_secretbox_detached_inplace(
        &mut dryocsecretbox.tag,
        &mut dryocsecretbox.data,
        nonce,
        key,
    );

    let mut ciphertext = dryocsecretbox.data;
    // Resize to prepend mac
    ciphertext.resize(ciphertext.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
    // Rotate everything to the right
    ciphertext.rotate_right(CRYPTO_SECRETBOX_MACBYTES);
    // Copy mac into ciphertext
    ciphertext[..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(dryocsecretbox.tag.as_slice());

    Ok(ciphertext)
}

/// Decrypts `ciphertext` with `nonce` and `key` in-place, without allocating
/// additional memory for the message.
pub fn crypto_secretbox_open_easy_inplace(
    ciphertext: Vec<u8>,
    nonce: &Nonce,
    key: &Key,
) -> Result<OutputBase, Error> {
    if ciphertext.len() < CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        use std::convert::TryInto;
        let mac: Mac = ciphertext[0..CRYPTO_SECRETBOX_MACBYTES].try_into()?;

        let mut dryocsecretbox = DryocSecretBox::from_data_and_mac(mac, ciphertext);

        dryocsecretbox.data.rotate_left(CRYPTO_SECRETBOX_MACBYTES);
        dryocsecretbox
            .data
            .resize(dryocsecretbox.data.len() - CRYPTO_SECRETBOX_MACBYTES, 0);

        crypto_secretbox_open_detached_inplace(
            &dryocsecretbox.tag,
            &mut dryocsecretbox.data,
            nonce,
            key,
        )?;

        Ok(dryocsecretbox.data)
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
            use sodiumoxide::crypto::secretbox::{Key, Nonce as SONonce};

            let key = crypto_secretbox_keygen();
            let nonce: Nonce = Nonce::gen();

            let words = vec!["love Doge".to_string(); i];
            let message = words.join(" <3 ");

            let ciphertext = crypto_secretbox_easy(message.as_bytes(), &nonce, &key).unwrap();
            let so_ciphertext = secretbox::seal(
                message.as_bytes(),
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &Key::from_slice(key.as_slice()).unwrap(),
            );
            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let decrypted = crypto_secretbox_open_easy(&ciphertext, &nonce, &key).unwrap();
            let so_decrypted = secretbox::open(
                &ciphertext,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &Key::from_slice(key.as_slice()).unwrap(),
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
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            let key = crypto_secretbox_keygen();
            let nonce = Nonce::gen();

            let words = vec!["love Doge".to_string(); i];
            let message: Vec<u8> = words.join(" <3 ").into();
            let message_copy = message.clone();

            let ciphertext = crypto_secretbox_easy_inplace(message, &nonce, &key).unwrap();
            let so_ciphertext = secretbox::seal(
                &message_copy,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &SOKey::from_slice(key.as_slice()).unwrap(),
            );
            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let ciphertext_copy = ciphertext.clone();
            let decrypted = crypto_secretbox_open_easy_inplace(ciphertext, &nonce, &key).unwrap();
            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &SOKey::from_slice(key.as_slice()).unwrap(),
            )
            .expect("decrypt failed");

            assert_eq!(&decrypted, &message_copy);
            assert_eq!(decrypted, so_decrypted);
        }
    }
}
