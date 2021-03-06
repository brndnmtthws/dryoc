//! # Authenticated public-key cryptography functions
//!
//! Implements libsodium's public-key authenticated crypto boxes.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).
//!
//! # Basic usage
//!
//! ```
//! use dryoc::rng::randombytes_buf;
//! use dryoc::crypto_box::{crypto_box_keypair, crypto_box_easy, crypto_box_open_easy};
//! use dryoc::constants::CRYPTO_BOX_NONCEBYTES;
//!
//! // Create a sender keypair
//! let keypair_sender = crypto_box_keypair();
//!
//! // Recipient keypair
//! let keypair_recipient = crypto_box_keypair();
//!
//! // Generate a random nonce
//! let nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES);
//!
//! let message = "hello".as_bytes();
//! // Encrypt message
//! let ciphertext = crypto_box_easy(
//!     message,
//!     nonce.as_slice(),
//!     &keypair_recipient.public_key,
//!     &keypair_sender.secret_key,
//! )
//! .unwrap();
//!
//! // Decrypt message
//! let decrypted_message = crypto_box_open_easy(
//!     ciphertext.as_slice(),
//!     nonce.as_slice(),
//!     &keypair_sender.public_key,
//!     &keypair_recipient.secret_key,
//! )
//! .unwrap();
//!
//! assert_eq!(message, decrypted_message);
//! ```

use crate::constants::*;
use crate::crypto_box_impl::*;
use crate::crypto_secretbox::*;
use crate::crypto_secretbox_impl::*;
use crate::dryocbox::*;
use crate::error::Error;
use crate::keypair::*;
use crate::types::*;

use zeroize::Zeroize;

/// Generates a public/secret key pair using OS provided data using
/// [rand_core::OsRng]
pub fn crypto_box_keypair() -> KeyPair {
    crypto_box_curve25519xsalsa20poly1305_keypair()
}

/// Deterministically derives a keypair from `seed`.
pub fn crypto_box_seed_keypair(seed: &Input) -> KeyPair {
    crypto_box_curve25519xsalsa20poly1305_seed_keypair(seed)
}

/// Computes a shared secret for the given `public_key` and `private_key`.
/// Resulting shared secret can be used with the precalculation interface.
pub fn crypto_box_beforenm(public_key: &PublicKey, secret_key: &SecretKey) -> SecretboxKey {
    crypto_box_curve25519xsalsa20poly1305_beforenm(public_key, secret_key)
}

/// Precalculation variant of [crypto_box_easy]
pub fn crypto_box_detached_afternm(
    message: &Input,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<DryocBox, Error> {
    Ok(crypto_secretbox_detached(message, nonce, key))
}

/// In-place variant of [crypto_box_detached_afternm]
pub fn crypto_box_detached_afternm_inplace(
    dryocbox: &mut DryocBox,
    nonce: &Nonce,
    key: &SecretboxKey,
) {
    crypto_secretbox_detached_inplace(dryocbox, nonce, key);
}

/// Detached variant of [crypto_box_easy]
pub fn crypto_box_detached(
    message: &Input,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<DryocBox, Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let res = crypto_box_detached_afternm(message, nonce, &key)?;

    key.zeroize();

    Ok(res)
}

/// In-place variant of [crypto_box_detached]
pub fn crypto_box_detached_inplace(
    message: Vec<u8>,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<DryocBox, Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let mut dryocbox = DryocBox::from_data(message);

    crypto_box_detached_afternm_inplace(&mut dryocbox, nonce, &key);

    key.zeroize();

    Ok(dryocbox)
}

/// Encrypts `message` with recipient's public key `recipient_public_key` and
/// sender's secret key `sender_secret_key` using `nonce`
pub fn crypto_box_easy(
    message: &Input,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<Output, Error> {
    if message.len() > CRYPTO_BOX_MESSAGEBYTES_MAX {
        Err(dryoc_error!(format!(
            "Message length {} exceeds max message length {}",
            message.len(),
            CRYPTO_BOX_MESSAGEBYTES_MAX
        )))
    } else {
        let dryocbox =
            crypto_box_detached(message, nonce, recipient_public_key, sender_secret_key)?;
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&dryocbox.mac);
        ciphertext.extend(dryocbox.data);
        Ok(ciphertext)
    }
}

/// Encrypts `message` with recipient's public key `recipient_public_key` and
/// sender's secret key `sender_secret_key` using `nonce` in-place, without
/// allocated additional memory for the message
pub fn crypto_box_easy_inplace(
    message: Vec<u8>,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<Output, Error> {
    if message.len() > CRYPTO_BOX_MESSAGEBYTES_MAX {
        Err(dryoc_error!(format!(
            "Message length {} exceeds max message length {}",
            message.len(),
            CRYPTO_BOX_MESSAGEBYTES_MAX
        )))
    } else {
        let dryocbox =
            crypto_box_detached_inplace(message, nonce, recipient_public_key, sender_secret_key)?;

        let mut ciphertext = dryocbox.data;
        // Resize to prepend mac
        ciphertext.resize(ciphertext.len() + CRYPTO_BOX_MACBYTES, 0);
        // Rotate everything to the right
        ciphertext.rotate_right(CRYPTO_BOX_MACBYTES);
        // Copy mac into ciphertext
        ciphertext[..CRYPTO_BOX_MACBYTES].copy_from_slice(&dryocbox.mac);

        Ok(ciphertext)
    }
}

/// Precalculation variant of [crypto_box_open_easy]
pub fn crypto_box_open_detached_afternm(
    mac: &Mac,
    ciphertext: &Input,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    crypto_secretbox_open_detached(mac, ciphertext, nonce, key)
}

/// In-place variant of [crypto_box_open_detached_afternm]
pub fn crypto_box_open_detached_afternm_inplace(
    ciphertext: Vec<u8>,
    nonce: &Nonce,
    key: &SecretboxKey,
) -> Result<Output, Error> {
    let mut mac: Mac = [0u8; CRYPTO_BOX_MACBYTES];
    mac.copy_from_slice(&ciphertext[0..CRYPTO_BOX_MACBYTES]);

    let mut dryocbox = DryocBox::from_data_and_mac(mac, ciphertext);

    dryocbox.data.rotate_left(CRYPTO_BOX_MACBYTES);
    dryocbox
        .data
        .resize(dryocbox.data.len() - CRYPTO_BOX_MACBYTES, 0);

    crypto_secretbox_open_detached_inplace(&mut dryocbox, nonce, key)?;

    Ok(dryocbox.data)
}

/// Detached variant of [crypto_box_easy_open]
pub fn crypto_box_open_detached(
    mac: &Mac,
    ciphertext: &Input,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<Output, Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let res = crypto_box_open_detached_afternm(mac, ciphertext, nonce, &key)?;

    key.zeroize();

    Ok(res)
}

/// In-place variant of [crypto_box_open_detached]
pub fn crypto_box_open_detached_inplace(
    ciphertext: Vec<u8>,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<Output, Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let res = crypto_box_open_detached_afternm_inplace(ciphertext, nonce, &key)?;

    key.zeroize();

    Ok(res)
}

/// Decrypts `ciphertext` with recipient's secret key `recipient_secret_key` and
/// sender's public key `sender_public_key` using `nonce`
pub fn crypto_box_open_easy(
    ciphertext: &Input,
    nonce: &Nonce,
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<Output, Error> {
    if ciphertext.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else {
        let mut mac: Mac = [0u8; CRYPTO_BOX_MACBYTES];
        mac.copy_from_slice(&ciphertext[0..CRYPTO_BOX_MACBYTES]);

        crypto_box_open_detached(
            &mac,
            &ciphertext[CRYPTO_BOX_MACBYTES..],
            nonce,
            sender_public_key,
            recipient_secret_key,
        )
    }
}

/// Decrypts `ciphertext` with recipient's secret key `recipient_secret_key` and
/// sender's public key `sender_public_key` using `nonce` in-place, without
/// allocated additional memory for the message
pub fn crypto_box_open_easy_inplace(
    ciphertext: Vec<u8>,
    nonce: &Nonce,
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<Output, Error> {
    if ciphertext.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else {
        let mut mac: Mac = [0u8; CRYPTO_BOX_MACBYTES];
        mac.copy_from_slice(&ciphertext[0..CRYPTO_BOX_MACBYTES]);

        crypto_box_open_detached(
            &mac,
            &ciphertext[CRYPTO_BOX_MACBYTES..],
            nonce,
            sender_public_key,
            recipient_secret_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::*;

    #[test]
    fn test_crypto_box_easy() {
        for i in 0..20 {
            use base64::encode;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{Nonce, PublicKey, SecretKey};

            let keypair_sender = crypto_box_keypair();
            let keypair_recipient = crypto_box_keypair();
            let nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES);
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let ciphertext = crypto_box_easy(
                message.as_bytes(),
                nonce.as_slice(),
                &keypair_recipient.public_key,
                &keypair_sender.secret_key,
            )
            .unwrap();

            let so_ciphertext = box_::seal(
                message.as_bytes(),
                &Nonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let m = crypto_box_open_easy(
                ciphertext.as_slice(),
                nonce.as_slice(),
                &keypair_sender.public_key,
                &keypair_recipient.secret_key,
            )
            .unwrap();
            let so_m = box_::open(
                ciphertext.as_slice(),
                &Nonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key).unwrap(),
            )
            .unwrap();

            assert_eq!(m, message.as_bytes());
            assert_eq!(m, so_m);
        }
    }

    #[test]
    fn test_crypto_box_easy_inplace() {
        for i in 0..20 {
            use base64::encode;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{Nonce, PublicKey, SecretKey};

            let keypair_sender = crypto_box_keypair();
            let keypair_recipient = crypto_box_keypair();
            let nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES);
            let words = vec!["hello1".to_string(); i];
            let message: Vec<u8> = words.join(" :D ").as_bytes().to_vec();
            let message_copy = message.clone();

            let ciphertext = crypto_box_easy_inplace(
                message,
                nonce.as_slice(),
                &keypair_recipient.public_key,
                &keypair_sender.secret_key,
            )
            .unwrap();
            let so_ciphertext = box_::seal(
                message_copy.as_slice(),
                &Nonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let ciphertext_clone = ciphertext.clone();

            let m = crypto_box_open_easy_inplace(
                ciphertext_clone,
                nonce.as_slice(),
                &keypair_sender.public_key,
                &keypair_recipient.secret_key,
            )
            .unwrap();
            assert_eq!(encode(&m), encode(&message_copy));
        }
    }
}
