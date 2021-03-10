//! # Authenticated public-key cryptography functions
//!
//! Implements libsodium's public-key authenticated crypto boxes.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).
//!
//! # Classic API example
//!
//! ```
//! use dryoc::prelude::*;
//! use dryoc::rng::randombytes_buf; // Not included in prelude
//! use dryoc::constants::CRYPTO_BOX_NONCEBYTES; // Not included in prelude
//! use std::convert::TryInto;
//!
//! // Create a random sender keypair
//! let keypair_sender = crypto_box_keypair();
//!
//! // Create a random recipient keypair
//! let keypair_recipient = crypto_box_keypair();
//!
//! // Generate a random nonce
//! let nonce: Nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES).try_into().unwrap();
//!
//! let message = "hello".as_bytes();
//! // Encrypt message
//! let ciphertext = crypto_box_easy(
//!     message,
//!     &nonce,
//!     &keypair_recipient.public_key.0,
//!     &keypair_sender.secret_key.0,
//! )
//! .unwrap();
//!
//! // Decrypt message
//! let decrypted_message = crypto_box_open_easy(
//!     &ciphertext,
//!     &nonce,
//!     &keypair_sender.public_key.0,
//!     &keypair_recipient.secret_key.0,
//! )
//! .unwrap();
//!
//! assert_eq!(message, decrypted_message);
//! ```

use crate::constants::*;
use crate::crypto_box_impl::*;
use crate::crypto_secretbox::*;
use crate::crypto_secretbox_impl::*;
use crate::dryocbox::DryocBox;
use crate::error::Error;
use crate::keypair::*;
use crate::nonce::*;
use crate::types::*;

use zeroize::Zeroize;

/// Generates a public/secret key pair using OS provided data using
/// [rand_core::OsRng]
pub fn crypto_box_keypair() -> KeyPair {
    crypto_box_curve25519xsalsa20poly1305_keypair()
}

/// Deterministically derives a keypair from `seed`.
pub fn crypto_box_seed_keypair(seed: &InputBase) -> KeyPair {
    crypto_box_curve25519xsalsa20poly1305_seed_keypair(seed)
}

/// Computes a shared secret for the given `public_key` and `private_key`.
/// Resulting shared secret can be used with the precalculation interface.
pub fn crypto_box_beforenm(
    public_key: &PublicKeyBase,
    secret_key: &SecretKeyBase,
) -> SecretBoxKeyBase {
    crypto_box_curve25519xsalsa20poly1305_beforenm(public_key, secret_key)
}

/// Precalculation variant of [`crate::crypto_box::crypto_box_easy`]
pub fn crypto_box_detached_afternm(
    message: &InputBase,
    nonce: &Nonce,
    key: &SecretBoxKeyBase,
) -> Result<DryocBox, Error> {
    Ok(crypto_secretbox_detached(message, nonce, key).into())
}

/// In-place variant of [`crypto_box_detached_afternm`]
pub fn crypto_box_detached_afternm_inplace(
    dryocbox: &mut DryocBox,
    nonce: &Nonce,
    key: &SecretBoxKeyBase,
) {
    crypto_secretbox_detached_inplace(&mut dryocbox.mac, &mut dryocbox.data, nonce, key);
}

/// Detached variant of [`crypto_box_easy`]
pub fn crypto_box_detached(
    message: &InputBase,
    nonce: &Nonce,
    recipient_public_key: &PublicKeyBase,
    sender_secret_key: &SecretKeyBase,
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
    recipient_public_key: &PublicKeyBase,
    sender_secret_key: &SecretKeyBase,
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
    message: &InputBase,
    nonce: &Nonce,
    recipient_public_key: &PublicKeyBase,
    sender_secret_key: &SecretKeyBase,
) -> Result<OutputBase, Error> {
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
    recipient_public_key: &PublicKeyBase,
    sender_secret_key: &SecretKeyBase,
) -> Result<OutputBase, Error> {
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
    mac: &MacBase,
    ciphertext: &InputBase,
    nonce: &Nonce,
    key: &SecretBoxKeyBase,
) -> Result<OutputBase, Error> {
    crypto_secretbox_open_detached(mac, ciphertext, nonce, key)
}

/// In-place variant of [crypto_box_open_detached_afternm]
pub fn crypto_box_open_detached_afternm_inplace(
    mac: &MacBase,
    ciphertext: &mut Vec<u8>,
    nonce: &Nonce,
    key: &SecretBoxKeyBase,
) -> Result<(), Error> {
    crypto_secretbox_open_detached_inplace(mac, ciphertext, nonce, key)
}

/// Detached variant of [`crate::crypto_box::crypto_box_open_easy`]
pub fn crypto_box_open_detached(
    mac: &MacBase,
    ciphertext: &InputBase,
    nonce: &Nonce,
    recipient_public_key: &PublicKeyBase,
    sender_secret_key: &SecretKeyBase,
) -> Result<OutputBase, Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let res = crypto_box_open_detached_afternm(mac, ciphertext, nonce, &key)?;

    key.zeroize();

    Ok(res)
}

/// In-place variant of ['crypto_box_open_detached']
pub fn crypto_box_open_detached_inplace(
    mac: &MacBase,
    ciphertext: &mut Vec<u8>,
    nonce: &Nonce,
    recipient_public_key: &PublicKeyBase,
    sender_secret_key: &SecretKeyBase,
) -> Result<(), Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let res = crypto_box_open_detached_afternm_inplace(mac, ciphertext, nonce, &key);

    key.zeroize();

    res
}

/// Decrypts `ciphertext` with recipient's secret key `recipient_secret_key` and
/// sender's public key `sender_public_key` using `nonce`
pub fn crypto_box_open_easy(
    ciphertext: &InputBase,
    nonce: &Nonce,
    sender_public_key: &PublicKeyBase,
    recipient_secret_key: &SecretKeyBase,
) -> Result<OutputBase, Error> {
    if ciphertext.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else {
        let mut mac: MacBase = [0u8; CRYPTO_BOX_MACBYTES];
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
    ciphertext: &mut Vec<u8>,
    nonce: &Nonce,
    sender_public_key: &PublicKeyBase,
    recipient_secret_key: &SecretKeyBase,
) -> Result<(), Error> {
    if ciphertext.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else {
        let mut mac: MacBase = [0u8; CRYPTO_BOX_MACBYTES];
        mac.copy_from_slice(&ciphertext[0..CRYPTO_BOX_MACBYTES]);

        ciphertext.rotate_left(CRYPTO_BOX_MACBYTES);
        ciphertext.resize(ciphertext.len() - CRYPTO_BOX_MACBYTES, 0);

        match crypto_box_open_detached_inplace(
            &mac,
            ciphertext,
            nonce,
            sender_public_key,
            recipient_secret_key,
        ) {
            Err(err) => {
                ciphertext.resize(ciphertext.len() + CRYPTO_BOX_MACBYTES, 0);
                ciphertext.rotate_right(CRYPTO_BOX_MACBYTES);
                ciphertext[0..CRYPTO_BOX_MACBYTES].copy_from_slice(&mac);
                Err(err)
            }
            Ok(()) => Ok(()),
        }
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
            use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};
            use std::convert::TryInto;

            let keypair_sender = crypto_box_keypair();
            let keypair_recipient = crypto_box_keypair();
            let nonce: Nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES).try_into().unwrap();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let ciphertext = crypto_box_easy(
                message.as_bytes(),
                &nonce,
                &keypair_recipient.public_key.0,
                &keypair_sender.secret_key.0,
            )
            .unwrap();

            let so_ciphertext = box_::seal(
                message.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key.0).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key.0).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let m = crypto_box_open_easy(
                ciphertext.as_slice(),
                &nonce,
                &keypair_sender.public_key.0,
                &keypair_recipient.secret_key.0,
            )
            .unwrap();
            let so_m = box_::open(
                ciphertext.as_slice(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key.0).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key.0).unwrap(),
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
            use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};
            use std::convert::TryInto;

            let keypair_sender = crypto_box_keypair();
            let keypair_recipient = crypto_box_keypair();
            let nonce: Nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES).try_into().unwrap();
            let words = vec!["hello1".to_string(); i];
            let message: Vec<u8> = words.join(" :D ").as_bytes().to_vec();
            let message_copy = message.clone();

            let ciphertext = crypto_box_easy_inplace(
                message,
                &nonce,
                &keypair_recipient.public_key.0,
                &keypair_sender.secret_key.0,
            )
            .unwrap();
            let so_ciphertext = box_::seal(
                message_copy.as_slice(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key.0).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key.0).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let mut ciphertext_clone = ciphertext.clone();

            crypto_box_open_easy_inplace(
                &mut ciphertext_clone,
                &nonce,
                &keypair_sender.public_key.0,
                &keypair_recipient.secret_key.0,
            )
            .expect("decrypt failed");
            let so_m = box_::open(
                ciphertext.as_slice(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient.public_key.0).unwrap(),
                &SecretKey::from_slice(&keypair_sender.secret_key.0).unwrap(),
            )
            .expect("decrypt failed");

            assert_eq!(encode(&ciphertext_clone), encode(&message_copy));
            assert_eq!(encode(&so_m), encode(&message_copy));
        }
    }

    #[test]
    fn test_crypto_box_easy_invalid() {
        for _ in 0..20 {
            use std::convert::TryInto;

            let keypair_sender = crypto_box_keypair();
            let keypair_recipient = crypto_box_keypair();
            let nonce: Nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES).try_into().unwrap();

            let ciphertext: Vec<u8> = vec![];

            crypto_box_open_easy(
                &ciphertext,
                &nonce,
                &keypair_sender.public_key.0,
                &keypair_recipient.secret_key.0,
            )
            .expect_err("expected an error");
        }
    }
    #[test]
    fn test_crypto_box_easy_inplace_invalid() {
        for _ in 0..20 {
            use base64::encode;
            use std::convert::TryInto;

            let keypair_sender = crypto_box_keypair();
            let keypair_recipient = crypto_box_keypair();
            let nonce: Nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES).try_into().unwrap();

            let mut ciphertext: Vec<u8> = vec![];

            crypto_box_open_easy_inplace(
                &mut ciphertext,
                &nonce,
                &keypair_sender.public_key.0,
                &keypair_recipient.secret_key.0,
            )
            .expect_err("expected an error");

            ciphertext.resize(1024, 0);
            copy_randombytes(ciphertext.as_mut_slice());
            let ciphertext_copy = ciphertext.clone();

            crypto_box_open_easy_inplace(
                &mut ciphertext,
                &nonce,
                &keypair_sender.public_key.0,
                &keypair_recipient.secret_key.0,
            )
            .expect_err("expected an error");

            assert_eq!(ciphertext.len(), ciphertext_copy.len());
            assert_eq!(
                encode(&ciphertext[0..CRYPTO_BOX_MACBYTES]),
                encode(&ciphertext_copy[0..CRYPTO_BOX_MACBYTES])
            );
        }
    }

    #[test]
    fn test_crypto_box_seed_keypair() {
        use base64::encode;
        use sodiumoxide::crypto::box_::{keypair_from_seed, Seed};

        for _ in 0..10 {
            let seed = randombytes_buf(CRYPTO_BOX_SEEDBYTES);

            let keypair = crypto_box_seed_keypair(&seed);
            let (so_pk, so_sk) = keypair_from_seed(&Seed::from_slice(&seed).unwrap());

            assert_eq!(encode(&keypair.public_key.0), encode(so_pk.as_ref()));
            assert_eq!(encode(&keypair.secret_key.0), encode(so_sk.as_ref()));
        }
    }
}
