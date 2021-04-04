/*!
# Authenticated public-key cryptography functions

Implements libsodium's public-key authenticated crypto boxes.

For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).

# Classic API example

```
use dryoc::crypto_box::*;
use dryoc::types::*;
use dryoc::constants::CRYPTO_BOX_MACBYTES;

// Create a random sender keypair
let (sender_pk, sender_sk) = crypto_box_keypair();

// Create a random recipient keypair
let (recipient_pk, recipient_sk) = crypto_box_keypair();

// Generate a random nonce
let nonce = Nonce::gen();

let message = "hello".as_bytes();
// Encrypt message
let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES];
crypto_box_easy(
    &mut ciphertext,
    message,
    &nonce,
    &recipient_pk,
    &sender_sk,
)
.expect("encrypt failed");

// Decrypt message
let mut decrypted_message = vec![0u8; ciphertext.len() - CRYPTO_BOX_MACBYTES];
crypto_box_open_easy(
    &mut decrypted_message,
    &ciphertext,
    &nonce,
    &sender_pk,
    &recipient_sk,
)
.expect("decrypt failed");

assert_eq!(message, decrypted_message);
```
*/

use zeroize::Zeroize;

use crate::constants::*;
use crate::crypto_box_impl::*;
use crate::crypto_secretbox::*;
use crate::crypto_secretbox_impl::*;
use crate::error::Error;
use crate::types::*;

/// Container for crypto box message authentication code.
pub type Mac = [u8; CRYPTO_BOX_MACBYTES];

/// A nonce for crypto boxes.
pub type Nonce = [u8; CRYPTO_BOX_NONCEBYTES];
/// A public key for public key authenticated crypto boxes.
pub type PublicKey = [u8; CRYPTO_BOX_PUBLICKEYBYTES];
/// A secret key for public key authenticated crypto boxes.
pub type SecretKey = [u8; CRYPTO_BOX_SECRETKEYBYTES];

/// Generates a public/secret key pair using OS provided data using
/// [rand_core::OsRng].
pub fn crypto_box_keypair() -> (PublicKey, SecretKey) {
    crypto_box_curve25519xsalsa20poly1305_keypair()
}

/// Deterministically derives a keypair from `seed`.
///
/// Compatible with libsodium's `crypto_box_seed_keypair`.
pub fn crypto_box_seed_keypair(seed: &[u8]) -> (PublicKey, SecretKey) {
    crypto_box_curve25519xsalsa20poly1305_seed_keypair(seed)
}

/// Computes a shared secret for the given `public_key` and `private_key`.
/// Resulting shared secret can be used with the precalculation interface.
///
/// Compatible with libsodium's `crypto_box_beforenm`.
pub fn crypto_box_beforenm(public_key: &PublicKey, secret_key: &SecretKey) -> Key {
    crypto_box_curve25519xsalsa20poly1305_beforenm(public_key, secret_key)
}

/// Precalculation variant of [`crate::crypto_box::crypto_box_easy`]
///
/// Compatible with libsodium's `crypto_box_detached_afternm`.
pub fn crypto_box_detached_afternm(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    Ok(crypto_secretbox_detached(ciphertext, mac, message, nonce, key).into())
}

/// In-place variant of [`crypto_box_detached_afternm`].
pub fn crypto_box_detached_afternm_inplace(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    nonce: &Nonce,
    key: &Key,
) {
    crypto_secretbox_detached_inplace(ciphertext, mac, nonce, key);
}

/// Detached variant of [`crypto_box_easy`].
///
/// Compatible with libsodium's `crypto_box_detached`.
pub fn crypto_box_detached(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    crypto_box_detached_afternm(ciphertext, mac, message, nonce, &key)?;

    key.zeroize();

    Ok(())
}

/// In-place variant of [crypto_box_detached]
pub fn crypto_box_detached_inplace(
    message: &mut [u8],
    mac: &mut Mac,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    crypto_box_detached_afternm_inplace(message, mac, nonce, &key);

    key.zeroize();

    Ok(())
}

/// Encrypts `message` with recipient's public key `recipient_public_key` and
/// sender's secret key `sender_secret_key` using `nonce`.
///
/// Compatible with libsodium's `crypto_box_easy`.
pub fn crypto_box_easy(
    ciphertext: &mut [u8],
    message: &[u8],
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<(), Error> {
    if ciphertext.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "ciphertext length {} less than minimum {}",
            ciphertext.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else if message.len() > CRYPTO_BOX_MESSAGEBYTES_MAX {
        Err(dryoc_error!(format!(
            "message length {} exceeds max message length {}",
            message.len(),
            CRYPTO_BOX_MESSAGEBYTES_MAX
        )))
    } else {
        let (mac, ciphertext) = ciphertext.split_at_mut(CRYPTO_BOX_MACBYTES);
        let mac = mac.as_mut_array();
        crypto_box_detached(
            ciphertext,
            mac,
            message,
            nonce,
            recipient_public_key,
            sender_secret_key,
        )
    }
}

/// Encrypts `message` with recipient's public key `recipient_public_key` and
/// sender's secret key `sender_secret_key` using `nonce` in-place, without
/// allocated additional memory for the message.
pub fn crypto_box_easy_inplace(
    data: &mut [u8],
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<(), Error> {
    if data.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Message length {} less than {}, impossibly small",
            data.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else if data.len() > CRYPTO_BOX_MESSAGEBYTES_MAX {
        Err(dryoc_error!(format!(
            "Message length {} exceeds max message length {}",
            data.len(),
            CRYPTO_BOX_MESSAGEBYTES_MAX
        )))
    } else {
        data.rotate_right(CRYPTO_BOX_MACBYTES);

        let (mac, data) = data.split_at_mut(CRYPTO_BOX_MACBYTES);
        let mac = mac.as_mut_array();

        crypto_box_detached_inplace(data, mac, nonce, recipient_public_key, sender_secret_key)?;

        Ok(())
    }
}

/// Precalculation variant of [crypto_box_open_easy].
///
/// Compatible with libsodium's `crypto_box_open_detached_afternm`.
pub fn crypto_box_open_detached_afternm(
    message: &mut [u8],
    mac: &Mac,
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    crypto_secretbox_open_detached(message, mac, ciphertext, nonce, key)
}

/// In-place variant of [crypto_box_open_detached_afternm].
pub fn crypto_box_open_detached_afternm_inplace(
    data: &mut [u8],
    mac: &Mac,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    crypto_secretbox_open_detached_inplace(data, mac, nonce, key)
}

/// Detached variant of [`crate::crypto_box::crypto_box_open_easy`].
///
/// Compatible with libsodium's `crypto_box_open_detached`.
pub fn crypto_box_open_detached(
    message: &mut [u8],
    mac: &Mac,
    ciphertext: &[u8],
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    let res = crypto_box_open_detached_afternm(message, mac, ciphertext, nonce, &key)?;

    key.zeroize();

    Ok(res)
}

/// In-place variant of [crypto_box_open_detached].
pub fn crypto_box_open_detached_inplace(
    data: &mut [u8],
    mac: &Mac,
    nonce: &Nonce,
    recipient_public_key: &PublicKey,
    sender_secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    crypto_box_open_detached_afternm_inplace(data, mac, nonce, &key)?;

    key.zeroize();

    Ok(())
}

/// Decrypts `ciphertext` with recipient's secret key `recipient_secret_key` and
/// sender's public key `sender_public_key` using `nonce`.
///
/// Compatible with libsodium's `crypto_box_open_easy`.
pub fn crypto_box_open_easy(
    message: &mut [u8],
    ciphertext: &[u8],
    nonce: &Nonce,
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<(), Error> {
    if ciphertext.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else {
        let (mac, ciphertext) = ciphertext.split_at(CRYPTO_BOX_MACBYTES);
        let mac = mac.as_array();

        crypto_box_open_detached(
            message,
            mac,
            &ciphertext,
            nonce,
            sender_public_key,
            recipient_secret_key,
        )
    }
}

/// Decrypts `ciphertext` with recipient's secret key `recipient_secret_key` and
/// sender's public key `sender_public_key` using `nonce` in-place, without
/// allocated additional memory for the message.
pub fn crypto_box_open_easy_inplace(
    data: &mut [u8],
    nonce: &Nonce,
    sender_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<(), Error> {
    if data.len() < CRYPTO_BOX_MACBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            data.len(),
            CRYPTO_BOX_MACBYTES
        )))
    } else {
        let (mac, d) = data.split_at_mut(CRYPTO_BOX_MACBYTES);
        let mac = mac.as_array();

        crypto_box_open_detached_inplace(d, mac, nonce, sender_public_key, recipient_secret_key)?;

        data.rotate_left(CRYPTO_BOX_MACBYTES);

        Ok(())
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

            let (sender_pk, sender_sk) = crypto_box_keypair();
            let (recipient_pk, recipient_sk) = crypto_box_keypair();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES];
            crypto_box_easy(
                &mut ciphertext,
                message.as_bytes(),
                &nonce,
                &recipient_pk,
                &sender_sk,
            )
            .expect("encrypt failed");

            let so_ciphertext = box_::seal(
                message.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
                &SecretKey::from_slice(&sender_sk).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let mut m = vec![0u8; ciphertext.len() - CRYPTO_BOX_MACBYTES];
            crypto_box_open_easy(
                &mut m,
                ciphertext.as_slice(),
                &nonce,
                &sender_pk,
                &recipient_sk,
            )
            .expect("decrypt failed");
            let so_m = box_::open(
                ciphertext.as_slice(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
                &SecretKey::from_slice(&sender_sk).unwrap(),
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

            let (sender_pk, sender_sk) = crypto_box_keypair();
            let (recipient_pk, recipient_sk) = crypto_box_keypair();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message: Vec<u8> = words.join(" :D ").as_bytes().to_vec();
            let message_copy = message.clone();

            let mut ciphertext = message.clone();
            ciphertext.resize(message.len() + CRYPTO_BOX_MACBYTES, 0);
            crypto_box_easy_inplace(&mut ciphertext, &nonce, &recipient_pk, &sender_sk)
                .expect("encrypt failed");
            let so_ciphertext = box_::seal(
                message_copy.as_slice(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
                &SecretKey::from_slice(&sender_sk).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let mut ciphertext_clone = ciphertext.clone();
            crypto_box_open_easy_inplace(&mut ciphertext_clone, &nonce, &sender_pk, &recipient_sk)
                .expect("decrypt failed");
            ciphertext_clone.resize(message.len(), 0);

            let so_m = box_::open(
                ciphertext.as_slice(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
                &SecretKey::from_slice(&sender_sk).unwrap(),
            )
            .expect("decrypt failed");

            assert_eq!(encode(&ciphertext_clone), encode(&message_copy));
            assert_eq!(encode(&so_m), encode(&message_copy));
        }
    }

    #[test]
    fn test_crypto_box_easy_invalid() {
        for _ in 0..20 {
            let (sender_pk, sender_sk) = crypto_box_keypair();
            let (recipient_pk, recipient_sk) = crypto_box_keypair();
            let nonce = Nonce::gen();

            let mut ciphertext: Vec<u8> = vec![];
            let message: Vec<u8> = vec![];

            crypto_box_open_easy(&mut ciphertext, &message, &nonce, &sender_pk, &recipient_sk)
                .expect_err("expected an error");
        }
    }
    #[test]
    fn test_crypto_box_easy_inplace_invalid() {
        for _ in 0..20 {
            use base64::encode;

            let (sender_pk, sender_sk) = crypto_box_keypair();
            let (recipient_pk, recipient_sk) = crypto_box_keypair();
            let nonce = Nonce::gen();

            let mut ciphertext: Vec<u8> = vec![];

            crypto_box_open_easy_inplace(&mut ciphertext, &nonce, &sender_pk, &recipient_sk)
                .expect_err("expected an error");

            ciphertext.resize(1024, 0);
            copy_randombytes(ciphertext.as_mut_slice());
            let ciphertext_copy = ciphertext.clone();

            crypto_box_open_easy_inplace(&mut ciphertext, &nonce, &sender_pk, &recipient_sk)
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

            let (pk, sk) = crypto_box_seed_keypair(&seed);
            let (so_pk, so_sk) = keypair_from_seed(&Seed::from_slice(&seed).unwrap());

            assert_eq!(encode(&pk), encode(so_pk.as_ref()));
            assert_eq!(encode(&sk), encode(so_sk.as_ref()));
        }
    }
}
