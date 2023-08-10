//! # Authenticated public-key cryptography functions
//!
//! Implements libsodium's public-key authenticated crypto boxes.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption).
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_box::*;
//! use dryoc::constants::CRYPTO_BOX_MACBYTES;
//! use dryoc::types::*;
//!
//! // Create a random sender keypair
//! let (sender_pk, sender_sk) = crypto_box_keypair();
//!
//! // Create a random recipient keypair
//! let (recipient_pk, recipient_sk) = crypto_box_keypair();
//!
//! // Generate a random nonce
//! let nonce = Nonce::gen();
//!
//! let message = "hello".as_bytes();
//! // Encrypt message
//! let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES];
//! crypto_box_easy(&mut ciphertext, message, &nonce, &recipient_pk, &sender_sk)
//!     .expect("encrypt failed");
//!
//! // Decrypt message
//! let mut decrypted_message = vec![0u8; ciphertext.len() - CRYPTO_BOX_MACBYTES];
//! crypto_box_open_easy(
//!     &mut decrypted_message,
//!     &ciphertext,
//!     &nonce,
//!     &sender_pk,
//!     &recipient_sk,
//! )
//! .expect("decrypt failed");
//!
//! assert_eq!(message, decrypted_message);
//! ```

use zeroize::Zeroize;

use super::crypto_generichash::{
    crypto_generichash_final, crypto_generichash_init, crypto_generichash_update,
};
use crate::classic::crypto_box_impl::*;
use crate::classic::crypto_secretbox::*;
use crate::classic::crypto_secretbox_impl::*;
use crate::constants::*;
use crate::error::Error;
use crate::types::*;

/// Crypto box message authentication code.
pub type Mac = [u8; CRYPTO_BOX_MACBYTES];

/// Nonce for crypto boxes.
pub type Nonce = [u8; CRYPTO_BOX_NONCEBYTES];
/// Public key for public key authenticated crypto boxes.
pub type PublicKey = [u8; CRYPTO_BOX_PUBLICKEYBYTES];
/// Secret key for public key authenticated crypto boxes.
pub type SecretKey = [u8; CRYPTO_BOX_SECRETKEYBYTES];

/// In-place variant of [`crypto_box_keypair`]
pub fn crypto_box_keypair_inplace(public_key: &mut PublicKey, secret_key: &mut SecretKey) {
    crypto_box_curve25519xsalsa20poly1305_keypair_inplace(public_key, secret_key)
}

/// In-place variant of [`crypto_box_seed_keypair`]
pub fn crypto_box_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &[u8],
) {
    crypto_box_curve25519xsalsa20poly1305_seed_keypair_inplace(public_key, secret_key, seed)
}

/// Generates a public/secret key pair using OS provided data using
/// [`rand_core::OsRng`].
pub fn crypto_box_keypair() -> (PublicKey, SecretKey) {
    crypto_box_curve25519xsalsa20poly1305_keypair()
}

/// Deterministically derives a keypair from `seed`, which can be of arbitrary
/// length.
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

/// Precalculation variant of
/// [`crypto_box_easy`].
///
/// Compatible with libsodium's `crypto_box_detached_afternm`.
pub fn crypto_box_detached_afternm(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) {
    crypto_secretbox_detached(ciphertext, mac, message, nonce, key)
}

/// In-place variant of [`crypto_box_detached_afternm`].
pub fn crypto_box_detached_afternm_inplace(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    nonce: &Nonce,
    key: &Key,
) {
    crypto_secretbox_detached_inplace(ciphertext, mac, nonce, key)
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
) {
    let mut key = crypto_box_beforenm(recipient_public_key, sender_secret_key);

    crypto_box_detached_afternm(ciphertext, mac, message, nonce, &key);

    key.zeroize();
}

/// In-place variant of [`crypto_box_detached`].
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

/// Encrypts `message` with recipient's public key `recipient_public_key`,
/// sender's secret key `sender_secret_key`, and `nonce`. The result is placed
/// into `ciphertext` which must be the length of the message plus
/// [`CRYPTO_BOX_MACBYTES`] bytes, for the message tag.
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
        );

        Ok(())
    }
}

pub(crate) fn crypto_box_seal_nonce(nonce: &mut Nonce, epk: &PublicKey, rpk: &SecretKey) {
    let mut state = crypto_generichash_init(None, CRYPTO_BOX_NONCEBYTES).expect("state");
    crypto_generichash_update(&mut state, epk);
    crypto_generichash_update(&mut state, rpk);
    crypto_generichash_final(state, nonce).expect("hash error");
}

/// Encrypts `message` with recipient's public key `recipient_public_key`, using
/// an ephemeral keypair and nonce. The length of `ciphertext` must be the
/// length of the message plus [`CRYPTO_BOX_SEALBYTES`] bytes for the message
/// tag and ephemeral public key.
///
/// Compatible with libsodium's `crypto_box_seal`.
pub fn crypto_box_seal(
    ciphertext: &mut [u8],
    message: &[u8],
    recipient_public_key: &PublicKey,
) -> Result<(), Error> {
    if ciphertext.len() < message.len() + CRYPTO_BOX_SEALBYTES {
        Err(dryoc_error!(format!(
            "ciphertext length invalid ({} != {}",
            ciphertext.len(),
            message.len() + CRYPTO_BOX_SEALBYTES,
        )))
    } else {
        let mut nonce = Nonce::new_byte_array();
        let (mut epk, mut esk) = crypto_box_keypair();
        crypto_box_seal_nonce(&mut nonce, &epk, recipient_public_key);

        crypto_box_easy(
            &mut ciphertext[CRYPTO_BOX_PUBLICKEYBYTES..],
            message,
            &nonce,
            recipient_public_key,
            &esk,
        )?;

        ciphertext[..CRYPTO_BOX_PUBLICKEYBYTES].copy_from_slice(&epk);

        epk.zeroize();
        esk.zeroize();
        nonce.zeroize();

        Ok(())
    }
}

/// Encrypts `message` with recipient's public key `recipient_public_key` and
/// sender's secret key `sender_secret_key` using `nonce` in-place in `data`,
/// without allocated additional memory for the message.
///
/// The caller of this function is responsible for allocating `data` such that
/// there's enough capacity for the message plus the additional
/// [`CRYPTO_BOX_MACBYTES`] bytes for the authentication tag.
///
/// For this reason, the last [`CRYPTO_BOX_MACBYTES`] bytes from the input
/// is ignored. The length of `data` should be the length of your message plus
/// [`CRYPTO_BOX_MACBYTES`] bytes.
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

/// Precalculation variant of [`crypto_box_open_easy`].
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

/// In-place variant of [`crypto_box_open_detached_afternm`].
pub fn crypto_box_open_detached_afternm_inplace(
    data: &mut [u8],
    mac: &Mac,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    crypto_secretbox_open_detached_inplace(data, mac, nonce, key)
}

/// Detached variant of [`crypto_box_open_easy`].
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

    crypto_box_open_detached_afternm(message, mac, ciphertext, nonce, &key)?;

    key.zeroize();

    Ok(())
}

/// In-place variant of [`crypto_box_open_detached`].
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
            ciphertext,
            nonce,
            sender_public_key,
            recipient_secret_key,
        )
    }
}

/// Decrypts a sealed box from `ciphertext` with recipient's secret key
/// `recipient_secret_key`, placing the result into `message`. The nonce and
/// public are derived from `ciphertext`. `message` length should be equal to
/// the length of `ciphertext` minus [`CRYPTO_BOX_SEALBYTES`] bytes for the
/// message tag and ephemeral public key.
///
/// Compatible with libsodium's `crypto_box_seal_open`.
pub fn crypto_box_seal_open(
    message: &mut [u8],
    ciphertext: &[u8],
    recipient_public_key: &PublicKey,
    recipient_secret_key: &SecretKey,
) -> Result<(), Error> {
    if ciphertext.len() < CRYPTO_BOX_SEALBYTES {
        Err(dryoc_error!(format!(
            "Impossibly small box ({} < {}",
            ciphertext.len(),
            CRYPTO_BOX_SEALBYTES,
        )))
    } else if message.len() != ciphertext.len() - CRYPTO_BOX_SEALBYTES {
        Err(dryoc_error!(format!(
            "message length invalid ({} != {}",
            message.len(),
            ciphertext.len() - CRYPTO_BOX_SEALBYTES,
        )))
    } else {
        let mut nonce = Nonce::new_byte_array();
        let mut epk = PublicKey::new_byte_array();
        epk.copy_from_slice(&ciphertext[..CRYPTO_BOX_PUBLICKEYBYTES]);

        crypto_box_seal_nonce(&mut nonce, &epk, recipient_public_key);

        crypto_box_open_easy(
            message,
            &ciphertext[CRYPTO_BOX_PUBLICKEYBYTES..],
            &nonce,
            &epk,
            recipient_secret_key,
        )
    }
}

/// Decrypts `ciphertext` with recipient's secret key `recipient_secret_key` and
/// sender's public key `sender_public_key` with `nonce` in-place in `data`,
/// without allocated additional memory for the message.
///
/// The caller of this function is responsible for allocating `data` such that
/// there's enough capacity for the message plus the additional
/// [`CRYPTO_BOX_MACBYTES`] bytes for the authentication tag.
///
/// After opening the box, the last [`CRYPTO_BOX_MACBYTES`] bytes can be
/// discarded or ignored at the caller's preference.
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
            use base64::engine::general_purpose;
            use base64::Engine as _;
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

            assert_eq!(
                general_purpose::STANDARD_NO_PAD.encode(&ciphertext),
                general_purpose::STANDARD_NO_PAD.encode(&so_ciphertext)
            );

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
            use base64::engine::general_purpose;
            use base64::Engine as _;
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

            assert_eq!(
                general_purpose::STANDARD_NO_PAD.encode(&ciphertext),
                general_purpose::STANDARD_NO_PAD.encode(&so_ciphertext)
            );

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

            assert_eq!(
                general_purpose::STANDARD_NO_PAD.encode(&ciphertext_clone),
                general_purpose::STANDARD_NO_PAD.encode(&message_copy)
            );
            assert_eq!(
                general_purpose::STANDARD_NO_PAD.encode(&so_m),
                general_purpose::STANDARD_NO_PAD.encode(&message_copy)
            );
        }
    }

    #[test]
    fn test_crypto_box_easy_invalid() {
        for _ in 0..20 {
            let (sender_pk, _sender_sk) = crypto_box_keypair();
            let (_recipient_pk, recipient_sk) = crypto_box_keypair();
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
            use base64::engine::general_purpose;
            use base64::Engine as _;

            let (sender_pk, _sender_sk) = crypto_box_keypair();
            let (_recipient_pk, recipient_sk) = crypto_box_keypair();
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
                general_purpose::STANDARD_NO_PAD.encode(&ciphertext[0..CRYPTO_BOX_MACBYTES]),
                general_purpose::STANDARD_NO_PAD.encode(&ciphertext_copy[0..CRYPTO_BOX_MACBYTES])
            );
        }
    }

    #[test]
    fn test_crypto_box_seed_keypair() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use sodiumoxide::crypto::box_::{keypair_from_seed, Seed};

        for _ in 0..10 {
            let seed = randombytes_buf(CRYPTO_BOX_SEEDBYTES);

            let (pk, sk) = crypto_box_seed_keypair(&seed);
            let (so_pk, so_sk) = keypair_from_seed(&Seed::from_slice(&seed).unwrap());

            assert_eq!(
                general_purpose::STANDARD_NO_PAD.encode(pk),
                general_purpose::STANDARD_NO_PAD.encode(so_pk.as_ref())
            );
            assert_eq!(
                general_purpose::STANDARD_NO_PAD.encode(sk),
                general_purpose::STANDARD_NO_PAD.encode(so_sk.as_ref())
            );
        }
    }

    #[test]
    fn test_crypto_box_seal() {
        for i in 0..20 {
            use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
            use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305;

            let (recipient_pk, recipient_sk) = crypto_box_keypair();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_SEALBYTES];
            crypto_box_seal(&mut ciphertext, message.as_bytes(), &recipient_pk)
                .expect("encrypt failed");

            let mut m = vec![0u8; ciphertext.len() - CRYPTO_BOX_SEALBYTES];
            crypto_box_seal_open(&mut m, ciphertext.as_slice(), &recipient_pk, &recipient_sk)
                .expect("decrypt failed");
            let so_m = curve25519blake2bxsalsa20poly1305::open(
                ciphertext.as_slice(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
                &SecretKey::from_slice(&recipient_sk).unwrap(),
            )
            .unwrap();

            assert_eq!(m, message.as_bytes());
            assert_eq!(m, so_m);
        }
    }

    #[test]
    fn test_crypto_box_seal_open() {
        for i in 0..20 {
            use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
            use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305;

            let (recipient_pk, recipient_sk) = crypto_box_keypair();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let so_ciphertext = curve25519blake2bxsalsa20poly1305::seal(
                message.as_bytes(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
            );

            let mut m = vec![0u8; so_ciphertext.len() - CRYPTO_BOX_SEALBYTES];
            crypto_box_seal_open(
                &mut m,
                so_ciphertext.as_slice(),
                &recipient_pk,
                &recipient_sk,
            )
            .expect("decrypt failed");
            let so_m = curve25519blake2bxsalsa20poly1305::open(
                so_ciphertext.as_slice(),
                &PublicKey::from_slice(&recipient_pk).unwrap(),
                &SecretKey::from_slice(&recipient_sk).unwrap(),
            )
            .unwrap();

            assert_eq!(m, message.as_bytes());
            assert_eq!(m, so_m);
        }
    }
}
