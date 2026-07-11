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
//!     Key, Nonce, crypto_secretbox_easy, crypto_secretbox_keygen, crypto_secretbox_open_easy,
//! };
//! use dryoc::constants::{CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES};
//! use dryoc::rng::randombytes_buf;
//! use dryoc::types::*;
//!
//! let key: Key = crypto_secretbox_keygen();
//! let nonce = Nonce::generate();
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
/// [`copy_randombytes`].
pub fn crypto_secretbox_keygen() -> Key {
    Key::generate()
}

/// Detached version of [`crypto_secretbox_easy`].
///
/// Compatible with libsodium's `crypto_secretbox_detached`.
///
/// # Errors
///
/// Returns an error if `ciphertext` is shorter than `message`.
pub fn crypto_secretbox_detached(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    if ciphertext.len() < message.len() {
        return Err(dryoc_error!(format!(
            "ciphertext length {} less than message length {}",
            ciphertext.len(),
            message.len()
        )));
    }

    crypto_secretbox_detached_b2b(&mut ciphertext[..message.len()], mac, message, nonce, key);
    Ok(())
}

/// Detached version of [`crypto_secretbox_open_easy`].
///
/// Compatible with libsodium's `crypto_secretbox_open_detached`.
///
/// # Errors
///
/// Returns an error if `message` is shorter than `ciphertext` or
/// authentication fails.
pub fn crypto_secretbox_open_detached(
    message: &mut [u8],
    mac: &Mac,
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let c_len = ciphertext.len();
    if message.len() < c_len {
        return Err(dryoc_error!(format!(
            "message length {} less than ciphertext length {}",
            message.len(),
            c_len
        )));
    }

    crypto_secretbox_open_detached_b2b(&mut message[..c_len], mac, ciphertext, nonce, key)
}

/// Encrypts `message` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_easy`.
///
/// # Errors
///
/// Returns an error if the required ciphertext length overflows `usize` or
/// `ciphertext` is not exactly one authentication tag longer than `message`.
pub fn crypto_secretbox_easy(
    ciphertext: &mut [u8],
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let expected_len = message
        .len()
        .checked_add(CRYPTO_SECRETBOX_MACBYTES)
        .ok_or_else(|| dryoc_error!("ciphertext length overflow"))?;
    if ciphertext.len() != expected_len {
        return Err(dryoc_error!(format!(
            "ciphertext length invalid ({} != {})",
            ciphertext.len(),
            expected_len
        )));
    }

    let mut mac = Mac::default();
    crypto_secretbox_detached(
        &mut ciphertext[CRYPTO_SECRETBOX_MACBYTES..],
        &mut mac,
        message,
        nonce,
        key,
    )?;

    ciphertext[..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(&mac);

    Ok(())
}

/// Decrypts `ciphertext` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_open_easy`.
///
/// # Errors
///
/// Returns an error if `ciphertext` is shorter than an authentication tag,
/// `message` has the wrong length, or authentication fails.
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
    } else if message.len() != ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES {
        Err(dryoc_error!(format!(
            "message length invalid ({} != {})",
            message.len(),
            ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES
        )))
    } else {
        let (mac, ciphertext) = ciphertext.split_at(CRYPTO_SECRETBOX_MACBYTES);
        let mac = ByteArray::as_array(mac);
        crypto_secretbox_open_detached(message, mac, ciphertext, nonce, key)
    }
}

/// Encrypts `message` with `nonce` and `key` in-place, without allocating
/// additional memory for ciphertext.
///
/// # Errors
///
/// Returns an error if `data` is shorter than an authentication tag.
pub fn crypto_secretbox_easy_inplace(
    data: &mut [u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    if data.len() < CRYPTO_SECRETBOX_MACBYTES {
        return Err(dryoc_error!(format!(
            "data length {} less than minimum {}",
            data.len(),
            CRYPTO_SECRETBOX_MACBYTES
        )));
    }
    data.rotate_right(CRYPTO_SECRETBOX_MACBYTES);
    let (mac, data) = data.split_at_mut(CRYPTO_SECRETBOX_MACBYTES);
    let mac = MutByteArray::as_mut_array(mac);

    crypto_secretbox_detached_inplace(data, mac, nonce, key);

    Ok(())
}

/// Decrypts `ciphertext` with `nonce` and `key` in-place, without allocating
/// additional memory for the message.
///
/// # Errors
///
/// Returns an error if `ciphertext` is shorter than an authentication tag or
/// authentication fails.
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
        let mac = ByteArray::as_array(mac);

        crypto_secretbox_open_detached_inplace(data, mac, nonce, key)?;

        ciphertext.rotate_left(CRYPTO_SECRETBOX_MACBYTES);

        Ok(())
    }
}

#[cfg(all(test, dryoc_native_tests))]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;

    use super::*;

    #[test]
    fn test_crypto_secretbox_rejects_invalid_buffer_lengths_without_mutation() {
        let key = Key::default();
        let nonce = Nonce::default();
        let message = b"buffer length validation";

        let mut short_detached = vec![0xa5; message.len() - 1];
        let original_short_detached = short_detached.clone();
        let mut mac = [0x5a; CRYPTO_SECRETBOX_MACBYTES];
        let original_mac = mac;
        assert!(
            crypto_secretbox_detached(&mut short_detached, &mut mac, message, &nonce, &key)
                .is_err()
        );
        assert_eq!(short_detached, original_short_detached);
        assert_eq!(mac, original_mac);

        for output_len in [
            message.len() + CRYPTO_SECRETBOX_MACBYTES - 1,
            message.len() + CRYPTO_SECRETBOX_MACBYTES + 1,
        ] {
            let mut output = vec![0xa5; output_len];
            let original = output.clone();
            assert!(crypto_secretbox_easy(&mut output, message, &nonce, &key).is_err());
            assert_eq!(output, original);
        }

        let mut ciphertext = vec![0u8; message.len() + CRYPTO_SECRETBOX_MACBYTES];
        crypto_secretbox_easy(&mut ciphertext, message, &nonce, &key).expect("encrypt failed");

        for output_len in [message.len() - 1, message.len() + 1] {
            let mut output = vec![0xa5; output_len];
            let original = output.clone();
            assert!(crypto_secretbox_open_easy(&mut output, &ciphertext, &nonce, &key).is_err());
            assert_eq!(output, original);
        }

        let mut short_open = vec![0xa5; message.len() - 1];
        let original_short_open = short_open.clone();
        assert!(
            crypto_secretbox_open_detached(
                &mut short_open,
                ByteArray::as_array(&ciphertext[..CRYPTO_SECRETBOX_MACBYTES]),
                &ciphertext[CRYPTO_SECRETBOX_MACBYTES..],
                &nonce,
                &key,
            )
            .is_err()
        );
        assert_eq!(short_open, original_short_open);

        let mut too_short_inplace = vec![0xa5; CRYPTO_SECRETBOX_MACBYTES - 1];
        let original_too_short_inplace = too_short_inplace.clone();
        assert!(crypto_secretbox_easy_inplace(&mut too_short_inplace, &nonce, &key).is_err());
        assert_eq!(too_short_inplace, original_too_short_inplace);
    }

    #[test]
    fn test_crypto_secretbox_easy() {
        for i in 0..20 {
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            let key: Key = crypto_secretbox_keygen();
            let nonce = Nonce::generate();

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
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            let key = crypto_secretbox_keygen();
            let nonce = Nonce::generate();

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

    #[test]
    fn test_crypto_secretbox_detached_only_touches_message_len() {
        let key = crypto_secretbox_keygen();
        let nonce = Nonce::generate();
        let message = b"detached secretbox buffer prefix";
        let mut ciphertext = vec![0xa5; message.len() + 8];
        let mut mac = Mac::default();

        crypto_secretbox_detached(&mut ciphertext, &mut mac, message, &nonce, &key)
            .expect("encrypt failed");

        assert_eq!(&ciphertext[message.len()..], &[0xa5; 8]);

        let mut decrypted = vec![0x5a; message.len() + 8];
        crypto_secretbox_open_detached(
            &mut decrypted,
            &mac,
            &ciphertext[..message.len()],
            &nonce,
            &key,
        )
        .expect("decrypt failed");

        assert_eq!(&decrypted[..message.len()], message);
        assert_eq!(&decrypted[message.len()..], &[0x5a; 8]);
    }

    #[test]
    fn test_crypto_secretbox_open_failure_keeps_output() {
        let key = crypto_secretbox_keygen();
        let nonce = Nonce::generate();
        let message = b"authenticated plaintext";
        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = Mac::default();

        crypto_secretbox_detached(&mut ciphertext, &mut mac, message, &nonce, &key)
            .expect("encrypt failed");
        mac[0] ^= 1;

        let mut decrypted = vec![0x5a; message.len()];
        let original_decrypted = decrypted.clone();
        assert!(
            crypto_secretbox_open_detached(&mut decrypted, &mac, &ciphertext, &nonce, &key)
                .is_err()
        );
        assert_eq!(decrypted, original_decrypted);

        let mut inplace = ciphertext.clone();
        assert!(crypto_secretbox_open_detached_inplace(&mut inplace, &mac, &nonce, &key).is_err());
        assert_eq!(inplace, ciphertext);
    }

    #[cfg(feature = "nightly")]
    fn bench_crypto_secretbox_detached(b: &mut test::Bencher, message_len: usize) {
        let key: Key = crypto_secretbox_keygen();
        let nonce = Nonce::generate();
        let mut message = vec![0u8; message_len];
        crate::rng::copy_randombytes(&mut message);
        let mut ciphertext = vec![0u8; message_len];
        let mut mac = Mac::default();

        b.bytes = message_len as u64;
        b.iter(|| {
            crypto_secretbox_detached(
                test::black_box(&mut ciphertext),
                test::black_box(&mut mac),
                test::black_box(&message),
                test::black_box(&nonce),
                test::black_box(&key),
            )
            .expect("encrypt failed");
        });
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn crypto_secretbox_detached_64b_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 64);
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn crypto_secretbox_detached_1kib_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 1024);
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn crypto_secretbox_detached_16kib_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 16 * 1024);
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn crypto_secretbox_detached_1mib_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 1024 * 1024);
    }
}
