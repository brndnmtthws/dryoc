//! # Secret-key authenticated encryption
//!
//! Implements libsodium's `crypto_secretbox_*` functions. These functions
//! encrypt a message with a shared secret key and detect tampering.
//!
//! Nonces are public, but a nonce must never repeat with the same key. See the
//! [libsodium documentation](https://doc.libsodium.org/secret-key_cryptography/secretbox)
//! for details.
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
//! let message = "A message to encrypt";
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
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_MESSAGEBYTES_MAX,
    CRYPTO_SECRETBOX_NONCEBYTES,
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

fn validate_message_len(message_len: usize, context: crate::ErrorContext) -> Result<(), Error> {
    validate_length!(max CRYPTO_SECRETBOX_MESSAGEBYTES_MAX, message_len, context);
    Ok(())
}

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
/// Returns an error if `message` is too long or `ciphertext` is shorter than
/// `message`.
pub fn crypto_secretbox_detached(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(message.len(), crate::ErrorContext::Message)?;
    validate_length!(min message.len(), ciphertext.len(), crate::ErrorContext::Ciphertext);

    crypto_secretbox_detached_b2b(&mut ciphertext[..message.len()], mac, message, nonce, key);
    Ok(())
}

/// Detached version of [`crypto_secretbox_open_easy`].
///
/// Compatible with libsodium's `crypto_secretbox_open_detached`.
///
/// # Errors
///
/// Returns an error if `ciphertext` is too long, `message` is shorter than
/// `ciphertext`, or authentication fails.
pub fn crypto_secretbox_open_detached(
    message: &mut [u8],
    mac: &Mac,
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let c_len = ciphertext.len();
    validate_message_len(c_len, crate::ErrorContext::Ciphertext)?;
    validate_length!(min c_len, message.len(), crate::ErrorContext::Message);

    crypto_secretbox_open_detached_b2b(&mut message[..c_len], mac, ciphertext, nonce, key)
}

/// Encrypts `message` with `nonce` and `key`.
///
/// Compatible with libsodium's `crypto_secretbox_easy`.
///
/// # Errors
///
/// Returns an error if `message` is too long or `ciphertext` is not exactly one
/// authentication tag longer than `message`.
pub fn crypto_secretbox_easy(
    ciphertext: &mut [u8],
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(message.len(), crate::ErrorContext::Message)?;

    let expected_len = message.len() + CRYPTO_SECRETBOX_MACBYTES;
    validate_length!(exact expected_len, ciphertext.len(), crate::ErrorContext::Ciphertext);

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
    validate_length!(
        min CRYPTO_SECRETBOX_MACBYTES,
        ciphertext.len(),
        crate::ErrorContext::Ciphertext
    );
    validate_length!(
        exact ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES,
        message.len(),
        crate::ErrorContext::Message
    );

    let (mac, ciphertext) = ciphertext.split_at(CRYPTO_SECRETBOX_MACBYTES);
    let mac = ByteArray::as_array(mac);
    crypto_secretbox_open_detached(message, mac, ciphertext, nonce, key)
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
    validate_length!(min CRYPTO_SECRETBOX_MACBYTES, data.len(), crate::ErrorContext::Data);
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
    validate_length!(
        min CRYPTO_SECRETBOX_MACBYTES,
        ciphertext.len(),
        crate::ErrorContext::Ciphertext
    );

    let (mac, data) = ciphertext.split_at_mut(CRYPTO_SECRETBOX_MACBYTES);
    let mac = ByteArray::as_array(mac);

    crypto_secretbox_open_detached_inplace(data, mac, nonce, key)?;

    ciphertext.rotate_left(CRYPTO_SECRETBOX_MACBYTES);

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    extern crate test;

    use super::*;

    #[test]
    fn rejects_lengths_above_the_libsodium_limit() {
        let too_long = CRYPTO_SECRETBOX_MESSAGEBYTES_MAX + 1;

        assert!(matches!(
            validate_message_len(too_long, crate::ErrorContext::Message),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Message,
                actual,
                constraint: crate::LengthConstraint::AtMost(CRYPTO_SECRETBOX_MESSAGEBYTES_MAX),
            }) if actual == too_long
        ));
    }

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

    #[cfg(dryoc_native_tests)]
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

    #[cfg(dryoc_native_tests)]
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

    /// A deterministic key, nonce and message of `len` bytes.
    fn fixture(len: usize) -> (Key, Nonce, Vec<u8>) {
        let mut rng = crate::utils::test_util::XorShift64::new(0x5ec2_e7b0_1d3a_9f41);
        let key = rng.next_bytes32();
        let nonce: Nonce = rng.next_bytes32()[..CRYPTO_SECRETBOX_NONCEBYTES]
            .try_into()
            .unwrap();
        let message = (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ 0x3c)
            .collect();
        (key, nonce, message)
    }

    /// Every failing `crypto_secretbox_open_easy_inplace` (and `open_easy`)
    /// must leave its whole buffer as it found it: a flipped bit in the
    /// first and last tag byte, in the first and last ciphertext byte, and
    /// a buffer one byte short of a tag.
    #[test]
    fn test_open_easy_inplace_failures_leave_buffer_untouched() {
        let (key, nonce, message) = fixture(100);
        let mut sealed = message.clone();
        sealed.resize(message.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
        crypto_secretbox_easy_inplace(&mut sealed, &nonce, &key).expect("encrypt failed");

        let mut cases = Vec::new();
        for (name, index) in [
            ("first tag byte", 0),
            ("last tag byte", CRYPTO_SECRETBOX_MACBYTES - 1),
            ("first ciphertext byte", CRYPTO_SECRETBOX_MACBYTES),
            ("last ciphertext byte", sealed.len() - 1),
        ] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            cases.push((name, tampered));
        }
        for (name, tampered) in cases {
            let mut buffer = tampered.clone();
            assert!(
                matches!(
                    crypto_secretbox_open_easy_inplace(&mut buffer, &nonce, &key),
                    Err(Error::AuthenticationFailed)
                ),
                "{name}: in place"
            );
            assert_eq!(buffer, tampered, "{name}: in place buffer");

            let mut output = vec![0xa5u8; message.len()];
            assert!(
                matches!(
                    crypto_secretbox_open_easy(&mut output, &tampered, &nonce, &key),
                    Err(Error::AuthenticationFailed)
                ),
                "{name}: b2b"
            );
            assert_eq!(output, vec![0xa5u8; message.len()], "{name}: b2b output");
        }

        let mut short = sealed[..CRYPTO_SECRETBOX_MACBYTES - 1].to_vec();
        let original = short.clone();
        assert!(matches!(
            crypto_secretbox_open_easy_inplace(&mut short, &nonce, &key),
            Err(Error::InvalidLength { .. })
        ));
        assert_eq!(short, original);
        let mut output = [0xa5u8];
        assert!(matches!(
            crypto_secretbox_open_easy(&mut output, &original, &nonce, &key),
            Err(Error::InvalidLength { .. })
        ));
        assert_eq!(output, [0xa5]);

        let mut buffer = sealed.clone();
        crypto_secretbox_open_easy_inplace(&mut buffer, &nonce, &key).expect("decrypt failed");
        assert_eq!(&buffer[..message.len()], message);
    }

    /// Message lengths around the Poly1305 and Salsa20 blocks, and around
    /// the XSalsa20 kernel chunks (5, 8 and 16 blocks): the message's
    /// keystream starts 32 bytes into block 0, so a chunk boundary falls 32
    /// bytes before a multiple of the chunk.
    #[cfg(dryoc_native_tests)]
    fn boundary_lens() -> Vec<usize> {
        let mut lens = vec![0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65];
        for chunk in [5 * 64, 8 * 64, 16 * 64] {
            lens.extend([
                chunk - 33,
                chunk - 32,
                chunk - 31,
                chunk - 1,
                chunk,
                chunk + 1,
                2 * chunk - 33,
                2 * chunk - 32,
                2 * chunk - 31,
            ]);
        }
        lens.sort_unstable();
        lens.dedup();
        lens
    }

    /// Every seal function must produce libsodium's `crypto_secretbox_easy`
    /// and `crypto_secretbox_detached` output, and every open function must
    /// recover the message from it, at every length in [`boundary_lens`].
    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_matches_libsodium_at_boundary_lengths() {
        use libc::c_ulonglong;

        for len in boundary_lens() {
            let (key, nonce, message) = fixture(len);
            let mut expected = vec![0u8; len];
            let mut expected_mac = Mac::default();
            let mut expected_easy = vec![0u8; len + CRYPTO_SECRETBOX_MACBYTES];
            // SAFETY: every buffer is valid for the length passed beside it;
            // `mac`, `nonce` and `key` are exact-size arrays.
            unsafe {
                assert_eq!(
                    libsodium_sys::crypto_secretbox_detached(
                        expected.as_mut_ptr(),
                        expected_mac.as_mut_ptr(),
                        message.as_ptr(),
                        len as c_ulonglong,
                        nonce.as_ptr(),
                        key.as_ptr(),
                    ),
                    0
                );
                assert_eq!(
                    libsodium_sys::crypto_secretbox_easy(
                        expected_easy.as_mut_ptr(),
                        message.as_ptr(),
                        len as c_ulonglong,
                        nonce.as_ptr(),
                        key.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(expected_easy[..CRYPTO_SECRETBOX_MACBYTES], expected_mac);
            assert_eq!(expected_easy[CRYPTO_SECRETBOX_MACBYTES..], expected);

            let mut ciphertext = vec![0u8; len];
            let mut mac = Mac::default();
            crypto_secretbox_detached(&mut ciphertext, &mut mac, &message, &nonce, &key)
                .expect("detached");
            assert_eq!(
                (&ciphertext, mac),
                (&expected, expected_mac),
                "len {len}: detached"
            );

            let mut data = message.clone();
            let mut mac = Mac::default();
            crypto_secretbox_detached_inplace(&mut data, &mut mac, &nonce, &key);
            assert_eq!(
                (&data, mac),
                (&expected, expected_mac),
                "len {len}: detached in place"
            );

            let mut easy = vec![0u8; len + CRYPTO_SECRETBOX_MACBYTES];
            crypto_secretbox_easy(&mut easy, &message, &nonce, &key).expect("easy");
            assert_eq!(easy, expected_easy, "len {len}: easy");

            let mut data = message.clone();
            data.resize(len + CRYPTO_SECRETBOX_MACBYTES, 0);
            crypto_secretbox_easy_inplace(&mut data, &nonce, &key).expect("easy in place");
            assert_eq!(data, expected_easy, "len {len}: easy in place");

            let mut output = vec![0u8; len];
            crypto_secretbox_open_detached(&mut output, &expected_mac, &expected, &nonce, &key)
                .expect("open detached");
            assert_eq!(output, message, "len {len}: open detached");

            let mut data = expected.clone();
            crypto_secretbox_open_detached_inplace(&mut data, &expected_mac, &nonce, &key)
                .expect("open detached in place");
            assert_eq!(data, message, "len {len}: open detached in place");

            let mut output = vec![0u8; len];
            crypto_secretbox_open_easy(&mut output, &expected_easy, &nonce, &key)
                .expect("open easy");
            assert_eq!(output, message, "len {len}: open easy");

            let mut data = expected_easy.clone();
            crypto_secretbox_open_easy_inplace(&mut data, &nonce, &key)
                .expect("open easy in place");
            assert_eq!(&data[..len], message, "len {len}: open easy in place");
        }
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
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

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn crypto_secretbox_detached_64b_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 64);
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn crypto_secretbox_detached_1kib_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 1024);
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn crypto_secretbox_detached_16kib_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 16 * 1024);
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn crypto_secretbox_detached_1mib_bench(b: &mut test::Bencher) {
        bench_crypto_secretbox_detached(b, 1024 * 1024);
    }

    /// libsodium's `crypto_secretbox_detached` with the same buffers as
    /// `bench_crypto_secretbox_detached`, so the two rows are directly
    /// comparable.
    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    fn bench_libsodium_secretbox_detached(b: &mut test::Bencher, message_len: usize) {
        sodiumoxide::init().expect("sodiumoxide init");

        let key: Key = crypto_secretbox_keygen();
        let nonce = Nonce::generate();
        let mut message = vec![0u8; message_len];
        crate::rng::copy_randombytes(&mut message);
        let mut ciphertext = vec![0u8; message_len];
        let mut mac = Mac::default();

        b.bytes = message_len as u64;
        b.iter(|| {
            // SAFETY: `ciphertext` and `message` are both `message_len` bytes,
            // and `mac`, `nonce` and `key` are exact-size arrays.
            let rc = unsafe {
                libsodium_sys::crypto_secretbox_detached(
                    ciphertext.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    test::black_box(message.as_ptr()),
                    message_len as u64,
                    nonce.as_ptr(),
                    key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            test::black_box((&ciphertext, &mac));
        });
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn libsodium_secretbox_detached_64b_bench(b: &mut test::Bencher) {
        bench_libsodium_secretbox_detached(b, 64);
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn libsodium_secretbox_detached_1kib_bench(b: &mut test::Bencher) {
        bench_libsodium_secretbox_detached(b, 1024);
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn libsodium_secretbox_detached_16kib_bench(b: &mut test::Bencher) {
        bench_libsodium_secretbox_detached(b, 16 * 1024);
    }

    #[cfg(all(feature = "nightly", dryoc_native_tests))]
    #[bench]
    fn libsodium_secretbox_detached_1mib_bench(b: &mut test::Bencher) {
        bench_libsodium_secretbox_detached(b, 1024 * 1024);
    }
}
