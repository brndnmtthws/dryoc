//! # XChaCha20-Poly1305-IETF authenticated encryption
//!
//! Implements libsodium's `crypto_aead_xchacha20poly1305_ietf_*` functions.
//! This construction authenticates optional additional data, appends the
//! authentication tag in combined mode, and uses 192-bit public nonces.
//!
//! ## Compatibility note
//!
//! This module follows libsodium's XChaCha20-Poly1305-IETF API and message
//! size limit. The `_ietf` suffix refers to the RFC 8439 AEAD layout and
//! Poly1305 input format; libsodium's XChaCha implementation uses an
//! extended-counter XChaCha20 stream so it can support larger individual
//! messages than plain ChaCha20-Poly1305-IETF.
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_aead_xchacha20poly1305_ietf::*;
//! use dryoc::constants::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
//! use dryoc::types::*;
//!
//! let key = crypto_aead_xchacha20poly1305_ietf_keygen();
//! let nonce = Nonce::generate();
//! let message = b"hello";
//! let aad = b"metadata";
//!
//! let mut ciphertext = vec![0u8; message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
//! crypto_aead_xchacha20poly1305_ietf_encrypt(&mut ciphertext, message, Some(aad), &nonce, &key)
//!     .expect("encrypt failed");
//!
//! let mut decrypted = vec![0u8; message.len()];
//! crypto_aead_xchacha20poly1305_ietf_decrypt(
//!     &mut decrypted,
//!     &ciphertext,
//!     Some(aad),
//!     &nonce,
//!     &key,
//! )
//! .expect("decrypt failed");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```

use zeroize::Zeroize;

use crate::chacha20::ChaCha20;
use crate::classic::crypto_aead_chacha20poly1305_impl::impl_chacha20poly1305_aead;
use crate::classic::crypto_core::{HChaCha20Key, crypto_core_hchacha20};
use crate::constants::{
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, CRYPTO_CORE_HCHACHA20_INPUTBYTES,
};
use crate::types::*;

/// Authentication tag for XChaCha20-Poly1305-IETF AEAD.
pub type Mac = [u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
/// Public nonce for XChaCha20-Poly1305-IETF AEAD.
pub type Nonce = [u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES];
/// Secret key for XChaCha20-Poly1305-IETF AEAD.
pub type Key = [u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES];

/// libsodium's `chacha20_ietf_ext` stream for `nonce` and `key`, positioned
/// at block `counter`.
fn xchacha20_stream(nonce: &Nonce, key: &Key, counter: u64) -> ChaCha20 {
    let mut subkey = HChaCha20Key::default();
    crypto_core_hchacha20(
        &mut subkey,
        ByteArray::as_array(&nonce[..CRYPTO_CORE_HCHACHA20_INPUTBYTES]),
        key,
        None,
    );

    // libsodium's `chacha20_ietf_ext` starts with IETF layout but allows the
    // 32-bit block counter to overflow into the leading zero nonce word. With
    // XChaCha's `0 || nonce_tail` derived nonce, that is equivalent to the
    // original 64-bit-counter ChaCha20 layout with `nonce_tail`.
    let nonce_tail = ByteArray::as_array(&nonce[CRYPTO_CORE_HCHACHA20_INPUTBYTES..]);
    let cipher = ChaCha20::legacy(&subkey, nonce_tail, counter);
    subkey.zeroize();
    cipher
}

impl_chacha20poly1305_aead! {
    abytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES,
    // libsodium's XChaCha bound: the extended-counter stream never wraps
    // within an addressable message.
    messagebytes_max: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX,
    stream: |nonce: &Nonce, key: &Key| xchacha20_stream(nonce, key, 0),
    key: Key,
    nonce: Nonce,
    mac: Mac,

    /// In-place variant of [`crypto_aead_xchacha20poly1305_ietf_keygen`].
    keygen_inplace: crypto_aead_xchacha20poly1305_ietf_keygen_inplace,

    /// Generates a random key using [`copy_randombytes`](crate::rng::copy_randombytes).
    keygen: crypto_aead_xchacha20poly1305_ietf_keygen,

    /// Detached version of [`crypto_aead_xchacha20poly1305_ietf_encrypt`].
    ///
    /// Compatible with libsodium's
    /// `crypto_aead_xchacha20poly1305_ietf_encrypt_detached`.
    ///
    /// # Errors
    ///
    /// Returns an error if `message` exceeds the maximum supported length or
    /// `ciphertext.len()` does not equal `message.len()`.
    encrypt_detached: crypto_aead_xchacha20poly1305_ietf_encrypt_detached,

    /// In-place detached variant of
    /// [`crypto_aead_xchacha20poly1305_ietf_encrypt_detached`].
    ///
    /// # Errors
    ///
    /// Returns an error if `data` exceeds the maximum supported message length.
    encrypt_detached_inplace: crypto_aead_xchacha20poly1305_ietf_encrypt_detached_inplace,

    /// Detached version of [`crypto_aead_xchacha20poly1305_ietf_decrypt`].
    ///
    /// Compatible with libsodium's
    /// `crypto_aead_xchacha20poly1305_ietf_decrypt_detached`.
    ///
    /// # Errors
    ///
    /// Returns an error if `ciphertext` is too long, `message.len()` does not equal
    /// `ciphertext.len()`, or authentication fails.
    decrypt_detached: crypto_aead_xchacha20poly1305_ietf_decrypt_detached,

    /// In-place detached variant of
    /// [`crypto_aead_xchacha20poly1305_ietf_decrypt_detached`].
    ///
    /// # Errors
    ///
    /// Returns an error if `data` exceeds the maximum supported message length or
    /// authentication fails.
    decrypt_detached_inplace: crypto_aead_xchacha20poly1305_ietf_decrypt_detached_inplace,

    /// Encrypts `message` with `nonce`, `key`, and optional associated data.
    ///
    /// Compatible with libsodium's `crypto_aead_xchacha20poly1305_ietf_encrypt`.
    ///
    /// # Errors
    ///
    /// Returns an error if `message` exceeds the maximum supported length or
    /// `ciphertext` is not exactly one authentication tag longer than `message`.
    encrypt: crypto_aead_xchacha20poly1305_ietf_encrypt,

    /// Decrypts `ciphertext` with `nonce`, `key`, and optional associated data.
    ///
    /// Compatible with libsodium's `crypto_aead_xchacha20poly1305_ietf_decrypt`.
    ///
    /// # Errors
    ///
    /// Returns an error if `ciphertext` is shorter than an authentication tag,
    /// `message` has the wrong length, or authentication fails.
    decrypt: crypto_aead_xchacha20poly1305_ietf_decrypt,

    /// Encrypts `data` in place and appends the authentication tag.
    ///
    /// The last [`CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES`] bytes are reserved
    /// for the tag and are ignored as plaintext input.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is shorter than an authentication tag or its
    /// plaintext portion exceeds the maximum supported message length.
    encrypt_inplace: crypto_aead_xchacha20poly1305_ietf_encrypt_inplace,

    /// Decrypts `data` in place after verifying the appended authentication tag.
    ///
    /// After success, the first `data.len() -
    /// CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES` bytes contain the plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is shorter than an authentication tag or
    /// authentication fails.
    decrypt_inplace: crypto_aead_xchacha20poly1305_ietf_decrypt_inplace,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, LengthConstraint};

    #[test]
    fn test_message_len_bound_is_xchacha_max() {
        const MAX: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX;
        const ABYTES: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

        assert!(validate_message_len(MAX).is_ok());
        assert!(matches!(
            validate_message_len(MAX + 1),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Message,
                actual,
                constraint: LengthConstraint::AtMost(max),
            }) if actual == MAX + 1 && max == MAX
        ));

        // libsodium's bound leaves exactly one tag below the address space, so
        // every combined length at or above `ABYTES` is a valid message length.
        assert!(matches!(
            message_len_from_combined_len(MAX + ABYTES, crate::ErrorContext::Ciphertext),
            Ok(len) if len == MAX
        ));
        assert!(matches!(
            message_len_from_combined_len(ABYTES - 1, crate::ErrorContext::Ciphertext),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Ciphertext,
                constraint: LengthConstraint::AtLeast(ABYTES),
                ..
            })
        ));
    }

    const MESSAGE: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const AD: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const KEY: Key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const NONCE: Nonce = [
        0xf2, 0x8a, 0x50, 0xa7, 0x8a, 0x7e, 0x23, 0xc9, 0xcb, 0xa6, 0x78, 0x34, 0x66, 0xf8, 0x03,
        0x59, 0x0f, 0x04, 0xe9, 0x22, 0x31, 0xa3, 0x2d, 0x5d,
    ];
    const EXPECTED: &[u8] = &[
        0x20, 0xf1, 0xae, 0x75, 0xe1, 0xe5, 0xe0, 0x00, 0x40, 0x29, 0x4f, 0x0f, 0xb1, 0x0e, 0xbb,
        0x08, 0x10, 0xc5, 0x93, 0xc7, 0xdb, 0xa4, 0xec, 0x10, 0x4c, 0x1e, 0x5e, 0xf9, 0x50, 0x7f,
        0xae, 0xef, 0x58, 0xfc, 0x28, 0x98, 0xbb, 0xd0, 0xe4, 0x7b, 0x2f, 0x53, 0x31, 0xfb, 0xc3,
        0x67, 0xd3, 0xc2, 0x78, 0x4e, 0x36, 0x48, 0xce, 0x1e, 0xaa, 0x77, 0x87, 0xad, 0x18, 0x6d,
        0xb2, 0x68, 0x5e, 0xe8, 0x9a, 0xe4, 0xd3, 0x44, 0x1f, 0x6e, 0xa0, 0xb2, 0x22, 0x4c, 0xd5,
        0xa1, 0x34, 0x16, 0x1b, 0x55, 0x4d, 0x8b, 0x48, 0x35, 0x0b, 0x4a, 0xd4, 0x01, 0x15, 0xdb,
        0x81, 0xea, 0x82, 0x09, 0x68, 0xe9, 0x43, 0x89, 0x2f, 0x2b, 0x80, 0x51, 0xcb, 0x5f, 0x7a,
        0x86, 0x66, 0xe7, 0xe7, 0xef, 0x7f, 0x84, 0xc0, 0xa2, 0xf8, 0x0a, 0x12, 0xd0, 0x66, 0x80,
        0xc8, 0xee, 0xbb, 0xd9, 0x30, 0x04, 0x10, 0x9d, 0xe8, 0x42,
    ];

    #[test]
    fn test_known_answer() {
        let mut ciphertext = vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            &mut ciphertext,
            MESSAGE,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("encrypt");
        assert_eq!(ciphertext, EXPECTED);

        let mut decrypted = vec![0u8; MESSAGE.len()];
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            &mut decrypted,
            &ciphertext,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("decrypt");
        assert_eq!(decrypted, MESSAGE);
    }

    #[test]
    fn test_detached_matches_combined() {
        let mut combined = vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_xchacha20poly1305_ietf_encrypt(&mut combined, MESSAGE, Some(AD), &NONCE, &KEY)
            .expect("encrypt");

        let mut detached = vec![0u8; MESSAGE.len()];
        let mut mac = Mac::default();
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            &mut detached,
            &mut mac,
            MESSAGE,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("detached encrypt");

        assert_eq!(detached, combined[..MESSAGE.len()]);
        assert_eq!(mac.as_slice(), &combined[MESSAGE.len()..]);
    }

    #[test]
    fn test_failures_do_not_mutate_output() {
        let mut ciphertext = vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            &mut ciphertext,
            MESSAGE,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("encrypt");
        ciphertext[0] ^= 1;

        let mut decrypted = vec![0xa5; MESSAGE.len()];
        let original = decrypted.clone();
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            &mut decrypted,
            &ciphertext,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect_err("expected auth failure");
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_empty_message_and_no_aad() {
        let mut ciphertext = vec![0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_xchacha20poly1305_ietf_encrypt(&mut ciphertext, &[], None, &NONCE, &KEY)
            .expect("encrypt");

        let mut decrypted = vec![];
        crypto_aead_xchacha20poly1305_ietf_decrypt(&mut decrypted, &ciphertext, None, &NONCE, &KEY)
            .expect("decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let mut ciphertext = vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            &mut ciphertext,
            MESSAGE,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("encrypt");

        let mut decrypted = vec![0u8; MESSAGE.len()];
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            &mut decrypted,
            &ciphertext,
            Some(b"wrong aad"),
            &NONCE,
            &KEY,
        )
        .expect_err("expected auth failure");
    }

    #[test]
    fn test_wrong_key_and_nonce_fail() {
        let mut ciphertext = vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            &mut ciphertext,
            MESSAGE,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("encrypt");

        let mut wrong_key = KEY;
        wrong_key[0] ^= 1;
        let mut decrypted = vec![0u8; MESSAGE.len()];
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            &mut decrypted,
            &ciphertext,
            Some(AD),
            &NONCE,
            &wrong_key,
        )
        .expect_err("expected wrong key auth failure");

        let mut wrong_nonce = NONCE;
        wrong_nonce[0] ^= 1;
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            &mut decrypted,
            &ciphertext,
            Some(AD),
            &wrong_nonce,
            &KEY,
        )
        .expect_err("expected wrong nonce auth failure");
    }

    #[test]
    fn test_wrong_mac_and_short_ciphertext_fail() {
        let mut ciphertext = vec![0u8; MESSAGE.len()];
        let mut mac = Mac::default();
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            &mut ciphertext,
            &mut mac,
            MESSAGE,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("detached encrypt");

        mac[0] ^= 1;
        let mut decrypted = vec![0u8; MESSAGE.len()];
        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            &mut decrypted,
            &ciphertext,
            &mac,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect_err("expected wrong mac auth failure");

        let mut short_decrypted = vec![];
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            &mut short_decrypted,
            &[0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES - 1],
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect_err("expected short ciphertext failure");
    }

    #[test]
    fn test_inplace_roundtrip() {
        let mut data = MESSAGE.to_vec();
        data.resize(MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, 0);
        crypto_aead_xchacha20poly1305_ietf_encrypt_inplace(&mut data, Some(AD), &NONCE, &KEY)
            .expect("inplace encrypt");
        assert_eq!(data, EXPECTED);

        crypto_aead_xchacha20poly1305_ietf_decrypt_inplace(&mut data, Some(AD), &NONCE, &KEY)
            .expect("inplace decrypt");
        assert_eq!(&data[..MESSAGE.len()], MESSAGE);
    }

    #[test]
    fn test_xietf_ext_stream_crosses_ietf_counter_boundary() {
        let mut cipher = xchacha20_stream(&NONCE, &KEY, u64::from(u32::MAX));

        let mut stream = [0u8; 128];
        cipher.apply_keystream(&mut stream);

        assert_ne!(&stream[..64], &[0u8; 64]);
        assert_ne!(&stream[64..], &[0u8; 64]);
        assert_ne!(&stream[..64], &stream[64..]);
    }

    #[test]
    fn test_inplace_failures_do_not_mutate_data() {
        let mut data = MESSAGE.to_vec();
        data.resize(MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, 0);
        crypto_aead_xchacha20poly1305_ietf_encrypt_inplace(&mut data, Some(AD), &NONCE, &KEY)
            .expect("inplace encrypt");
        data[MESSAGE.len()] ^= 1;
        let original = data.clone();

        crypto_aead_xchacha20poly1305_ietf_decrypt_inplace(&mut data, Some(AD), &NONCE, &KEY)
            .expect_err("expected auth failure");
        assert_eq!(data, original);

        let mut detached = MESSAGE.to_vec();
        let mut mac = Mac::default();
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached_inplace(
            &mut detached,
            &mut mac,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("detached inplace encrypt");
        mac[0] ^= 1;
        let original = detached.clone();

        crypto_aead_xchacha20poly1305_ietf_decrypt_detached_inplace(
            &mut detached,
            &mac,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect_err("expected detached auth failure");
        assert_eq!(detached, original);
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;

        #[test]
        fn test_sodiumoxide_interop() {
            use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{
                Key as SOKey, Nonce as SONonce, open, seal,
            };

            let so_key = SOKey::from_slice(&KEY).expect("key");
            let so_nonce = SONonce::from_slice(&NONCE).expect("nonce");

            let mut ciphertext =
                vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                &mut ciphertext,
                MESSAGE,
                Some(AD),
                &NONCE,
                &KEY,
            )
            .expect("encrypt");
            let so_plaintext =
                open(&ciphertext, Some(AD), &so_nonce, &so_key).expect("sodiumoxide open");
            assert_eq!(so_plaintext, MESSAGE);

            let so_ciphertext = seal(MESSAGE, Some(AD), &so_nonce, &so_key);
            let mut plaintext = vec![0u8; MESSAGE.len()];
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                &mut plaintext,
                &so_ciphertext,
                Some(AD),
                &NONCE,
                &KEY,
            )
            .expect("decrypt");
            assert_eq!(plaintext, MESSAGE);
        }

        #[test]
        fn test_counter_boundary_matches_libsodium_xchacha_stream() {
            use libsodium_sys::crypto_stream_xchacha20_xor_ic;

            let initial_counter = u64::from(u32::MAX);
            let input = [0u8; 128];
            let mut expected = [0u8; 128];
            // SAFETY: All pointers are derived from initialized fixed-size
            // buffers with lengths matching the arguments passed to
            // libsodium. The key and nonce are exact-size test vectors.
            unsafe {
                assert_eq!(
                    crypto_stream_xchacha20_xor_ic(
                        expected.as_mut_ptr(),
                        input.as_ptr(),
                        input.len() as u64,
                        NONCE.as_ptr(),
                        initial_counter,
                        KEY.as_ptr(),
                    ),
                    0
                );
            }

            let mut actual = [0u8; 128];
            let mut cipher = xchacha20_stream(&NONCE, &KEY, initial_counter);
            cipher.apply_keystream(&mut actual);

            assert_eq!(actual, expected);
        }
    }
}
