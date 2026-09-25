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
//! ## Behavior on failure
//!
//! Every decrypt function checks the buffer lengths and verifies the tag
//! before it writes anything, so any error, a length error or
//! [`Error::AuthenticationFailed`](crate::Error::AuthenticationFailed), leaves
//! the output (or, in place, `data`) exactly as it found it. The tag case is
//! the one deliberate departure from libsodium, whose
//! `crypto_aead_xchacha20poly1305_ietf_decrypt*` zero the output buffer on a
//! failed tag check, destroying the ciphertext when decrypting in place.
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
        nonce
            .first_chunk::<CRYPTO_CORE_HCHACHA20_INPUTBYTES>()
            .expect("XChaCha20 nonce holds the HChaCha20 input"),
        key,
        None,
    );

    // libsodium's `chacha20_ietf_ext` starts with IETF layout but allows the
    // 32-bit block counter to overflow into the leading zero nonce word. With
    // XChaCha's `0 || nonce_tail` derived nonce, that is equivalent to the
    // original 64-bit-counter ChaCha20 layout with `nonce_tail`.
    let nonce_tail = nonce
        .last_chunk()
        .expect("XChaCha20 nonce ends with the ChaCha20 nonce");
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
    /// `crypto_aead_xchacha20poly1305_ietf_decrypt_detached`, except that a
    /// failed tag check leaves `message` untouched (see [Behavior on
    /// failure](self#behavior-on-failure)).
    ///
    /// # Errors
    ///
    /// Returns an error if `ciphertext` is too long, `message.len()` does not equal
    /// `ciphertext.len()`, or authentication fails.
    decrypt_detached: crypto_aead_xchacha20poly1305_ietf_decrypt_detached,

    /// In-place detached variant of
    /// [`crypto_aead_xchacha20poly1305_ietf_decrypt_detached`]. On a failed tag
    /// check `data` is left unchanged, so the ciphertext survives (libsodium
    /// zeroes it; see [Behavior on failure](self#behavior-on-failure)).
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
    /// Compatible with libsodium's `crypto_aead_xchacha20poly1305_ietf_decrypt`,
    /// except that a failed tag check leaves `message` untouched (see
    /// [Behavior on failure](self#behavior-on-failure)).
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
    /// On a failed tag check `data` is left unchanged, so the ciphertext
    /// survives (libsodium zeroes it; see [Behavior on
    /// failure](self#behavior-on-failure)).
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
    #[cfg(dryoc_native_tests)]
    use crate::classic::crypto_aead_chacha20poly1305_impl::test_util::check_matches_libsodium;
    use crate::classic::crypto_aead_chacha20poly1305_impl::test_util::{
        Aead, check_failures_leave_outputs_untouched,
    };
    use crate::error::{Error, LengthConstraint};

    #[test]
    fn test_message_len_bound_is_xchacha_max() {
        const MAX: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX;
        const ABYTES: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

        // libsodium's bound leaves exactly one tag below the address space, so
        // every combined length at or above `ABYTES` is a valid message length.
        // The MESSAGEBYTES_MAX check itself is unreachable here: a combined
        // length of `MAX + ABYTES + 1` does not fit in `usize`.
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

    /// The XChaCha20 stream's block function input: the original
    /// 64-bit-counter ChaCha20 layout keyed by HChaCha20 of the first 16
    /// nonce bytes, with the last 8 nonce bytes as its nonce (words 14 and
    /// 15) and the counter supplied per block.
    fn xchacha20_state(nonce: &Nonce, key: &Key) -> [u32; 16] {
        let mut subkey = HChaCha20Key::default();
        crypto_core_hchacha20(
            &mut subkey,
            nonce.first_chunk::<16>().expect("16-byte prefix"),
            key,
            None,
        );
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&crate::utils::SIGMA);
        for (word, bytes) in state[4..12].iter_mut().zip(subkey.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        for (word, bytes) in state[14..].iter_mut().zip(nonce[16..].as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        state
    }

    /// The extended stream across the IETF 32-bit counter boundary and at
    /// the end of the 64-bit counter: 128 bytes from `u32::MAX` are blocks
    /// `u32::MAX` and `2^32` (word 13 becomes 1), and from `u64::MAX` block
    /// `u64::MAX` followed by block 0.
    #[test]
    fn test_xietf_ext_stream_crosses_counter_boundaries() {
        let state = xchacha20_state(&NONCE, &KEY);
        for start in [u64::from(u32::MAX), u64::MAX] {
            let mut expected = [0u8; 128];
            let (first, second) = expected.split_at_mut(64);
            crate::chacha20::scalar_block(&state, start, first.try_into().unwrap());
            crate::chacha20::scalar_block(
                &state,
                start.wrapping_add(1),
                second.try_into().unwrap(),
            );
            assert_ne!(first, second);

            let mut stream = [0u8; 128];
            xchacha20_stream(&NONCE, &KEY, start).apply_keystream(&mut stream);
            assert_eq!(stream, expected, "from {start:#x}");
        }
    }

    fn aead() -> Aead<Nonce> {
        Aead {
            encrypt_detached: crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
            encrypt_detached_inplace: crypto_aead_xchacha20poly1305_ietf_encrypt_detached_inplace,
            decrypt_detached: crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
            decrypt_detached_inplace: crypto_aead_xchacha20poly1305_ietf_decrypt_detached_inplace,
            encrypt: crypto_aead_xchacha20poly1305_ietf_encrypt,
            decrypt: crypto_aead_xchacha20poly1305_ietf_decrypt,
            encrypt_inplace: crypto_aead_xchacha20poly1305_ietf_encrypt_inplace,
            decrypt_inplace: crypto_aead_xchacha20poly1305_ietf_decrypt_inplace,
        }
    }

    #[test]
    fn test_failures_leave_outputs_untouched() {
        check_failures_leave_outputs_untouched(&aead(), &KEY, &NONCE);
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;

        #[test]
        fn test_libsodium_interop() {
            use crate::native_test_util::{
                crypto_aead_xchacha20poly1305_ietf_decrypt as open,
                crypto_aead_xchacha20poly1305_ietf_encrypt as seal,
            };

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
            let so_plaintext = open(&ciphertext, Some(AD), &NONCE, &KEY).expect("libsodium open");
            assert_eq!(so_plaintext, MESSAGE);

            let so_ciphertext = seal(MESSAGE, Some(AD), &NONCE, &KEY);
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

        /// The extended stream at the IETF 32-bit counter boundary and at the
        /// end of the 64-bit counter, two blocks from each, against
        /// libsodium's `crypto_stream_xchacha20_xor_ic`.
        #[test]
        fn test_counter_boundaries_match_libsodium_xchacha_stream() {
            use libsodium_sys::crypto_stream_xchacha20_xor_ic;

            crate::native_test_util::init();

            for start in [u64::from(u32::MAX), u64::MAX] {
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
                            start,
                            KEY.as_ptr(),
                        ),
                        0
                    );
                }

                let mut actual = [0u8; 128];
                xchacha20_stream(&NONCE, &KEY, start).apply_keystream(&mut actual);
                assert_eq!(actual, expected, "from {start:#x}");
            }
        }

        #[test]
        fn test_matches_libsodium_detached_and_combined() {
            crate::native_test_util::init();
            check_matches_libsodium(
                &aead(),
                libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
                &KEY,
                &NONCE,
            );
        }
    }
}
