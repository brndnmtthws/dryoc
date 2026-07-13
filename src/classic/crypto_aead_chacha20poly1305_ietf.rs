//! # ChaCha20-Poly1305-IETF authenticated encryption
//!
//! Implements libsodium's `crypto_aead_chacha20poly1305_ietf_*` functions.
//! This construction authenticates optional additional data, appends the
//! authentication tag in combined mode, and uses 96-bit public nonces as
//! specified by RFC 8439. This is not the legacy 64-bit-nonce construction.
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_aead_chacha20poly1305_ietf::*;
//! use dryoc::constants::{
//!     CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
//! };
//! use dryoc::types::*;
//!
//! let key = crypto_aead_chacha20poly1305_ietf_keygen();
//! // This 96-bit nonce must be unique for every message encrypted with `key`.
//! let nonce = [0u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES];
//! let message =
//!     b"Our doubts are traitors, and make us lose the good we oft might win, by fearing to attempt.";
//! let aad = b"metadata";
//!
//! let mut ciphertext = vec![0u8; message.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
//! crypto_aead_chacha20poly1305_ietf_encrypt(&mut ciphertext, message, Some(aad), &nonce, &key)
//!     .expect("encrypt failed");
//!
//! let mut decrypted = vec![0u8; message.len()];
//! crypto_aead_chacha20poly1305_ietf_decrypt(&mut decrypted, &ciphertext, Some(aad), &nonce, &key)
//!     .expect("decrypt failed");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```

use chacha20::cipher::array::Array;
use chacha20::cipher::consts::U64;
use chacha20::cipher::{Block, KeyIvInit, StreamCipherCore};
use chacha20::variants::Ietf;
use chacha20::{ChaChaCore, R20};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
};
use crate::error::Error;
use crate::poly1305::{Key as Poly1305Key, Poly1305};
use crate::rng::copy_randombytes;
use crate::types::*;
use crate::utils::pad16;

/// Authentication tag for ChaCha20-Poly1305-IETF AEAD.
pub type Mac = [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
/// Public nonce for ChaCha20-Poly1305-IETF AEAD.
pub type Nonce = [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES];
/// Secret key for ChaCha20-Poly1305-IETF AEAD.
pub type Key = [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];

const PAD0: [u8; 16] = [0u8; 16];

/// In-place variant of [`crypto_aead_chacha20poly1305_ietf_keygen`].
pub fn crypto_aead_chacha20poly1305_ietf_keygen_inplace(key: &mut Key) {
    copy_randombytes(key)
}

/// Generates a random key using [`copy_randombytes`].
pub fn crypto_aead_chacha20poly1305_ietf_keygen() -> Key {
    Key::generate()
}

fn validate_message_len(message_len: usize) -> Result<(), Error> {
    if message_len > CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX {
        Err(length_error!(
            crate::ErrorContext::Message,
            message_len,
            max CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
        ))
    } else {
        Ok(())
    }
}

fn validate_output_len(
    output_len: usize,
    expected_len: usize,
    context: crate::ErrorContext,
) -> Result<(), Error> {
    if output_len != expected_len {
        Err(length_error!(context, output_len, exact expected_len))
    } else {
        Ok(())
    }
}

fn message_len_from_combined_len(
    combined_len: usize,
    context: crate::ErrorContext,
) -> Result<usize, Error> {
    if combined_len < CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES {
        Err(length_error!(context, combined_len, min CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES))
    } else {
        let message_len = combined_len - CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
        validate_message_len(message_len)?;
        Ok(message_len)
    }
}

type ChaCha20IetfCore = ChaChaCore<R20, Ietf>;

fn apply_chacha20_ietf_keystream(data: &mut [u8], counter: u32, nonce: &Nonce, key: &Key) {
    let available_blocks = u64::from(u32::MAX) - u64::from(counter) + 1;
    debug_assert!((data.len() as u64) <= available_blocks * 64);

    let mut cipher = ChaCha20IetfCore::new(key.into(), nonce.into());
    cipher.set_block_pos(counter);

    // The core instance is local and discarded after this call, so allowing
    // the final counter block to wrap the internal position cannot cause
    // keystream reuse. The slice-based wrapper intentionally rejects that
    // block because it supports subsequent calls on the same instance.
    let (blocks, tail) = Array::<u8, U64>::slice_as_chunks_mut(data);
    cipher.apply_keystream_blocks(blocks);
    if !tail.is_empty() {
        let mut block = Block::<ChaCha20IetfCore>::default();
        cipher.write_keystream_block(&mut block);
        for (byte, keystream_byte) in tail.iter_mut().zip(block.iter()) {
            *byte ^= keystream_byte;
        }
        block.zeroize();
    }
}

fn poly1305_key(nonce: &Nonce, key: &Key) -> Poly1305Key {
    let mut mac_key = Poly1305Key::new();
    apply_chacha20_ietf_keystream(&mut mac_key, 0, nonce, key);
    mac_key
}

fn compute_mac(mac: &mut Mac, mac_key: &mut Poly1305Key, ciphertext: &[u8], ad: &[u8]) {
    let mut state = Poly1305::new(mac_key);
    mac_key.zeroize();

    state.update(ad);
    state.update(&PAD0[..pad16(ad.len())]);
    state.update(ciphertext);
    state.update(&PAD0[..pad16(ciphertext.len())]);
    state.update(&(ad.len() as u64).to_le_bytes());
    state.update(&(ciphertext.len() as u64).to_le_bytes());
    state.finalize(mac);
}

fn compute_mac_to_array(mac_key: &mut Poly1305Key, ciphertext: &[u8], ad: &[u8]) -> Mac {
    let mut mac = Mac::default();
    compute_mac(&mut mac, mac_key, ciphertext, ad);
    mac
}

fn verify_mac(mac: &Mac, computed_mac: &Mac) -> Result<(), Error> {
    if mac.ct_eq(computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

/// Detached version of [`crypto_aead_chacha20poly1305_ietf_encrypt`].
///
/// Compatible with libsodium's
/// `crypto_aead_chacha20poly1305_ietf_encrypt_detached`.
///
/// # Errors
///
/// Returns an error if `message` exceeds the maximum supported length or
/// `ciphertext.len()` does not equal `message.len()`.
pub fn crypto_aead_chacha20poly1305_ietf_encrypt_detached(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(message.len())?;
    validate_output_len(
        ciphertext.len(),
        message.len(),
        crate::ErrorContext::Ciphertext,
    )?;

    let associated_data = associated_data.unwrap_or(&[]);
    let mut mac_key = poly1305_key(nonce, key);

    ciphertext.copy_from_slice(message);
    apply_chacha20_ietf_keystream(ciphertext, 1, nonce, key);

    compute_mac(mac, &mut mac_key, ciphertext, associated_data);
    Ok(())
}

/// In-place detached variant of
/// [`crypto_aead_chacha20poly1305_ietf_encrypt_detached`].
///
/// # Errors
///
/// Returns an error if `data` exceeds the maximum supported message length.
pub fn crypto_aead_chacha20poly1305_ietf_encrypt_detached_inplace(
    data: &mut [u8],
    mac: &mut Mac,
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(data.len())?;

    let associated_data = associated_data.unwrap_or(&[]);
    let mut mac_key = poly1305_key(nonce, key);

    apply_chacha20_ietf_keystream(data, 1, nonce, key);

    compute_mac(mac, &mut mac_key, data, associated_data);
    Ok(())
}

/// Detached version of [`crypto_aead_chacha20poly1305_ietf_decrypt`].
///
/// Compatible with libsodium's
/// `crypto_aead_chacha20poly1305_ietf_decrypt_detached`.
///
/// # Errors
///
/// Returns an error if `ciphertext` is too long, `message.len()` does not equal
/// `ciphertext.len()`, or authentication fails.
pub fn crypto_aead_chacha20poly1305_ietf_decrypt_detached(
    message: &mut [u8],
    ciphertext: &[u8],
    mac: &Mac,
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(ciphertext.len())?;
    validate_output_len(
        message.len(),
        ciphertext.len(),
        crate::ErrorContext::Message,
    )?;

    let associated_data = associated_data.unwrap_or(&[]);
    let mut mac_key = poly1305_key(nonce, key);
    let computed_mac = compute_mac_to_array(&mut mac_key, ciphertext, associated_data);

    verify_mac(mac, &computed_mac)?;
    message.copy_from_slice(ciphertext);
    apply_chacha20_ietf_keystream(message, 1, nonce, key);
    Ok(())
}

/// In-place detached variant of
/// [`crypto_aead_chacha20poly1305_ietf_decrypt_detached`].
///
/// # Errors
///
/// Returns an error if `data` exceeds the maximum supported message length or
/// authentication fails.
pub fn crypto_aead_chacha20poly1305_ietf_decrypt_detached_inplace(
    data: &mut [u8],
    mac: &Mac,
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(data.len())?;

    let associated_data = associated_data.unwrap_or(&[]);
    let mut mac_key = poly1305_key(nonce, key);
    let computed_mac = compute_mac_to_array(&mut mac_key, data, associated_data);

    verify_mac(mac, &computed_mac)?;
    apply_chacha20_ietf_keystream(data, 1, nonce, key);
    Ok(())
}

/// Encrypts `message` with `nonce`, `key`, and optional associated data.
///
/// Compatible with libsodium's `crypto_aead_chacha20poly1305_ietf_encrypt`.
///
/// # Errors
///
/// Returns an error if `message` exceeds the maximum supported length or
/// `ciphertext` is not exactly one authentication tag longer than `message`.
pub fn crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext: &mut [u8],
    message: &[u8],
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    validate_message_len(message.len())?;
    validate_output_len(
        ciphertext.len(),
        message.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
        crate::ErrorContext::Ciphertext,
    )?;

    let (ciphertext, mac) = ciphertext.split_at_mut(message.len());
    let mac = MutByteArray::as_mut_array(mac);
    crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        ciphertext,
        mac,
        message,
        associated_data,
        nonce,
        key,
    )
}

/// Decrypts `ciphertext` with `nonce`, `key`, and optional associated data.
///
/// Compatible with libsodium's `crypto_aead_chacha20poly1305_ietf_decrypt`.
///
/// # Errors
///
/// Returns an error if `ciphertext` is shorter than an authentication tag,
/// `message` has the wrong length, or authentication fails.
pub fn crypto_aead_chacha20poly1305_ietf_decrypt(
    message: &mut [u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let message_len =
        message_len_from_combined_len(ciphertext.len(), crate::ErrorContext::Ciphertext)?;
    validate_output_len(message.len(), message_len, crate::ErrorContext::Message)?;

    let (ciphertext, mac) = ciphertext.split_at(message_len);
    let mac = ByteArray::as_array(mac);
    crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        message,
        ciphertext,
        mac,
        associated_data,
        nonce,
        key,
    )
}

/// Encrypts `data` in place and appends the authentication tag.
///
/// The last [`CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES`] bytes are reserved
/// for the tag and are ignored as plaintext input.
///
/// # Errors
///
/// Returns an error if `data` is shorter than an authentication tag or its
/// plaintext portion exceeds the maximum supported message length.
pub fn crypto_aead_chacha20poly1305_ietf_encrypt_inplace(
    data: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let message_len = message_len_from_combined_len(data.len(), crate::ErrorContext::Data)?;
    let (data, mac) = data.split_at_mut(message_len);
    let mac = MutByteArray::as_mut_array(mac);
    crypto_aead_chacha20poly1305_ietf_encrypt_detached_inplace(
        data,
        mac,
        associated_data,
        nonce,
        key,
    )
}

/// Decrypts `data` in place after verifying the appended authentication tag.
///
/// After success, the first `data.len() -
/// CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES` bytes contain the plaintext.
///
/// # Errors
///
/// Returns an error if `data` is shorter than an authentication tag or
/// authentication fails.
pub fn crypto_aead_chacha20poly1305_ietf_decrypt_inplace(
    data: &mut [u8],
    associated_data: Option<&[u8]>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let message_len = message_len_from_combined_len(data.len(), crate::ErrorContext::Data)?;
    let (data, mac) = data.split_at_mut(message_len);
    let mac = ByteArray::as_array(mac);
    crypto_aead_chacha20poly1305_ietf_decrypt_detached_inplace(
        data,
        mac,
        associated_data,
        nonce,
        key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];

    fn expected() -> Vec<u8> {
        hex::decode(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2",
            "a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58",
            "fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b",
            "61161ae10b594f09e26a7e902ecbd0600691"
        ))
        .expect("valid test vector")
    }

    #[test]
    fn test_rfc_8439_known_answer() {
        let mut ciphertext = vec![0u8; MESSAGE.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_chacha20poly1305_ietf_encrypt(&mut ciphertext, MESSAGE, Some(AD), &NONCE, &KEY)
            .expect("encrypt");
        assert_eq!(ciphertext, expected());

        let mut decrypted = vec![0u8; MESSAGE.len()];
        crypto_aead_chacha20poly1305_ietf_decrypt(
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
    fn test_detached_and_inplace_match_combined() {
        let expected = expected();
        let mut detached = MESSAGE.to_vec();
        let mut mac = Mac::default();
        crypto_aead_chacha20poly1305_ietf_encrypt_detached_inplace(
            &mut detached,
            &mut mac,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("detached encrypt");
        assert_eq!(detached, expected[..MESSAGE.len()]);
        assert_eq!(mac, expected[MESSAGE.len()..]);

        crypto_aead_chacha20poly1305_ietf_decrypt_detached_inplace(
            &mut detached,
            &mac,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("detached decrypt");
        assert_eq!(detached, MESSAGE);

        let mut combined = MESSAGE.to_vec();
        combined.resize(MESSAGE.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, 0);
        crypto_aead_chacha20poly1305_ietf_encrypt_inplace(&mut combined, Some(AD), &NONCE, &KEY)
            .expect("in-place encrypt");
        assert_eq!(combined, expected);
    }

    #[test]
    fn test_authentication_failure_does_not_mutate_output() {
        let mut ciphertext = expected();
        ciphertext[0] ^= 1;
        let mut plaintext = vec![0xa5; MESSAGE.len()];
        let original = plaintext.clone();

        assert!(matches!(
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut plaintext,
                &ciphertext,
                Some(AD),
                &NONCE,
                &KEY,
            ),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(plaintext, original);

        let mut inplace = ciphertext;
        let original = inplace.clone();
        assert!(matches!(
            crypto_aead_chacha20poly1305_ietf_decrypt_inplace(&mut inplace, Some(AD), &NONCE, &KEY,),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(inplace, original);

        let mut plaintext = vec![0xa5; MESSAGE.len()];
        assert!(matches!(
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut plaintext,
                &expected(),
                Some(b"wrong associated data"),
                &NONCE,
                &KEY,
            ),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(plaintext, vec![0xa5; MESSAGE.len()]);
    }

    #[test]
    fn test_empty_message_and_length_errors() {
        let mut ciphertext = [0u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
        crypto_aead_chacha20poly1305_ietf_encrypt(&mut ciphertext, &[], None, &NONCE, &KEY)
            .expect("empty encrypt");
        crypto_aead_chacha20poly1305_ietf_decrypt(&mut [], &ciphertext, None, &NONCE, &KEY)
            .expect("empty decrypt");

        assert!(
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut [],
                &[0u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES - 1],
                None,
                &NONCE,
                &KEY,
            )
            .is_err()
        );
        assert!(
            crypto_aead_chacha20poly1305_ietf_encrypt(&mut [0u8; 1], &[], None, &NONCE, &KEY,)
                .is_err()
        );
    }

    #[test]
    fn test_final_counter_block_is_available() {
        let mut block = [0u8; 64];
        apply_chacha20_ietf_keystream(&mut block, u32::MAX, &NONCE, &KEY);
        assert_ne!(block, [0u8; 64]);

        apply_chacha20_ietf_keystream(&mut block, u32::MAX, &NONCE, &KEY);
        assert_eq!(block, [0u8; 64]);
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_final_counter_block_matches_libsodium() {
        use libsodium_sys::crypto_stream_chacha20_ietf_xor_ic;

        let message = [0xa5u8; 64];
        let mut actual = message;
        apply_chacha20_ietf_keystream(&mut actual, u32::MAX, &NONCE, &KEY);

        let mut expected = [0u8; 64];
        // SAFETY: All pointers reference initialized, correctly sized arrays
        // that remain valid and non-overlapping for the duration of the call.
        let result = unsafe {
            crypto_stream_chacha20_ietf_xor_ic(
                expected.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                NONCE.as_ptr(),
                u32::MAX,
                KEY.as_ptr(),
            )
        };
        assert_eq!(result, 0);
        assert_eq!(actual, expected);
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_libsodium_constants() {
        use libsodium_sys::{
            crypto_aead_chacha20poly1305_ietf_abytes, crypto_aead_chacha20poly1305_ietf_keybytes,
            crypto_aead_chacha20poly1305_ietf_messagebytes_max,
            crypto_aead_chacha20poly1305_ietf_npubbytes,
            crypto_aead_chacha20poly1305_ietf_nsecbytes,
        };

        use crate::constants::CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES;

        // SAFETY: These parameter-free libsodium functions only return compile-time
        // constants.
        unsafe {
            assert_eq!(
                crypto_aead_chacha20poly1305_ietf_keybytes(),
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES
            );
            assert_eq!(
                crypto_aead_chacha20poly1305_ietf_nsecbytes(),
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES
            );
            assert_eq!(
                crypto_aead_chacha20poly1305_ietf_npubbytes(),
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
            );
            assert_eq!(
                crypto_aead_chacha20poly1305_ietf_abytes(),
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES
            );
            assert_eq!(
                crypto_aead_chacha20poly1305_ietf_messagebytes_max(),
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
            );
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_sodiumoxide_interop() {
        use sodiumoxide::crypto::aead::chacha20poly1305_ietf::{
            Key as SodiumKey, Nonce as SodiumNonce, open, seal,
        };

        let sodium_key = SodiumKey::from_slice(&KEY).expect("key");
        let sodium_nonce = SodiumNonce::from_slice(&NONCE).expect("nonce");
        let ciphertext = expected();
        assert_eq!(
            open(&ciphertext, Some(AD), &sodium_nonce, &sodium_key).expect("sodiumoxide open"),
            MESSAGE
        );

        let sodium_ciphertext = seal(MESSAGE, Some(AD), &sodium_nonce, &sodium_key);
        let mut plaintext = vec![0u8; MESSAGE.len()];
        crypto_aead_chacha20poly1305_ietf_decrypt(
            &mut plaintext,
            &sodium_ciphertext,
            Some(AD),
            &NONCE,
            &KEY,
        )
        .expect("dryoc decrypt");
        assert_eq!(plaintext, MESSAGE);
    }
}
