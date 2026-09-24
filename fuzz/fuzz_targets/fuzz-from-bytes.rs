#![no_main]
//! The Rustaceous `from_bytes` parsers: each accepts exactly the inputs at
//! least as long as its fixed prefix (a `CRYPTO_*` constant or
//! `dryocsealedbox::SEALBYTES`), and on success the parts it hands back are
//! the corresponding byte splits of the input, which `to_vec` reassembles
//! verbatim.
//!
//! Boundary-length seeds around `SEALBYTES` (1135/1136/1137) live in
//! `seeds/fuzz-from-bytes`; pass that directory after the corpus, since
//! libFuzzer otherwise grows inputs towards post-quantum sealed-box sizes
//! only slowly: `cargo fuzz run fuzz-from-bytes corpus/fuzz-from-bytes
//! seeds/fuzz-from-bytes`.
use dryoc::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_BOX_MACBYTES, CRYPTO_BOX_PUBLICKEYBYTES,
    CRYPTO_BOX_SEALBYTES, CRYPTO_KEM_XWING_CIPHERTEXTBYTES, CRYPTO_SECRETBOX_MACBYTES,
    CRYPTO_SIGN_BYTES,
};
use dryoc::dryocbox::VecBox as VecDryocBox;
use dryoc::dryocsealedbox::{SEALBYTES, VecBox as VecSealedBox};
use dryoc::dryocsecretbox::VecBox as VecSecretBox;
use dryoc::sign::VecSignedMessage;
use dryoc::types::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // DryocBox: `tag || ciphertext`.
    match VecDryocBox::from_bytes(data) {
        Ok(dryocbox) => {
            assert!(data.len() >= CRYPTO_BOX_MACBYTES);
            assert_eq!(dryocbox.to_vec(), data);
            let (tag, ciphertext, ephemeral_pk) = dryocbox.into_parts();
            let (expected_tag, expected_ciphertext) = data.split_at(CRYPTO_BOX_MACBYTES);
            assert_eq!(tag.as_slice(), expected_tag);
            assert_eq!(ciphertext, expected_ciphertext);
            assert!(ephemeral_pk.is_none());
        }
        Err(_) => assert!(data.len() < CRYPTO_BOX_MACBYTES),
    }

    // Sealed DryocBox: `ephemeral_pk || tag || ciphertext`.
    match VecDryocBox::from_sealed_bytes(data) {
        Ok(dryocbox) => {
            assert!(data.len() >= CRYPTO_BOX_SEALBYTES);
            assert_eq!(dryocbox.to_vec(), data);
            let (tag, ciphertext, ephemeral_pk) = dryocbox.into_parts();
            let (expected_pk, rest) = data.split_at(CRYPTO_BOX_PUBLICKEYBYTES);
            let (expected_tag, expected_ciphertext) = rest.split_at(CRYPTO_BOX_MACBYTES);
            assert_eq!(
                ephemeral_pk
                    .expect("sealed box has an ephemeral key")
                    .as_slice(),
                expected_pk
            );
            assert_eq!(tag.as_slice(), expected_tag);
            assert_eq!(ciphertext, expected_ciphertext);
        }
        Err(_) => assert!(data.len() < CRYPTO_BOX_SEALBYTES),
    }

    // Post-quantum DryocSealedBox: `enc || ciphertext || tag`.
    match VecSealedBox::from_bytes(data) {
        Ok(sealed) => {
            assert!(data.len() >= SEALBYTES);
            assert_eq!(sealed.to_vec(), data);
            let (enc, tag, ciphertext) = sealed.into_parts();
            let (expected_enc, rest) = data.split_at(CRYPTO_KEM_XWING_CIPHERTEXTBYTES);
            let (expected_ciphertext, expected_tag) =
                rest.split_at(rest.len() - CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
            assert_eq!(enc.as_slice(), expected_enc);
            assert_eq!(ciphertext, expected_ciphertext);
            assert_eq!(tag.as_slice(), expected_tag);
        }
        Err(_) => assert!(data.len() < SEALBYTES),
    }

    // DryocSecretBox: `tag || ciphertext`.
    match VecSecretBox::from_bytes(data) {
        Ok(secretbox) => {
            assert!(data.len() >= CRYPTO_SECRETBOX_MACBYTES);
            assert_eq!(secretbox.to_vec(), data);
            let (tag, ciphertext) = secretbox.into_parts();
            let (expected_tag, expected_ciphertext) = data.split_at(CRYPTO_SECRETBOX_MACBYTES);
            assert_eq!(tag.as_slice(), expected_tag);
            assert_eq!(ciphertext, expected_ciphertext);
        }
        Err(_) => assert!(data.len() < CRYPTO_SECRETBOX_MACBYTES),
    }

    // SignedMessage: `signature || message`.
    match VecSignedMessage::from_bytes(data) {
        Ok(signed_message) => {
            assert!(data.len() >= CRYPTO_SIGN_BYTES);
            assert_eq!(signed_message.to_vec(), data);
            let (signature, message) = signed_message.into_parts();
            let (expected_signature, expected_message) = data.split_at(CRYPTO_SIGN_BYTES);
            assert_eq!(signature.as_slice(), expected_signature);
            assert_eq!(message, expected_message);
        }
        Err(_) => assert!(data.len() < CRYPTO_SIGN_BYTES),
    }
});
