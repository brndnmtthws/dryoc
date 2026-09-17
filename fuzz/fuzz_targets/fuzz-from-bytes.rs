#![no_main]
//! The Rustaceous `from_bytes` parsers: each accepts exactly the inputs at
//! least as long as its fixed prefix (a `CRYPTO_*` constant), and on success
//! the parts it hands back are the corresponding byte splits of the input,
//! which `to_vec` reassembles verbatim.
use dryoc::constants::{
    CRYPTO_BOX_MACBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES,
    CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SIGN_BYTES,
};
use dryoc::dryocbox::VecBox as VecDryocBox;
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
