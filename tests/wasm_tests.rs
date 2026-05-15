#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use dryoc::classic::crypto_generichash::crypto_generichash;
use dryoc::dryocbox::{DryocBox, KeyPair, NewByteArray, Nonce};
use dryoc::dryocsecretbox::{DryocSecretBox, Key};
use dryoc::precalc::PrecalcSecretKey;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn dryocbox_roundtrip() {
    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"wasm dryocbox";

    let dryocbox = DryocBox::encrypt_to_vecbox(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let decrypted = dryocbox
        .decrypt_to_vec(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[wasm_bindgen_test]
fn dryocbox_precalc_roundtrip() {
    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"wasm dryocbox precalc";
    let shared_key =
        PrecalcSecretKey::precalculate(&recipient_keypair.public_key, &sender_keypair.secret_key);

    let dryocbox =
        DryocBox::precalc_encrypt_to_vecbox(message, &nonce, &shared_key).expect("encrypt failed");
    let decrypted = dryocbox
        .decrypt_to_vec(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[wasm_bindgen_test]
fn dryocsecretbox_roundtrip() {
    let secret_key = Key::generate();
    let nonce = dryoc::dryocsecretbox::Nonce::generate();
    let message = b"wasm dryocsecretbox";

    let dryocsecretbox: dryoc::dryocsecretbox::VecBox =
        DryocSecretBox::encrypt(message, &nonce, &secret_key);
    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[wasm_bindgen_test]
fn generichash_known_answer() {
    let mut hash = [0u8; 32];
    crypto_generichash(&mut hash, b"abc", None).expect("hash failed");

    assert_eq!(
        &hash,
        &[
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ]
    );
}
