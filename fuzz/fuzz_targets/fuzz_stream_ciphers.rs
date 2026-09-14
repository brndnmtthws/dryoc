#![no_main]
//! XSalsa20 and ChaCha20 keystreams, as reached through `crypto_secretbox`
//! and the two ChaCha20-Poly1305 AEADs, against the RustCrypto stream
//! ciphers, for every message length the fuzzer finds (one call per
//! primitive, as the AEADs and secretbox make). On AArch64 this drives the
//! NEON/SVE2 kernels and their scalar tails.
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, XChaCha20};
use dryoc::classic::crypto_aead_chacha20poly1305_ietf::{
    crypto_aead_chacha20poly1305_ietf_decrypt, crypto_aead_chacha20poly1305_ietf_encrypt,
};
use dryoc::classic::crypto_aead_xchacha20poly1305_ietf::{
    crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt,
};
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_detached, crypto_secretbox_easy, crypto_secretbox_open_easy,
};
use dryoc::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
    CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use libfuzzer_sys::fuzz_target;
use salsa20::XSalsa20;

#[path = "common.rs"]
mod common;
use common::fill;

/// A length in `0..=4095` from two bytes, so multi-chunk kernel runs and
/// every tail length are reachable.
fn take_len(data: &mut &[u8]) -> usize {
    let bytes = fill::<2>(data);
    usize::from(u16::from_le_bytes(bytes)) & 0xfff
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let key = fill::<32>(&mut data);
    let nonce = fill::<CRYPTO_SECRETBOX_NONCEBYTES>(&mut data);
    let aad_len = take_len(&mut data).min(64);
    let message_len = take_len(&mut data);
    // The message is the remaining input, repeated to the chosen length so
    // long messages do not need long fuzz inputs.
    let message: Vec<u8> = if data.is_empty() {
        vec![0u8; message_len]
    } else {
        data.iter().copied().cycle().take(message_len).collect()
    };
    let aad = if aad_len == 0 {
        None
    } else {
        Some(&message[..aad_len.min(message.len())])
    };

    // XSalsa20: the secretbox keystream starts at byte 32 (the first 32
    // bytes key Poly1305).
    let mut expected = vec![0u8; 32 + message.len()];
    expected[32..].copy_from_slice(&message);
    XSalsa20::new(&key.into(), &nonce.into()).apply_keystream(&mut expected);
    let mut boxed = vec![0u8; CRYPTO_SECRETBOX_MACBYTES + message.len()];
    crypto_secretbox_easy(&mut boxed, &message, &nonce, &key).expect("secretbox");
    assert_eq!(&boxed[CRYPTO_SECRETBOX_MACBYTES..], &expected[32..]);
    let mut detached = vec![0u8; message.len()];
    let mut mac = [0u8; CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_detached(&mut detached, &mut mac, &message, &nonce, &key)
        .expect("secretbox detached");
    assert_eq!(detached, &expected[32..]);
    assert_eq!(mac, boxed[..CRYPTO_SECRETBOX_MACBYTES]);
    let mut opened = vec![0u8; message.len()];
    crypto_secretbox_open_easy(&mut opened, &boxed, &nonce, &key).expect("secretbox open");
    assert_eq!(opened, message);

    // ChaCha20 (IETF): block 0 keys Poly1305, the message starts at block 1.
    let ietf_nonce: [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES] = nonce
        [..CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES]
        .try_into()
        .unwrap();
    let mut expected = message.clone();
    let mut cipher = ChaCha20::new(&key.into(), &ietf_nonce.into());
    cipher.seek(64u64);
    cipher.apply_keystream(&mut expected);
    let mut sealed = vec![0u8; message.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
    crypto_aead_chacha20poly1305_ietf_encrypt(&mut sealed, &message, aad, &ietf_nonce, &key)
        .expect("chacha20poly1305 encrypt");
    assert_eq!(&sealed[..message.len()], &expected);
    let mut opened = vec![0u8; message.len()];
    crypto_aead_chacha20poly1305_ietf_decrypt(&mut opened, &sealed, aad, &ietf_nonce, &key)
        .expect("chacha20poly1305 decrypt");
    assert_eq!(opened, message);

    // XChaCha20: HChaCha20 subkey, then the IETF layout with block 0 keying
    // Poly1305.
    let xnonce: [u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES] = nonce;
    let mut expected = message.clone();
    let mut cipher = XChaCha20::new(&key.into(), &xnonce.into());
    cipher.seek(64u64);
    cipher.apply_keystream(&mut expected);
    let mut sealed = vec![0u8; message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
    crypto_aead_xchacha20poly1305_ietf_encrypt(&mut sealed, &message, aad, &xnonce, &key)
        .expect("xchacha20poly1305 encrypt");
    assert_eq!(&sealed[..message.len()], &expected);
    let mut opened = vec![0u8; message.len()];
    crypto_aead_xchacha20poly1305_ietf_decrypt(&mut opened, &sealed, aad, &xnonce, &key)
        .expect("xchacha20poly1305 decrypt");
    assert_eq!(opened, message);
});
