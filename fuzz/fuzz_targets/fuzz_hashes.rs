#![no_main]
//! SHA-256, SHA-512 and their HMACs against the `sha2` crate, plus streamed
//! and one-shot BLAKE2b and Poly1305 against each other, at every length
//! and chunking the fuzzer finds. On AArch64 this drives the SHA2/SHA3
//! hardware compressions, the register-scheduled BLAKE2b rounds and the
//! NEON Poly1305 bulk path.
use dryoc::classic::crypto_auth_hmacsha256::{
    crypto_auth_hmacsha256, crypto_auth_hmacsha256_final, crypto_auth_hmacsha256_init,
    crypto_auth_hmacsha256_update, crypto_auth_hmacsha256_verify,
};
use dryoc::classic::crypto_auth_hmacsha512::{
    crypto_auth_hmacsha512, crypto_auth_hmacsha512_final, crypto_auth_hmacsha512_init,
    crypto_auth_hmacsha512_update, crypto_auth_hmacsha512_verify,
};
use dryoc::classic::crypto_auth_hmacsha512256::{
    crypto_auth_hmacsha512256, crypto_auth_hmacsha512256_final, crypto_auth_hmacsha512256_init,
    crypto_auth_hmacsha512256_update,
};
use dryoc::classic::crypto_generichash::{
    crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update,
};
use dryoc::classic::crypto_hash::{
    crypto_hash_sha256, crypto_hash_sha256_final, crypto_hash_sha256_init,
    crypto_hash_sha256_update, crypto_hash_sha512, crypto_hash_sha512_final,
    crypto_hash_sha512_init, crypto_hash_sha512_update,
};
use dryoc::classic::crypto_onetimeauth::{
    crypto_onetimeauth, crypto_onetimeauth_final, crypto_onetimeauth_init,
    crypto_onetimeauth_update, crypto_onetimeauth_verify,
};
use libfuzzer_sys::fuzz_target;
use sha2::Digest;

#[path = "common.rs"]
mod common;
use common::fill;

/// Cut points into `message` derived from the fuzz input.
fn cuts(data: &mut &[u8], len: usize) -> Vec<usize> {
    let count = usize::from(fill::<1>(data)[0] & 7);
    let mut cuts: Vec<usize> = (0..count)
        .map(|_| usize::from(u16::from_le_bytes(fill::<2>(data))) % (len + 1))
        .collect();
    cuts.push(0);
    cuts.push(len);
    cuts.sort_unstable();
    cuts
}

/// HMAC as RFC 2104 spells it, over the `sha2` hash `H` with block size `B`.
fn reference_hmac<H: Digest, const B: usize>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut block = [0u8; B];
    if key.len() > B {
        let digest = H::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    let inner = H::new()
        .chain_update(&ipad)
        .chain_update(message)
        .finalize();
    H::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize()
        .to_vec()
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let key = fill::<32>(&mut data);
    let hash_key = fill::<64>(&mut data);
    let hash_keylen = usize::from(fill::<1>(&mut data)[0]) % 65;
    let hmac_key = fill::<256>(&mut data);
    let hmac_keylen = usize::from(u16::from_le_bytes(fill::<2>(&mut data))) % 257;
    let long_hmac_keylen = 129 + usize::from(fill::<1>(&mut data)[0]) % 128;
    let outlen = 16 + usize::from(fill::<1>(&mut data)[0]) % 49;
    let message_len = usize::from(u16::from_le_bytes(fill::<2>(&mut data))) & 0xfff;
    let message: Vec<u8> = if data.is_empty() {
        vec![0u8; message_len]
    } else {
        data.iter().copied().cycle().take(message_len).collect()
    };
    let cuts = cuts(&mut data, message.len());
    let chunks = || cuts.windows(2).map(|w| &message[w[0]..w[1]]);

    // SHA-256 / SHA-512 one-shot and streamed against `sha2`.
    let expected = sha2::Sha256::digest(&message);
    let mut digest = [0u8; 32];
    crypto_hash_sha256(&mut digest, &message);
    assert_eq!(digest[..], expected[..]);
    let mut state = crypto_hash_sha256_init();
    chunks().for_each(|chunk| crypto_hash_sha256_update(&mut state, chunk));
    crypto_hash_sha256_final(state, &mut digest);
    assert_eq!(digest[..], expected[..]);

    let expected = sha2::Sha512::digest(&message);
    let mut digest = [0u8; 64];
    crypto_hash_sha512(&mut digest, &message);
    assert_eq!(digest[..], expected[..]);
    let mut state = crypto_hash_sha512_init();
    chunks().for_each(|chunk| crypto_hash_sha512_update(&mut state, chunk));
    crypto_hash_sha512_final(state, &mut digest);
    assert_eq!(digest[..], expected[..]);

    // HMACs: fixed-size keys one-shot (the paired-block HMAC-SHA-512 init on
    // AArch64), fuzz-selected 0..=256-byte keys streamed, and a second
    // guaranteed >128-byte streamed pass for long-key normalization.
    let expected = reference_hmac::<sha2::Sha256, 64>(&key, &message);
    let mut mac = [0u8; 32];
    crypto_auth_hmacsha256(&mut mac, &message, &key);
    assert_eq!(mac[..], expected[..]);
    crypto_auth_hmacsha256_verify(&mac, &message, &key).expect("hmacsha256 verify");
    let expected = reference_hmac::<sha2::Sha256, 64>(&hmac_key[..hmac_keylen], &message);
    let mut state = crypto_auth_hmacsha256_init(&hmac_key[..hmac_keylen]);
    chunks().for_each(|chunk| crypto_auth_hmacsha256_update(&mut state, chunk));
    crypto_auth_hmacsha256_final(state, &mut mac);
    assert_eq!(mac[..], expected[..]);
    let expected = reference_hmac::<sha2::Sha256, 64>(&hmac_key[..long_hmac_keylen], &message);
    let mut state = crypto_auth_hmacsha256_init(&hmac_key[..long_hmac_keylen]);
    chunks().for_each(|chunk| crypto_auth_hmacsha256_update(&mut state, chunk));
    crypto_auth_hmacsha256_final(state, &mut mac);
    assert_eq!(mac[..], expected[..]);

    let expected = reference_hmac::<sha2::Sha512, 128>(&key, &message);
    let mut mac = [0u8; 64];
    crypto_auth_hmacsha512(&mut mac, &message, &key);
    assert_eq!(mac[..], expected[..]);
    crypto_auth_hmacsha512_verify(&mac, &message, &key).expect("hmacsha512 verify");
    let expected = reference_hmac::<sha2::Sha512, 128>(&hmac_key[..hmac_keylen], &message);
    let mut state = crypto_auth_hmacsha512_init(&hmac_key[..hmac_keylen]);
    chunks().for_each(|chunk| crypto_auth_hmacsha512_update(&mut state, chunk));
    crypto_auth_hmacsha512_final(state, &mut mac);
    assert_eq!(mac[..], expected[..]);
    let expected = reference_hmac::<sha2::Sha512, 128>(&hmac_key[..long_hmac_keylen], &message);
    let mut state = crypto_auth_hmacsha512_init(&hmac_key[..long_hmac_keylen]);
    chunks().for_each(|chunk| crypto_auth_hmacsha512_update(&mut state, chunk));
    crypto_auth_hmacsha512_final(state, &mut mac);
    assert_eq!(mac[..], expected[..]);

    let expected = reference_hmac::<sha2::Sha512, 128>(&key, &message);
    let mut mac = [0u8; 32];
    crypto_auth_hmacsha512256(&mut mac, &message, &key);
    assert_eq!(mac[..], expected[..32]);
    let expected = reference_hmac::<sha2::Sha512, 128>(&hmac_key[..hmac_keylen], &message);
    let mut state = crypto_auth_hmacsha512256_init(&hmac_key[..hmac_keylen]);
    chunks().for_each(|chunk| crypto_auth_hmacsha512256_update(&mut state, chunk));
    crypto_auth_hmacsha512256_final(state, &mut mac);
    assert_eq!(mac[..], expected[..32]);
    let expected = reference_hmac::<sha2::Sha512, 128>(&hmac_key[..long_hmac_keylen], &message);
    let mut state = crypto_auth_hmacsha512256_init(&hmac_key[..long_hmac_keylen]);
    chunks().for_each(|chunk| crypto_auth_hmacsha512256_update(&mut state, chunk));
    crypto_auth_hmacsha512256_final(state, &mut mac);
    assert_eq!(mac[..], expected[..32]);

    // BLAKE2b: one-shot (single-block fast path included) against streamed,
    // unkeyed and keyed.
    let generichash_key = (hash_keylen >= 16).then_some(&hash_key[..hash_keylen]);
    let mut expected = vec![0u8; outlen];
    crypto_generichash(&mut expected, &message, generichash_key).expect("generichash");
    let mut state = crypto_generichash_init(generichash_key, outlen).expect("generichash init");
    chunks().for_each(|chunk| crypto_generichash_update(&mut state, chunk));
    let mut actual = vec![0u8; outlen];
    crypto_generichash_final(state, &mut actual).expect("generichash final");
    assert_eq!(actual, expected);

    // Poly1305: one-shot (the bulk path for long messages) against streamed
    // (partial blocks buffered across the cuts).
    let mut expected = [0u8; 16];
    crypto_onetimeauth(&mut expected, &message, &key);
    crypto_onetimeauth_verify(&expected, &message, &key).expect("onetimeauth verify");
    let mut state = crypto_onetimeauth_init(&key);
    chunks().for_each(|chunk| crypto_onetimeauth_update(&mut state, chunk));
    let mut actual = [0u8; 16];
    crypto_onetimeauth_final(state, &mut actual);
    assert_eq!(actual, expected);
});
