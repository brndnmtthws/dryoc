#![no_main]
//! SHA-256, SHA-512 and their HMACs against the `sha2` crate, SipHash-2-4
//! against the paper's reference below, SHA3-256/512 and the SHAKE and
//! TurboSHAKE XOFs (fuzz-selected domain and output length, streamed input and
//! output) against the `sha3` 0.10 crate, plus streamed and one-shot BLAKE2b
//! and Poly1305 against each other (and BLAKE2b's key/output length
//! contract), at every length and chunking the fuzzer finds. On AArch64 this
//! drives the SHA2 hardware compressions, the SHA3-extension Keccak
//! permutation, the register-scheduled BLAKE2b rounds and the NEON Poly1305
//! bulk path.
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
    crypto_hash_sha512_init, crypto_hash_sha512_update, crypto_hash_sha3256,
    crypto_hash_sha3256_final, crypto_hash_sha3256_init, crypto_hash_sha3256_update,
    crypto_hash_sha3512, crypto_hash_sha3512_final, crypto_hash_sha3512_init,
    crypto_hash_sha3512_update,
};
use dryoc::classic::crypto_onetimeauth::{
    crypto_onetimeauth, crypto_onetimeauth_final, crypto_onetimeauth_init,
    crypto_onetimeauth_update, crypto_onetimeauth_verify,
};
use dryoc::classic::crypto_shorthash::crypto_shorthash;
use dryoc::classic::crypto_xof::*;
use dryoc::constants::{CRYPTO_GENERICHASH_BYTES_MAX, CRYPTO_GENERICHASH_KEYBYTES_MAX};
use dryoc::sha3::{Sha3256, Sha3512};
use dryoc::xof::{Shake128, Shake256, TurboShake128, TurboShake256};
use libfuzzer_sys::fuzz_target;
use sha2::Digest;
use sha3::digest::{ExtendableOutput, Update, XofReader};

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

/// SipHash-2-4 as the paper (Aumasson & Bernstein, 2012) spells it.
fn reference_siphash24(key: &[u8; 16], message: &[u8]) -> [u8; 8] {
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    }
    fn absorb(v: &mut [u64; 4], m: u64) {
        v[3] ^= m;
        round(v);
        round(v);
        v[0] ^= m;
    }

    let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let (blocks, rest) = message.as_chunks::<8>();
    for block in blocks {
        absorb(&mut v, u64::from_le_bytes(*block));
    }
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    last[7] = message.len() as u8;
    absorb(&mut v, u64::from_le_bytes(last));
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    (v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes()
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let key = fill::<32>(&mut data);
    let hash_key = fill::<64>(&mut data);
    let hash_keylen = usize::from(fill::<1>(&mut data)[0]) % 65;
    let hmac_key = fill::<256>(&mut data);
    let hmac_keylen = usize::from(u16::from_le_bytes(fill::<2>(&mut data))) % 257;
    let long_hmac_keylen = 129 + usize::from(fill::<1>(&mut data)[0]) % 128;
    let outlen = 1 + usize::from(fill::<1>(&mut data)[0]) % 64;
    let xof_len = usize::from(u16::from_le_bytes(fill::<2>(&mut data))) % 600;
    let xof_domain = 1 + fill::<1>(&mut data)[0] % 0x7f;
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

    // SHA3-256 / SHA3-512 one-shot, streamed (rate boundaries 136 and 72 fall
    // within the chunking) and through the Rustaceous wrapper, against `sha3`.
    let expected = <sha3::Sha3_256 as sha3::Digest>::digest(&message);
    let mut digest = [0u8; 32];
    crypto_hash_sha3256(&mut digest, &message);
    assert_eq!(digest[..], expected[..]);
    let mut state = crypto_hash_sha3256_init();
    chunks().for_each(|chunk| crypto_hash_sha3256_update(&mut state, chunk));
    crypto_hash_sha3256_final(state, &mut digest);
    assert_eq!(digest[..], expected[..]);
    let mut hasher = Sha3256::new();
    chunks().for_each(|chunk| hasher.update(chunk));
    assert_eq!(hasher.finalize_to_vec(), expected[..]);

    let expected = <sha3::Sha3_512 as sha3::Digest>::digest(&message);
    let mut digest = [0u8; 64];
    crypto_hash_sha3512(&mut digest, &message);
    assert_eq!(digest[..], expected[..]);
    let mut state = crypto_hash_sha3512_init();
    chunks().for_each(|chunk| crypto_hash_sha3512_update(&mut state, chunk));
    crypto_hash_sha3512_final(state, &mut digest);
    assert_eq!(digest[..], expected[..]);
    let mut hasher = Sha3512::new();
    chunks().for_each(|chunk| hasher.update(chunk));
    assert_eq!(hasher.finalize_to_vec(), expected[..]);

    // XOFs: output squeezed in the same cut pattern (scaled onto the output
    // length) through the Classic state and the Rustaceous reader, against
    // `sha3`. TurboSHAKE also takes the fuzz-selected domain; out-of-range
    // domains are rejected.
    let output_cuts: Vec<usize> = cuts
        .iter()
        .map(|&c| c * xof_len / message.len().max(1))
        .map(|c| c.min(xof_len))
        .collect();
    let output_chunks = |output: &mut [u8], mut squeeze: Box<dyn FnMut(&mut [u8]) + '_>| {
        let mut last = 0;
        for &cut in output_cuts.iter().chain(std::iter::once(&xof_len)) {
            squeeze(&mut output[last..cut.max(last)]);
            last = cut.max(last);
        }
    };
    macro_rules! check_xof {
        (
            $oracle:expr, $domain:expr, $oneshot:ident, $init_with_domain:ident,
            $update:ident, $squeeze:ident, $xof:ty
        ) => {{
            let mut oracle = $oracle;
            oracle.update(&message);
            let mut expected = vec![0u8; xof_len];
            oracle.finalize_xof().read(&mut expected);

            if $domain == 0x1f {
                let mut output = vec![0u8; xof_len];
                $oneshot(&mut output, &message);
                assert_eq!(output, expected);
                assert_eq!(<$xof>::compute_to_vec(&message, xof_len), expected);
            }

            let mut state = $init_with_domain($domain).expect("valid domain");
            chunks().for_each(|chunk| $update(&mut state, chunk).expect("update"));
            let mut output = vec![0u8; xof_len];
            output_chunks(&mut output, Box::new(|out| $squeeze(&mut state, out)));
            assert_eq!(output, expected);
            assert!($update(&mut state, b"").is_err());

            let mut xof = <$xof>::with_domain($domain).expect("valid domain");
            chunks().for_each(|chunk| xof.update(chunk));
            let mut reader = xof.finalize();
            let mut output = vec![0u8; xof_len];
            output_chunks(&mut output, Box::new(|out| reader.squeeze(out)));
            assert_eq!(output, expected);
        }};
    }
    check_xof!(
        sha3::Shake128::default(),
        0x1f,
        crypto_xof_shake128,
        crypto_xof_shake128_init_with_domain,
        crypto_xof_shake128_update,
        crypto_xof_shake128_squeeze,
        Shake128
    );
    check_xof!(
        sha3::Shake256::default(),
        0x1f,
        crypto_xof_shake256,
        crypto_xof_shake256_init_with_domain,
        crypto_xof_shake256_update,
        crypto_xof_shake256_squeeze,
        Shake256
    );
    check_xof!(
        sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(xof_domain)),
        xof_domain,
        crypto_xof_turboshake128,
        crypto_xof_turboshake128_init_with_domain,
        crypto_xof_turboshake128_update,
        crypto_xof_turboshake128_squeeze,
        TurboShake128
    );
    check_xof!(
        sha3::TurboShake256::from_core(sha3::TurboShake256Core::new(xof_domain)),
        xof_domain,
        crypto_xof_turboshake256,
        crypto_xof_turboshake256_init_with_domain,
        crypto_xof_turboshake256_update,
        crypto_xof_turboshake256_squeeze,
        TurboShake256
    );
    let bad_domain = xof_domain | 0x80;
    assert!(crypto_xof_turboshake128_init_with_domain(bad_domain).is_err());
    assert!(TurboShake256::with_domain(0).is_err());

    // SipHash-2-4 against the paper, including every `len % 8` tail and the
    // `len as u8` length byte wrapping past 255.
    let siphash_key: [u8; 16] = key[..16].try_into().unwrap();
    let mut shorthash = [0u8; 8];
    crypto_shorthash(&mut shorthash, &message, &siphash_key);
    assert_eq!(shorthash, reference_siphash24(&siphash_key, &message));

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
    // unkeyed and keyed. As in libsodium, keys of 0 to 64 bytes (an empty key
    // being no key) and outputs of 1 to 64 bytes are accepted by both the
    // one-shot and the incremental interface, and longer ones are rejected.
    let generichash_key = Some(&hash_key[..hash_keylen]);
    let mut expected = vec![0u8; outlen];
    crypto_generichash(&mut expected, &message, generichash_key).expect("generichash");
    let mut state = crypto_generichash_init(generichash_key, outlen).expect("generichash init");
    chunks().for_each(|chunk| crypto_generichash_update(&mut state, chunk));
    let mut actual = vec![0u8; outlen];
    crypto_generichash_final(state, &mut actual).expect("generichash final");
    assert_eq!(actual, expected);
    if hash_keylen == 0 {
        crypto_generichash(&mut actual, &message, None).expect("unkeyed generichash");
        assert_eq!(actual, expected);
    }
    let long_key = [0u8; CRYPTO_GENERICHASH_KEYBYTES_MAX + 1];
    assert!(crypto_generichash(&mut actual, &message, Some(&long_key)).is_err());
    assert!(crypto_generichash_init(Some(&long_key), outlen).is_err());
    for bad_outlen in [0, CRYPTO_GENERICHASH_BYTES_MAX + 1] {
        let mut output = vec![0u8; bad_outlen];
        assert!(crypto_generichash(&mut output, &message, generichash_key).is_err());
        assert!(crypto_generichash_init(generichash_key, bad_outlen).is_err());
    }

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
