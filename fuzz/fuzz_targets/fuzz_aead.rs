#![no_main]
//! ChaCha20-Poly1305 (IETF), XChaCha20-Poly1305 (IETF) and `crypto_secretbox`
//! (XSalsa20-Poly1305) against independent oracles, at message and
//! associated-data lengths up to 4096 bytes: the keystreams come from the
//! RustCrypto `chacha20`/`salsa20` crates and the tags from the RFC 8439
//! Poly1305 spelled out below, so nothing is shared with dryoc's Poly1305
//! (whose one-shot/streamed agreement `fuzz_hashes` covers). Combined,
//! detached and in-place APIs plus the Rustaceous boxes must all agree, and an
//! input-selected corruption of the ciphertext, tag or associated data must be
//! rejected without touching the output buffer.
//!
//! Boundary-length seeds (0/1/15/16/17/31/32/64/65/255/256/257/4095/4096 for
//! both message and associated data) live in `seeds/fuzz_aead`; pass that
//! directory after the corpus: `cargo fuzz run fuzz_aead corpus/fuzz_aead
//! seeds/fuzz_aead`.
use std::cmp::Ordering;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, XChaCha20};
use dryoc::classic::crypto_aead_chacha20poly1305_ietf::{
    crypto_aead_chacha20poly1305_ietf_decrypt, crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    crypto_aead_chacha20poly1305_ietf_decrypt_inplace, crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_encrypt_detached,
    crypto_aead_chacha20poly1305_ietf_encrypt_inplace,
};
use dryoc::classic::crypto_aead_xchacha20poly1305_ietf::{
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_decrypt_inplace, crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_encrypt_inplace,
};
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_detached, crypto_secretbox_easy, crypto_secretbox_easy_inplace,
    crypto_secretbox_open_detached, crypto_secretbox_open_easy, crypto_secretbox_open_easy_inplace,
};
use dryoc::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
    CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use dryoc::dryocsecretbox::{DryocSecretBox, VecBox as SecretVecBox};
use dryoc::{Error, dryocaead};
use libfuzzer_sys::fuzz_target;
use salsa20::XSalsa20;

#[path = "common.rs"]
mod common;
use common::fill;

/// Longest message and associated data: several multi-lane kernel runs plus
/// every tail length.
const MAX_LEN: usize = 4096;
/// Source bytes for the associated data; the rest of the input is the message.
const AAD_SOURCE_BYTES: usize = 64;
const TAG_BYTES: usize = 16;

/// A length in `0..=MAX_LEN` from two bytes.
fn take_len(data: &mut &[u8]) -> usize {
    usize::from(u16::from_le_bytes(fill::<2>(data))) % (MAX_LEN + 1)
}

/// `len` bytes cycled from at most `source` bytes of `data` (zeros when the
/// input is exhausted), so long buffers need short inputs.
fn take_cycled(data: &mut &[u8], len: usize, source: usize) -> Vec<u8> {
    let n = len.min(source).min(data.len());
    let (head, rest) = data.split_at(n);
    *data = rest;
    if head.is_empty() {
        vec![0u8; len]
    } else {
        head.iter().copied().cycle().take(len).collect()
    }
}

/// Poly1305 as RFC 8439 §2.5 spells it: schoolbook arithmetic on 64-bit
/// limbs, reducing with `2^130 ≡ 5`; shares nothing with dryoc's Poly1305.
fn reference_poly1305(key: &[u8; 32], message: &[u8]) -> [u8; TAG_BYTES] {
    let r = u128::from_le_bytes(key[..16].try_into().unwrap())
        & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
    let s = u128::from_le_bytes(key[16..].try_into().unwrap());
    let r = [r as u64, (r >> 64) as u64];
    let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);

    // The accumulator stays below 2^131 between blocks.
    let mut acc = [0u64; 3];
    for block in message.chunks(16) {
        let mut n = [0u8; 17];
        n[..block.len()].copy_from_slice(block);
        n[block.len()] = 1;
        let n_lo = u128::from_le_bytes(n[..16].try_into().unwrap());

        // acc += n (n < 2^129, so acc < 2^132 and acc[2] < 16).
        let sum = u128::from(acc[0]) + (n_lo as u64 as u128);
        acc[0] = sum as u64;
        let sum = u128::from(acc[1]) + (n_lo >> 64) + (sum >> 64);
        acc[1] = sum as u64;
        acc[2] += u64::from(n[16]) + (sum >> 64) as u64;

        // acc *= r as a 256-bit product (acc < 2^132, r < 2^124).
        let terms = [
            wide(acc[0], r[0]),
            wide(acc[0], r[1]) + wide(acc[1], r[0]),
            wide(acc[1], r[1]) + wide(acc[2], r[0]),
            wide(acc[2], r[1]),
        ];
        let mut product = [0u64; 4];
        let mut carry = 0u128;
        for (limb, term) in product.iter_mut().zip(terms) {
            let v = term + carry;
            *limb = v as u64;
            carry = v >> 64;
        }
        assert_eq!(carry, 0);

        // product = lo + hi * 2^130 ≡ lo + 5 * hi; hi < 2^126, so the
        // result is below 2^130 + 5 * 2^126 < 2^131.
        let lo = [product[0], product[1], product[2] & 3];
        let hi = [(product[2] >> 2) | (product[3] << 62), product[3] >> 2, 0];
        let mut carry = 0u128;
        for i in 0..3 {
            let v = u128::from(lo[i]) + 5 * u128::from(hi[i]) + carry;
            acc[i] = v as u64;
            carry = v >> 64;
        }
        assert_eq!(carry, 0);
    }

    // acc < 2^131 < 3p: at most two subtractions of p = 2^130 - 5.
    const P: [u64; 3] = [u64::MAX - 4, u64::MAX, 3];
    for _ in 0..2 {
        if acc.iter().rev().cmp(P.iter().rev()) != Ordering::Less {
            let mut borrow = 0u64;
            for (a, p) in acc.iter_mut().zip(P) {
                let (d, b1) = a.overflowing_sub(p);
                let (d, b2) = d.overflowing_sub(borrow);
                *a = d;
                borrow = u64::from(b1 | b2);
            }
            assert_eq!(borrow, 0);
        }
    }
    let acc = u128::from(acc[0]) | (u128::from(acc[1]) << 64);
    acc.wrapping_add(s).to_le_bytes()
}

/// The RFC 8439 §2.8 AEAD MAC input: padded AAD, padded ciphertext, lengths.
fn aead_mac_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let pad = |len: usize| (16 - len % 16) % 16;
    let mut input = Vec::with_capacity(aad.len() + ciphertext.len() + 48);
    input.extend_from_slice(aad);
    input.resize(input.len() + pad(aad.len()), 0);
    input.extend_from_slice(ciphertext);
    input.resize(input.len() + pad(ciphertext.len()), 0);
    input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    input
}

/// Expected ChaCha20-Poly1305 output for a RustCrypto `cipher` positioned at
/// block 0: block 0 keys Poly1305, the message starts at block 1.
fn expected_chacha20poly1305<C: StreamCipher>(
    mut cipher: C,
    message: &[u8],
    aad: &[u8],
) -> (Vec<u8>, [u8; TAG_BYTES]) {
    let mut block0 = [0u8; 64];
    cipher.apply_keystream(&mut block0);
    let poly_key: [u8; 32] = block0[..32].try_into().unwrap();
    let mut ciphertext = message.to_vec();
    cipher.apply_keystream(&mut ciphertext);
    let tag = reference_poly1305(&poly_key, &aead_mac_input(aad, &ciphertext));
    (ciphertext, tag)
}

/// Where and how to corrupt a ciphertext.
struct Tamper {
    bit: usize,
    kind: u8,
}

impl Tamper {
    /// `combined` with one bit flipped, in the region `kind` selects.
    fn apply(&self, combined: &[u8]) -> Vec<u8> {
        let mut out = combined.to_vec();
        let message_len = combined.len() - TAG_BYTES;
        let idx = match self.kind % 3 {
            // Tag.
            0 => message_len + self.bit % TAG_BYTES,
            // Ciphertext, when there is one.
            1 if message_len > 0 => self.bit % message_len,
            // Anywhere.
            _ => self.bit % combined.len(),
        };
        out[idx] ^= 1 << (self.bit % 8);
        out
    }
}

type Aad<'a> = Option<&'a [u8]>;
type Res = Result<(), Error>;
type Tag = [u8; TAG_BYTES];
type Combined<const N: usize> = fn(&mut [u8], &[u8], Aad<'_>, &[u8; N], &[u8; 32]) -> Res;
type EncryptDetached<const N: usize> =
    fn(&mut [u8], &mut Tag, &[u8], Aad<'_>, &[u8; N], &[u8; 32]) -> Res;
type DecryptDetached<const N: usize> =
    fn(&mut [u8], &[u8], &Tag, Aad<'_>, &[u8; N], &[u8; 32]) -> Res;
type Inplace<const N: usize> = fn(&mut [u8], Aad<'_>, &[u8; N], &[u8; 32]) -> Res;

/// The classic functions of one ChaCha20-Poly1305 AEAD family.
struct Aead<const N: usize> {
    encrypt: Combined<N>,
    decrypt: Combined<N>,
    encrypt_detached: EncryptDetached<N>,
    decrypt_detached: DecryptDetached<N>,
    encrypt_inplace: Inplace<N>,
    decrypt_inplace: Inplace<N>,
}

const XCHACHA: Aead<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES> = Aead {
    encrypt: crypto_aead_xchacha20poly1305_ietf_encrypt,
    decrypt: crypto_aead_xchacha20poly1305_ietf_decrypt,
    encrypt_detached: crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    decrypt_detached: crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    encrypt_inplace: crypto_aead_xchacha20poly1305_ietf_encrypt_inplace,
    decrypt_inplace: crypto_aead_xchacha20poly1305_ietf_decrypt_inplace,
};

const CHACHA: Aead<CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES> = Aead {
    encrypt: crypto_aead_chacha20poly1305_ietf_encrypt,
    decrypt: crypto_aead_chacha20poly1305_ietf_decrypt,
    encrypt_detached: crypto_aead_chacha20poly1305_ietf_encrypt_detached,
    decrypt_detached: crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    encrypt_inplace: crypto_aead_chacha20poly1305_ietf_encrypt_inplace,
    decrypt_inplace: crypto_aead_chacha20poly1305_ietf_decrypt_inplace,
};

/// Checks every classic entry point of `aead` against the oracle output and
/// returns the combined ciphertext for the Rustaceous checks.
#[allow(clippy::too_many_arguments)]
fn check_aead<const N: usize>(
    aead: &Aead<N>,
    key: &[u8; 32],
    nonce: &[u8; N],
    aad: Option<&[u8]>,
    message: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8; TAG_BYTES],
    tamper: &Tamper,
) -> Vec<u8> {
    let mut combined = vec![0u8; message.len() + TAG_BYTES];
    (aead.encrypt)(&mut combined, message, aad, nonce, key).expect("combined encrypt");
    assert_eq!(&combined[..message.len()], expected_ct);
    assert_eq!(&combined[message.len()..], expected_tag);

    let mut detached = vec![0u8; message.len()];
    let mut tag = [0u8; TAG_BYTES];
    (aead.encrypt_detached)(&mut detached, &mut tag, message, aad, nonce, key)
        .expect("detached encrypt");
    assert_eq!(detached, expected_ct);
    assert_eq!(tag, *expected_tag);

    let mut inplace = message.to_vec();
    inplace.resize(message.len() + TAG_BYTES, 0);
    (aead.encrypt_inplace)(&mut inplace, aad, nonce, key).expect("inplace encrypt");
    assert_eq!(inplace, combined);

    let mut decrypted = vec![0u8; message.len()];
    (aead.decrypt)(&mut decrypted, &combined, aad, nonce, key).expect("combined decrypt");
    assert_eq!(decrypted, message);
    let mut decrypted = vec![0u8; message.len()];
    (aead.decrypt_detached)(&mut decrypted, &detached, &tag, aad, nonce, key)
        .expect("detached decrypt");
    assert_eq!(decrypted, message);
    (aead.decrypt_inplace)(&mut inplace, aad, nonce, key).expect("inplace decrypt");
    assert_eq!(&inplace[..message.len()], message);

    // Corruption is rejected and the output stays untouched, whichever entry
    // point sees it; mismatched associated data likewise.
    let bad = tamper.apply(&combined);
    let mut output = vec![0xa5u8; message.len()];
    assert!((aead.decrypt)(&mut output, &bad, aad, nonce, key).is_err());
    assert!(output.iter().all(|&b| b == 0xa5));
    let (bad_ct, bad_tag) = bad.split_at(message.len());
    assert!(
        (aead.decrypt_detached)(
            &mut output,
            bad_ct,
            bad_tag.try_into().unwrap(),
            aad,
            nonce,
            key
        )
        .is_err()
    );
    assert!(output.iter().all(|&b| b == 0xa5));
    let mut bad_inplace = bad.clone();
    assert!((aead.decrypt_inplace)(&mut bad_inplace, aad, nonce, key).is_err());
    assert_eq!(bad_inplace, bad);
    let other_aad = match aad {
        Some(aad) if !aad.is_empty() => Some(&aad[1..]),
        _ => Some(&[0u8][..]),
    };
    assert!((aead.decrypt)(&mut output, &combined, other_aad, nonce, key).is_err());
    assert!(output.iter().all(|&b| b == 0xa5));

    combined
}

/// The oracle's own known answer, checked once per process so a broken
/// reference can never silently accept or reject dryoc: RFC 8439 §2.5.2
/// (a general key) and A.3 #7 (a message driving the final reduction with an
/// accumulator just above `2^130 - 5`).
fn check_reference_poly1305() {
    static CHECKED: std::sync::Once = std::sync::Once::new();
    CHECKED.call_once(|| {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let tag = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(
            reference_poly1305(&key, b"Cryptographic Forum Research Group"),
            tag,
            "reference Poly1305 fails RFC 8439 2.5.2"
        );

        let mut key = [0u8; 32];
        key[0] = 1;
        let mut message = [0xffu8; 48];
        message[16..32].copy_from_slice(&[
            0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ]);
        message[32..].copy_from_slice(&[
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        let mut tag = [0u8; 16];
        tag[0] = 5;
        assert_eq!(
            reference_poly1305(&key, &message),
            tag,
            "reference Poly1305 fails RFC 8439 A.3 #7"
        );
    });
}

fuzz_target!(|data: &[u8]| {
    check_reference_poly1305();
    let mut data = data;
    let key = fill::<32>(&mut data);
    let nonce = fill::<CRYPTO_SECRETBOX_NONCEBYTES>(&mut data);
    let aad_len = take_len(&mut data);
    let message_len = take_len(&mut data);
    let tamper = Tamper {
        bit: usize::from(u16::from_le_bytes(fill::<2>(&mut data))),
        kind: fill::<1>(&mut data)[0],
    };
    let aad = take_cycled(&mut data, aad_len, AAD_SOURCE_BYTES);
    let message = take_cycled(&mut data, message_len, usize::MAX);
    // Empty associated data is presented both ways; the AEADs treat them
    // alike.
    let aad_opt = if aad.is_empty() && tamper.kind & 0x80 != 0 {
        None
    } else {
        Some(aad.as_slice())
    };

    // XChaCha20-Poly1305 (IETF).
    let (expected_ct, expected_tag) =
        expected_chacha20poly1305(XChaCha20::new(&key.into(), &nonce.into()), &message, &aad);
    let combined = check_aead(
        &XCHACHA,
        &key,
        &nonce,
        aad_opt,
        &message,
        &expected_ct,
        &expected_tag,
        &tamper,
    );
    let rust_key = dryocaead::Key::from(key);
    let rust_nonce = dryocaead::Nonce::from(nonce);
    let aead = dryocaead::VecBox::encrypt_to_vecbox(&message, aad_opt, &rust_nonce, &rust_key)
        .expect("xchacha vecbox encrypt");
    assert_eq!(aead.to_vec(), combined);
    assert_eq!(
        aead.decrypt_to_vec(aad_opt, &rust_nonce, &rust_key)
            .expect("xchacha vecbox decrypt"),
        message
    );
    let parsed = dryocaead::VecBox::from_bytes(&combined).expect("xchacha vecbox parses");
    assert_eq!(parsed.to_vec(), combined);
    assert!(
        dryocaead::VecBox::from_bytes(&tamper.apply(&combined))
            .expect("tampered xchacha vecbox parses")
            .decrypt_to_vec(aad_opt, &rust_nonce, &rust_key)
            .is_err()
    );

    // ChaCha20-Poly1305 (IETF): the first 12 nonce bytes.
    let ietf_nonce: [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES] = nonce
        [..CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES]
        .try_into()
        .unwrap();
    let (expected_ct, expected_tag) = expected_chacha20poly1305(
        ChaCha20::new(&key.into(), &ietf_nonce.into()),
        &message,
        &aad,
    );
    let combined = check_aead(
        &CHACHA,
        &key,
        &ietf_nonce,
        aad_opt,
        &message,
        &expected_ct,
        &expected_tag,
        &tamper,
    );
    {
        use dryocaead::chacha20poly1305_ietf::{Key, Nonce, VecBox};
        let rust_key = Key::from(key);
        let rust_nonce = Nonce::from(ietf_nonce);
        let aead = VecBox::encrypt_to_vecbox(&message, aad_opt, &rust_nonce, &rust_key)
            .expect("chacha vecbox encrypt");
        assert_eq!(aead.to_vec(), combined);
        assert_eq!(
            aead.decrypt_to_vec(aad_opt, &rust_nonce, &rust_key)
                .expect("chacha vecbox decrypt"),
            message
        );
        assert!(
            VecBox::from_bytes(&tamper.apply(&combined))
                .expect("tampered chacha vecbox parses")
                .decrypt_to_vec(aad_opt, &rust_nonce, &rust_key)
                .is_err()
        );
    }

    // crypto_secretbox: the first 32 keystream bytes key Poly1305 over the
    // bare ciphertext; the layout is `tag || ciphertext`.
    let mut keystream = vec![0u8; 32 + message.len()];
    keystream[32..].copy_from_slice(&message);
    XSalsa20::new(&key.into(), &nonce.into()).apply_keystream(&mut keystream);
    let poly_key: [u8; 32] = keystream[..32].try_into().unwrap();
    let expected_ct = &keystream[32..];
    let expected_tag = reference_poly1305(&poly_key, expected_ct);
    let mut expected_box = expected_tag.to_vec();
    expected_box.extend_from_slice(expected_ct);

    let mut boxed = vec![0u8; CRYPTO_SECRETBOX_MACBYTES + message.len()];
    crypto_secretbox_easy(&mut boxed, &message, &nonce, &key).expect("secretbox easy");
    assert_eq!(boxed, expected_box);
    let mut detached = vec![0u8; message.len()];
    let mut mac = [0u8; CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_detached(&mut detached, &mut mac, &message, &nonce, &key)
        .expect("secretbox detached");
    assert_eq!(detached, expected_ct);
    assert_eq!(mac, expected_tag);
    // In place: the message followed by tag-sized spare bytes.
    let mut inplace = message.clone();
    inplace.resize(message.len() + CRYPTO_SECRETBOX_MACBYTES, 0xa5);
    crypto_secretbox_easy_inplace(&mut inplace, &nonce, &key).expect("secretbox inplace");
    assert_eq!(inplace, expected_box);

    let mut opened = vec![0u8; message.len()];
    crypto_secretbox_open_easy(&mut opened, &boxed, &nonce, &key).expect("secretbox open");
    assert_eq!(opened, message);
    let mut opened = vec![0u8; message.len()];
    crypto_secretbox_open_detached(&mut opened, &mac, &detached, &nonce, &key)
        .expect("secretbox open detached");
    assert_eq!(opened, message);
    crypto_secretbox_open_easy_inplace(&mut inplace, &nonce, &key).expect("secretbox open inplace");
    assert_eq!(&inplace[..message.len()], message.as_slice());

    let secret_key = dryoc::dryocsecretbox::Key::from(key);
    let secret_nonce = dryoc::dryocsecretbox::Nonce::from(nonce);
    let secretbox = SecretVecBox::encrypt_to_vecbox(&message, &secret_nonce, &secret_key);
    assert_eq!(secretbox.to_vec(), expected_box);
    assert_eq!(
        secretbox
            .decrypt_to_vec(&secret_nonce, &secret_key)
            .expect("secretbox vecbox decrypt"),
        message
    );
    let parsed: SecretVecBox = DryocSecretBox::from_bytes(&boxed).expect("secretbox parses");
    assert_eq!(
        parsed
            .decrypt_to_vec(&secret_nonce, &secret_key)
            .expect("parsed secretbox decrypt"),
        message
    );

    // Corruption (the tag leads here, so flip within the whole box) is
    // rejected atomically by every open variant.
    let mut bad = boxed.clone();
    let idx = match tamper.kind % 3 {
        0 => tamper.bit % CRYPTO_SECRETBOX_MACBYTES,
        1 if !message.is_empty() => CRYPTO_SECRETBOX_MACBYTES + tamper.bit % message.len(),
        _ => tamper.bit % boxed.len(),
    };
    bad[idx] ^= 1 << (tamper.bit % 8);
    let mut output = vec![0xa5u8; message.len()];
    assert!(crypto_secretbox_open_easy(&mut output, &bad, &nonce, &key).is_err());
    assert!(output.iter().all(|&b| b == 0xa5));
    let (bad_mac, bad_ct) = bad.split_at(CRYPTO_SECRETBOX_MACBYTES);
    let bad_mac: &[u8; CRYPTO_SECRETBOX_MACBYTES] = bad_mac.try_into().unwrap();
    assert!(crypto_secretbox_open_detached(&mut output, bad_mac, bad_ct, &nonce, &key).is_err());
    assert!(output.iter().all(|&b| b == 0xa5));
    let mut bad_inplace = bad.clone();
    assert!(crypto_secretbox_open_easy_inplace(&mut bad_inplace, &nonce, &key).is_err());
    assert_eq!(bad_inplace, bad);
    let parsed: SecretVecBox = DryocSecretBox::from_bytes(&bad).expect("tampered secretbox parses");
    assert!(parsed.decrypt_to_vec(&secret_nonce, &secret_key).is_err());
});
