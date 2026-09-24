#![no_main]
//! X25519 and Ed25519 against `curve25519-dalek`, on arbitrary scalars,
//! points, seeds and messages, plus one structured edge case per input (a
//! blacklisted low-order X25519 point, a noncanonical field encoding, an
//! `S >= L` signature, a small-order or noncanonical `A`, a small-order `R`),
//! `crypto_sign`/`crypto_sign_open` atomicity, streamed Ed25519ph signatures
//! recomputed from RFC 8032, the Ed25519 to X25519 key conversions against
//! dalek's birational map, and `crypto_kx` against a dalek shared secret. On
//! AArch64 this drives the register-only field arithmetic and the NEON table
//! lookup of the fixed-base multiplication.
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use dryoc::classic::crypto_core::{
    crypto_core_ed25519_is_valid_point, crypto_scalarmult, crypto_scalarmult_base,
};
use dryoc::classic::crypto_generichash::crypto_generichash;
use dryoc::classic::crypto_kx::{
    crypto_kx_client_session_keys, crypto_kx_seed_keypair, crypto_kx_server_session_keys,
};
use dryoc::classic::crypto_sign::{
    SignerState, crypto_sign, crypto_sign_detached, crypto_sign_ed25519_sk_to_pk,
    crypto_sign_final_create, crypto_sign_final_verify, crypto_sign_init, crypto_sign_open,
    crypto_sign_seed_keypair, crypto_sign_update, crypto_sign_verify_detached,
};
use dryoc::classic::crypto_sign_ed25519::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
};
use dryoc::constants::{CRYPTO_KX_SESSIONKEYBYTES, CRYPTO_SIGN_BYTES};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha512};

#[path = "common.rs"]
mod common;
use common::fill;
#[path = "x25519.rs"]
mod x25519;
use x25519::{low_order_points, p_plus};

/// The Ed25519 group order `L`, little-endian (RFC 8032 §5.1).
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// RFC 8032 §5.1 `dom2(1, "")`, the Ed25519ph domain separator for the empty
/// context libsodium signs with.
const DOM2_PH: &[u8] = b"SigEd25519 no Ed25519 collisions\x01\x00";

/// An Ed25519ph state that has absorbed `message`, split at `cut`.
fn ph_state(message: &[u8], cut: usize) -> SignerState {
    let mut state = crypto_sign_init();
    crypto_sign_update(&mut state, &message[..cut]);
    crypto_sign_update(&mut state, &message[cut..]);
    state
}

/// Asserts `crypto_sign_ed25519_pk_to_curve25519` accepts `encoding` exactly
/// when `valid` (a canonical prime-order point), mapping it to dalek's
/// Montgomery `u`, and otherwise fails without touching the output.
fn check_pk_to_curve25519(encoding: &[u8; 32], valid: bool) {
    let mut u = [0xa5u8; 32];
    let result = crypto_sign_ed25519_pk_to_curve25519(&mut u, encoding);
    if valid {
        result.expect("prime-order point converts");
        let point = CompressedEdwardsY(*encoding).decompress().expect("decodes");
        assert_eq!(u, point.to_montgomery().to_bytes(), "{encoding:02x?}");
    } else {
        assert!(result.is_err(), "converted {encoding:02x?}");
        assert_eq!(u, [0xa5u8; 32], "failed conversion wrote output");
    }
}

/// Noncanonical Ed25519 encodings: `y` in `{p, p + 1, 2^255 - 1}` with either
/// sign bit.
fn noncanonical_encodings() -> Vec<[u8; 32]> {
    let mut all_ones = [0xffu8; 32];
    all_ones[31] = 0x7f;
    let mut encodings = vec![p_plus(0), p_plus(1), all_ones];
    let flipped: Vec<[u8; 32]> = encodings
        .iter()
        .map(|point| {
            let mut flipped = *point;
            flipped[31] |= 0x80;
            flipped
        })
        .collect();
    encodings.extend(flipped);
    encodings
}

/// Whether dalek decodes `encoding` to a point that re-encodes identically.
fn dalek_canonical(encoding: &[u8; 32]) -> bool {
    CompressedEdwardsY(*encoding)
        .decompress()
        .is_some_and(|point| point.compress().to_bytes() == *encoding)
}

/// `a + b` over little-endian 32-byte integers, wrapping at 2^256.
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// Asserts `crypto_sign_open` rejects `signed` under `public_key` without
/// touching the output buffer.
fn assert_open_rejected(signed: &[u8], public_key: &[u8; 32]) {
    let mut output = vec![0xa5u8; signed.len().saturating_sub(CRYPTO_SIGN_BYTES)];
    assert!(crypto_sign_open(&mut output, signed, public_key).is_err());
    assert!(
        output.iter().all(|&b| b == 0xa5),
        "failed open wrote output"
    );
}

/// One structured edge case, selected by `selector`, around the valid
/// `signature` of `message` under `public_key`.
fn edge_case(
    selector: u8,
    scalar: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) {
    let index = usize::from(selector / 6);
    match selector % 6 {
        // A blacklisted X25519 point: dalek's result is zero and dryoc
        // rejects it, zeroing the output.
        0 => {
            let points = low_order_points();
            let point = points[index % points.len()];
            assert_eq!(
                MontgomeryPoint(point).mul_clamped(*scalar).to_bytes(),
                [0u8; 32],
                "{point:02x?} is not low order"
            );
            let mut q = [0xa5u8; 32];
            assert!(crypto_scalarmult(&mut q, scalar, &point).is_err());
            assert_eq!(q, [0u8; 32]);
        }
        // Noncanonical `u = 2^255 - 1` (with or without bit 255) is `u = 18`.
        1 => {
            let mut point = [0xffu8; 32];
            if index % 2 == 0 {
                point[31] = 0x7f;
            }
            let mut canonical = [0u8; 32];
            canonical[0] = 18;
            let mut q = [0u8; 32];
            crypto_scalarmult(&mut q, scalar, &point).expect("u = 18 is not low order");
            let mut expected = [0u8; 32];
            crypto_scalarmult(&mut expected, scalar, &canonical).expect("canonical u = 18");
            assert_eq!(q, expected);
            assert_eq!(q, MontgomeryPoint(point).mul_clamped(*scalar).to_bytes());
        }
        // `S >= L`: exactly `L`, `L + 1`, `S + L` (the same scalar, encoded
        // noncanonically) and all ones. Dalek agrees none is canonical.
        2 => {
            let s: [u8; 32] = signature[32..].try_into().unwrap();
            let one = {
                let mut one = [0u8; 32];
                one[0] = 1;
                one
            };
            let bad_s = match index % 4 {
                0 => L,
                1 => add_le(&L, &one),
                2 => add_le(&s, &L),
                _ => [0xffu8; 32],
            };
            assert!(bool::from(Scalar::from_canonical_bytes(bad_s).is_none()));
            let mut tampered = *signature;
            tampered[32..].copy_from_slice(&bad_s);
            assert!(crypto_sign_verify_detached(&tampered, message, public_key).is_err());
            let mut signed = tampered.to_vec();
            signed.extend_from_slice(message);
            assert_open_rejected(&signed, public_key);
        }
        // Small-order `A`: rejected whatever the signature says, and not
        // converted to X25519.
        3 => {
            let torsion = EIGHT_TORSION[index % EIGHT_TORSION.len()];
            assert!(torsion.is_small_order());
            let small_a = torsion.compress().to_bytes();
            assert!(!crypto_core_ed25519_is_valid_point(&small_a));
            assert!(crypto_sign_verify_detached(signature, message, &small_a).is_err());
            check_pk_to_curve25519(&small_a, false);
            let mut signed = signature.to_vec();
            signed.extend_from_slice(message);
            assert_open_rejected(&signed, &small_a);
        }
        // Noncanonical `A`: rejected and not converted, and dalek confirms
        // the encoding does not round-trip.
        4 => {
            let encodings = noncanonical_encodings();
            let bad_a = encodings[index % encodings.len()];
            assert!(!dalek_canonical(&bad_a));
            assert!(!crypto_core_ed25519_is_valid_point(&bad_a));
            assert!(crypto_sign_verify_detached(signature, message, &bad_a).is_err());
            check_pk_to_curve25519(&bad_a, false);
        }
        // Small-order or noncanonical `R`: rejected before any arithmetic.
        _ => {
            let encodings = noncanonical_encodings();
            let bad_r = if index % 2 == 0 {
                EIGHT_TORSION[index / 2 % EIGHT_TORSION.len()]
                    .compress()
                    .to_bytes()
            } else {
                encodings[index / 2 % encodings.len()]
            };
            let mut tampered = *signature;
            tampered[..32].copy_from_slice(&bad_r);
            assert!(crypto_sign_verify_detached(&tampered, message, public_key).is_err());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let scalar = fill::<32>(&mut data);
    let point = fill::<32>(&mut data);
    let seed = fill::<32>(&mut data);
    let selector = fill::<1>(&mut data)[0];
    let message = data;

    // The group order constant is what dalek reduces to zero.
    assert_eq!(Scalar::from_bytes_mod_order(L), Scalar::ZERO);

    // X25519 fixed base.
    let mut q = [0u8; 32];
    crypto_scalarmult_base(&mut q, &scalar);
    assert_eq!(q, MontgomeryPoint::mul_base_clamped(scalar).to_bytes());

    // X25519 variable base: the top bit of the u coordinate is ignored (both
    // encodings of the point give the same result), and low-order points
    // (all-zero shared secret) are rejected.
    let expected = MontgomeryPoint(point).mul_clamped(scalar).to_bytes();
    let mut flipped = point;
    flipped[31] ^= 0x80;
    for point in [point, flipped] {
        let mut q = [0u8; 32];
        match crypto_scalarmult(&mut q, &scalar, &point) {
            Ok(()) => assert_eq!(q, expected),
            Err(_) => assert_eq!(expected, [0u8; 32], "rejected a non-low-order point"),
        }
        if expected == [0u8; 32] {
            assert!(crypto_scalarmult(&mut q, &scalar, &point).is_err());
        }
    }

    // Ed25519 key derivation: the clamped SHA-512 prefix of the seed times
    // the basepoint.
    let (public_key, secret_key) = crypto_sign_seed_keypair(&seed);
    let hash = Sha512::digest(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&hash[..32]);
    let expected_pk = EdwardsPoint::mul_base_clamped(a).compress().to_bytes();
    assert_eq!(public_key, expected_pk);
    assert_eq!(&secret_key[..32], &seed);
    assert_eq!(&secret_key[32..], &public_key);
    let mut extracted = [0u8; 32];
    crypto_sign_ed25519_sk_to_pk(&mut extracted, &secret_key);
    assert_eq!(extracted, public_key);
    assert!(crypto_core_ed25519_is_valid_point(&public_key));

    // Ed25519 to X25519 key conversion: the secret key is the seed's SHA-512
    // prefix with RFC 7748 clamping, and the public key is dalek's birational
    // map of `A`, which must also be the X25519 base multiple of the
    // converted secret key.
    let mut x25519_sk = [0u8; 32];
    crypto_sign_ed25519_sk_to_curve25519(&mut x25519_sk, &secret_key);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&hash[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    assert_eq!(x25519_sk, clamped);
    let mut x25519_pk = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(&mut x25519_pk, &public_key).expect("valid A");
    assert_eq!(
        x25519_pk,
        MontgomeryPoint::mul_base_clamped(x25519_sk).to_bytes()
    );

    // Ed25519 signature: R = [r]B with r = H(prefix || M), S = r + H(R || A
    // || M) a mod l, computed independently with dalek's scalar arithmetic.
    let mut signature = [0u8; 64];
    crypto_sign_detached(&mut signature, message, &secret_key).expect("sign");
    a[0] &= 248;
    a[31] &= 63;
    a[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(
        &Sha512::new()
            .chain_update(&hash[32..])
            .chain_update(message)
            .finalize(),
    );
    let r = Scalar::from_bytes_mod_order_wide(&wide);
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
    assert_eq!(&signature[..32], &big_r);
    wide.copy_from_slice(
        &Sha512::new()
            .chain_update(big_r)
            .chain_update(public_key)
            .chain_update(message)
            .finalize(),
    );
    let k = Scalar::from_bytes_mod_order_wide(&wide);
    let s = r + k * a;
    assert_eq!(&signature[32..], &s.to_bytes());
    crypto_sign_verify_detached(&signature, message, &public_key).expect("verify");

    // Combined signing is the detached signature followed by the message;
    // opening recovers the message, and a failed open (tampered signature,
    // tampered message, wrong key, wrong output length) leaves the output
    // buffer untouched.
    let mut signed = vec![0u8; CRYPTO_SIGN_BYTES + message.len()];
    crypto_sign(&mut signed, message, &secret_key).expect("combined sign");
    assert_eq!(&signed[..CRYPTO_SIGN_BYTES], &signature);
    assert_eq!(&signed[CRYPTO_SIGN_BYTES..], message);
    let mut opened = vec![0xa5u8; message.len()];
    crypto_sign_open(&mut opened, &signed, &public_key).expect("open");
    assert_eq!(opened, message);
    let mut tampered = signed.clone();
    let idx = usize::from(scalar[0]) % tampered.len();
    tampered[idx] ^= 1 << (scalar[1] % 8);
    assert_open_rejected(&tampered, &public_key);
    let mut wrong_key = public_key;
    wrong_key[usize::from(scalar[2]) % 32] ^= 1 << (scalar[3] % 8);
    assert_open_rejected(&signed, &wrong_key);
    assert_open_rejected(&signed[..CRYPTO_SIGN_BYTES - 1], &public_key);
    let mut short = vec![0xa5u8; message.len() + 1];
    assert!(crypto_sign_open(&mut short, &signed, &public_key).is_err());
    assert!(short.iter().all(|&b| b == 0xa5));

    // Verification rejects a flipped message bit or signature byte.
    if !message.is_empty() {
        let mut tampered = message.to_vec();
        tampered[0] ^= 1;
        assert!(crypto_sign_verify_detached(&signature, &tampered, &public_key).is_err());
    }
    let mut tampered = signature;
    tampered[usize::from(scalar[0]) % 64] ^= 1 << (scalar[1] % 8);
    assert!(crypto_sign_verify_detached(&tampered, message, &public_key).is_err());

    // Ed25519ph (RFC 8032 §5.1 with an empty context, libsodium's
    // `crypto_sign_init`/`_update`/`_final_*`), fed in two fuzz-chosen chunks:
    // with PH = SHA-512 and dom2 = "SigEd25519 no Ed25519 collisions" || 1
    // || 0, r = H(dom2 || prefix || PH(M)) and S = r + H(dom2 || R || A ||
    // PH(M)) a mod l, recomputed with dalek.
    let cut = usize::from(u16::from_le_bytes([scalar[4], scalar[5]])) % (message.len() + 1);
    let mut ph_signature = [0u8; 64];
    crypto_sign_final_create(ph_state(message, cut), &mut ph_signature, &secret_key)
        .expect("Ed25519ph sign");
    let prehash = Sha512::digest(message);
    wide.copy_from_slice(
        &Sha512::new()
            .chain_update(DOM2_PH)
            .chain_update(&hash[32..])
            .chain_update(prehash)
            .finalize(),
    );
    let r = Scalar::from_bytes_mod_order_wide(&wide);
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
    assert_eq!(&ph_signature[..32], &big_r);
    wide.copy_from_slice(
        &Sha512::new()
            .chain_update(DOM2_PH)
            .chain_update(big_r)
            .chain_update(public_key)
            .chain_update(prehash)
            .finalize(),
    );
    let s = r + Scalar::from_bytes_mod_order_wide(&wide) * a;
    assert_eq!(&ph_signature[32..], &s.to_bytes());
    crypto_sign_final_verify(ph_state(message, cut), &ph_signature, &public_key)
        .expect("Ed25519ph verify");
    // Rejected: a flipped signature bit, a changed (or extended, if empty)
    // message, a wrong key, and either signature under the other scheme.
    let mut tampered = ph_signature;
    tampered[usize::from(scalar[0]) % 64] ^= 1 << (scalar[1] % 8);
    assert!(crypto_sign_final_verify(ph_state(message, cut), &tampered, &public_key).is_err());
    let mut other_message = message.to_vec();
    match other_message.get_mut(usize::from(scalar[2]) % message.len().max(1)) {
        Some(byte) => *byte ^= 1 << (scalar[3] % 8),
        None => other_message.push(0),
    }
    let other_cut = cut.min(other_message.len());
    assert!(
        crypto_sign_final_verify(
            ph_state(&other_message, other_cut),
            &ph_signature,
            &public_key
        )
        .is_err()
    );
    assert!(crypto_sign_final_verify(ph_state(message, cut), &ph_signature, &wrong_key).is_err());
    assert!(crypto_sign_verify_detached(&ph_signature, message, &public_key).is_err());
    assert!(crypto_sign_final_verify(ph_state(message, cut), &signature, &public_key).is_err());

    edge_case(selector, &scalar, message, &signature, &public_key);

    // Point validation (canonical encoding, on the curve, prime order) agrees
    // with dalek's decoding for the fuzzed encoding, and so does the Ed25519
    // to X25519 public key conversion. The seed doubles as the candidate; a
    // random encoding decodes about half the time, and the public key is a
    // known-valid one.
    for candidate in [seed, public_key] {
        let expected = CompressedEdwardsY(candidate).decompress().is_some_and(|p| {
            p.compress().to_bytes() == candidate && !p.is_small_order() && p.is_torsion_free()
        });
        assert_eq!(
            crypto_core_ed25519_is_valid_point(&candidate),
            expected,
            "{candidate:02x?}"
        );
        check_pk_to_curve25519(&candidate, expected);
    }

    // crypto_kx: seed keypairs are BLAKE2b-256(seed) times the basepoint;
    // session keys are BLAKE2b-512(X25519(sk, pk) || client_pk || server_pk)
    // split in two, swapped between the roles. The X25519 step is dalek's;
    // the hashing is dryoc's own BLAKE2b (checked in `fuzz-hashes`).
    let (client_pk, client_sk) = crypto_kx_seed_keypair(&seed).expect("client seed keypair");
    let (server_pk, server_sk) = crypto_kx_seed_keypair(&scalar).expect("server seed keypair");
    for (seed, pk, sk) in [
        (&seed, &client_pk, &client_sk),
        (&scalar, &server_pk, &server_sk),
    ] {
        let mut expected_sk = [0u8; 32];
        crypto_generichash(&mut expected_sk, seed, None).expect("blake2b-256");
        assert_eq!(*sk, expected_sk);
        assert_eq!(*pk, MontgomeryPoint::mul_base_clamped(*sk).to_bytes());
    }
    let shared = MontgomeryPoint(server_pk).mul_clamped(client_sk).to_bytes();
    assert_eq!(
        shared,
        MontgomeryPoint(client_pk).mul_clamped(server_sk).to_bytes()
    );
    let mut expected_keys = [0u8; 2 * CRYPTO_KX_SESSIONKEYBYTES];
    let mut transcript = shared.to_vec();
    transcript.extend_from_slice(&client_pk);
    transcript.extend_from_slice(&server_pk);
    crypto_generichash(&mut expected_keys, &transcript, None).expect("blake2b-512");
    let (expected_client_rx, expected_client_tx) =
        expected_keys.split_at(CRYPTO_KX_SESSIONKEYBYTES);
    let mut rx = [0u8; CRYPTO_KX_SESSIONKEYBYTES];
    let mut tx = [0u8; CRYPTO_KX_SESSIONKEYBYTES];
    crypto_kx_client_session_keys(&mut rx, &mut tx, &client_pk, &client_sk, &server_pk)
        .expect("client session keys");
    assert_eq!(rx, expected_client_rx);
    assert_eq!(tx, expected_client_tx);
    crypto_kx_server_session_keys(&mut rx, &mut tx, &server_pk, &server_sk, &client_pk)
        .expect("server session keys");
    assert_eq!(rx, expected_client_tx);
    assert_eq!(tx, expected_client_rx);
    // A low-order peer key is rejected with both outputs untouched.
    let low_order = low_order_points();
    let low_order = low_order[usize::from(selector) % low_order.len()];
    let mut rx = [0xa5u8; CRYPTO_KX_SESSIONKEYBYTES];
    let mut tx = [0xa5u8; CRYPTO_KX_SESSIONKEYBYTES];
    assert!(
        crypto_kx_client_session_keys(&mut rx, &mut tx, &client_pk, &client_sk, &low_order)
            .is_err()
    );
    assert!(
        crypto_kx_server_session_keys(&mut rx, &mut tx, &server_pk, &server_sk, &low_order)
            .is_err()
    );
    assert_eq!(rx, [0xa5u8; CRYPTO_KX_SESSIONKEYBYTES]);
    assert_eq!(tx, [0xa5u8; CRYPTO_KX_SESSIONKEYBYTES]);
});
