#![no_main]
//! X25519 and Ed25519 against `curve25519-dalek`, on arbitrary scalars,
//! points, seeds and messages. On AArch64 this drives the register-only field
//! arithmetic and the NEON table lookup of the fixed-base multiplication.
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use dryoc::classic::crypto_core::{
    crypto_core_ed25519_is_valid_point, crypto_scalarmult, crypto_scalarmult_base,
};
use dryoc::classic::crypto_sign::{
    crypto_sign_detached, crypto_sign_ed25519_sk_to_pk, crypto_sign_seed_keypair,
    crypto_sign_verify_detached,
};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha512};

#[path = "common.rs"]
mod common;
use common::fill;

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let scalar = fill::<32>(&mut data);
    let point = fill::<32>(&mut data);
    let seed = fill::<32>(&mut data);
    let message = data;

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

    // Verification rejects a flipped message bit or signature byte.
    if !message.is_empty() {
        let mut tampered = message.to_vec();
        tampered[0] ^= 1;
        assert!(crypto_sign_verify_detached(&signature, &tampered, &public_key).is_err());
    }
    let mut tampered = signature;
    tampered[usize::from(scalar[0]) % 64] ^= 1 << (scalar[1] % 8);
    assert!(crypto_sign_verify_detached(&tampered, message, &public_key).is_err());

    // Point validation (canonical encoding, on the curve, prime order) agrees
    // with dalek's decoding for the fuzzed encoding. The seed doubles as the
    // candidate; a random encoding decodes about half the time, and the
    // public key is a known-valid one.
    for candidate in [seed, public_key] {
        let expected = CompressedEdwardsY(candidate).decompress().is_some_and(|p| {
            p.compress().to_bytes() == candidate && !p.is_small_order() && p.is_torsion_free()
        });
        assert_eq!(
            crypto_core_ed25519_is_valid_point(&candidate),
            expected,
            "{candidate:02x?}"
        );
    }
});
