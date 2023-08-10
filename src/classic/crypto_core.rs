use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_CORE_HCHACHA20_KEYBYTES,
    CRYPTO_CORE_HCHACHA20_OUTPUTBYTES, CRYPTO_CORE_HSALSA20_INPUTBYTES,
    CRYPTO_CORE_HSALSA20_KEYBYTES, CRYPTO_CORE_HSALSA20_OUTPUTBYTES, CRYPTO_SCALARMULT_BYTES,
    CRYPTO_SCALARMULT_SCALARBYTES,
};
use crate::scalarmult_curve25519::{
    crypto_scalarmult_curve25519, crypto_scalarmult_curve25519_base,
};
use crate::types::*;
use crate::utils::load_u32_le;

/// Stack-allocated HChaCha20 input.
pub type HChaCha20Input = [u8; CRYPTO_CORE_HCHACHA20_INPUTBYTES];
/// Stack-allocated HChaCha20 key.
pub type HChaCha20Key = [u8; CRYPTO_CORE_HCHACHA20_KEYBYTES];
/// Stack-allocated HChaCha20 output.
pub type HChaCha20Output = [u8; CRYPTO_CORE_HCHACHA20_OUTPUTBYTES];
/// Stack-allocated HSalsa20 input.
pub type HSalsa20Input = [u8; CRYPTO_CORE_HSALSA20_INPUTBYTES];
/// Stack-allocated HSalsa20 key.
pub type HSalsa20Key = [u8; CRYPTO_CORE_HSALSA20_KEYBYTES];
/// Stack-allocated HSalsa20 output.
pub type HSalsa20Output = [u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];

/// Computes the public key for a previously generated secret key.
///
/// Compatible with libsodium's `crypto_scalarmult_base`.
pub fn crypto_scalarmult_base(
    q: &mut [u8; CRYPTO_SCALARMULT_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_SCALARBYTES],
) {
    crypto_scalarmult_curve25519_base(q, n)
}

/// Computes a shared secret `q`, given `n`, our secret key, and `p`, their
/// public key, using a Diffie-Hellman key exchange.
///
/// Compatible with libsodium's `crypto_scalarmult`.
pub fn crypto_scalarmult(
    q: &mut [u8; CRYPTO_SCALARMULT_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_BYTES],
) {
    crypto_scalarmult_curve25519(q, n, p)
}

#[inline]
fn chacha20_round(x: &mut u32, y: &u32, z: &mut u32, rot: u32) {
    *x = x.wrapping_add(*y);
    *z = (*z ^ *x).rotate_left(rot);
}

#[inline]
fn chacha20_quarterround(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    chacha20_round(a, b, d, 16);
    chacha20_round(c, d, b, 12);
    chacha20_round(a, b, d, 8);
    chacha20_round(c, d, b, 7);
}

/// Implements the HChaCha20 function.
///
/// Compatible with libsodium's `crypto_core_hchacha20`.
pub fn crypto_core_hchacha20(
    output: &mut HChaCha20Output,
    input: &HChaCha20Input,
    key: &HChaCha20Key,
    constants: Option<(u32, u32, u32, u32)>,
) {
    let input = input.as_array();
    let key = key.as_array();
    assert_eq!(input.len(), 16);
    assert_eq!(key.len(), 32);
    let (mut x0, mut x1, mut x2, mut x3) =
        constants.unwrap_or((0x61707865, 0x3320646e, 0x79622d32, 0x6b206574));
    let (
        mut x4,
        mut x5,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
        mut x10,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x15,
    ) = (
        load_u32_le(&key[0..4]),
        load_u32_le(&key[4..8]),
        load_u32_le(&key[8..12]),
        load_u32_le(&key[12..16]),
        load_u32_le(&key[16..20]),
        load_u32_le(&key[20..24]),
        load_u32_le(&key[24..28]),
        load_u32_le(&key[28..32]),
        load_u32_le(&input[0..4]),
        load_u32_le(&input[4..8]),
        load_u32_le(&input[8..12]),
        load_u32_le(&input[12..16]),
    );

    for _ in 0..10 {
        chacha20_quarterround(&mut x0, &mut x4, &mut x8, &mut x12);
        chacha20_quarterround(&mut x1, &mut x5, &mut x9, &mut x13);
        chacha20_quarterround(&mut x2, &mut x6, &mut x10, &mut x14);
        chacha20_quarterround(&mut x3, &mut x7, &mut x11, &mut x15);
        chacha20_quarterround(&mut x0, &mut x5, &mut x10, &mut x15);
        chacha20_quarterround(&mut x1, &mut x6, &mut x11, &mut x12);
        chacha20_quarterround(&mut x2, &mut x7, &mut x8, &mut x13);
        chacha20_quarterround(&mut x3, &mut x4, &mut x9, &mut x14);
    }

    output[0..4].copy_from_slice(&x0.to_le_bytes());
    output[4..8].copy_from_slice(&x1.to_le_bytes());
    output[8..12].copy_from_slice(&x2.to_le_bytes());
    output[12..16].copy_from_slice(&x3.to_le_bytes());
    output[16..20].copy_from_slice(&x12.to_le_bytes());
    output[20..24].copy_from_slice(&x13.to_le_bytes());
    output[24..28].copy_from_slice(&x14.to_le_bytes());
    output[28..32].copy_from_slice(&x15.to_le_bytes());
}

#[inline]
fn salsa20_rotl32(x: u32, y: u32, rot: u32) -> u32 {
    x.wrapping_add(y).rotate_left(rot)
}

/// Implements the HSalsa20 function.
///
/// Compatible with libsodium's `crypto_core_hsalsa20`.
pub fn crypto_core_hsalsa20(
    output: &mut HSalsa20Output,
    input: &HSalsa20Input,
    key: &HSalsa20Key,
    constants: Option<(u32, u32, u32, u32)>,
) {
    let (mut x0, mut x5, mut x10, mut x15) =
        constants.unwrap_or((0x61707865, 0x3320646e, 0x79622d32, 0x6b206574));
    let (
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
    ) = (
        load_u32_le(&key[0..4]),
        load_u32_le(&key[4..8]),
        load_u32_le(&key[8..12]),
        load_u32_le(&key[12..16]),
        load_u32_le(&key[16..20]),
        load_u32_le(&key[20..24]),
        load_u32_le(&key[24..28]),
        load_u32_le(&key[28..32]),
        load_u32_le(&input[0..4]),
        load_u32_le(&input[4..8]),
        load_u32_le(&input[8..12]),
        load_u32_le(&input[12..16]),
    );

    for _ in (0..20).step_by(2) {
        x4 ^= salsa20_rotl32(x0, x12, 7);
        x8 ^= salsa20_rotl32(x4, x0, 9);
        x12 ^= salsa20_rotl32(x8, x4, 13);
        x0 ^= salsa20_rotl32(x12, x8, 18);
        x9 ^= salsa20_rotl32(x5, x1, 7);
        x13 ^= salsa20_rotl32(x9, x5, 9);
        x1 ^= salsa20_rotl32(x13, x9, 13);
        x5 ^= salsa20_rotl32(x1, x13, 18);
        x14 ^= salsa20_rotl32(x10, x6, 7);
        x2 ^= salsa20_rotl32(x14, x10, 9);
        x6 ^= salsa20_rotl32(x2, x14, 13);
        x10 ^= salsa20_rotl32(x6, x2, 18);
        x3 ^= salsa20_rotl32(x15, x11, 7);
        x7 ^= salsa20_rotl32(x3, x15, 9);
        x11 ^= salsa20_rotl32(x7, x3, 13);
        x15 ^= salsa20_rotl32(x11, x7, 18);
        x1 ^= salsa20_rotl32(x0, x3, 7);
        x2 ^= salsa20_rotl32(x1, x0, 9);
        x3 ^= salsa20_rotl32(x2, x1, 13);
        x0 ^= salsa20_rotl32(x3, x2, 18);
        x6 ^= salsa20_rotl32(x5, x4, 7);
        x7 ^= salsa20_rotl32(x6, x5, 9);
        x4 ^= salsa20_rotl32(x7, x6, 13);
        x5 ^= salsa20_rotl32(x4, x7, 18);
        x11 ^= salsa20_rotl32(x10, x9, 7);
        x8 ^= salsa20_rotl32(x11, x10, 9);
        x9 ^= salsa20_rotl32(x8, x11, 13);
        x10 ^= salsa20_rotl32(x9, x8, 18);
        x12 ^= salsa20_rotl32(x15, x14, 7);
        x13 ^= salsa20_rotl32(x12, x15, 9);
        x14 ^= salsa20_rotl32(x13, x12, 13);
        x15 ^= salsa20_rotl32(x14, x13, 18);
    }

    output[0..4].copy_from_slice(&x0.to_le_bytes());
    output[4..8].copy_from_slice(&x5.to_le_bytes());
    output[8..12].copy_from_slice(&x10.to_le_bytes());
    output[12..16].copy_from_slice(&x15.to_le_bytes());
    output[16..20].copy_from_slice(&x6.to_le_bytes());
    output[20..24].copy_from_slice(&x7.to_le_bytes());
    output[24..28].copy_from_slice(&x8.to_le_bytes());
    output[28..32].copy_from_slice(&x9.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classic::crypto_box::*;

    #[test]
    fn test_crypto_scalarmult_base() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        for _ in 0..20 {
            use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

            let (pk, sk) = crypto_box_keypair();

            let mut public_key = [0u8; CRYPTO_SCALARMULT_BYTES];
            crypto_scalarmult_base(&mut public_key, &sk);

            assert_eq!(&pk, &public_key);

            let ge = scalarmult_base(&Scalar::from_slice(&sk).unwrap());

            assert_eq!(
                general_purpose::STANDARD.encode(ge.as_ref()),
                general_purpose::STANDARD.encode(public_key)
            );
        }
    }

    #[test]
    fn test_crypto_scalarmult() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        for _ in 0..20 {
            use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult, GroupElement, Scalar};

            let (_our_pk, our_sk) = crypto_box_keypair();
            let (their_pk, _their_sk) = crypto_box_keypair();

            let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
            crypto_scalarmult(&mut shared_secret, &our_sk, &their_pk);

            let ge = scalarmult(
                &Scalar::from_slice(&our_sk).unwrap(),
                &GroupElement::from_slice(&their_pk).unwrap(),
            )
            .expect("scalarmult failed");

            assert_eq!(
                general_purpose::STANDARD.encode(ge.as_ref()),
                general_purpose::STANDARD.encode(shared_secret)
            );
        }
    }

    #[test]
    fn test_crypto_core_hchacha20() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libsodium_sys::crypto_core_hchacha20 as so_crypto_core_hchacha20;

        use crate::rng::copy_randombytes;

        for _ in 0..10 {
            let mut key = [0u8; 32];
            let mut data = [0u8; 16];
            copy_randombytes(&mut key);
            copy_randombytes(&mut data);

            let mut out = [0u8; CRYPTO_CORE_HCHACHA20_OUTPUTBYTES];
            crypto_core_hchacha20(&mut out, &data, &key, None);

            let mut so_out = [0u8; 32];
            unsafe {
                let ret = so_crypto_core_hchacha20(
                    so_out.as_mut_ptr(),
                    data.as_ptr(),
                    key.as_ptr(),
                    std::ptr::null(),
                );
                assert_eq!(ret, 0);
            }
            assert_eq!(
                general_purpose::STANDARD.encode(out),
                general_purpose::STANDARD.encode(so_out)
            );
        }
    }

    #[test]
    fn test_crypto_core_hsalsa20() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libsodium_sys::crypto_core_hsalsa20 as so_crypto_core_hsalsa20;

        use crate::rng::copy_randombytes;

        for _ in 0..10 {
            let mut key = [0u8; CRYPTO_CORE_HSALSA20_KEYBYTES];
            let mut data = [0u8; CRYPTO_CORE_HSALSA20_INPUTBYTES];
            copy_randombytes(&mut key);
            copy_randombytes(&mut data);

            let mut out = [0u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
            crypto_core_hsalsa20(&mut out, &data, &key, None);

            let mut so_out = [0u8; 32];
            unsafe {
                let ret = so_crypto_core_hsalsa20(
                    so_out.as_mut_ptr(),
                    data.as_ptr(),
                    key.as_ptr(),
                    std::ptr::null(),
                );
                assert_eq!(ret, 0);
            }
            assert_eq!(
                general_purpose::STANDARD.encode(out),
                general_purpose::STANDARD.encode(so_out)
            );
        }
    }
}
