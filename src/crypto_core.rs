use generic_array::GenericArray;

use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_CORE_HCHACHA20_KEYBYTES,
    CRYPTO_CORE_HCHACHA20_OUTPUTBYTES, CRYPTO_SCALARMULT_BYTES,
};
use crate::scalarmult_curve25519::crypto_scalarmult_curve25519_base;
use crate::types::*;
use crate::utils::load32_le;

pub type HChaCha20Input = StackByteArray<CRYPTO_CORE_HCHACHA20_INPUTBYTES>;
pub type HChaCha20Key = StackByteArray<CRYPTO_CORE_HCHACHA20_KEYBYTES>;
pub type HChaCha20Output = StackByteArray<CRYPTO_CORE_HCHACHA20_OUTPUTBYTES>;

/// Computes the public key for a previously generated secret key.
///
/// Compatible with libsodium's `crypto_scalarmult_base`.
pub fn crypto_scalarmult_base(n: &[u8; CRYPTO_SCALARMULT_BYTES]) -> [u8; CRYPTO_SCALARMULT_BYTES] {
    crypto_scalarmult_curve25519_base(n)
}

#[inline]
fn round(x: &mut u32, y: &mut u32, z: &mut u32, rot: u32) {
    *x = x.wrapping_add(*y);
    *z = (*z ^ *x).rotate_left(rot);
}

#[inline]
fn quarterround(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    round(a, b, d, 16);
    round(c, d, b, 12);
    round(a, b, d, 8);
    round(c, d, b, 7);
}

/// Implements the HChaCha20 function.
///
/// Compatible with libsodium's `crypto_core_hchacha20`.
pub fn crypto_core_hchacha20<
    Input: ByteArray<CRYPTO_CORE_HCHACHA20_INPUTBYTES>,
    Key: ByteArray<CRYPTO_CORE_HCHACHA20_KEYBYTES>,
    Output: NewByteArray<CRYPTO_CORE_HCHACHA20_OUTPUTBYTES>,
>(
    input: &Input,
    key: &Key,
    constants: Option<(u32, u32, u32, u32)>,
) -> Output {
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
        load32_le(&key[0..4]),
        load32_le(&key[4..8]),
        load32_le(&key[8..12]),
        load32_le(&key[12..16]),
        load32_le(&key[16..20]),
        load32_le(&key[20..24]),
        load32_le(&key[24..28]),
        load32_le(&key[28..32]),
        load32_le(&input[0..4]),
        load32_le(&input[4..8]),
        load32_le(&input[8..12]),
        load32_le(&input[12..16]),
    );

    for _ in 0..10 {
        quarterround(&mut x0, &mut x4, &mut x8, &mut x12);
        quarterround(&mut x1, &mut x5, &mut x9, &mut x13);
        quarterround(&mut x2, &mut x6, &mut x10, &mut x14);
        quarterround(&mut x3, &mut x7, &mut x11, &mut x15);
        quarterround(&mut x0, &mut x5, &mut x10, &mut x15);
        quarterround(&mut x1, &mut x6, &mut x11, &mut x12);
        quarterround(&mut x2, &mut x7, &mut x8, &mut x13);
        quarterround(&mut x3, &mut x4, &mut x9, &mut x14);
    }

    let mut out = Output::new();

    let arr = out.as_mut_slice();
    arr[0..4].copy_from_slice(&x0.to_le_bytes());
    arr[4..8].copy_from_slice(&x1.to_le_bytes());
    arr[8..12].copy_from_slice(&x2.to_le_bytes());
    arr[12..16].copy_from_slice(&x3.to_le_bytes());
    arr[16..20].copy_from_slice(&x12.to_le_bytes());
    arr[20..24].copy_from_slice(&x13.to_le_bytes());
    arr[24..28].copy_from_slice(&x14.to_le_bytes());
    arr[28..32].copy_from_slice(&x15.to_le_bytes());

    out
}

/// Implements the HSalsa20 function.
///
/// Compatible with libsodium's `crypto_core_hsalsa20`.
pub fn crypto_core_hsalsa20(input: &[u8; 16], key: &[u8]) -> [u8; 32] {
    use salsa20::hsalsa20;

    let res = hsalsa20(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(input),
    );

    res.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_box::*;

    #[test]
    fn test_crypto_scalarmult_base() {
        use base64::encode;
        for _ in 0..20 {
            use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

            let keypair = crypto_box_keypair();

            let public_key = crypto_scalarmult_base(&keypair.secret_key);

            assert_eq!(&keypair.public_key, &public_key);

            let ge = scalarmult_base(&Scalar::from_slice(&keypair.secret_key).unwrap());

            assert_eq!(encode(ge.as_ref()), encode(public_key));
        }
    }

    #[test]
    fn test_crypto_core_hchacha20() {
        use base64::encode;
        use libsodium_sys::crypto_core_hchacha20 as so_crypto_core_hchacha20;

        use crate::rng::copy_randombytes;

        for _ in 0..10 {
            let mut key = [0u8; 32];
            let mut data = [0u8; 16];
            copy_randombytes(&mut key);
            copy_randombytes(&mut data);

            let out: Vec<u8> = crypto_core_hchacha20(&data, &key, None);

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
            assert_eq!(encode(&out), encode(&so_out));
        }
    }
}
