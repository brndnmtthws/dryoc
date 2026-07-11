use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_SCALARMULT_CURVE25519_BYTES, CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES,
};

fn clamp(
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
) -> [u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES] {
    let mut s = *n;
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

pub(crate) fn crypto_scalarmult_curve25519_base(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
) {
    let mut clamped = clamp(n);
    let mut sk = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();
    let pk = (ED25519_BASEPOINT_TABLE * &sk).to_montgomery();

    q.copy_from_slice(pk.as_bytes());
    sk.zeroize();
}

pub(crate) fn crypto_scalarmult_curve25519(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    // RFC 7748 requires X25519 implementations to ignore the most significant
    // bit of the final input byte for compatibility with existing point
    // formats.
    let mut encoded_point = *p;
    encoded_point[CRYPTO_SCALARMULT_CURVE25519_BYTES - 1] &= 0x7f;
    let pk = MontgomeryPoint(encoded_point);
    let mut shared_secret = pk.mul_clamped(*n);

    q.copy_from_slice(shared_secret.as_bytes());
    shared_secret.zeroize();
}
