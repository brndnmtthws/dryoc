use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

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
    let sk = Scalar::from_bytes_mod_order(clamp(n));
    let pk = (ED25519_BASEPOINT_TABLE * &sk).to_montgomery();

    q.copy_from_slice(pk.as_bytes());
}

pub(crate) fn crypto_scalarmult_curve25519(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    let sk = Scalar::from_bytes_mod_order(clamp(n));
    let pk = MontgomeryPoint(*p);
    let shared_secret = sk * pk;

    q.copy_from_slice(shared_secret.as_bytes());
}
