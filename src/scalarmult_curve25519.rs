use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekSecretKey};

use crate::constants::{
    CRYPTO_SCALARMULT_CURVE25519_BYTES, CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES,
};

pub(crate) fn crypto_scalarmult_curve25519_base(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
) {
    let secret_key = DalekSecretKey::from(*n);
    let public_key = DalekPublicKey::from(&secret_key);

    q.copy_from_slice(public_key.as_bytes());
}

pub(crate) fn crypto_scalarmult_curve25519(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    let secret_key = DalekSecretKey::from(*n);
    let public_key = DalekPublicKey::from(*p);

    let shared_secret = secret_key.diffie_hellman(&public_key);

    q.copy_from_slice(shared_secret.as_bytes());
}
