use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekSecretKey};

use crate::constants::*;

pub(crate) fn crypto_scalarmult_curve25519_base(
    out: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    let secret_key = DalekSecretKey::from(*n);
    let public_key = DalekPublicKey::from(&secret_key);

    out.copy_from_slice(&public_key.to_bytes());
}
