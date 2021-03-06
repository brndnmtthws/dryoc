use crate::constants::*;
use x25519_dalek::PublicKey as DalekPublicKey;
use x25519_dalek::StaticSecret as DalekSecretKey;

pub(crate) fn crypto_scalarmult_curve25519_base(
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) -> [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES] {
    let secret_key = DalekSecretKey::from(*n);
    let public_key = DalekPublicKey::from(&secret_key);

    public_key.to_bytes()
}
