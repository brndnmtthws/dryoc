use crate::constants::*;
use crate::crypto_core::crypto_core_hsalsa20;
use crate::crypto_hash::crypto_hash_sha512;
use crate::keypair::*;
use crate::scalarmult_curve25519::*;
use crate::types::*;

use rand_core::OsRng;
use x25519_dalek::PublicKey as DalekPublicKey;
use x25519_dalek::StaticSecret as DalekSecretKey;
use zeroize::Zeroize;

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_beforenm(
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> SecretBoxKey {
    let sk = DalekSecretKey::from(secret_key.as_slice().to_owned());
    let pk = DalekPublicKey::from(public_key.as_slice().to_owned());

    let s = sk.diffie_hellman(&pk);

    let result = crypto_core_hsalsa20(&[0u8; 16], s.as_bytes());

    result.into()
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_keypair() -> KeyPair {
    let secret_key = DalekSecretKey::new(OsRng);
    let public_key = DalekPublicKey::from(&secret_key);

    KeyPair::from_slices(public_key.to_bytes(), secret_key.to_bytes())
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(seed: &InputBase) -> KeyPair {
    let mut hash = crypto_hash_sha512(seed);

    let mut secret_key = [0u8; CRYPTO_BOX_SEEDBYTES];
    secret_key.copy_from_slice(&hash[0..CRYPTO_BOX_SEEDBYTES]);

    hash.zeroize();

    KeyPair::from_slices(crypto_scalarmult_curve25519_base(&secret_key), secret_key)
}
