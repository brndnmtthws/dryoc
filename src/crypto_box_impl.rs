use rand_core::OsRng;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekSecretKey};
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_BOX_SEEDBYTES, CRYPTO_CORE_HSALSA20_INPUTBYTES, CRYPTO_CORE_HSALSA20_OUTPUTBYTES,
};
use crate::crypto_box::{PublicKey, SecretKey};
use crate::crypto_core::crypto_core_hsalsa20;
use crate::crypto_hash::crypto_hash_sha512;
use crate::crypto_secretbox::Key;
use crate::dryocstream::ByteArray;
use crate::scalarmult_curve25519::*;

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_beforenm(
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Key {
    let sk: &[u8; 32] = secret_key.as_array();
    let sk = DalekSecretKey::from(*sk);
    let pk: &[u8; 32] = public_key.as_array();
    let pk = DalekPublicKey::from(*pk);

    let s = sk.diffie_hellman(&pk);

    let mut hash = [0u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
    crypto_core_hsalsa20(
        &mut hash,
        &[0u8; CRYPTO_CORE_HSALSA20_INPUTBYTES],
        s.as_bytes(),
        None,
    );

    hash
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_keypair() -> (PublicKey, SecretKey) {
    let secret_key = DalekSecretKey::new(OsRng);
    let public_key = DalekPublicKey::from(&secret_key);

    (public_key.to_bytes(), secret_key.to_bytes())
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(
    seed: &[u8],
) -> (PublicKey, SecretKey) {
    let mut hash = crypto_hash_sha512(seed);

    let mut secret_key = [0u8; CRYPTO_BOX_SEEDBYTES];
    let mut public_key = [0u8; CRYPTO_BOX_SEEDBYTES];
    secret_key.copy_from_slice(&hash[0..CRYPTO_BOX_SEEDBYTES]);

    hash.zeroize();

    crypto_scalarmult_curve25519_base(&mut public_key, &secret_key);

    (public_key, secret_key)
}
