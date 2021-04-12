use zeroize::Zeroize;

use super::crypto_core::crypto_scalarmult;
use crate::classic::crypto_box::{PublicKey, SecretKey};
use crate::classic::crypto_core::crypto_core_hsalsa20;
use crate::classic::crypto_hash::crypto_hash_sha512;
use crate::classic::crypto_secretbox::Key;
use crate::constants::{
    CRYPTO_BOX_SEEDBYTES, CRYPTO_CORE_HSALSA20_INPUTBYTES, CRYPTO_CORE_HSALSA20_OUTPUTBYTES,
    CRYPTO_HASH_SHA512_BYTES, CRYPTO_SCALARMULT_BYTES,
};
use crate::dryocstream::ByteArray;
use crate::rng::copy_randombytes;
use crate::scalarmult_curve25519::*;

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_beforenm(
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Key {
    let mut s = [0u8; CRYPTO_SCALARMULT_BYTES];
    crypto_scalarmult(&mut s, secret_key.as_array(), public_key.as_array());

    let mut hash = [0u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
    crypto_core_hsalsa20(&mut hash, &[0u8; CRYPTO_CORE_HSALSA20_INPUTBYTES], &s, None);

    hash
}

#[inline]
pub(crate) fn crypto_box_curve25519xsalsa20poly1305_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
) {
    copy_randombytes(secret_key);
    crypto_scalarmult_curve25519_base(public_key, secret_key);
}

#[inline]
pub(crate) fn crypto_box_curve25519xsalsa20poly1305_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &[u8],
) {
    let mut hash = [0u8; CRYPTO_HASH_SHA512_BYTES];
    crypto_hash_sha512(&mut hash, seed);

    secret_key.copy_from_slice(&hash[0..CRYPTO_BOX_SEEDBYTES]);

    hash.zeroize();

    crypto_scalarmult_curve25519_base(public_key, secret_key);
}
pub(crate) fn crypto_box_curve25519xsalsa20poly1305_keypair() -> (PublicKey, SecretKey) {
    let mut secret_key = SecretKey::default();
    let mut public_key = PublicKey::default();

    crypto_box_curve25519xsalsa20poly1305_keypair_inplace(&mut public_key, &mut secret_key);

    (public_key, secret_key)
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(
    seed: &[u8],
) -> (PublicKey, SecretKey) {
    let mut secret_key = [0u8; CRYPTO_BOX_SEEDBYTES];
    let mut public_key = [0u8; CRYPTO_BOX_SEEDBYTES];

    crypto_box_curve25519xsalsa20poly1305_seed_keypair_inplace(
        &mut public_key,
        &mut secret_key,
        seed,
    );

    (public_key, secret_key)
}
