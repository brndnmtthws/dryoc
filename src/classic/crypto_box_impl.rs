use zeroize::{Zeroize, Zeroizing};

use super::crypto_core::crypto_scalarmult;
use crate::classic::crypto_box::{PublicKey, SecretKey};
use crate::classic::crypto_core::crypto_core_hsalsa20;
use crate::classic::crypto_hash::crypto_hash_sha512;
use crate::classic::crypto_secretbox::Key;
use crate::constants::{
    CRYPTO_BOX_SEEDBYTES, CRYPTO_CORE_HSALSA20_INPUTBYTES, CRYPTO_HASH_SHA512_BYTES,
    CRYPTO_SCALARMULT_BYTES,
};
use crate::dryocstream::ByteArray;
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::scalarmult_curve25519::*;

/// Computes the precomputed box key into `key`, which the caller owns (and
/// wipes), so the key is never copied through this function's frame or a
/// returned `Result`.
pub(crate) fn crypto_box_curve25519xsalsa20poly1305_beforenm_into(
    key: &mut Key,
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut s = Zeroizing::new([0u8; CRYPTO_SCALARMULT_BYTES]);
    crypto_scalarmult(&mut s, secret_key.as_array(), public_key.as_array())?;

    crypto_core_hsalsa20(key, &[0u8; CRYPTO_CORE_HSALSA20_INPUTBYTES], &s, None);

    Ok(())
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_beforenm(
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Result<Key, Error> {
    // Wiped when it goes out of scope; only the returned copy survives.
    let mut key = Zeroizing::new(Key::default());
    crypto_box_curve25519xsalsa20poly1305_beforenm_into(&mut key, public_key, secret_key)?;

    Ok(*key)
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
    seed: &[u8; CRYPTO_BOX_SEEDBYTES],
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
    seed: &[u8; CRYPTO_BOX_SEEDBYTES],
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
