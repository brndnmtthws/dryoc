use crate::crypto_hash::crypto_hash_sha512;
use crate::hsalsa20::crypto_core_hsalsa20;
use crate::types::*;

use rand_core::OsRng;
use x25519_dalek::PublicKey as DalekPublicKey;
use x25519_dalek::StaticSecret as DalekSecretKey;
use zeroize::Zeroize;

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_beforenm(
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> SecretboxKey {
    let sk = DalekSecretKey::from(*secret_key);
    let pk = DalekPublicKey::from(*public_key);

    let s = sk.diffie_hellman(&pk);

    let result = crypto_core_hsalsa20(&[0u8; 16], s.as_bytes());

    result
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_keypair() -> KeyPair {
    let secret_key = DalekSecretKey::new(OsRng);
    let public_key = DalekPublicKey::from(&secret_key);

    KeyPair {
        secret_key: secret_key.to_bytes(),
        public_key: public_key.to_bytes(),
    }
}

pub(crate) fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(seed: &[u8]) -> KeyPair {
    let mut hash = crypto_hash_sha512(seed);

    let mut seed_hash = [0u8; 32];
    for (i, n) in hash.iter().take(32).enumerate() {
        seed_hash[i] = *n;
    }

    let secret_key = DalekSecretKey::from(seed_hash);
    let public_key = DalekPublicKey::from(&secret_key);

    hash.zeroize();

    KeyPair {
        secret_key: secret_key.to_bytes(),
        public_key: public_key.to_bytes(),
    }
}
