//! # Ed25519 to Curve25519 conversion
//!
//! This module implements libsodium's Ed25519 to Curve25519 conversion
//! functions. You can use these functions when you want to sign messages with
//! the same keys used to encrypt messages (i.e., using a public-key box).
//!
//! Generally speaking, you should avoid signing and encrypting with the same
//! keypair. Additionally, an encrypted box doesn't need to be separately signed
//! as it already includes a message authentication code.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_HASH_SHA512_BYTES, CRYPTO_SCALARMULT_CURVE25519_BYTES,
    CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES, CRYPTO_SIGN_ED25519_BYTES,
    CRYPTO_SIGN_ED25519_PUBLICKEYBYTES, CRYPTO_SIGN_ED25519_SECRETKEYBYTES,
    CRYPTO_SIGN_ED25519_SEEDBYTES,
};
use crate::error::Error;
use crate::sha512::Sha512;

/// Type alias for an Ed25519 public key.
pub type PublicKey = [u8; CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
/// Type alias for an Ed25519 secret key with seed bytes.
pub type SecretKey = [u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES];
/// Type alias for an Ed25519 signature.
pub type Signature = [u8; CRYPTO_SIGN_ED25519_BYTES];

const DOM2PREFIX: &[u8] = b"SigEd25519 no Ed25519 collisions\x01\x00";

/// In-place variant of [`crypto_sign_ed25519_seed_keypair`].
#[inline]
pub(crate) fn crypto_sign_ed25519_seed_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
    seed: &[u8; CRYPTO_SIGN_ED25519_SEEDBYTES],
) {
    let hash: [u8; CRYPTO_HASH_SHA512_BYTES] = Sha512::compute(seed);

    let mut sk = Scalar::from_bytes_mod_order(clamp_hash(hash));

    let pk = (ED25519_BASEPOINT_TABLE * &sk).compress();
    secret_key[..CRYPTO_SIGN_ED25519_SEEDBYTES].copy_from_slice(seed);
    secret_key[CRYPTO_SIGN_ED25519_SEEDBYTES..].copy_from_slice(pk.as_bytes());

    public_key.copy_from_slice(pk.as_bytes());

    sk.zeroize();
}

/// Generates an Ed25519 keypair from `seed` which can be used for signing
/// messages.
pub(crate) fn crypto_sign_ed25519_seed_keypair(
    seed: &[u8; CRYPTO_SIGN_ED25519_SEEDBYTES],
) -> (PublicKey, SecretKey) {
    let mut public_key = PublicKey::default();
    let mut secret_key = [0u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES];

    crypto_sign_ed25519_seed_keypair_inplace(&mut public_key, &mut secret_key, seed);

    (public_key, secret_key)
}

/// In-place variant of [`crypto_sign_ed25519_keypair`].
#[inline]
pub(crate) fn crypto_sign_ed25519_keypair_inplace(
    public_key: &mut PublicKey,
    secret_key: &mut SecretKey,
) {
    use crate::rng::copy_randombytes;
    let mut seed = [0u8; CRYPTO_SIGN_ED25519_SEEDBYTES];
    copy_randombytes(&mut seed);
    crypto_sign_ed25519_seed_keypair_inplace(public_key, secret_key, &seed)
}

/// Generates a random Ed25519 keypair which can be used for signing
/// messages.
pub(crate) fn crypto_sign_ed25519_keypair() -> (PublicKey, SecretKey) {
    let mut public_key = PublicKey::default();
    let mut secret_key = [0u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES];
    crypto_sign_ed25519_keypair_inplace(&mut public_key, &mut secret_key);

    (public_key, secret_key)
}

fn clamp_hash(
    mut hash: [u8; CRYPTO_HASH_SHA512_BYTES],
) -> [u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES] {
    let mut scalar = [0u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES];
    scalar.copy_from_slice(&hash[..CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES]);
    hash.zeroize();
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// Converts an Ed25519 public key `ed25519_public_key` into an X25519 public
/// key, placing the result into `x25519_public_key` upon success.
///
/// Compatible with libsodium's `crypto_sign_ed25519_pk_to_curve25519`
pub fn crypto_sign_ed25519_pk_to_curve25519(
    x25519_public_key: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    ed25519_public_key: &PublicKey,
) -> Result<(), Error> {
    let ep = CompressedEdwardsY(*ed25519_public_key)
        .decompress()
        .ok_or_else(|| dryoc_error!("failed to convert to Edwards point"))?;
    x25519_public_key.copy_from_slice(ep.to_montgomery().as_bytes());

    Ok(())
}

/// Converts an Ed25519 secret key `ed25519_secret_key` into an X25519 secret
/// key key, placing the result into `x25519_secret_key`.
///
/// Compatible with libsodium's `crypto_sign_ed25519_sk_to_curve25519`
pub fn crypto_sign_ed25519_sk_to_curve25519(
    x25519_secret_key: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    ed25519_secret_key: &SecretKey,
) {
    let hash: [u8; CRYPTO_HASH_SHA512_BYTES] = Sha512::compute(&ed25519_secret_key[..32]);
    let mut scalar = clamp_hash(hash);
    x25519_secret_key.copy_from_slice(&scalar);
    scalar.zeroize()
}

pub(crate) fn crypto_sign_ed25519(
    signed_message: &mut [u8],
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    if signed_message.len() != message.len() + CRYPTO_SIGN_ED25519_BYTES {
        Err(dryoc_error!(format!(
            "signed_message length incorrect (expect {}, got {})",
            message.len() + CRYPTO_SIGN_ED25519_BYTES,
            signed_message.len()
        )))
    } else {
        let (sig, sm) = signed_message.split_at_mut(CRYPTO_SIGN_ED25519_BYTES);
        let sig: &mut [u8; CRYPTO_SIGN_ED25519_BYTES] =
            <&mut [u8; CRYPTO_SIGN_ED25519_BYTES]>::try_from(sig).unwrap();
        sm.copy_from_slice(message);
        crypto_sign_ed25519_detached(sig, message, secret_key)
    }
}

pub(crate) fn crypto_sign_ed25519_detached(
    signature: &mut Signature,
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_detached_impl(signature, message, secret_key, false)
}

#[inline]
fn crypto_sign_ed25519_detached_impl(
    signature: &mut Signature,
    message: &[u8],
    secret_key: &SecretKey,
    prehashed: bool,
) -> Result<(), Error> {
    if signature.len() != CRYPTO_SIGN_ED25519_BYTES {
        Err(dryoc_error!(format!(
            "signature length incorrect (expect {}, got {})",
            CRYPTO_SIGN_ED25519_BYTES,
            signature.len()
        )))
    } else {
        let mut az: [u8; CRYPTO_HASH_SHA512_BYTES] = Sha512::compute(&secret_key[..32]);

        let mut hasher = Sha512::new();
        if prehashed {
            hasher.update(DOM2PREFIX);
        }
        hasher.update(&az[32..]);
        hasher.update(message);
        let mut nonce: [u8; CRYPTO_HASH_SHA512_BYTES] = hasher.finalize();

        signature[32..].copy_from_slice(&secret_key[32..]);

        let r = Scalar::from_bytes_mod_order_wide(&nonce);
        let big_r = (ED25519_BASEPOINT_TABLE * &r).compress();

        signature[..32].copy_from_slice(big_r.as_bytes());

        let mut hasher = Sha512::new();
        if prehashed {
            hasher.update(DOM2PREFIX);
        }
        hasher.update(signature);
        hasher.update(message);
        let hram: [u8; CRYPTO_HASH_SHA512_BYTES] = hasher.finalize();

        let k = Scalar::from_bytes_mod_order_wide(&hram);
        let clamped = clamp_hash(az);
        let sig = (k * Scalar::from_bytes_mod_order(clamped)) + r;

        signature[32..].copy_from_slice(sig.as_bytes());

        az.zeroize();
        nonce.zeroize();

        Ok(())
    }
}

pub(crate) fn crypto_sign_ed25519_verify_detached(
    signature: &Signature,
    message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_verify_detached_impl(signature, message, public_key, false)
}

fn crypto_sign_ed25519_verify_detached_impl(
    signature: &Signature,
    message: &[u8],
    public_key: &PublicKey,
    prehashed: bool,
) -> Result<(), Error> {
    let s = Scalar::from_bytes_mod_order(
        *<&[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES]>::try_from(&signature[32..])
            .map_err(|_| dryoc_error!("bad signature"))?,
    );
    let big_r = CompressedEdwardsY::from_slice(&signature[..32])?
        .decompress()
        .ok_or_else(|| dryoc_error!("bad signature"))?;
    if big_r.is_small_order() {
        return Err(dryoc_error!("bad signature"));
    }
    let pk = CompressedEdwardsY::from_slice(public_key)?
        .decompress()
        .ok_or_else(|| dryoc_error!("bad public key"))?;
    if pk.is_small_order() {
        return Err(dryoc_error!("bad public key"));
    }

    let mut hasher = Sha512::new();
    if prehashed {
        hasher.update(DOM2PREFIX);
    }
    hasher.update(&signature[..32]);
    hasher.update(public_key);
    hasher.update(message);
    let h: [u8; CRYPTO_HASH_SHA512_BYTES] = hasher.finalize();

    let k = Scalar::from_bytes_mod_order_wide(&h);

    let sig_r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-pk), &s);

    if sig_r == big_r {
        Ok(())
    } else {
        Err(dryoc_error!("bad signature"))
    }
}

pub(crate) fn crypto_sign_ed25519_open(
    message: &mut [u8],
    signed_message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    if signed_message.len() < CRYPTO_SIGN_ED25519_BYTES {
        Err(dryoc_error!(format!(
            "signed_message length invalid ({} < {})",
            signed_message.len(),
            CRYPTO_SIGN_ED25519_BYTES,
        )))
    } else if message.len() != signed_message.len() - CRYPTO_SIGN_ED25519_BYTES {
        Err(dryoc_error!(format!(
            "message length incorrect (expect {}, got {})",
            signed_message.len() - CRYPTO_SIGN_ED25519_BYTES,
            message.len()
        )))
    } else {
        let (sig, sm) = signed_message.split_at(CRYPTO_SIGN_ED25519_BYTES);
        let sig: &[u8; CRYPTO_SIGN_ED25519_BYTES] =
            <&[u8; CRYPTO_SIGN_ED25519_BYTES]>::try_from(sig).unwrap();
        crypto_sign_ed25519_verify_detached(sig, sm, public_key)?;
        message.copy_from_slice(sm);
        Ok(())
    }
}

pub(crate) struct Ed25519SignerState {
    hasher: Sha512,
}

pub(crate) fn crypto_sign_ed25519ph_init() -> Ed25519SignerState {
    Ed25519SignerState {
        hasher: Sha512::new(),
    }
}

pub(crate) fn crypto_sign_ed25519ph_update(state: &mut Ed25519SignerState, message: &[u8]) {
    state.hasher.update(message)
}

pub(crate) fn crypto_sign_ed25519ph_final_create(
    state: Ed25519SignerState,
    signature: &mut Signature,
    secret_key: &SecretKey,
) -> Result<(), Error> {
    let mut hash: [u8; CRYPTO_HASH_SHA512_BYTES] = state.hasher.finalize();
    let res = crypto_sign_ed25519_detached_impl(signature, &hash, secret_key, true);
    hash.zeroize();
    res
}

pub(crate) fn crypto_sign_ed25519ph_final_verify(
    state: Ed25519SignerState,
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), Error> {
    let mut hash: [u8; CRYPTO_HASH_SHA512_BYTES] = state.hasher.finalize();
    let res = crypto_sign_ed25519_verify_detached_impl(signature, &hash, public_key, true);
    hash.zeroize();
    res
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose;
    use base64::Engine as _;

    use super::*;
    use crate::rng::copy_randombytes;

    #[test]
    fn test_keypair_seed() {
        use sodiumoxide::crypto::sign;

        for _ in 0..10 {
            let mut seed = [0u8; CRYPTO_SIGN_ED25519_SEEDBYTES];
            copy_randombytes(&mut seed);

            let (pk, sk) = crypto_sign_ed25519_seed_keypair(&seed);

            let (so_pk, so_sk) =
                sign::keypair_from_seed(&sign::Seed::from_slice(&seed).expect("seed failed"));

            assert_eq!(
                general_purpose::STANDARD.encode(pk),
                general_purpose::STANDARD.encode(so_pk.0)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(sk),
                general_purpose::STANDARD.encode(so_sk.0)
            );
        }
    }

    #[test]
    fn test_() {
        use libsodium_sys::{
            crypto_sign_ed25519_pk_to_curve25519 as so_crypto_sign_ed25519_pk_to_curve25519,
            crypto_sign_ed25519_sk_to_curve25519 as so_crypto_sign_ed25519_sk_to_curve25519,
        };

        for _ in 0..10 {
            let (pk, sk) = crypto_sign_ed25519_keypair();
            let mut xpk = [0u8; CRYPTO_SCALARMULT_CURVE25519_BYTES];
            let mut xsk = [0u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES];
            crypto_sign_ed25519_pk_to_curve25519(&mut xpk, &pk).expect("pk failed");
            crypto_sign_ed25519_sk_to_curve25519(&mut xsk, &sk);

            let mut so_xpk = [0u8; CRYPTO_SCALARMULT_CURVE25519_BYTES];
            let mut so_xsk = [0u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES];

            unsafe {
                so_crypto_sign_ed25519_pk_to_curve25519(so_xpk.as_mut_ptr(), pk.as_ptr());
                so_crypto_sign_ed25519_sk_to_curve25519(so_xsk.as_mut_ptr(), sk.as_ptr());
            }

            assert_eq!(
                general_purpose::STANDARD.encode(xpk),
                general_purpose::STANDARD.encode(so_xpk)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(xsk),
                general_purpose::STANDARD.encode(so_xsk)
            );
        }
    }
}
