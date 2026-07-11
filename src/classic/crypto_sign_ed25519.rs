//! # Ed25519 signing helpers
//!
//! This module implements libsodium's Ed25519 helper functions, including
//! Ed25519 to Curve25519 conversion and secret-key extraction. You can use the
//! conversion functions when you want to sign messages with the same keys used
//! to encrypt messages (i.e., using a public-key box).
//!
//! Generally speaking, you should avoid signing and encrypting with the same
//! keypair. Additionally, an encrypted box doesn't need to be separately signed
//! as it already includes a message authentication code.
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_sign::{
//!     crypto_sign_ed25519_sk_to_pk, crypto_sign_ed25519_sk_to_seed, crypto_sign_seed_keypair,
//! };
//! use dryoc::constants::{CRYPTO_SIGN_PUBLICKEYBYTES, CRYPTO_SIGN_SEEDBYTES};
//!
//! let seed = [7u8; CRYPTO_SIGN_SEEDBYTES];
//! let (public_key, secret_key) = crypto_sign_seed_keypair(&seed);
//!
//! let mut extracted_seed = [0u8; CRYPTO_SIGN_SEEDBYTES];
//! let mut extracted_public_key = [0u8; CRYPTO_SIGN_PUBLICKEYBYTES];
//! crypto_sign_ed25519_sk_to_seed(&mut extracted_seed, &secret_key);
//! crypto_sign_ed25519_sk_to_pk(&mut extracted_public_key, &secret_key);
//!
//! assert_eq!(extracted_seed, seed);
//! assert_eq!(extracted_public_key, public_key);
//! ```

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use super::crypto_core::decompress_canonical_ed25519_point;
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
    let mut hash: [u8; CRYPTO_HASH_SHA512_BYTES] = Sha512::compute(seed);

    let mut clamped = clamp_hash(&mut hash);
    let mut sk = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();

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
    crypto_sign_ed25519_seed_keypair_inplace(public_key, secret_key, &seed);
    seed.zeroize();
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
    hash: &mut [u8; CRYPTO_HASH_SHA512_BYTES],
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
/// Compatible with libsodium's `crypto_sign_ed25519_pk_to_curve25519`.
///
/// # Errors
///
/// Returns an error if `ed25519_public_key` is noncanonical, has small order,
/// is not on the curve, or is not in the main subgroup.
pub fn crypto_sign_ed25519_pk_to_curve25519(
    x25519_public_key: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    ed25519_public_key: &PublicKey,
) -> Result<(), Error> {
    let ep = decompress_canonical_ed25519_point(ed25519_public_key)
        .filter(|point| !point.is_small_order() && point.is_torsion_free())
        .ok_or(Error::invalid_key(crate::ErrorContext::Ed25519PublicKey))?;
    x25519_public_key.copy_from_slice(ep.to_montgomery().as_bytes());

    Ok(())
}

/// Converts an Ed25519 secret key `ed25519_secret_key` into an X25519 secret
/// key, placing the result into `x25519_secret_key`.
///
/// Compatible with libsodium's `crypto_sign_ed25519_sk_to_curve25519`.
pub fn crypto_sign_ed25519_sk_to_curve25519(
    x25519_secret_key: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    ed25519_secret_key: &SecretKey,
) {
    let mut hash: [u8; CRYPTO_HASH_SHA512_BYTES] = Sha512::compute(&ed25519_secret_key[..32]);
    let mut scalar = clamp_hash(&mut hash);
    x25519_secret_key.copy_from_slice(&scalar);
    scalar.zeroize()
}

/// Extracts the Ed25519 seed from `secret_key`, placing the result into `seed`.
///
/// Compatible with libsodium's `crypto_sign_ed25519_sk_to_seed`.
pub fn crypto_sign_ed25519_sk_to_seed(
    seed: &mut [u8; CRYPTO_SIGN_ED25519_SEEDBYTES],
    secret_key: &SecretKey,
) {
    seed.copy_from_slice(&secret_key[..CRYPTO_SIGN_ED25519_SEEDBYTES]);
}

/// Extracts the Ed25519 public key from `secret_key`, placing the result into
/// `public_key`.
///
/// Compatible with libsodium's `crypto_sign_ed25519_sk_to_pk`.
pub fn crypto_sign_ed25519_sk_to_pk(public_key: &mut PublicKey, secret_key: &SecretKey) {
    public_key.copy_from_slice(
        &secret_key[CRYPTO_SIGN_ED25519_SEEDBYTES..CRYPTO_SIGN_ED25519_SECRETKEYBYTES],
    );
}

pub(crate) fn crypto_sign_ed25519(
    signed_message: &mut [u8],
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    if signed_message.len() != message.len() + CRYPTO_SIGN_ED25519_BYTES {
        Err(length_error!(
            crate::ErrorContext::SignedMessage,
            signed_message.len(),
            exact message.len() + CRYPTO_SIGN_ED25519_BYTES
        ))
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
        Err(length_error!(
            crate::ErrorContext::Signature,
            signature.len(),
            exact CRYPTO_SIGN_ED25519_BYTES
        ))
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

        let mut r = Scalar::from_bytes_mod_order_wide(&nonce);
        let big_r = (ED25519_BASEPOINT_TABLE * &r).compress();

        signature[..32].copy_from_slice(big_r.as_bytes());

        let mut hasher = Sha512::new();
        if prehashed {
            hasher.update(DOM2PREFIX);
        }
        hasher.update(signature);
        hasher.update(message);
        let mut hram: [u8; CRYPTO_HASH_SHA512_BYTES] = hasher.finalize();

        let mut k = Scalar::from_bytes_mod_order_wide(&hram);
        let mut clamped = clamp_hash(&mut az);
        let mut signing_scalar = Scalar::from_bytes_mod_order(clamped);
        clamped.zeroize();
        let mut sig = (k * signing_scalar) + r;

        signature[32..].copy_from_slice(sig.as_bytes());

        az.zeroize();
        nonce.zeroize();
        hram.zeroize();
        r.zeroize();
        k.zeroize();
        signing_scalar.zeroize();
        sig.zeroize();

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
    let s_bytes = *<&[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES]>::try_from(&signature[32..])
        .map_err(|_| Error::AuthenticationFailed)?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or(Error::AuthenticationFailed)?;
    let r_bytes = <&[u8; CRYPTO_SIGN_ED25519_PUBLICKEYBYTES]>::try_from(&signature[..32])
        .map_err(|_| Error::AuthenticationFailed)?;
    let big_r = decompress_canonical_ed25519_point(r_bytes).ok_or(Error::AuthenticationFailed)?;
    if big_r.is_small_order() {
        return Err(Error::AuthenticationFailed);
    }
    let pk = decompress_canonical_ed25519_point(public_key)
        .ok_or(Error::invalid_key(crate::ErrorContext::Ed25519PublicKey))?;
    if pk.is_small_order() {
        return Err(Error::invalid_key(crate::ErrorContext::Ed25519PublicKey));
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
        Err(Error::AuthenticationFailed)
    }
}

pub(crate) fn crypto_sign_ed25519_open(
    message: &mut [u8],
    signed_message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    if signed_message.len() < CRYPTO_SIGN_ED25519_BYTES {
        Err(length_error!(
            crate::ErrorContext::SignedMessage,
            signed_message.len(),
            min CRYPTO_SIGN_ED25519_BYTES
        ))
    } else if message.len() != signed_message.len() - CRYPTO_SIGN_ED25519_BYTES {
        Err(length_error!(
            crate::ErrorContext::Message,
            message.len(),
            exact signed_message.len() - CRYPTO_SIGN_ED25519_BYTES
        ))
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
mod regression_tests {
    use super::*;

    const ED25519_GROUP_ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    pub(super) fn add_group_order_to_s(signature: &mut Signature) {
        let mut carry = 0u16;
        for (s, order) in signature[32..].iter_mut().zip(ED25519_GROUP_ORDER) {
            let sum = u16::from(*s) + u16::from(order) + carry;
            *s = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "a reduced Ed25519 scalar plus L fits in 256 bits");
    }

    #[test]
    fn verification_rejects_s_plus_group_order() {
        let message = b"malleability regression";
        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&[7u8; 32]);

        let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519_detached(&mut signature, message, &secret_key).unwrap();
        crypto_sign_ed25519_verify_detached(&signature, message, &public_key).unwrap();
        add_group_order_to_s(&mut signature);
        assert!(matches!(
            crypto_sign_ed25519_verify_detached(&signature, message, &public_key),
            Err(Error::AuthenticationFailed)
        ));

        let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519(&mut signed_message, message, &secret_key).unwrap();
        let embedded_signature =
            <&mut Signature>::try_from(&mut signed_message[..CRYPTO_SIGN_ED25519_BYTES]).unwrap();
        add_group_order_to_s(embedded_signature);
        let mut opened_message = vec![0u8; message.len()];
        assert!(matches!(
            crypto_sign_ed25519_open(&mut opened_message, &signed_message, &public_key),
            Err(Error::AuthenticationFailed)
        ));

        let mut signer = crypto_sign_ed25519ph_init();
        crypto_sign_ed25519ph_update(&mut signer, message);
        let mut prehash_signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519ph_final_create(signer, &mut prehash_signature, &secret_key).unwrap();
        add_group_order_to_s(&mut prehash_signature);

        let mut verifier = crypto_sign_ed25519ph_init();
        crypto_sign_ed25519ph_update(&mut verifier, message);
        assert!(matches!(
            crypto_sign_ed25519ph_final_verify(verifier, &prehash_signature, &public_key),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn public_key_conversion_rejects_invalid_edwards_points() {
        let identity = {
            let mut point = [0u8; 32];
            point[0] = 1;
            point
        };
        let noncanonical_identity = {
            let mut point = [0xff; 32];
            point[0] = 0xee;
            point[31] = 0x7f;
            point
        };
        let mixed_order = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT
            + curve25519_dalek::constants::EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        let mixed_point = decompress_canonical_ed25519_point(&mixed_order).unwrap();
        assert!(!mixed_point.is_small_order());
        assert!(!mixed_point.is_torsion_free());

        for invalid_key in [identity, noncanonical_identity, mixed_order] {
            let mut output = [0xa5; CRYPTO_SCALARMULT_CURVE25519_BYTES];
            assert!(crypto_sign_ed25519_pk_to_curve25519(&mut output, &invalid_key).is_err());
            assert_eq!(
                output, [0xa5; CRYPTO_SCALARMULT_CURVE25519_BYTES],
                "conversion failure must not modify the output"
            );
        }
    }

    #[test]
    fn public_key_conversion_accepts_valid_high_sign_bit() {
        let basepoint = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let mut negative_basepoint = basepoint;
        negative_basepoint[31] |= 0x80;

        let mut positive_output = [0u8; CRYPTO_SCALARMULT_CURVE25519_BYTES];
        let mut negative_output = [0u8; CRYPTO_SCALARMULT_CURVE25519_BYTES];
        crypto_sign_ed25519_pk_to_curve25519(&mut positive_output, &basepoint).unwrap();
        crypto_sign_ed25519_pk_to_curve25519(&mut negative_output, &negative_basepoint).unwrap();
        assert_eq!(positive_output, negative_output);
    }
}

#[cfg(all(test, dryoc_native_tests))]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose;

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
    fn test_key_conversion() {
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

    #[test]
    fn test_invalid_public_key_conversion_compatibility() {
        use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519 as sodium_convert;

        let identity = {
            let mut point = [0u8; 32];
            point[0] = 1;
            point
        };
        let noncanonical_identity = {
            let mut point = [0xff; 32];
            point[0] = 0xee;
            point[31] = 0x7f;
            point
        };
        let mixed_order = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT
            + curve25519_dalek::constants::EIGHT_TORSION[1])
            .compress()
            .to_bytes();

        for invalid_key in [identity, noncanonical_identity, mixed_order] {
            let mut output = [0u8; CRYPTO_SCALARMULT_CURVE25519_BYTES];
            let dryoc_result = crypto_sign_ed25519_pk_to_curve25519(&mut output, &invalid_key);
            let sodium_result =
                unsafe { sodium_convert(output.as_mut_ptr(), invalid_key.as_ptr()) };
            assert!(dryoc_result.is_err());
            assert_eq!(sodium_result, -1);
        }
    }

    #[test]
    fn test_noncanonical_signature_scalar_compatibility() {
        use libsodium_sys::crypto_sign_verify_detached as sodium_verify;

        let message = b"malleability regression";
        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&[7u8; 32]);
        let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519_detached(&mut signature, message, &secret_key).unwrap();
        super::regression_tests::add_group_order_to_s(&mut signature);

        assert!(crypto_sign_ed25519_verify_detached(&signature, message, &public_key).is_err());
        let sodium_result = unsafe {
            sodium_verify(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                public_key.as_ptr(),
            )
        };
        assert_eq!(sodium_result, -1);
    }

    #[test]
    fn test_secret_key_extraction() {
        use libsodium_sys::{
            crypto_sign_ed25519_sk_to_pk as so_crypto_sign_ed25519_sk_to_pk,
            crypto_sign_ed25519_sk_to_seed as so_crypto_sign_ed25519_sk_to_seed,
        };

        for _ in 0..10 {
            let (pk, sk) = crypto_sign_ed25519_keypair();
            let mut seed = [0u8; CRYPTO_SIGN_ED25519_SEEDBYTES];
            let mut extracted_pk = [0u8; CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
            crypto_sign_ed25519_sk_to_seed(&mut seed, &sk);
            crypto_sign_ed25519_sk_to_pk(&mut extracted_pk, &sk);

            let mut so_seed = [0u8; CRYPTO_SIGN_ED25519_SEEDBYTES];
            let mut so_pk = [0u8; CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];

            unsafe {
                so_crypto_sign_ed25519_sk_to_seed(so_seed.as_mut_ptr(), sk.as_ptr());
                so_crypto_sign_ed25519_sk_to_pk(so_pk.as_mut_ptr(), sk.as_ptr());
            }

            assert_eq!(seed, so_seed);
            assert_eq!(extracted_pk, pk);
            assert_eq!(extracted_pk, so_pk);
        }
    }
}
