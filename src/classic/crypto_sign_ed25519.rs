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

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use super::crypto_core::{
    decompress_canonical_ed25519_point, decompress_prime_order_ed25519_point,
};
use crate::constants::{
    CRYPTO_HASH_SHA512_BYTES, CRYPTO_SCALARMULT_CURVE25519_BYTES,
    CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES, CRYPTO_SIGN_ED25519_BYTES,
    CRYPTO_SIGN_ED25519_PUBLICKEYBYTES, CRYPTO_SIGN_ED25519_SECRETKEYBYTES,
    CRYPTO_SIGN_ED25519_SEEDBYTES,
};
use crate::edwards25519::mul_base;
use crate::error::Error;
use crate::scalarmult_curve25519::clamp_scalar;
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
    let pk = mul_base(&clamped).compress();
    clamped.zeroize();

    secret_key[..CRYPTO_SIGN_ED25519_SEEDBYTES].copy_from_slice(seed);
    secret_key[CRYPTO_SIGN_ED25519_SEEDBYTES..].copy_from_slice(&pk);

    public_key.copy_from_slice(&pk);
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
    clamp_scalar(&mut scalar);
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
    let ep = decompress_prime_order_ed25519_point(ed25519_public_key)
        .ok_or(Error::invalid_key(crate::ErrorContext::Ed25519PublicKey))?;
    *x25519_public_key = ep.to_montgomery();

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
    validate_length!(
        exact message.len() + CRYPTO_SIGN_ED25519_BYTES,
        signed_message.len(),
        crate::ErrorContext::SignedMessage
    );

    let (sig, sm) = signed_message.split_at_mut(CRYPTO_SIGN_ED25519_BYTES);
    let sig: &mut [u8; CRYPTO_SIGN_ED25519_BYTES] =
        <&mut [u8; CRYPTO_SIGN_ED25519_BYTES]>::try_from(sig).unwrap();
    sm.copy_from_slice(message);
    crypto_sign_ed25519_detached(sig, message, secret_key)
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
    validate_length!(
        exact CRYPTO_SIGN_ED25519_BYTES,
        signature.len(),
        crate::ErrorContext::Signature
    );

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
    let mut r_bytes = r.to_bytes();
    let big_r = mul_base(&r_bytes).compress();
    r_bytes.zeroize();

    signature[..32].copy_from_slice(&big_r);

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

    // R' = [k](-A) + [s]B must equal R; both sides are public.
    let sig_r = pk
        .neg()
        .double_scalar_mul_basepoint_vartime(&k.to_bytes(), &s.to_bytes());

    if sig_r.eq_vartime(&big_r) {
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
    validate_length!(
        min CRYPTO_SIGN_ED25519_BYTES,
        signed_message.len(),
        crate::ErrorContext::SignedMessage
    );
    validate_length!(
        exact signed_message.len() - CRYPTO_SIGN_ED25519_BYTES,
        message.len(),
        crate::ErrorContext::Message
    );

    let (sig, sm) = signed_message.split_at(CRYPTO_SIGN_ED25519_BYTES);
    let sig: &[u8; CRYPTO_SIGN_ED25519_BYTES] =
        <&[u8; CRYPTO_SIGN_ED25519_BYTES]>::try_from(sig).unwrap();
    crypto_sign_ed25519_verify_detached(sig, sm, public_key)?;
    message.copy_from_slice(sm);
    Ok(())
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
    use crate::classic::crypto_core::ed25519_is_torsion_free;

    pub(super) const ED25519_GROUP_ORDER: [u8; 32] = [
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
        assert!(!ed25519_is_torsion_free(&mixed_point));

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

#[cfg(test)]
mod vector_tests {
    use curve25519_dalek::constants::EIGHT_TORSION;

    use super::regression_tests::ED25519_GROUP_ORDER;
    use super::*;
    use crate::scalarmult_curve25519::test_vectors::field_prime_plus;
    use crate::test_prelude::*;
    use crate::utils::test_util::hex32 as hex;

    /// RFC 8032 section 7.1 vector: seed, public key, message and signature.
    struct Vector {
        seed: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    const TEST_1024_MESSAGE: &str = concat!(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98",
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8",
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc",
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e",
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef",
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7",
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1",
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24",
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270",
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc",
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07",
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a",
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e",
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7",
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c",
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df",
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08",
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649",
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4",
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e",
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f",
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5",
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1",
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
    );

    /// RFC 8032 section 7.1: TEST 1, 2, 3, 1024 and SHA(abc).
    const ED25519_VECTORS: [Vector; 5] = [
        Vector {
            seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            message: "",
            signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        Vector {
            seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            message: "72",
            signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        Vector {
            seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            message: "af82",
            signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
        Vector {
            seed: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            public_key: "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            message: TEST_1024_MESSAGE,
            signature: "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        },
        Vector {
            seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            public_key: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        },
    ];

    /// RFC 8032 section 7.3, TEST abc: Ed25519ph with the SHA(abc) key.
    const ED25519PH_VECTOR: Vector = Vector {
        seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        public_key: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        message: "616263",
        signature: "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
    };

    fn hex64(s: &str) -> Signature {
        hex::decode(s).expect("hex").try_into().expect("64 bytes")
    }

    /// Point encodings every verifier must refuse as `R` or `A`: the three
    /// non-canonical `y >= p` values `p`, `p + 1` and `2^255 - 1` with both
    /// sign bits, the eight small-order points, and the two alternate
    /// encodings of the `x = 0` points (`y = 1` and `y = -1` with the sign
    /// bit set).
    pub(super) fn rejected_point_encodings() -> Vec<[u8; 32]> {
        let mut encodings = Vec::with_capacity(16);
        for offset in [0, 1, 18] {
            let low = field_prime_plus(offset);
            let mut high = low;
            high[31] |= 0x80;
            encodings.extend([low, high]);
        }
        encodings.extend(EIGHT_TORSION.iter().map(|t| t.compress().to_bytes()));
        let mut identity_negative_sign = [0u8; 32];
        identity_negative_sign[0] = 1;
        identity_negative_sign[31] = 0x80;
        let mut minus_one_negative_sign = field_prime_plus(-1);
        minus_one_negative_sign[31] |= 0x80;
        encodings.extend([identity_negative_sign, minus_one_negative_sign]);
        assert_eq!(encodings.len(), 16);
        encodings
    }

    /// `S` values a canonical verifier must refuse: `L`, `L + 1` and
    /// `2^256 - 1`.
    pub(super) fn rejected_scalars() -> [[u8; 32]; 3] {
        let mut order_plus_one = ED25519_GROUP_ORDER;
        order_plus_one[0] += 1;
        [ED25519_GROUP_ORDER, order_plus_one, [0xff; 32]]
    }

    #[test]
    fn rfc8032_ed25519_vectors() {
        for (i, vector) in ED25519_VECTORS.iter().enumerate() {
            let seed = hex(vector.seed);
            let message = hex::decode(vector.message).expect("hex");
            let expected_signature = hex64(vector.signature);

            let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&seed);
            assert_eq!(public_key, hex(vector.public_key), "public key {i}");
            assert_eq!(secret_key[..32], seed, "secret key seed {i}");
            assert_eq!(secret_key[32..], public_key, "secret key suffix {i}");

            let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
            crypto_sign_ed25519_detached(&mut signature, &message, &secret_key).unwrap();
            assert_eq!(signature, expected_signature, "signature {i}");
            crypto_sign_ed25519_verify_detached(&expected_signature, &message, &public_key)
                .unwrap_or_else(|e| panic!("verify {i}: {e}"));

            let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_ED25519_BYTES];
            crypto_sign_ed25519(&mut signed_message, &message, &secret_key).unwrap();
            assert_eq!(
                signed_message[..CRYPTO_SIGN_ED25519_BYTES],
                expected_signature,
                "combined signature {i}"
            );
            assert_eq!(
                signed_message[CRYPTO_SIGN_ED25519_BYTES..],
                message,
                "combined message {i}"
            );
            let mut opened = vec![0xa5; message.len()];
            crypto_sign_ed25519_open(&mut opened, &signed_message, &public_key)
                .unwrap_or_else(|e| panic!("open {i}: {e}"));
            assert_eq!(opened, message, "opened {i}");
        }
    }

    /// The incremental interface is Ed25519ph: it produces the section 7.3
    /// signature however the message is split, and its signatures are not
    /// interchangeable with plain Ed25519 ones over the same bytes.
    #[test]
    fn rfc8032_ed25519ph_vector() {
        let seed = hex(ED25519PH_VECTOR.seed);
        let message = hex::decode(ED25519PH_VECTOR.message).expect("hex");
        assert_eq!(message, b"abc");
        let expected_signature = hex64(ED25519PH_VECTOR.signature);

        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&seed);
        assert_eq!(public_key, hex(ED25519PH_VECTOR.public_key));

        for split in 0..=message.len() {
            let mut signer = crypto_sign_ed25519ph_init();
            crypto_sign_ed25519ph_update(&mut signer, &message[..split]);
            crypto_sign_ed25519ph_update(&mut signer, &message[split..]);
            let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
            crypto_sign_ed25519ph_final_create(signer, &mut signature, &secret_key).unwrap();
            assert_eq!(signature, expected_signature, "split {split}");

            let mut verifier = crypto_sign_ed25519ph_init();
            crypto_sign_ed25519ph_update(&mut verifier, &message[..message.len() - split]);
            crypto_sign_ed25519ph_update(&mut verifier, &message[message.len() - split..]);
            crypto_sign_ed25519ph_final_verify(verifier, &expected_signature, &public_key)
                .unwrap_or_else(|e| panic!("split {split}: {e}"));
        }

        assert!(matches!(
            crypto_sign_ed25519_verify_detached(&expected_signature, &message, &public_key),
            Err(Error::AuthenticationFailed)
        ));
        let mut plain_signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519_detached(&mut plain_signature, &message, &secret_key).unwrap();
        assert_ne!(plain_signature, expected_signature);
        let mut verifier = crypto_sign_ed25519ph_init();
        crypto_sign_ed25519ph_update(&mut verifier, &message);
        assert!(matches!(
            crypto_sign_ed25519ph_final_verify(verifier, &plain_signature, &public_key),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn verification_rejects_scalar_at_or_above_group_order() {
        let message = b"scalar boundary";
        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&[11u8; 32]);
        let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519(&mut signed_message, message, &secret_key).unwrap();

        for s in rejected_scalars() {
            let mut signature: Signature = signed_message[..CRYPTO_SIGN_ED25519_BYTES]
                .try_into()
                .unwrap();
            signature[32..].copy_from_slice(&s);
            assert!(
                matches!(
                    crypto_sign_ed25519_verify_detached(&signature, message, &public_key),
                    Err(Error::AuthenticationFailed)
                ),
                "S {s:02x?}"
            );

            let mut tampered = signed_message.clone();
            tampered[32..CRYPTO_SIGN_ED25519_BYTES].copy_from_slice(&s);
            let mut opened = vec![0u8; message.len()];
            assert!(
                matches!(
                    crypto_sign_ed25519_open(&mut opened, &tampered, &public_key),
                    Err(Error::AuthenticationFailed)
                ),
                "S {s:02x?}"
            );
        }
    }

    /// A non-canonical or small-order `R` fails authentication; the same
    /// encodings as `A` are rejected as an invalid key, before any curve
    /// arithmetic.
    #[test]
    fn verification_rejects_noncanonical_and_small_order_points() {
        let message = b"point encoding policy";
        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&[12u8; 32]);
        let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519_detached(&mut signature, message, &secret_key).unwrap();

        for encoding in rejected_point_encodings() {
            let mut bad_r = signature;
            bad_r[..32].copy_from_slice(&encoding);
            assert!(
                matches!(
                    crypto_sign_ed25519_verify_detached(&bad_r, message, &public_key),
                    Err(Error::AuthenticationFailed)
                ),
                "R {encoding:02x?}"
            );
            assert!(
                matches!(
                    crypto_sign_ed25519_verify_detached(&signature, message, &encoding),
                    Err(Error::InvalidKey {
                        context: crate::ErrorContext::Ed25519PublicKey,
                    })
                ),
                "A {encoding:02x?}"
            );
        }
    }

    /// `crypto_sign_open` verifies before it copies: a failed open leaves
    /// the caller's message buffer exactly as it was.
    #[test]
    fn open_failure_leaves_message_buffer_untouched() {
        let message = b"failure atomicity";
        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&[13u8; 32]);
        let (other_public_key, _) = crypto_sign_ed25519_seed_keypair(&[14u8; 32]);
        let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519(&mut signed_message, message, &secret_key).unwrap();

        let mut tampered_r = signed_message.clone();
        tampered_r[0] ^= 1;
        let mut tampered_s = signed_message.clone();
        tampered_s[32] ^= 1;
        let mut tampered_message = signed_message.clone();
        tampered_message[CRYPTO_SIGN_ED25519_BYTES] ^= 1;

        let sentinel = vec![0xa5; message.len()];
        for (signed, key) in [
            (&tampered_r, &public_key),
            (&tampered_s, &public_key),
            (&tampered_message, &public_key),
            (&signed_message, &other_public_key),
        ] {
            let mut opened = sentinel.clone();
            assert!(matches!(
                crypto_sign_ed25519_open(&mut opened, signed, key),
                Err(Error::AuthenticationFailed)
            ));
            assert_eq!(opened, sentinel);
        }

        let mut opened = sentinel.clone();
        crypto_sign_ed25519_open(&mut opened, &signed_message, &public_key).unwrap();
        assert_eq!(opened, message);
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
        use crate::native_test_util::sign_ed25519_seed_keypair;

        for _ in 0..10 {
            let mut seed = [0u8; CRYPTO_SIGN_ED25519_SEEDBYTES];
            copy_randombytes(&mut seed);

            let (pk, sk) = crypto_sign_ed25519_seed_keypair(&seed);

            let (so_pk, so_sk) = sign_ed25519_seed_keypair(&seed);

            assert_eq!(
                general_purpose::STANDARD.encode(pk),
                general_purpose::STANDARD.encode(so_pk)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(sk),
                general_purpose::STANDARD.encode(so_sk)
            );
        }
    }

    #[test]
    fn test_key_conversion() {
        use libsodium_sys::{
            crypto_sign_ed25519_pk_to_curve25519 as so_crypto_sign_ed25519_pk_to_curve25519,
            crypto_sign_ed25519_sk_to_curve25519 as so_crypto_sign_ed25519_sk_to_curve25519,
        };

        crate::native_test_util::init();

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

        crate::native_test_util::init();

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

        crate::native_test_util::init();

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

    fn sodium_verify_detached(
        signature: &Signature,
        message: &[u8],
        public_key: &PublicKey,
    ) -> bool {
        crate::native_test_util::init();
        let result = unsafe {
            libsodium_sys::crypto_sign_verify_detached(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                public_key.as_ptr(),
            )
        };
        assert!(result == 0 || result == -1);
        result == 0
    }

    /// libsodium (1.0.18 and later: `sc25519_is_canonical`,
    /// `ge25519_is_canonical`, `ge25519_has_small_order`) refuses the same
    /// `S` values and the same `R` and `A` encodings.
    #[test]
    fn test_rejected_encodings_match_libsodium() {
        let message = b"encoding policy compatibility";
        let (public_key, secret_key) = crypto_sign_ed25519_seed_keypair(&[15u8; 32]);
        let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        crypto_sign_ed25519_detached(&mut signature, message, &secret_key).unwrap();
        assert!(sodium_verify_detached(&signature, message, &public_key));

        for s in super::vector_tests::rejected_scalars() {
            let mut bad_s = signature;
            bad_s[32..].copy_from_slice(&s);
            assert!(crypto_sign_ed25519_verify_detached(&bad_s, message, &public_key).is_err());
            assert!(
                !sodium_verify_detached(&bad_s, message, &public_key),
                "S {s:02x?}"
            );
        }

        for encoding in super::vector_tests::rejected_point_encodings() {
            let mut bad_r = signature;
            bad_r[..32].copy_from_slice(&encoding);
            assert!(crypto_sign_ed25519_verify_detached(&bad_r, message, &public_key).is_err());
            assert!(
                !sodium_verify_detached(&bad_r, message, &public_key),
                "R {encoding:02x?}"
            );

            assert!(crypto_sign_ed25519_verify_detached(&signature, message, &encoding).is_err());
            assert!(
                !sodium_verify_detached(&signature, message, &encoding),
                "A {encoding:02x?}"
            );
        }
    }

    /// Verification checks `A` for small order but, like libsodium, not for
    /// membership in the prime-order subgroup: a signature made for the
    /// mixed-order key `A + T` (`T` of order 8) verifies whenever the
    /// challenge `k` is a multiple of 8, and a torsion component in `R`
    /// never verifies. Both outcomes agree with libsodium.
    #[test]
    fn test_mixed_order_points_match_libsodium() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
        use curve25519_dalek::edwards::CompressedEdwardsY;

        let seed = [16u8; 32];
        let (public_key, _) = crypto_sign_ed25519_seed_keypair(&seed);
        let mut h: [u8; CRYPTO_HASH_SHA512_BYTES] = Sha512::compute(&seed);
        let a = Scalar::from_bytes_mod_order(clamp_hash(&mut h));
        let a_point = CompressedEdwardsY(public_key).decompress().unwrap();
        let torsion = EIGHT_TORSION[1];
        let mixed_key = (a_point + torsion).compress().to_bytes();
        assert!(!crate::classic::crypto_core::crypto_core_ed25519_is_valid_point(&mixed_key));

        let r = Scalar::from_bytes_mod_order([17u8; 32]);
        let big_r = (ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();
        let challenge = |big_r: &[u8; 32], key: &[u8; 32], message: &[u8]| {
            let mut hasher = Sha512::new();
            hasher.update(big_r);
            hasher.update(key);
            hasher.update(message);
            Scalar::from_bytes_mod_order_wide(&hasher.finalize())
        };
        let (message, k) = (0u32..)
            .map(|i| {
                let message = format!("mixed order {i}").into_bytes();
                let k = challenge(&big_r, &mixed_key, &message);
                (message, k)
            })
            .find(|(_, k)| k.as_bytes()[0] & 7 == 0)
            .unwrap();
        let mut signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice((r + k * a).as_bytes());

        assert!(crypto_sign_ed25519_verify_detached(&signature, &message, &mixed_key).is_ok());
        assert!(sodium_verify_detached(&signature, &message, &mixed_key));

        // A torsion component in R: the challenge commits to the encoding of
        // R + T, but [S]B - [k]A is R.
        let mixed_r = ((ED25519_BASEPOINT_TABLE * &r) + torsion)
            .compress()
            .to_bytes();
        let k = challenge(&mixed_r, &public_key, &message);
        signature[..32].copy_from_slice(&mixed_r);
        signature[32..].copy_from_slice((r + k * a).as_bytes());
        assert!(matches!(
            crypto_sign_ed25519_verify_detached(&signature, &message, &public_key),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!sodium_verify_detached(&signature, &message, &public_key));
    }

    #[test]
    fn test_secret_key_extraction() {
        use libsodium_sys::{
            crypto_sign_ed25519_sk_to_pk as so_crypto_sign_ed25519_sk_to_pk,
            crypto_sign_ed25519_sk_to_seed as so_crypto_sign_ed25519_sk_to_seed,
        };

        crate::native_test_util::init();

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
