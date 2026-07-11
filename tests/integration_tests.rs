use std::vec;

use dryoc::precalc::PrecalcSecretKey;

struct RejectingByteArray<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> dryoc::types::Bytes for RejectingByteArray<LENGTH> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        LENGTH
    }

    fn is_empty(&self) -> bool {
        LENGTH == 0
    }
}

impl<const LENGTH: usize> dryoc::types::ByteArray<LENGTH> for RejectingByteArray<LENGTH> {
    fn as_array(&self) -> &[u8; LENGTH] {
        &self.0
    }
}

impl<const LENGTH: usize> zeroize::Zeroize for RejectingByteArray<LENGTH> {
    fn zeroize(&mut self) {
        self.0.fill(0);
    }
}

impl<'a, const LENGTH: usize> TryFrom<&'a [u8]> for RejectingByteArray<LENGTH> {
    type Error = ();

    fn try_from(_: &'a [u8]) -> Result<Self, Self::Error> {
        Err(())
    }
}

#[test]
fn test_structured_public_errors() {
    use dryoc::classic::crypto_auth_hmacsha256::{
        crypto_auth_hmacsha256, crypto_auth_hmacsha256_keygen, crypto_auth_hmacsha256_verify,
    };
    use dryoc::constants::{
        CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_BOX_MACBYTES, CRYPTO_BOX_PUBLICKEYBYTES,
        CRYPTO_BOX_SEALBYTES, CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_SECRETBOX_MACBYTES,
    };
    use dryoc::types::StackByteArray;
    use dryoc::{Error, LengthConstraint};

    let slice_error =
        StackByteArray::<4>::try_from(&[1, 2][..]).expect_err("short slices should be rejected");
    assert_eq!(
        slice_error.to_string(),
        "invalid slice length: expected exactly 4, got 2"
    );
    assert!(matches!(
        slice_error,
        Error::InvalidLength {
            context: dryoc::ErrorContext::Slice,
            actual: 2,
            constraint: LengthConstraint::Exact(4),
        }
    ));

    let key = crypto_auth_hmacsha256_keygen();
    let mut mac = [0u8; CRYPTO_AUTH_HMACSHA256_BYTES];
    crypto_auth_hmacsha256(&mut mac, b"message", &key);
    let authentication_error = crypto_auth_hmacsha256_verify(&mac, b"tampered", &key)
        .expect_err("tampered messages should fail authentication");
    assert_eq!(authentication_error.to_string(), "authentication failed");
    assert!(matches!(authentication_error, Error::AuthenticationFailed));

    let tag_error = dryoc::dryocstream::Tag::try_from(0x80)
        .expect_err("unknown secretstream tag bits should be rejected");
    assert_eq!(
        tag_error.to_string(),
        "invalid tag value: expected a value containing only bits from mask 0x3, got 128"
    );
    assert!(matches!(
        tag_error,
        Error::InvalidValue {
            context: dryoc::ErrorContext::Tag,
            actual: 0x80,
            constraint: dryoc::ValueConstraint::AllowedBits { .. },
        }
    ));

    type RejectingAeadBox = dryoc::dryocaead::AeadBox<
        dryoc::dryocaead::XChaCha20Poly1305Ietf,
        RejectingByteArray<16>,
        Vec<u8>,
    >;
    let conversion_error = match RejectingAeadBox::from_bytes(&[0u8; 16]) {
        Ok(_) => panic!("a target type may reject a correctly sized tag"),
        Err(error) => error,
    };
    assert_eq!(
        conversion_error.to_string(),
        "invalid authentication tag encoding"
    );
    assert!(matches!(
        conversion_error,
        Error::InvalidEncoding {
            context: dryoc::ErrorContext::AuthenticationTag,
        }
    ));

    type RejectingKeyPair = dryoc::keypair::KeyPair<
        RejectingByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        RejectingByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >;
    let conversion_error = match RejectingKeyPair::from_slices(
        &[0u8; CRYPTO_BOX_PUBLICKEYBYTES],
        &[0u8; CRYPTO_BOX_SECRETKEYBYTES],
    ) {
        Ok(_) => panic!("a target type may reject a correctly sized key"),
        Err(error) => error,
    };
    assert_eq!(conversion_error.to_string(), "invalid public key");
    assert!(matches!(
        conversion_error,
        Error::InvalidKey {
            context: dryoc::ErrorContext::PublicKey,
        }
    ));

    let box_public_key_error = dryoc::keypair::StackKeyPair::from_slices(
        &[0u8; CRYPTO_BOX_PUBLICKEYBYTES - 1],
        &[0u8; CRYPTO_BOX_SECRETKEYBYTES],
    )
    .expect_err("a short box public key should fail");
    assert!(matches!(
        box_public_key_error,
        Error::InvalidLength {
            context: dryoc::ErrorContext::PublicKey,
            actual,
            constraint: LengthConstraint::Exact(CRYPTO_BOX_PUBLICKEYBYTES),
        } if actual == CRYPTO_BOX_PUBLICKEYBYTES - 1
    ));

    let box_secret_key_error = dryoc::keypair::StackKeyPair::from_slices(
        &[0u8; CRYPTO_BOX_PUBLICKEYBYTES],
        &[0u8; CRYPTO_BOX_SECRETKEYBYTES - 1],
    )
    .expect_err("a short box secret key should fail");
    assert!(matches!(
        box_secret_key_error,
        Error::InvalidLength {
            context: dryoc::ErrorContext::SecretKey,
            actual,
            constraint: LengthConstraint::Exact(CRYPTO_BOX_SECRETKEYBYTES),
        } if actual == CRYPTO_BOX_SECRETKEYBYTES - 1
    ));

    type StackSigningKeyPair =
        dryoc::sign::SigningKeyPair<dryoc::sign::PublicKey, dryoc::sign::SecretKey>;
    let signing_public_key_error = StackSigningKeyPair::from_slices(
        &[0u8; dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES - 1],
        &[0u8; dryoc::constants::CRYPTO_SIGN_SECRETKEYBYTES],
    )
    .expect_err("a short signing public key should fail");
    assert!(matches!(
        signing_public_key_error,
        Error::InvalidLength {
            context: dryoc::ErrorContext::PublicKey,
            actual,
            constraint: LengthConstraint::Exact(dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES),
        } if actual == dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES - 1
    ));

    let signing_secret_key_error = StackSigningKeyPair::from_slices(
        &[0u8; dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES],
        &[0u8; dryoc::constants::CRYPTO_SIGN_SECRETKEYBYTES - 1],
    )
    .expect_err("a short signing secret key should fail");
    assert!(matches!(
        signing_secret_key_error,
        Error::InvalidLength {
            context: dryoc::ErrorContext::SecretKey,
            actual,
            constraint: LengthConstraint::Exact(dryoc::constants::CRYPTO_SIGN_SECRETKEYBYTES),
        } if actual == dryoc::constants::CRYPTO_SIGN_SECRETKEYBYTES - 1
    ));

    assert!(matches!(
        dryoc::dryocbox::VecBox::from_bytes(&[]),
        Err(Error::InvalidLength {
            context: dryoc::ErrorContext::Box,
            actual: 0,
            constraint: LengthConstraint::AtLeast(CRYPTO_BOX_MACBYTES),
        })
    ));
    assert!(matches!(
        dryoc::dryocbox::VecBox::from_sealed_bytes(&[]),
        Err(Error::InvalidLength {
            context: dryoc::ErrorContext::SealedBox,
            actual: 0,
            constraint: LengthConstraint::AtLeast(CRYPTO_BOX_SEALBYTES),
        })
    ));
    assert!(matches!(
        dryoc::dryocsecretbox::VecBox::from_bytes(&[]),
        Err(Error::InvalidLength {
            context: dryoc::ErrorContext::SecretBox,
            actual: 0,
            constraint: LengthConstraint::AtLeast(CRYPTO_SECRETBOX_MACBYTES),
        })
    ));
}

#[test]
fn test_sha3_public_api() {
    use dryoc::classic::crypto_hash::{
        Sha3256Digest, Sha3512Digest, crypto_hash_sha3256, crypto_hash_sha3256_final,
        crypto_hash_sha3256_init, crypto_hash_sha3256_update, crypto_hash_sha3512,
        crypto_hash_sha3512_final, crypto_hash_sha3512_init, crypto_hash_sha3512_update,
    };
    use dryoc::sha3::{
        Sha3256, Sha3256Digest as RustSha3256Digest, Sha3512, Sha3512Digest as RustSha3512Digest,
    };
    use dryoc::types::Bytes;

    let message = b"public API message";

    let mut classic_one_shot256 = Sha3256Digest::default();
    crypto_hash_sha3256(&mut classic_one_shot256, message);
    let mut classic_state256 = crypto_hash_sha3256_init();
    crypto_hash_sha3256_update(&mut classic_state256, b"public API ");
    crypto_hash_sha3256_update(&mut classic_state256, b"message");
    let mut classic_streaming256 = Sha3256Digest::default();
    crypto_hash_sha3256_final(classic_state256, &mut classic_streaming256);
    assert_eq!(classic_one_shot256, classic_streaming256);

    let rust_one_shot256: RustSha3256Digest = Sha3256::compute(message);
    let mut rust_state256 = Sha3256::new();
    rust_state256.update(b"public API ");
    rust_state256.update(b"message");
    let rust_streaming256: RustSha3256Digest = rust_state256.finalize();
    assert_eq!(rust_one_shot256, rust_streaming256);
    assert_eq!(classic_one_shot256.as_slice(), rust_one_shot256.as_slice());

    let mut classic_one_shot512: Sha3512Digest = [0u8; 64];
    crypto_hash_sha3512(&mut classic_one_shot512, message);
    let mut classic_state512 = crypto_hash_sha3512_init();
    crypto_hash_sha3512_update(&mut classic_state512, b"public API ");
    crypto_hash_sha3512_update(&mut classic_state512, b"message");
    let mut classic_streaming512: Sha3512Digest = [0u8; 64];
    crypto_hash_sha3512_final(classic_state512, &mut classic_streaming512);
    assert_eq!(classic_one_shot512, classic_streaming512);

    let rust_one_shot512: RustSha3512Digest = Sha3512::compute(message);
    let mut rust_state512 = Sha3512::new();
    rust_state512.update(b"public API ");
    rust_state512.update(b"message");
    let rust_streaming512: RustSha3512Digest = rust_state512.finalize();
    assert_eq!(rust_one_shot512, rust_streaming512);
    assert_eq!(classic_one_shot512.as_slice(), rust_one_shot512.as_slice());
}

#[test]
fn test_classic_hmac_and_hkdf_public_api() {
    use dryoc::classic::crypto_auth_hmacsha256::{
        Mac as HmacSha256Mac, crypto_auth_hmacsha256, crypto_auth_hmacsha256_final,
        crypto_auth_hmacsha256_init, crypto_auth_hmacsha256_keygen, crypto_auth_hmacsha256_update,
        crypto_auth_hmacsha256_verify,
    };
    use dryoc::classic::crypto_auth_hmacsha512::{
        crypto_auth_hmacsha512, crypto_auth_hmacsha512_final, crypto_auth_hmacsha512_init,
        crypto_auth_hmacsha512_keygen, crypto_auth_hmacsha512_update,
        crypto_auth_hmacsha512_verify,
    };
    use dryoc::classic::crypto_auth_hmacsha512256::{
        Mac as HmacSha512256Mac, crypto_auth_hmacsha512256, crypto_auth_hmacsha512256_final,
        crypto_auth_hmacsha512256_init, crypto_auth_hmacsha512256_keygen,
        crypto_auth_hmacsha512256_update, crypto_auth_hmacsha512256_verify,
    };
    use dryoc::classic::crypto_kdf::{
        HkdfSha256Key, crypto_kdf_hkdf_sha256_expand, crypto_kdf_hkdf_sha256_extract,
        crypto_kdf_hkdf_sha512_expand, crypto_kdf_hkdf_sha512_extract,
    };
    use dryoc::constants::{CRYPTO_AUTH_HMACSHA512_BYTES, CRYPTO_KDF_HKDF_SHA512_KEYBYTES};

    let message = b"public API message";

    let key256 = crypto_auth_hmacsha256_keygen();
    let mut one_shot256 = HmacSha256Mac::default();
    crypto_auth_hmacsha256(&mut one_shot256, message, &key256);
    let mut state256 = crypto_auth_hmacsha256_init(&key256);
    crypto_auth_hmacsha256_update(&mut state256, b"public API ");
    crypto_auth_hmacsha256_update(&mut state256, b"message");
    let mut streaming256 = HmacSha256Mac::default();
    crypto_auth_hmacsha256_final(state256, &mut streaming256);
    assert_eq!(one_shot256, streaming256);
    crypto_auth_hmacsha256_verify(&one_shot256, message, &key256).expect("verify failed");
    crypto_auth_hmacsha256_verify(&one_shot256, b"invalid", &key256)
        .expect_err("verify should fail");

    let key512 = crypto_auth_hmacsha512_keygen();
    let mut one_shot512 = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
    crypto_auth_hmacsha512(&mut one_shot512, message, &key512);
    let mut state512 = crypto_auth_hmacsha512_init(&key512);
    crypto_auth_hmacsha512_update(&mut state512, b"public API ");
    crypto_auth_hmacsha512_update(&mut state512, b"message");
    let mut streaming512 = [0u8; CRYPTO_AUTH_HMACSHA512_BYTES];
    crypto_auth_hmacsha512_final(state512, &mut streaming512);
    assert_eq!(one_shot512, streaming512);
    crypto_auth_hmacsha512_verify(&one_shot512, message, &key512).expect("verify failed");
    crypto_auth_hmacsha512_verify(&one_shot512, b"invalid", &key512)
        .expect_err("verify should fail");

    let key512256 = crypto_auth_hmacsha512256_keygen();
    let mut one_shot512256 = HmacSha512256Mac::default();
    crypto_auth_hmacsha512256(&mut one_shot512256, message, &key512256);
    let mut state512256 = crypto_auth_hmacsha512256_init(&key512256);
    crypto_auth_hmacsha512256_update(&mut state512256, b"public API ");
    crypto_auth_hmacsha512256_update(&mut state512256, b"message");
    let mut streaming512256 = HmacSha512256Mac::default();
    crypto_auth_hmacsha512256_final(state512256, &mut streaming512256);
    assert_eq!(one_shot512256, streaming512256);
    crypto_auth_hmacsha512256_verify(&one_shot512256, message, &key512256).expect("verify failed");
    crypto_auth_hmacsha512256_verify(&one_shot512256, b"invalid", &key512256)
        .expect_err("verify should fail");

    let mut prk256 = HkdfSha256Key::default();
    crypto_kdf_hkdf_sha256_extract(&mut prk256, Some(b"salt"), b"input keying material");
    let mut okm256 = [0u8; 48];
    crypto_kdf_hkdf_sha256_expand(&mut okm256, b"context", &prk256).expect("expand failed");

    let mut prk512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
    crypto_kdf_hkdf_sha512_extract(&mut prk512, Some(b"salt"), b"input keying material");
    let mut okm512 = [0u8; 96];
    crypto_kdf_hkdf_sha512_expand(&mut okm512, b"context", &prk512).expect("expand failed");
}

#[test]
fn test_rustaceous_hmac_and_hkdf_public_api() {
    use dryoc::hkdf::{HkdfSha256, HkdfSha256Prk, HkdfSha512};
    use dryoc::hmac::{
        HmacSha256, HmacSha256Key, HmacSha256Mac, HmacSha512, HmacSha512Key, HmacSha512256,
        HmacSha512256Key,
    };
    use dryoc::types::*;

    let message = b"public API message";

    let key256 = HmacSha256Key::generate();
    let mac256: HmacSha256Mac = HmacSha256::compute(key256.clone(), message);
    HmacSha256::compute_and_verify(&mac256, key256, message).expect("verify failed");

    let key512 = HmacSha512Key::generate();
    let mut auth512 = HmacSha512::new(key512.clone());
    auth512.update(b"public API ");
    auth512.update(b"message");
    let mac512 = auth512.finalize_to_vec();
    let mut verify512 = HmacSha512::new(key512);
    verify512.update(b"public API ");
    verify512.update(b"message");
    verify512.verify(&mac512).expect("verify failed");

    let key512256 = HmacSha512256Key::generate();
    let mac512256 = HmacSha512256::compute_to_vec(key512256.clone(), message);
    HmacSha512256::compute_and_verify(&mac512256, key512256, b"invalid")
        .expect_err("verify should fail");

    let hkdf256 = HkdfSha256::extract(Some(b"salt"), b"input keying material");
    let okm256: HkdfSha256Prk = hkdf256.expand(b"context").expect("expand failed");
    assert_eq!(okm256.len(), 32);
    let okm256 = hkdf256
        .expand_to_vec(42, b"context")
        .expect("expand failed");
    assert_eq!(okm256.len(), 42);

    let okm512 = HkdfSha512::extract_and_expand_to_vec(
        96,
        Some(b"salt"),
        b"input keying material",
        b"context",
    )
    .expect("expand failed");
    assert_eq!(okm512.len(), 96);
}

#[test]
fn test_signing_key_extraction_public_api() {
    use dryoc::classic::crypto_sign::{
        crypto_sign_ed25519_sk_to_pk, crypto_sign_ed25519_sk_to_seed, crypto_sign_seed_keypair,
    };
    use dryoc::sign::{
        PublicKey, SecretKey, Seed, SigningKeyPair, secret_key_to_public_key, secret_key_to_seed,
    };
    use dryoc::types::*;

    let seed = [7u8; dryoc::constants::CRYPTO_SIGN_SEEDBYTES];
    let (classic_public_key, classic_secret_key) = crypto_sign_seed_keypair(&seed);
    let mut classic_extracted_seed = [0u8; dryoc::constants::CRYPTO_SIGN_SEEDBYTES];
    let mut classic_extracted_public_key = [0u8; dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_seed(&mut classic_extracted_seed, &classic_secret_key);
    crypto_sign_ed25519_sk_to_pk(&mut classic_extracted_public_key, &classic_secret_key);
    assert_eq!(classic_extracted_seed, seed);
    assert_eq!(classic_extracted_public_key, classic_public_key);

    let signing_keypair = SigningKeyPair::<PublicKey, SecretKey>::from_seed(&seed);
    let rustaceous_seed: Seed = signing_keypair.to_seed();
    let rustaceous_public_key: PublicKey = signing_keypair.to_public_key();
    assert_eq!(rustaceous_seed.as_slice(), seed);
    assert_eq!(
        rustaceous_public_key.as_slice(),
        signing_keypair.public_key.as_slice()
    );

    let rustaceous_seed_vec: Vec<u8> = secret_key_to_seed(&signing_keypair.secret_key);
    let rustaceous_public_key_vec: Vec<u8> = secret_key_to_public_key(&signing_keypair.secret_key);
    assert_eq!(rustaceous_seed_vec.as_slice(), seed.as_slice());
    assert_eq!(
        rustaceous_public_key_vec.as_slice(),
        signing_keypair.public_key.as_slice()
    );
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_rustaceous_hmac_and_hkdf_protected() {
    use dryoc::hkdf::HkdfSha512Expander;
    use dryoc::hkdf::protected::{
        HeapBytes as HkdfHeapBytes, HkdfSha512Prk, Locked as HkdfLocked, LockedHkdfSha512,
    };
    use dryoc::hmac::HmacSha256;
    use dryoc::hmac::protected::{
        HeapBytes as HmacHeapBytes, HmacSha256Key, HmacSha256Mac, Locked as HmacLocked,
    };
    use dryoc::protected::{NewLocked, NewLockedFromSlice};

    let key_bytes = [7u8; 32];
    let key = HmacSha256Key::from_slice_into_readonly_locked(&key_bytes).expect("key failed");
    let verify_key =
        HmacSha256Key::from_slice_into_readonly_locked(&key_bytes).expect("key failed");
    let input =
        HmacHeapBytes::from_slice_into_readonly_locked(b"protected message").expect("input failed");
    let mac: HmacLocked<HmacSha256Mac> = HmacSha256::compute(key, &input);
    HmacSha256::compute_and_verify(&mac, verify_key, &input).expect("verify failed");

    let ikm = HkdfHeapBytes::from_slice_into_readonly_locked(b"input keying material")
        .expect("ikm failed");
    let hkdf: LockedHkdfSha512 =
        HkdfSha512Expander::<HkdfLocked<HkdfSha512Prk>>::extract(None::<&[u8]>, &ikm);
    let output: HkdfLocked<HkdfHeapBytes> =
        hkdf.expand_to_bytes(64, b"context").expect("expand failed");
    assert_eq!(output.len(), 64);

    let prk = HkdfSha512Prk::generate_readonly_locked().expect("prk failed");
    let hkdf = HkdfSha512Expander::from_prk(prk);
    let output: HkdfLocked<HkdfHeapBytes> =
        hkdf.expand_to_bytes(32, b"context").expect("expand failed");
    assert_eq!(output.len(), 32);
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_protected_generation_compatibility_api() {
    use dryoc::dryocbox::protected::{
        LockedKeyPair, LockedROKeyPair, Nonce as BoxNonce, PublicKey as BoxPublicKey,
        SecretKey as BoxSecretKey,
    };
    use dryoc::dryocstream::protected::Key as StreamKey;
    use dryoc::keypair::KeyPair;
    use dryoc::protected::{LockedRO, NewLocked};
    use dryoc::sign::SigningKeyPair;
    use dryoc::sign::protected::{
        LockedSigningKeyPair, PublicKey as SignPublicKey, SecretKey as SignSecretKey,
    };
    use dryoc::types::Bytes;

    let key = StreamKey::generate_locked().expect("key failed");
    assert_eq!(
        key.len(),
        dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES
    );
    let nonce = BoxNonce::generate_readonly_locked().expect("nonce failed");
    assert_eq!(nonce.len(), dryoc::constants::CRYPTO_BOX_NONCEBYTES);

    let locked_box_keypair = LockedKeyPair::generate_locked_keypair().expect("box keypair");
    assert_eq!(
        locked_box_keypair.public_key.len(),
        dryoc::constants::CRYPTO_BOX_PUBLICKEYBYTES
    );
    let readonly_box_keypair =
        LockedROKeyPair::generate_readonly_locked_keypair().expect("readonly box keypair");
    assert_eq!(
        readonly_box_keypair.secret_key.len(),
        dryoc::constants::CRYPTO_BOX_SECRETKEYBYTES
    );

    let locked_signing_keypair =
        LockedSigningKeyPair::generate_locked_keypair().expect("signing keypair");
    assert_eq!(
        locked_signing_keypair.public_key.len(),
        dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES
    );
    let readonly_signing_keypair: SigningKeyPair<LockedRO<SignPublicKey>, LockedRO<SignSecretKey>> =
        SigningKeyPair::generate_readonly_locked_keypair().expect("readonly signing keypair");
    assert_eq!(
        readonly_signing_keypair.secret_key.len(),
        dryoc::constants::CRYPTO_SIGN_SECRETKEYBYTES
    );

    #[allow(deprecated)]
    {
        let legacy_key = StreamKey::gen_locked().expect("legacy key failed");
        assert_eq!(
            legacy_key.len(),
            dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES
        );
        let legacy_nonce = BoxNonce::gen_readonly_locked().expect("legacy nonce failed");
        assert_eq!(legacy_nonce.len(), dryoc::constants::CRYPTO_BOX_NONCEBYTES);

        let legacy_box_keypair = LockedKeyPair::gen_locked_keypair().expect("legacy box keypair");
        assert_eq!(
            legacy_box_keypair.secret_key.len(),
            dryoc::constants::CRYPTO_BOX_SECRETKEYBYTES
        );
        let legacy_readonly_box_keypair: KeyPair<LockedRO<BoxPublicKey>, LockedRO<BoxSecretKey>> =
            KeyPair::gen_readonly_locked_keypair().expect("legacy readonly box keypair");
        assert_eq!(
            legacy_readonly_box_keypair.public_key.len(),
            dryoc::constants::CRYPTO_BOX_PUBLICKEYBYTES
        );

        let legacy_signing_keypair =
            LockedSigningKeyPair::gen_locked_keypair().expect("legacy signing keypair");
        assert_eq!(
            legacy_signing_keypair.secret_key.len(),
            dryoc::constants::CRYPTO_SIGN_SECRETKEYBYTES
        );
        let legacy_readonly_signing_keypair: SigningKeyPair<
            LockedRO<SignPublicKey>,
            LockedRO<SignSecretKey>,
        > = SigningKeyPair::gen_readonly_locked_keypair().expect("legacy readonly signing keypair");
        assert_eq!(
            legacy_readonly_signing_keypair.public_key.len(),
            dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES
        );
    }
}

#[cfg(all(feature = "serde", feature = "protected", any(unix, windows)))]
#[test]
fn test_protected_serde_sequence_deserialization() {
    use dryoc::protected::{HeapByteArray, Locked, LockedBytes};
    use dryoc::types::Bytes;

    let bytes: LockedBytes = serde_json::from_str("[1,2,3]").expect("bytes failed");
    assert_eq!(bytes.as_slice(), &[1, 2, 3]);

    let array: Locked<HeapByteArray<3>> = serde_json::from_str("[4,5,6]").expect("array failed");
    assert_eq!(array.as_slice(), &[4, 5, 6]);
}

#[test]
fn test_dryocbox() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"hey";

    let dryocbox = DryocBox::encrypt_to_vecbox(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let decrypted = dryocbox
        .decrypt_to_vec(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());

    let shared_key =
        PrecalcSecretKey::precalculate(&recipient_keypair.public_key, &sender_keypair.secret_key)
            .expect("precalculation failed");

    let dryocbox = DryocBox::precalc_encrypt_to_vecbox(message, &nonce, &shared_key)
        .expect("unable to encrypt");

    let decrypted = dryocbox
        .decrypt_to_vec(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_dryocsecretbox() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey";

    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_dryocaead() {
    use dryoc::dryocaead::*;

    let key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey with metadata";
    let aad = b"metadata";

    let dryocaead =
        VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("unable to encrypt");

    let decrypted = dryocaead
        .decrypt_to_vec(Some(aad), &nonce, &key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());

    let envelope = VecEnvelope::seal_to_vec(message, Some(aad), &key).expect("unable to seal");
    let decrypted = envelope
        .open_to_vec(Some(aad), &key)
        .expect("unable to open");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocbox_serde_json() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"hey friend";

    let dryocbox: VecBox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let json = serde_json::to_string(&dryocbox).expect("doesn't serialize");

    let dryocbox: VecBox = serde_json::from_str(&json).unwrap();

    let decrypted: Vec<u8> = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocsecretbox_serde_json() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey buddy bro";

    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let json = serde_json::to_string(&dryocsecretbox).expect("doesn't serialize");

    let dryocsecretbox: VecBox = serde_json::from_str(&json).unwrap();

    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocaead_serde_json() {
    use dryoc::dryocaead::*;

    let key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey authenticated friend";
    let aad = b"metadata";

    let dryocaead =
        VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("unable to encrypt");
    let json = serde_json::to_string(&dryocaead).expect("doesn't serialize");
    let dryocaead: VecBox = serde_json::from_str(&json).unwrap();
    let decrypted = dryocaead
        .decrypt_to_vec(Some(aad), &nonce, &key)
        .expect("decrypt failed");
    assert_eq!(message, decrypted.as_slice());

    let envelope = VecEnvelope::seal_to_vec(message, Some(aad), &key).expect("unable to seal");
    let json = serde_json::to_string(&envelope).expect("doesn't serialize");
    let envelope: VecEnvelope = serde_json::from_str(&json).unwrap();
    let decrypted = envelope.open_to_vec(Some(aad), &key).expect("open failed");
    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_dryocbox_wincode_bytes() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"hey friend";

    let dryocbox: VecBox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let encoded = wincode::serialize(&dryocbox.to_vec()).expect("doesn't serialize");

    let bytes: Vec<u8> = wincode::deserialize(&encoded).unwrap();
    let dryocbox = VecBox::from_bytes(&bytes).expect("doesn't deserialize");

    let decrypted: Vec<u8> = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_dryocaead_wincode_bytes() {
    use dryoc::dryocaead::*;

    let key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey authenticated friend";
    let aad = b"metadata";

    let dryocaead =
        VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("unable to encrypt");
    let encoded = wincode::serialize(&dryocaead.to_vec()).expect("doesn't serialize");
    let bytes: Vec<u8> = wincode::deserialize(&encoded).unwrap();
    let dryocaead = VecBox::from_bytes(&bytes).expect("doesn't deserialize");
    let decrypted = dryocaead
        .decrypt_to_vec(Some(aad), &nonce, &key)
        .expect("decrypt failed");
    assert_eq!(message, decrypted.as_slice());

    let envelope = VecEnvelope::seal_to_vec(message, Some(aad), &key).expect("unable to seal");
    let encoded = wincode::serialize(&envelope.to_vec()).expect("doesn't serialize");
    let bytes: Vec<u8> = wincode::deserialize(&encoded).unwrap();
    let envelope = VecEnvelope::from_bytes(&bytes).expect("doesn't deserialize");
    let decrypted = envelope.open_to_vec(Some(aad), &key).expect("open failed");
    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "wincode")]
#[test]
fn test_dryocbox_wincode() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"hey friend";

    let dryocbox: VecBox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let encoded = wincode::serialize(&dryocbox).expect("doesn't serialize");
    let dryocbox: VecBox = wincode::deserialize(&encoded).expect("doesn't deserialize");

    let decrypted: Vec<u8> = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "wincode")]
#[test]
fn test_dryocaead_wincode() {
    use dryoc::dryocaead::*;

    let key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey authenticated friend";
    let aad = b"metadata";

    let dryocaead =
        VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("unable to encrypt");
    let encoded = wincode::serialize(&dryocaead).expect("doesn't serialize");
    let dryocaead: VecBox = wincode::deserialize(&encoded).expect("doesn't deserialize");
    let decrypted = dryocaead
        .decrypt_to_vec(Some(aad), &nonce, &key)
        .expect("decrypt failed");
    assert_eq!(message, decrypted.as_slice());

    let envelope = VecEnvelope::seal_to_vec(message, Some(aad), &key).expect("unable to seal");
    let encoded = wincode::serialize(&envelope).expect("doesn't serialize");
    let envelope: VecEnvelope = wincode::deserialize(&encoded).expect("doesn't deserialize");
    let decrypted = envelope.open_to_vec(Some(aad), &key).expect("open failed");
    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "wincode")]
#[test]
fn test_dryocbox_sealed_wincode() {
    use dryoc::dryocbox::*;

    let recipient_keypair = KeyPair::generate();
    let message = b"hey sealed friend";

    let dryocbox: VecBox =
        DryocBox::seal(message, &recipient_keypair.public_key).expect("unable to seal");

    let encoded = wincode::serialize(&dryocbox).expect("doesn't serialize");
    let dryocbox: VecBox = wincode::deserialize(&encoded).expect("doesn't deserialize");

    let decrypted: Vec<u8> = dryocbox
        .unseal(&recipient_keypair)
        .expect("unable to unseal");

    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_dryocsecretbox_wincode_bytes() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey buddy bro";

    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let encoded = wincode::serialize(&dryocsecretbox.to_vec()).expect("doesn't serialize");

    let bytes: Vec<u8> = wincode::deserialize(&encoded).unwrap();
    let dryocsecretbox = VecBox::from_bytes(&bytes).expect("doesn't deserialize");

    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "wincode")]
#[test]
fn test_dryocsecretbox_wincode() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::generate();
    let nonce = Nonce::generate();
    let message = b"hey buddy bro";

    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let encoded = wincode::serialize(&dryocsecretbox).expect("doesn't serialize");
    let dryocsecretbox: VecBox = wincode::deserialize(&encoded).expect("doesn't deserialize");

    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_dryocsecretbox_protected_wincode_bytes() {
    use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;
    use dryoc::dryocsecretbox::protected::*;
    use dryoc::dryocsecretbox::*;

    let secret_key = protected::Key::generate_locked()
        .and_then(|s| s.mprotect_readonly())
        .expect("key failed");

    let nonce = protected::Nonce::generate_readonly_locked().expect("nonce failed");

    let message =
        HeapBytes::from_slice_into_readonly_locked(b"Secret message from the tooth fairy")
            .expect("message failed");

    let dryocsecretbox: protected::LockedBox =
        DryocSecretBox::encrypt(&message, &nonce, &secret_key);

    let bytes: Vec<u8> = dryocsecretbox.to_bytes();
    let encoded = wincode::serialize(&bytes).expect("doesn't serialize");

    let bytes: Vec<u8> = wincode::deserialize(&encoded).unwrap();
    let (tag, data) = bytes.split_at(CRYPTO_SECRETBOX_MACBYTES);
    let tag = protected::Mac::from_slice_into_locked(tag).expect("doesn't deserialize tag");
    let data = HeapBytes::from_slice_into_locked(data).expect("doesn't deserialize data");
    let dryocsecretbox: protected::LockedBox = protected::LockedBox::from_parts(tag, data);

    let decrypted: LockedBytes = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("decrypt failed");

    assert_eq!(message.as_slice(), decrypted.as_slice());
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_dryocaead_protected() {
    use dryoc::dryocaead::protected::*;

    let key = Key::generate_readonly_locked().expect("key failed");
    let nonce = Nonce::generate_readonly_locked().expect("nonce failed");
    let message =
        HeapBytes::from_slice_into_readonly_locked(b"protected aead message").expect("message");
    let aad = HeapBytes::from_slice_into_readonly_locked(b"metadata").expect("aad");

    let dryocaead: LockedBox =
        LockedBox::encrypt(&message, Some(aad.as_slice()), &nonce, &key).expect("encrypt failed");
    let decrypted: LockedBytes = dryocaead
        .decrypt(Some(aad.as_slice()), &nonce, &key)
        .expect("decrypt failed");
    assert_eq!(message.as_slice(), decrypted.as_slice());

    let envelope: LockedEnvelope =
        LockedEnvelope::seal(&message, Some(aad.as_slice()), &key).expect("seal failed");
    let decrypted: LockedBytes = envelope
        .open(Some(aad.as_slice()), &key)
        .expect("open failed");
    assert_eq!(message.as_slice(), decrypted.as_slice());
}

#[test]
fn test_streams() {
    use dryoc::classic::crypto_secretstream_xchacha20poly1305::*;
    use dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
    use dryoc::dryocstream::Tag;
    let message1 = b"Arbitrary data to encrypt";
    let message2 = b"split into";
    let message3 = b"three messages";

    // Generate a key
    let mut key = Key::default();
    crypto_secretstream_xchacha20poly1305_keygen(&mut key);

    // Create stream push state
    let mut state = State::new();
    let mut header = Header::default();
    crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &key);

    let (mut c1, mut c2, mut c3) = (
        vec![0u8; message1.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
        vec![0u8; message2.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
        vec![0u8; message3.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
    );
    // Encrypt a series of messages
    crypto_secretstream_xchacha20poly1305_push(
        &mut state,
        &mut c1,
        message1,
        None,
        Tag::MESSAGE.bits(),
    )
    .expect("Encrypt failed");
    // Encrypt a series of messages
    crypto_secretstream_xchacha20poly1305_push(
        &mut state,
        &mut c2,
        message2,
        None,
        Tag::MESSAGE.bits(),
    )
    .expect("Encrypt failed");
    // Encrypt a series of messages
    crypto_secretstream_xchacha20poly1305_push(
        &mut state,
        &mut c3,
        message3,
        None,
        Tag::FINAL.bits(),
    )
    .expect("Encrypt failed");

    // Create stream pull state, using the same key as above with a new state.
    let mut state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);

    let (mut m1, mut m2, mut m3) = (
        vec![0u8; message1.len()],
        vec![0u8; message2.len()],
        vec![0u8; message3.len()],
    );
    let (mut tag1, mut tag2, mut tag3) = (0u8, 0u8, 0u8);

    // Decrypt the stream of messages
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut m1, &mut tag1, &c1, None)
        .expect("Decrypt failed");
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut m2, &mut tag2, &c2, None)
        .expect("Decrypt failed");
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut m3, &mut tag3, &c3, None)
        .expect("Decrypt failed");

    assert_eq!(message1, m1.as_slice());
    assert_eq!(message2, m2.as_slice());
    assert_eq!(message3, m3.as_slice());

    assert_eq!(tag1, Tag::MESSAGE.bits());
    assert_eq!(tag2, Tag::MESSAGE.bits());
    assert_eq!(tag3, Tag::FINAL.bits());
}

#[test]
fn test_streams_rustaceous() {
    use dryoc::dryocstream::*;
    let message1 = b"Arbitrary data to encrypt";
    let message2 = b"split into";
    let message3 = b"three messages";

    let key = Key::generate();

    let (mut push_stream, header): (_, Header) = DryocStream::init_push(&key);
    let c1: Vec<u8> = push_stream
        .push(message1, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c2: Vec<u8> = push_stream
        .push(message2, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c3: Vec<u8> = push_stream
        .push(message3, None, Tag::FINAL)
        .expect("Encrypt failed");

    let mut pull_stream = DryocStream::init_pull(&key, &header);

    let (m1, tag1): (Vec<u8>, Tag) = pull_stream.pull(&c1, None).expect("Decrypt failed");
    let (m2, tag2): (Vec<u8>, Tag) = pull_stream.pull(&c2, None).expect("Decrypt failed");
    let (m3, tag3): (Vec<u8>, Tag) = pull_stream.pull(&c3, None).expect("Decrypt failed");

    assert_eq!(message1, m1.as_slice());
    assert_eq!(message2, m2.as_slice());
    assert_eq!(message3, m3.as_slice());

    assert_eq!(tag1, Tag::MESSAGE);
    assert_eq!(tag2, Tag::MESSAGE);
    assert_eq!(tag3, Tag::FINAL);
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocbox_serde_known_good() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::from_slices(
        &[
            19, 102, 68, 158, 243, 5, 191, 249, 31, 150, 224, 99, 131, 223, 250, 86, 183, 59, 12,
            207, 166, 197, 248, 213, 150, 17, 186, 94, 179, 184, 168, 31,
        ],
        &[
            32, 93, 215, 217, 145, 250, 115, 60, 43, 161, 237, 154, 192, 46, 239, 131, 101, 167,
            229, 195, 16, 170, 88, 53, 253, 30, 21, 29, 150, 214, 140, 64,
        ],
    )
    .expect("sender keypair failed");
    let recipient_keypair = KeyPair::from_slices(
        &[
            203, 213, 109, 27, 115, 197, 227, 35, 161, 27, 73, 179, 181, 104, 237, 253, 207, 206,
            186, 108, 254, 67, 246, 221, 47, 60, 68, 37, 148, 169, 242, 109,
        ],
        &[
            0, 209, 170, 57, 221, 216, 185, 113, 114, 217, 32, 72, 65, 99, 132, 187, 137, 68, 72,
            19, 14, 237, 37, 220, 77, 172, 148, 163, 106, 5, 201, 101,
        ],
    )
    .expect("recipient keypair failed");
    let nonce = Nonce::from(&[
        52, 53, 237, 208, 81, 208, 57, 122, 253, 6, 222, 28, 25, 157, 13, 108, 28, 38, 41, 60, 242,
        45, 126, 101,
    ]);
    let message = b"hey friend";

    let dryocbox: VecBox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let json = serde_json::to_string(&dryocbox).expect("doesn't serialize");

    assert_eq!(
        json,
        "{\"ephemeral_pk\":null,\"tag\":[105,111,140,72,164,126,195,203,17,25,161,50,61,65,22,82],\
         \"data\":[183,35,105,8,103,239,207,9,37,137]}"
    );

    let dryocbox: VecBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocbox
        .decrypt_to_vec(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_dryocsecretbox_protected() {
    use dryoc::dryocsecretbox::protected::*;
    use dryoc::dryocsecretbox::*;

    let secret_key = protected::Key::generate_locked()
        .and_then(|s| s.mprotect_readonly())
        .expect("key failed");

    let nonce = protected::Nonce::generate_readonly_locked().expect("nonce failed");

    let message =
        HeapBytes::from_slice_into_readonly_locked(b"Secret message from the tooth fairy")
            .expect("message failed");

    let dryocsecretbox: protected::LockedBox =
        DryocSecretBox::encrypt(&message, &nonce, &secret_key);

    let decrypted: LockedBytes = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("decrypt failed");

    assert_eq!(message.as_slice(), decrypted.as_slice());
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_dryocbox_protected() {
    use dryoc::dryocbox::DryocBox;
    use dryoc::dryocbox::protected::*;
    use dryoc::precalc::PrecalcSecretKey;

    let sender_keypair = LockedKeyPair::generate_locked_keypair().expect("keypair");
    let recipient_keypair = LockedKeyPair::generate_locked_keypair().expect("keypair");

    let nonce = Nonce::generate_readonly_locked().expect("nonce failed");

    let message = HeapBytes::from_slice_into_locked(b"Secret message from Santa Claus")
        .expect("unable to lock");

    let dryocbox: LockedBox = DryocBox::encrypt(
        &message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("encrypt failed");

    let decrypted: LockedBytes = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message.as_slice(), decrypted.as_slice());

    let shared_key = PrecalcSecretKey::precalculate_locked(
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("shared key");

    let dryocbox: LockedBox =
        DryocBox::precalc_encrypt(&message, &nonce, &shared_key).expect("encrypt failed");

    let decrypted: LockedBytes = dryocbox
        .precalc_decrypt(&nonce, &shared_key)
        .expect("decrypt with shared key failed");

    assert_eq!(message.as_slice(), decrypted.as_slice());
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_streams_protected() {
    use dryoc::dryocstream::protected::*;
    use dryoc::dryocstream::{DryocStream, Tag};

    let message1 = HeapBytes::from_slice_into_readonly_locked(b"Arbitrary data to encrypt")
        .expect("from slice failed");
    let message2 =
        HeapBytes::from_slice_into_readonly_locked(b"split into").expect("from slice failed");
    let message3 =
        HeapBytes::from_slice_into_readonly_locked(b"three messages").expect("from slice failed");

    let key = Key::generate_readonly_locked().expect("key failed");

    let (mut push_stream, header): (_, Header) = DryocStream::init_push(&key);
    let c1: LockedBytes = push_stream
        .push(&message1, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c2: LockedBytes = push_stream
        .push(&message2, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c3: LockedBytes = push_stream
        .push(&message3, None, Tag::FINAL)
        .expect("Encrypt failed");

    let mut pull_stream = DryocStream::init_pull(&key, &header);

    let (m1, tag1): (LockedBytes, Tag) = pull_stream.pull(&c1, None).expect("Decrypt failed");
    let (m2, tag2): (LockedBytes, Tag) = pull_stream.pull(&c2, None).expect("Decrypt failed");
    let (m3, tag3): (LockedBytes, Tag) = pull_stream.pull(&c3, None).expect("Decrypt failed");

    assert_eq!(message1.as_slice(), m1.as_slice());
    assert_eq!(message2.as_slice(), m2.as_slice());
    assert_eq!(message3.as_slice(), m3.as_slice());

    assert_eq!(tag1, Tag::MESSAGE);
    assert_eq!(tag2, Tag::MESSAGE);
    assert_eq!(tag3, Tag::FINAL);
}

#[test]
fn test_dryocbox_seal() {
    use dryoc::dryocbox::*;

    let recipient_keypair = KeyPair::generate();
    let message = b"juicybox";

    let dryocbox =
        DryocBox::seal_to_vecbox(message, &recipient_keypair.public_key).expect("unable to seal");

    let decrypted = dryocbox
        .unseal_to_vec(&recipient_keypair)
        .expect("unable to unseal");

    assert_eq!(message, decrypted.as_slice());
}
