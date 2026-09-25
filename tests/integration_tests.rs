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
fn test_xof_public_api() {
    use dryoc::classic::crypto_xof::{
        crypto_xof_turboshake128, crypto_xof_turboshake128_init_with_domain,
        crypto_xof_turboshake128_squeeze, crypto_xof_turboshake128_update,
    };
    use dryoc::xof::TurboShake128;

    // RFC 9861: TurboSHAKE128(M = `FF FF FF`, D = `07`, 32).
    let expected = hex::decode("b658576001cad9b1e5f399a9f77723bba05458042d68206f7252682dba3663ed")
        .expect("hex");

    let mut state = crypto_xof_turboshake128_init_with_domain(0x07).expect("domain");
    crypto_xof_turboshake128_update(&mut state, &[0xff]).expect("update");
    crypto_xof_turboshake128_update(&mut state, &[0xff, 0xff]).expect("update");
    let mut classic = [0u8; 32];
    crypto_xof_turboshake128_squeeze(&mut state, &mut classic[..10]);
    crypto_xof_turboshake128_squeeze(&mut state, &mut classic[10..]);
    assert_eq!(classic.to_vec(), expected);

    let mut xof = TurboShake128::with_domain(0x07).expect("domain");
    xof.update(&[0xff, 0xff, 0xff]);
    let mut reader = xof.finalize();
    assert_eq!(reader.squeeze_to_vec(32), expected);

    // The standard-domain one-shot functions agree across both APIs.
    let mut one_shot = [0u8; 100];
    crypto_xof_turboshake128(&mut one_shot, b"public API message");
    assert_eq!(
        TurboShake128::compute_to_vec(b"public API message", 100),
        one_shot
    );
}

/// Field `key` of the first record in a `key = value` vector file.
fn first_record_field(text: &str, key: &str) -> Vec<u8> {
    let prefix = format!("{key} = ");
    let line = text
        .lines()
        .find(|line| line.starts_with(&prefix))
        .expect("field present");
    hex::decode(&line[prefix.len()..]).expect("hex")
}

#[test]
fn test_kem_public_api() {
    use dryoc::classic::crypto_kem::{crypto_kem_dec, crypto_kem_enc};
    use dryoc::constants::CRYPTO_KEM_CIPHERTEXTBYTES;
    use dryoc::kem::{self, Ciphertext, KeyPair, Seed, SharedSecret, StackKeyPair};
    use dryoc::types::{ByteArray, Bytes};

    // draft-connolly-cfrg-xwing-kem Appendix C, first vector.
    let vectors = include_str!("../src/mlkem/test-vectors/xwing_draft.txt");
    let seed = Seed::try_from(first_record_field(vectors, "seed").as_slice()).expect("seed");
    let keypair = StackKeyPair::from_seed(&seed);
    assert_eq!(
        keypair.public_key.as_slice(),
        first_record_field(vectors, "pk")
    );
    let restored = StackKeyPair::from_secret_key(keypair.secret_key.clone());
    assert_eq!(restored.public_key, keypair.public_key);

    // Rustaceous encapsulation opens with the Classic API, and the reverse.
    let (ciphertext, sent): (Ciphertext, SharedSecret) =
        kem::encapsulate(&keypair.public_key).expect("encapsulate");
    let mut received = [0u8; 32];
    crypto_kem_dec(
        &mut received,
        ciphertext.as_array(),
        keypair.secret_key.as_array(),
    )
    .expect("dec");
    assert_eq!(received, *sent.as_array());

    let mut ciphertext = [0u8; CRYPTO_KEM_CIPHERTEXTBYTES];
    let mut sent = [0u8; 32];
    crypto_kem_enc(&mut ciphertext, &mut sent, keypair.public_key.as_array()).expect("enc");
    let received: SharedSecret = KeyPair::decapsulate(&restored, &ciphertext).expect("decapsulate");
    assert_eq!(*received.as_array(), sent);

    // ML-KEM-768 alone: the public key is recoverable from the secret key.
    let keypair = kem::mlkem768::StackKeyPair::generate();
    let restored = kem::mlkem768::StackKeyPair::from_secret_key(keypair.secret_key.clone());
    assert_eq!(restored.public_key, keypair.public_key);
    let (ciphertext, sent): (kem::mlkem768::Ciphertext, kem::mlkem768::SharedSecret) =
        kem::mlkem768::encapsulate(&keypair.public_key).expect("encapsulate");
    let received: kem::mlkem768::SharedSecret =
        restored.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(received, sent);
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_sealed_box_protected_keys() {
    use dryoc::dryocsealedbox::protected::{LockedBox, PublicKey, SecretKey};
    use dryoc::dryocsealedbox::{DryocSealedBox, KeyPair};
    use dryoc::protected::*;

    let stack = dryoc::dryocsealedbox::StackKeyPair::generate();
    let keypair = KeyPair::<Locked<PublicKey>, LockedRO<SecretKey>>::from_secret_key(
        SecretKey::from_slice_into_readonly_locked(stack.secret_key.as_slice()).expect("key"),
    );
    let message = HeapBytes::from_slice_into_readonly_locked(b"to the recipient").expect("message");
    let sealed: LockedBox = DryocSealedBox::seal(&message, &keypair.public_key).expect("seal");
    let opened: LockedBytes = sealed.unseal(&keypair).expect("unseal");
    assert_eq!(opened.as_slice(), message.as_slice());
    // The locked box has the same wire format as a stack one.
    let bytes: Vec<u8> = sealed.to_bytes();
    let parsed = dryoc::dryocsealedbox::VecBox::from_bytes(&bytes).expect("parse");
    assert_eq!(
        parsed.unseal_to_vec(&stack).expect("unseal"),
        b"to the recipient"
    );
}

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_kem_protected() {
    use dryoc::kem;
    use dryoc::kem::protected::*;

    let keypair = LockedROKeyPair::generate_readonly_locked_keypair().expect("keypair");
    // A read-only secret key is enough to rebuild the key pair.
    let secret_key = SecretKey::from_slice_into_readonly_locked(keypair.secret_key.as_slice())
        .expect("secret key");
    let rebuilt = kem::KeyPair::<kem::PublicKey, _>::from_secret_key(secret_key);
    assert_eq!(rebuilt.public_key.as_slice(), keypair.public_key.as_slice());
    let (ciphertext, sent): (kem::Ciphertext, Locked<SharedSecret>) =
        kem::encapsulate(&keypair.public_key).expect("encapsulate");
    let received: Locked<SharedSecret> = keypair.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(received.as_slice(), sent.as_slice());

    let keypair =
        kem::mlkem768::protected::LockedKeyPair::generate_locked_keypair().expect("keypair");
    let (ciphertext, sent): (kem::mlkem768::Ciphertext, kem::mlkem768::SharedSecret) =
        kem::mlkem768::encapsulate(&keypair.public_key).expect("encapsulate");
    let received: Locked<kem::mlkem768::protected::SharedSecret> =
        keypair.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(received.as_slice(), sent.as_slice());
}

/// `bytes` as a JSON array of numbers, the encoding of the crate's byte
/// types and of `Vec<u8>`.
#[cfg(feature = "serde")]
fn json_bytes(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("[{}]", items.join(","))
}

/// The JSON encoding of a KEM key pair.
#[cfg(feature = "serde")]
fn kem_keypair_json(public_key: &[u8], secret_key: &[u8]) -> String {
    format!(
        r#"{{"public_key":{},"secret_key":{}}}"#,
        json_bytes(public_key),
        json_bytes(secret_key)
    )
}

#[cfg(feature = "serde")]
#[test]
fn test_kem_serde_json() {
    use dryoc::kem::{self, Ciphertext, PublicKey, SecretKey, Seed, SharedSecret, StackKeyPair};
    use dryoc::types::Bytes;

    // draft-connolly-cfrg-xwing-kem Appendix C, first vector: the decoded
    // key pair and ciphertext reproduce the draft's shared secret.
    let vectors = include_str!("../src/mlkem/test-vectors/xwing_draft.txt");
    let seed = first_record_field(vectors, "seed");
    let pk = first_record_field(vectors, "pk");
    let ct = first_record_field(vectors, "ct");
    let ss = first_record_field(vectors, "ss");
    let keypair = StackKeyPair::from_seed(&Seed::try_from(seed.as_slice()).expect("seed"));

    let json = serde_json::to_string(&keypair).expect("serialize");
    assert_eq!(json, kem_keypair_json(&pk, &seed));
    let decoded: StackKeyPair = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.public_key.as_slice(), pk);
    assert_eq!(decoded.secret_key.as_slice(), seed);

    let ciphertext = Ciphertext::try_from(ct.as_slice()).expect("ciphertext");
    assert_eq!(
        serde_json::to_string(&ciphertext).expect("serialize"),
        json_bytes(&ct)
    );
    let ciphertext: Ciphertext = serde_json::from_str(&json_bytes(&ct)).expect("deserialize");
    let received: SharedSecret = decoded.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(
        serde_json::to_string(&received).expect("serialize"),
        json_bytes(&ss)
    );
    let decoded_secret: SharedSecret = serde_json::from_str(&json_bytes(&ss)).expect("deserialize");
    assert_eq!(decoded_secret, received);
    let public_key: PublicKey = serde_json::from_str(&json_bytes(&pk)).expect("deserialize");
    assert_eq!(public_key, keypair.public_key);
    let secret_key: SecretKey = serde_json::from_str(&json_bytes(&seed)).expect("deserialize");
    assert_eq!(secret_key, keypair.secret_key);

    // Swapped or missing fields and wrong lengths are rejected.
    for invalid in [
        kem_keypair_json(&seed, &pk),
        format!(r#"{{"public_key":{}}}"#, json_bytes(&pk)),
        kem_keypair_json(&pk, &seed[1..]),
    ] {
        assert!(serde_json::from_str::<StackKeyPair>(&invalid).is_err());
    }
    assert!(serde_json::from_str::<Ciphertext>(&json_bytes(&ct[1..])).is_err());
    assert!(
        serde_json::from_str::<PublicKey>(&json_bytes(&[pk.as_slice(), &[0]].concat())).is_err()
    );
    assert!(serde_json::from_str::<SharedSecret>(&json_bytes(&ss[1..])).is_err());

    // ML-KEM-768 (NIST ACVP decapsulation, first case): the public key is
    // the encapsulation key embedded in the expanded secret key after the
    // 1152-byte secret vector.
    let vectors = include_str!("../src/mlkem/test-vectors/mlkem768_acvp_decap.txt");
    let dk = first_record_field(vectors, "dk");
    let c = first_record_field(vectors, "c");
    let k = first_record_field(vectors, "k");
    let keypair = kem::mlkem768::StackKeyPair::from_secret_key(
        kem::mlkem768::SecretKey::try_from(dk.as_slice()).expect("secret key"),
    );
    let mlkem_json = serde_json::to_string(&keypair).expect("serialize");
    assert_eq!(mlkem_json, kem_keypair_json(&dk[1152..1152 + 1184], &dk));
    let decoded: kem::mlkem768::StackKeyPair =
        serde_json::from_str(&mlkem_json).expect("deserialize");
    let ciphertext: kem::mlkem768::Ciphertext =
        serde_json::from_str(&json_bytes(&c)).expect("deserialize");
    let received: kem::mlkem768::SharedSecret =
        decoded.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(received.as_slice(), k);
    // The two algorithms' encodings are not interchangeable.
    assert!(serde_json::from_str::<kem::mlkem768::StackKeyPair>(&json).is_err());
    assert!(serde_json::from_str::<StackKeyPair>(&mlkem_json).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocsealedbox_serde_json() {
    use dryoc::Error;
    use dryoc::dryocsealedbox::{StackKeyPair, VecBox};
    use dryoc::types::Bytes;

    let keypair = StackKeyPair::generate();
    let message = b"Now is the winter of our discontent";
    let sealed = VecBox::seal_to_vecbox(message, &keypair.public_key).expect("seal");

    // The fields are encoded separately, in wire order but with the tag
    // before the data.
    let json = serde_json::to_string(&sealed).expect("serialize");
    let (enc, tag, data) = sealed.clone().into_parts();
    assert_eq!(
        json,
        format!(
            r#"{{"enc":{},"tag":{},"data":{}}}"#,
            json_bytes(enc.as_slice()),
            json_bytes(tag.as_slice()),
            json_bytes(&data)
        )
    );
    let decoded: VecBox = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.to_vec(), sealed.to_vec());
    assert_eq!(decoded.unseal_to_vec(&keypair).expect("unseal"), message);

    let value: serde_json::Value = serde_json::from_str(&json).expect("json");
    // A changed byte in any field decodes but fails to open.
    for field in ["enc", "tag", "data"] {
        let mut tampered = value.clone();
        let byte = tampered[field][0].as_u64().expect("byte");
        tampered[field][0] = (byte ^ 1).into();
        let tampered: VecBox = serde_json::from_value(tampered).expect("deserialize");
        assert!(
            matches!(
                tampered.unseal_to_vec(&keypair),
                Err(Error::AuthenticationFailed)
            ),
            "{field}"
        );
    }
    // The fixed-size fields must have their exact length and every field
    // must be present; a shortened message decodes but fails to open.
    for field in ["enc", "tag", "data"] {
        let mut truncated = value.clone();
        truncated[field].as_array_mut().expect("array").pop();
        let decoded = serde_json::from_value::<VecBox>(truncated);
        if field == "data" {
            assert!(matches!(
                decoded.expect("deserialize").unseal_to_vec(&keypair),
                Err(Error::AuthenticationFailed)
            ));
        } else {
            assert!(decoded.is_err(), "{field}");
        }
        let mut missing = value.clone();
        missing.as_object_mut().expect("object").remove(field);
        assert!(
            serde_json::from_value::<VecBox>(missing).is_err(),
            "{field}"
        );
    }
}

#[cfg(all(feature = "serde", feature = "protected", any(unix, windows)))]
#[test]
fn test_kem_and_sealed_box_protected_serde_json() {
    use dryoc::dryocsealedbox::VecBox;
    use dryoc::dryocsealedbox::protected::LockedBox;
    use dryoc::kem::protected::*;
    use dryoc::kem::{self, Ciphertext, StackKeyPair};

    let vectors = include_str!("../src/mlkem/test-vectors/xwing_draft.txt");
    let seed = first_record_field(vectors, "seed");
    let pk = first_record_field(vectors, "pk");
    let ct = first_record_field(vectors, "ct");
    let ss = first_record_field(vectors, "ss");
    let json = kem_keypair_json(&pk, &seed);

    // Locked key pairs use the stack encoding in both directions.
    let keypair: LockedKeyPair = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(keypair.public_key.as_slice(), pk);
    assert_eq!(keypair.secret_key.as_slice(), seed);
    assert_eq!(serde_json::to_string(&keypair).expect("serialize"), json);
    let ciphertext = Ciphertext::try_from(ct.as_slice()).expect("ciphertext");
    let received: Locked<SharedSecret> = keypair.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(received.as_slice(), ss);
    assert_eq!(
        serde_json::to_string(&received).expect("serialize"),
        json_bytes(&ss)
    );
    assert!(serde_json::from_str::<LockedKeyPair>(&kem_keypair_json(&seed, &pk)).is_err());

    // A stack box's encoding decodes into a locked box that opens with the
    // locked key pair, and encodes back unchanged.
    let stack_keypair: StackKeyPair = serde_json::from_str(&json).expect("deserialize");
    let message = b"to the recipient";
    let sealed = VecBox::seal_to_vecbox(message, &stack_keypair.public_key).expect("seal");
    let box_json = serde_json::to_string(&sealed).expect("serialize");
    let locked: LockedBox = serde_json::from_str(&box_json).expect("deserialize");
    let opened: LockedBytes = locked.unseal(&keypair).expect("unseal");
    assert_eq!(opened.as_slice(), message);
    assert_eq!(serde_json::to_string(&locked).expect("serialize"), box_json);
    let bytes: Vec<u8> = locked.to_bytes();
    assert_eq!(bytes, sealed.to_vec());

    // ML-KEM-768 locked key pairs encode like stack ones.
    let mlkem =
        kem::mlkem768::protected::LockedKeyPair::generate_locked_keypair().expect("keypair");
    let mlkem_json = serde_json::to_string(&mlkem).expect("serialize");
    assert_eq!(
        mlkem_json,
        kem_keypair_json(mlkem.public_key.as_slice(), mlkem.secret_key.as_slice())
    );
    let decoded: kem::mlkem768::StackKeyPair =
        serde_json::from_str(&mlkem_json).expect("deserialize");
    let (ciphertext, sent): (kem::mlkem768::Ciphertext, kem::mlkem768::SharedSecret) =
        kem::mlkem768::encapsulate(&decoded.public_key).expect("encapsulate");
    let received: Locked<kem::mlkem768::protected::SharedSecret> =
        mlkem.decapsulate(&ciphertext).expect("decapsulate");
    assert_eq!(received.as_slice(), sent.as_slice());
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
        HmacSha256, HmacSha256Key, HmacSha256Mac, HmacSha512, HmacSha512Key, HmacSha512Mac,
        HmacSha512256, HmacSha512256Key, HmacSha512256Mac,
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
    let mac512 = HmacSha512Mac::try_from(mac512.as_slice()).expect("MAC length");
    verify512.verify(&mac512).expect("verify failed");

    let key512256 = HmacSha512256Key::generate();
    let mac512256: HmacSha512256Mac = HmacSha512256::compute(key512256.clone(), message);
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

    let rustaceous_seed_array: [u8; dryoc::constants::CRYPTO_SIGN_SEEDBYTES] =
        secret_key_to_seed(&signing_keypair.secret_key);
    let rustaceous_public_key_array: [u8; dryoc::constants::CRYPTO_SIGN_PUBLICKEYBYTES] =
        secret_key_to_public_key(&signing_keypair.secret_key);
    assert_eq!(rustaceous_seed_array, seed);
    assert_eq!(
        &rustaceous_public_key_array,
        signing_keypair.public_key.as_array()
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
fn test_protected_generation_api() {
    use dryoc::dryocbox::protected::{LockedKeyPair, LockedROKeyPair, Nonce as BoxNonce};
    use dryoc::dryocstream::protected::Key as StreamKey;
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
}

#[cfg(all(feature = "serde", feature = "protected", any(unix, windows)))]
#[test]
fn test_protected_serde_json_roundtrips() {
    use dryoc::protected::{
        HeapByteArray, HeapBytes, Locked, LockedBytes, LockedRO, NewLockedFromSlice,
    };
    use dryoc::types::Bytes;

    let data = [1u8, 2, 3];
    let json = serde_json::to_string(&data).expect("array json");

    let heap_bytes = HeapBytes::from(&data[..]);
    assert_eq!(serde_json::to_string(&heap_bytes).expect("serialize"), json);
    let decoded: HeapBytes = serde_json::from_str(&json).expect("heap bytes");
    assert_eq!(decoded, heap_bytes);

    let locked_bytes = HeapBytes::from_slice_into_locked(&data).expect("lock");
    assert_eq!(
        serde_json::to_string(&locked_bytes).expect("serialize"),
        json
    );
    let decoded: LockedBytes = serde_json::from_str(&json).expect("locked bytes");
    assert_eq!(decoded.as_slice(), &data);

    // `LockedRO<HeapBytes>` implements `Serialize` only; it has no
    // `Deserialize` impl, so it must serialize exactly like the read-write
    // forms above.
    let readonly: LockedRO<HeapBytes> =
        HeapBytes::from_slice_into_readonly_locked(&data).expect("readonly lock");
    assert_eq!(serde_json::to_string(&readonly).expect("serialize"), json);

    let heap_array = HeapByteArray::<3>::from(&data);
    assert_eq!(serde_json::to_string(&heap_array).expect("serialize"), json);
    let decoded: HeapByteArray<3> = serde_json::from_str(&json).expect("heap array");
    assert_eq!(decoded, heap_array);

    let locked_array = HeapByteArray::<3>::from_slice_into_locked(&data).expect("lock");
    assert_eq!(
        serde_json::to_string(&locked_array).expect("serialize"),
        json
    );
    let decoded: Locked<HeapByteArray<3>> = serde_json::from_str(&json).expect("locked array");
    assert_eq!(decoded.as_slice(), &data);

    // A JSON string is delivered to the visitors as a byte string.
    let from_string: HeapBytes = serde_json::from_str("\"abc\"").expect("heap bytes string");
    assert_eq!(from_string.as_slice(), b"abc");
    let from_string: Locked<HeapByteArray<3>> =
        serde_json::from_str("\"abc\"").expect("locked array string");
    assert_eq!(from_string.as_slice(), b"abc");

    let empty: LockedBytes = serde_json::from_str("[]").expect("empty locked bytes");
    assert!(empty.is_empty());
    let empty: HeapBytes = serde_json::from_str("[]").expect("empty heap bytes");
    assert!(empty.is_empty());
    assert_eq!(serde_json::to_string(&empty).expect("serialize"), "[]");

    for short_or_long in ["[1,2]", "[1,2,3,4]", "\"ab\"", "\"abcd\"", "[]"] {
        assert!(
            serde_json::from_str::<HeapByteArray<3>>(short_or_long).is_err(),
            "{short_or_long}"
        );
        assert!(
            serde_json::from_str::<Locked<HeapByteArray<3>>>(short_or_long).is_err(),
            "{short_or_long}"
        );
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_stack_byte_array_serde_json_roundtrip_requires_exact_length() {
    use dryoc::types::{Bytes, StackByteArray};

    let array = StackByteArray::from([1u8, 2, 3]);
    let json = serde_json::to_string(&array).expect("serialize");
    assert_eq!(json, "[1,2,3]");

    let decoded: StackByteArray<3> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, array);

    let from_string: StackByteArray<3> = serde_json::from_str("\"abc\"").expect("string");
    assert_eq!(from_string.as_slice(), b"abc");

    for short_or_long in ["[1,2]", "[1,2,3,4]", "\"ab\"", "\"abcd\"", "[]"] {
        assert!(
            serde_json::from_str::<StackByteArray<3>>(short_or_long).is_err(),
            "{short_or_long}"
        );
    }
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

#[test]
fn test_crypto_aead_chacha20poly1305_ietf() {
    use dryoc::classic::crypto_aead_chacha20poly1305_ietf::*;
    use dryoc::constants::CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;

    let key = crypto_aead_chacha20poly1305_ietf_keygen();
    let nonce = [0x42; 12];
    let message = b"ChaCha20-Poly1305-IETF";
    let associated_data = b"metadata";
    let mut ciphertext = vec![0u8; message.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];

    crypto_aead_chacha20poly1305_ietf_encrypt(
        &mut ciphertext,
        message,
        Some(associated_data),
        &nonce,
        &key,
    )
    .expect("encrypt");

    let mut plaintext = vec![0u8; message.len()];
    crypto_aead_chacha20poly1305_ietf_decrypt(
        &mut plaintext,
        &ciphertext,
        Some(associated_data),
        &nonce,
        &key,
    )
    .expect("decrypt");

    assert_eq!(plaintext, message);
}

#[test]
fn test_dryocaead_chacha20poly1305_ietf() {
    use dryoc::classic::crypto_aead_chacha20poly1305_ietf::crypto_aead_chacha20poly1305_ietf_encrypt;
    use dryoc::constants::{
        CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
    };
    use dryoc::dryocaead::chacha20poly1305_ietf::*;

    let key = Key::generate();
    let nonce = Nonce::from([0x42; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES]);
    let message = b"Rustaceous ChaCha20-Poly1305-IETF";
    let aad = b"metadata";

    let dryocaead =
        VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("encrypt failed");
    let mut classic = vec![0u8; message.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
    crypto_aead_chacha20poly1305_ietf_encrypt(
        &mut classic,
        message,
        Some(aad),
        nonce.as_array(),
        key.as_array(),
    )
    .expect("classic encrypt failed");
    assert_eq!(dryocaead.to_vec(), classic);

    let parsed = VecBox::from_bytes(&classic).expect("from bytes");
    assert_eq!(
        parsed
            .decrypt_to_vec(Some(aad), &nonce, &key)
            .expect("decrypt failed"),
        message
    );

    let (tag, data) = dryocaead.into_parts();
    let envelope = VecEnvelope::from_parts(nonce, tag, data);
    assert_eq!(
        envelope.to_vec().len(),
        CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
            + message.len()
            + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES
    );
    let parsed = VecEnvelope::from_bytes(&envelope.to_vec()).expect("from bytes");
    assert_eq!(
        parsed.open_to_vec(Some(aad), &key).expect("open failed"),
        message
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocaead_chacha20poly1305_ietf_serde_json() {
    use dryoc::dryocaead::chacha20poly1305_ietf::*;

    let key = Key::generate();
    let nonce = Nonce::from([0x42; 12]);
    let dryocaead = VecBox::encrypt_to_vecbox(b"message", None, &nonce, &key).expect("encrypt");
    let encoded = serde_json::to_string(&dryocaead).expect("serialize");
    let decoded: VecBox = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(
        decoded.decrypt_to_vec(None, &nonce, &key).expect("decrypt"),
        b"message"
    );
}

#[cfg(feature = "wincode_0_6")]
#[test]
fn test_dryocaead_chacha20poly1305_ietf_wincode() {
    use dryoc::dryocaead::chacha20poly1305_ietf::*;

    let key = Key::generate();
    let nonce = Nonce::from([0x42; 12]);
    let aead_box = VecBox::encrypt_to_vecbox(b"message", None, &nonce, &key).expect("encrypt");
    let (tag, data) = aead_box.into_parts();
    let envelope = VecEnvelope::from_parts(nonce, tag, data);
    let encoded = wincode::serialize(&envelope).expect("serialize");
    let decoded: VecEnvelope = wincode::deserialize(&encoded).expect("deserialize");
    assert_eq!(decoded.open_to_vec(None, &key).expect("open"), b"message");
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

/// The bincode-style wire layout the crate's `SchemaWrite` impls promise:
/// fixed arrays are written raw and `Vec<u8>` as a little-endian `u64` length
/// prefix followed by the bytes.
#[cfg(feature = "wincode_0_6")]
fn wincode_vec(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

#[cfg(feature = "wincode_0_6")]
#[test]
fn test_dryocbox_wincode_wire_format() {
    use dryoc::classic::crypto_box::crypto_box_detached;
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::from_seed(&[1u8; 32]);
    let recipient_keypair = KeyPair::from_seed(&[2u8; 32]);
    let nonce = Nonce::from([3u8; 24]);
    let message = b"hey friend";

    // Independent oracle for the ciphertext and tag.
    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = [0u8; 16];
    crypto_box_detached(
        &mut ciphertext,
        &mut mac,
        message,
        nonce.as_array(),
        recipient_keypair.public_key.as_array(),
        sender_keypair.secret_key.as_array(),
    )
    .expect("classic encrypt");

    // Regular box: `Option::None` tag, tag, then the length-prefixed data.
    let dryocbox: VecBox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");
    let encoded = wincode::serialize(&dryocbox).expect("doesn't serialize");

    let mut expected = vec![0u8];
    expected.extend_from_slice(&mac);
    expected.extend_from_slice(&wincode_vec(&ciphertext));
    assert_eq!(encoded, expected);

    let decoded: VecBox = wincode::deserialize(&expected).expect("doesn't deserialize");
    let decrypted: Vec<u8> = decoded
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");
    assert_eq!(message, decrypted.as_slice());

    // Sealed box: `Option::Some` tag followed by the ephemeral public key.
    let sealed: VecBox = DryocBox::seal(message, &recipient_keypair.public_key).expect("seal");
    let encoded = wincode::serialize(&sealed).expect("doesn't serialize");
    let (tag, data, ephemeral_pk) = sealed.into_parts();
    let ephemeral_pk = ephemeral_pk.expect("sealed box has an ephemeral public key");

    let mut expected = vec![1u8];
    expected.extend_from_slice(ephemeral_pk.as_slice());
    expected.extend_from_slice(tag.as_slice());
    expected.extend_from_slice(&wincode_vec(&data));
    assert_eq!(encoded, expected);

    let decoded: VecBox = wincode::deserialize(&expected).expect("doesn't deserialize");
    let decrypted: Vec<u8> = decoded.unseal(&recipient_keypair).expect("unseal failed");
    assert_eq!(message, decrypted.as_slice());

    // Truncated input is rejected rather than read past the end.
    assert!(wincode::deserialize::<VecBox>(&expected[..expected.len() - 1]).is_err());
}

#[cfg(feature = "wincode_0_6")]
#[test]
fn test_dryocaead_wincode_wire_format() {
    use dryoc::classic::crypto_aead_xchacha20poly1305_ietf::crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
    use dryoc::dryocaead::*;

    let key = Key::from([4u8; 32]);
    let nonce = Nonce::from([5u8; 24]);
    let message = b"hey authenticated friend";
    let aad = b"metadata";

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = [0u8; 16];
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        &mut ciphertext,
        &mut mac,
        message,
        Some(aad),
        nonce.as_array(),
        key.as_array(),
    )
    .expect("classic encrypt");

    // Box: length-prefixed ciphertext, then the tag.
    let aead_box =
        VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("unable to encrypt");
    let encoded = wincode::serialize(&aead_box).expect("doesn't serialize");

    let mut expected = wincode_vec(&ciphertext);
    expected.extend_from_slice(&mac);
    assert_eq!(encoded, expected);

    let decoded: VecBox = wincode::deserialize(&expected).expect("doesn't deserialize");
    assert_eq!(
        decoded
            .decrypt_to_vec(Some(aad), &nonce, &key)
            .expect("decrypt failed"),
        message
    );

    // Envelope: nonce, length-prefixed ciphertext, then the tag.
    let (tag, data) = aead_box.into_parts();
    let envelope = VecEnvelope::from_parts(nonce.clone(), tag, data);
    let encoded = wincode::serialize(&envelope).expect("doesn't serialize");

    let mut expected = nonce.as_slice().to_vec();
    expected.extend_from_slice(&wincode_vec(&ciphertext));
    expected.extend_from_slice(&mac);
    assert_eq!(encoded, expected);

    let decoded: VecEnvelope = wincode::deserialize(&expected).expect("doesn't deserialize");
    assert_eq!(
        decoded.open_to_vec(Some(aad), &key).expect("open failed"),
        message
    );

    assert!(wincode::deserialize::<VecEnvelope>(&expected[..expected.len() - 1]).is_err());
}

#[cfg(feature = "wincode_0_6")]
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

#[cfg(feature = "wincode_0_6")]
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

#[cfg(feature = "wincode_0_6")]
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

#[cfg(feature = "wincode_0_6")]
#[test]
fn test_dryocsecretbox_wincode_wire_format() {
    use dryoc::classic::crypto_secretbox::crypto_secretbox_detached;
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::from([6u8; 32]);
    let nonce = Nonce::from([7u8; 24]);
    let message = b"hey buddy bro";

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = [0u8; 16];
    crypto_secretbox_detached(
        &mut ciphertext,
        &mut mac,
        message,
        nonce.as_array(),
        secret_key.as_array(),
    )
    .expect("classic encrypt");

    // Tag, then the length-prefixed ciphertext.
    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);
    let encoded = wincode::serialize(&dryocsecretbox).expect("doesn't serialize");

    let mut expected = mac.to_vec();
    expected.extend_from_slice(&wincode_vec(&ciphertext));
    assert_eq!(encoded, expected);

    let decoded: VecBox = wincode::deserialize(&expected).expect("doesn't deserialize");
    let decrypted: Vec<u8> = decoded
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");
    assert_eq!(message, decrypted.as_slice());

    assert!(wincode::deserialize::<VecBox>(&expected[..expected.len() - 1]).is_err());
}

#[cfg(feature = "wincode_0_6")]
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
fn test_dryocsecretbox_protected_to_bytes_from_parts() {
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

    // `to_bytes` writes `tag || ciphertext`, the same layout `VecBox::to_vec`
    // produces for the unprotected form.
    let bytes: Vec<u8> = dryocsecretbox.to_bytes();
    assert_eq!(bytes.len(), CRYPTO_SECRETBOX_MACBYTES + message.len());

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

#[cfg(all(feature = "protected", any(unix, windows)))]
#[test]
fn test_dryocaead_chacha20poly1305_ietf_protected() {
    use dryoc::dryocaead::chacha20poly1305_ietf::protected::*;

    let key = Key::generate_readonly_locked().expect("key failed");
    let nonce = Nonce::from_slice_into_locked(&[0x42; 12]).expect("nonce failed");
    let message = HeapBytes::from_slice_into_readonly_locked(b"protected ietf aead message")
        .expect("message");

    let dryocaead: LockedBox =
        LockedBox::encrypt(&message, None, &nonce, &key).expect("encrypt failed");
    let decrypted: LockedBytes = dryocaead
        .decrypt(None, &nonce, &key)
        .expect("decrypt failed");
    assert_eq!(message.as_slice(), decrypted.as_slice());

    let (tag, data) = dryocaead.into_parts();
    let envelope: LockedEnvelope = LockedEnvelope::from_parts(nonce, tag, data);
    let decrypted: LockedBytes = envelope.open(None, &key).expect("open failed");
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
