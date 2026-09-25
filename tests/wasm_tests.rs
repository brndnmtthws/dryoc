#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use std::collections::BTreeMap;

use dryoc::auth::Auth;
use dryoc::classic::crypto_aead_chacha20poly1305_ietf::{
    crypto_aead_chacha20poly1305_ietf_decrypt, crypto_aead_chacha20poly1305_ietf_encrypt,
};
use dryoc::classic::crypto_generichash::crypto_generichash;
use dryoc::classic::crypto_kem_mlkem768::crypto_kem_mlkem768_enc_deterministic;
use dryoc::classic::crypto_kem_xwing::{crypto_kem_xwing_dec, crypto_kem_xwing_enc_deterministic};
use dryoc::classic::crypto_xof::{
    crypto_xof_shake256_init, crypto_xof_shake256_squeeze, crypto_xof_shake256_update,
    crypto_xof_turboshake128_init_with_domain, crypto_xof_turboshake128_squeeze,
    crypto_xof_turboshake128_update, crypto_xof_turboshake256_init_with_domain,
};
use dryoc::constants::{CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_XWING_CIPHERTEXTBYTES};
use dryoc::dryocaead::{Key as AeadKey, Nonce as AeadNonce, VecBox as AeadVecBox};
use dryoc::dryocbox::{DryocBox, KeyPair, NewByteArray, Nonce};
use dryoc::dryocsecretbox::{DryocSecretBox, Key};
use dryoc::dryocstream::{DryocStream, Header, Key as StreamKey, Tag};
use dryoc::generichash::GenericHash;
use dryoc::hkdf::HkdfSha256;
use dryoc::hmac::{HmacSha256, HmacSha256Key, HmacSha512, HmacSha512Key};
use dryoc::kdf::StackKdf;
use dryoc::kx::{KeyPair as KxKeyPair, StackSession};
use dryoc::onetimeauth::OnetimeAuth;
use dryoc::precalc::PrecalcSecretKey;
#[cfg(feature = "base64")]
use dryoc::pwhash::VecPwHash;
use dryoc::sign::{SigningKeyPair, VecSignedMessage};
use dryoc::types::{ByteArray, Bytes, StackByteArray};
use dryoc::xof::{Shake128, TurboShake128, TurboShake256};
use wasm_bindgen_test::wasm_bindgen_test;

fn unhex(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("valid hex")
}

fn unhex_array<const N: usize>(hex: &str) -> [u8; N] {
    unhex(hex).try_into().expect("expected length")
}

/// Parses a file from `src/mlkem/test-vectors/`: `#` comments, then
/// blank-line-separated records of `key = value` lines. Works line by line,
/// like the native tests' parser, so a CRLF checkout parses the same; a
/// repeated key within a record is an error.
fn records(text: &str) -> Vec<BTreeMap<&str, &str>> {
    let mut records = vec![BTreeMap::new()];
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let record = records.last_mut().expect("at least one record");
        if line.is_empty() {
            if !record.is_empty() {
                records.push(BTreeMap::new());
            }
        } else {
            let (key, value) = line.split_once(" = ").expect("key = value");
            assert!(record.insert(key, value).is_none(), "repeated key {key}");
        }
    }
    records.retain(|record| !record.is_empty());
    records
}

/// Decodes the hex field `key` of `record` into a fixed-size array.
fn field<const N: usize>(record: &BTreeMap<&str, &str>, key: &str) -> [u8; N] {
    unhex_array(record[key])
}

/// HPKE's `suite_id` for X-Wing, HKDF-SHA256 and ChaCha20-Poly1305.
const HPKE_SUITE_ID: &[u8] = b"HPKE\x64\x7a\x00\x01\x00\x03";

/// RFC 9180 `LabeledExtract(salt, label, ikm)`.
fn hpke_labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> HkdfSha256 {
    HkdfSha256::extract(
        Some(salt),
        &[b"HPKE-v1", HPKE_SUITE_ID, label, ikm].concat(),
    )
}

/// RFC 9180 `LabeledExpand(prk, label, info, len)`.
fn hpke_labeled_expand(prk: &HkdfSha256, label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let len_bytes = u16::try_from(len).expect("short output").to_be_bytes();
    let labeled_info = [&len_bytes[..], b"HPKE-v1", HPKE_SUITE_ID, label, info].concat();
    prk.expand_to_vec(len, &labeled_info)
        .expect("expand failed")
}

/// RFC 9180 `KeySchedule` in base mode (no PSK): the AEAD key and base
/// nonce for `shared_secret` and `info`. Written from the RFC, independently
/// of `dryoc::dryocsealedbox`, to check the sealed-box format.
fn hpke_key_schedule(shared_secret: &[u8], info: &[u8]) -> ([u8; 32], [u8; 12]) {
    let psk_id_hash = hpke_labeled_extract(b"", b"psk_id_hash", b"").into_prk();
    let info_hash = hpke_labeled_extract(b"", b"info_hash", info).into_prk();
    let context = [&[0u8][..], psk_id_hash.as_slice(), info_hash.as_slice()].concat();
    let secret = hpke_labeled_extract(shared_secret, b"secret", b"");
    (
        hpke_labeled_expand(&secret, b"key", &context, 32)
            .try_into()
            .expect("key length"),
        hpke_labeled_expand(&secret, b"base_nonce", &context, 12)
            .try_into()
            .expect("nonce length"),
    )
}

/// RFC 4231 test case 1 key, zero-padded to the fixed key length; HMAC pads
/// short keys with zeros, so the tags are unchanged.
fn rfc4231_key<const N: usize>() -> [u8; N] {
    let mut key = [0u8; N];
    key[..20].fill(0x0b);
    key
}

#[wasm_bindgen_test]
fn dryocbox_roundtrip() {
    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"wasm dryocbox";

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
}

#[wasm_bindgen_test]
fn dryocbox_precalc_roundtrip() {
    let sender_keypair = KeyPair::generate();
    let recipient_keypair = KeyPair::generate();
    let nonce = Nonce::generate();
    let message = b"wasm dryocbox precalc";
    let shared_key =
        PrecalcSecretKey::precalculate(&recipient_keypair.public_key, &sender_keypair.secret_key)
            .expect("precalculation failed");

    let dryocbox =
        DryocBox::precalc_encrypt_to_vecbox(message, &nonce, &shared_key).expect("encrypt failed");
    let decrypted = dryocbox
        .decrypt_to_vec(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[wasm_bindgen_test]
fn dryocsecretbox_roundtrip() {
    let secret_key = Key::generate();
    let nonce = dryoc::dryocsecretbox::Nonce::generate();
    let message = b"wasm dryocsecretbox";

    let dryocsecretbox: dryoc::dryocsecretbox::VecBox =
        DryocSecretBox::encrypt(message, &nonce, &secret_key);
    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[wasm_bindgen_test]
fn dryocstream_roundtrip() {
    let key = StreamKey::generate();
    let (mut push_stream, header): (_, Header) = DryocStream::init_push(&key);
    let message = b"wasm secretstream".to_vec();
    let associated_data = b"fixed-width lengths".to_vec();
    let ciphertext = push_stream
        .push_to_vec(&message, Some(&associated_data), Tag::FINAL)
        .expect("secretstream push failed");

    let mut pull_stream = DryocStream::init_pull(&key, &header);
    let (decrypted, tag) = pull_stream
        .pull_to_vec(&ciphertext, Some(&associated_data))
        .expect("secretstream pull failed");

    assert_eq!(decrypted, message);
    assert_eq!(tag, Tag::FINAL);
}

#[wasm_bindgen_test]
fn generichash_known_answer() {
    let mut hash = [0u8; 32];
    crypto_generichash(&mut hash, b"abc", None).expect("hash failed");

    assert_eq!(
        &hash,
        &[
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ]
    );
}

#[wasm_bindgen_test]
fn aead_xchacha20poly1305_known_answer() {
    // The RFC 8439 section 2.8.2 key, associated data and message with a
    // 24-byte nonce; the expected bytes are libsodium's output for those
    // inputs, checked against libsodium at runtime by the crate's native
    // `classic::crypto_aead_xchacha20poly1305_ietf` tests.
    const MESSAGE: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const AD: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const NONCE: [u8; 24] = [
        0xf2, 0x8a, 0x50, 0xa7, 0x8a, 0x7e, 0x23, 0xc9, 0xcb, 0xa6, 0x78, 0x34, 0x66, 0xf8, 0x03,
        0x59, 0x0f, 0x04, 0xe9, 0x22, 0x31, 0xa3, 0x2d, 0x5d,
    ];
    const EXPECTED: &[u8] = &[
        0x20, 0xf1, 0xae, 0x75, 0xe1, 0xe5, 0xe0, 0x00, 0x40, 0x29, 0x4f, 0x0f, 0xb1, 0x0e, 0xbb,
        0x08, 0x10, 0xc5, 0x93, 0xc7, 0xdb, 0xa4, 0xec, 0x10, 0x4c, 0x1e, 0x5e, 0xf9, 0x50, 0x7f,
        0xae, 0xef, 0x58, 0xfc, 0x28, 0x98, 0xbb, 0xd0, 0xe4, 0x7b, 0x2f, 0x53, 0x31, 0xfb, 0xc3,
        0x67, 0xd3, 0xc2, 0x78, 0x4e, 0x36, 0x48, 0xce, 0x1e, 0xaa, 0x77, 0x87, 0xad, 0x18, 0x6d,
        0xb2, 0x68, 0x5e, 0xe8, 0x9a, 0xe4, 0xd3, 0x44, 0x1f, 0x6e, 0xa0, 0xb2, 0x22, 0x4c, 0xd5,
        0xa1, 0x34, 0x16, 0x1b, 0x55, 0x4d, 0x8b, 0x48, 0x35, 0x0b, 0x4a, 0xd4, 0x01, 0x15, 0xdb,
        0x81, 0xea, 0x82, 0x09, 0x68, 0xe9, 0x43, 0x89, 0x2f, 0x2b, 0x80, 0x51, 0xcb, 0x5f, 0x7a,
        0x86, 0x66, 0xe7, 0xe7, 0xef, 0x7f, 0x84, 0xc0, 0xa2, 0xf8, 0x0a, 0x12, 0xd0, 0x66, 0x80,
        0xc8, 0xee, 0xbb, 0xd9, 0x30, 0x04, 0x10, 0x9d, 0xe8, 0x42,
    ];

    let key = AeadKey::from(KEY);
    let nonce = AeadNonce::from(NONCE);

    let aead_box =
        AeadVecBox::encrypt_to_vecbox(MESSAGE, Some(AD), &nonce, &key).expect("encrypt failed");
    assert_eq!(aead_box.to_vec(), EXPECTED);

    let decrypted = AeadVecBox::from_bytes(EXPECTED)
        .expect("parse failed")
        .decrypt_to_vec(Some(AD), &nonce, &key)
        .expect("decrypt failed");
    assert_eq!(decrypted, MESSAGE);

    let mut tampered = EXPECTED.to_vec();
    tampered[0] ^= 1;
    assert!(
        AeadVecBox::from_bytes(&tampered)
            .expect("parse failed")
            .decrypt_to_vec(Some(AD), &nonce, &key)
            .is_err()
    );
}

#[wasm_bindgen_test]
fn sign_rfc_8032_known_answer() {
    // RFC 8032 section 7.1, test 1 (empty message).
    let seed = StackByteArray::from(unhex_array::<32>(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let expected_public_key =
        unhex_array::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_signature = unhex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555",
        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ));

    let keypair: SigningKeyPair<dryoc::sign::PublicKey, dryoc::sign::SecretKey> =
        SigningKeyPair::from_seed(&seed);
    assert_eq!(keypair.public_key.as_slice(), &expected_public_key);

    let signed: VecSignedMessage = keypair.sign(Vec::new()).expect("sign failed");
    signed.verify(&keypair.public_key).expect("verify failed");
    assert_eq!(signed.to_vec(), expected_signature);

    let mut tampered = signed.to_vec();
    tampered[0] ^= 1;
    assert!(
        VecSignedMessage::from_bytes(&tampered)
            .expect("parse failed")
            .verify(&keypair.public_key)
            .is_err()
    );
}

#[wasm_bindgen_test]
fn kdf_known_answer() {
    // Frozen from a libsodium `crypto_kdf_derive_from_key` cross-check.
    let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let kdf = StackKdf::from_parts(
        StackByteArray::from(key),
        StackByteArray::from(*b"wasmtest"),
    );

    let subkey = kdf
        .derive_subkey::<16, [u8; 16]>(0)
        .expect("derive failed")
        .to_vec();
    assert_eq!(subkey, unhex("f885a670a774b20d98fd80412dd3eb6c"));

    let subkey = kdf
        .derive_subkey::<32, [u8; 32]>(1)
        .expect("derive failed")
        .to_vec();
    assert_eq!(
        subkey,
        unhex("a74d317a77e218b974eb6823b5e200dee5f9bec1af011a7d7ef6211a0c6835a5")
    );

    let subkey = kdf
        .derive_subkey::<64, [u8; 64]>(u64::MAX)
        .expect("derive failed")
        .to_vec();
    assert_eq!(
        subkey,
        unhex(concat!(
            "a656a24fbe64b6c335a4d99c30b28120bc05b4c86f044a43051fb35fa9df811d",
            "1b4dfc5ca9c544f68bd9b34081baee1d38017b2d8c25064db43fffdbc07f831b",
        ))
    );
}

#[wasm_bindgen_test]
fn kx_known_answer() {
    // Frozen from a libsodium `crypto_kx_*_session_keys` cross-check using
    // `crypto_box_seed_keypair` keypairs from seeds `[0x11; 32]`/`[0x22; 32]`.
    let client = KxKeyPair::from_seed(&StackByteArray::from([0x11u8; 32]));
    let server = KxKeyPair::from_seed(&StackByteArray::from([0x22u8; 32]));
    assert_eq!(
        client.public_key.as_slice(),
        &unhex_array::<32>("7a46e129fd805047448437e4744f1f1576be8c449fdf57e0c580d36c5cfc6668")
    );
    assert_eq!(
        server.public_key.as_slice(),
        &unhex_array::<32>("9d8d78b9c9e6661e552f2f1af02095ee2f8743fa2e6183f41bb7077ef51b5379")
    );

    let client_session =
        StackSession::new_client(&client, &server.public_key).expect("client session failed");
    let server_session =
        StackSession::new_server(&server, &client.public_key).expect("server session failed");
    let (client_rx, client_tx) = client_session.into_parts();
    let (server_rx, server_tx) = server_session.into_parts();

    assert_eq!(
        client_rx.as_slice(),
        &unhex_array::<32>("0bbadb7307530679f114d38ba5a1045ca8358ddcb8a0fe5cf0c1ec0011c454ea")
    );
    assert_eq!(
        client_tx.as_slice(),
        &unhex_array::<32>("250d3401f305141e2fa4c31a95886bcaea99f2e14dea7e325ef1a17dd396811b")
    );
    assert_eq!(client_rx, server_tx);
    assert_eq!(client_tx, server_rx);
}

#[wasm_bindgen_test]
fn auth_rfc_4231_known_answer() {
    // RFC 4231 test case 1, HMAC-SHA-512 truncated to 256 bits.
    let expected = unhex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde");
    let key = dryoc::auth::Key::from(rfc4231_key::<32>());

    assert_eq!(Auth::compute_to_vec(key.clone(), b"Hi There"), expected);

    let mut auth = Auth::new(key.clone());
    auth.update(b"Hi ");
    auth.update(b"There");
    auth.verify(&dryoc::auth::Mac::try_from(expected.as_slice()).expect("mac"))
        .expect("verify failed");

    let mut auth = Auth::new(key);
    auth.update(b"Hi there");
    assert!(
        auth.verify(&dryoc::auth::Mac::try_from(expected.as_slice()).expect("mac"))
            .is_err()
    );
}

#[wasm_bindgen_test]
fn onetimeauth_rfc_7539_known_answer() {
    // RFC 7539 section 2.5.2.
    let key = dryoc::onetimeauth::Key::from([
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ]);
    let expected = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];

    assert_eq!(
        OnetimeAuth::compute_to_vec(key.clone(), b"Cryptographic Forum Research Group"),
        expected
    );

    let mut auth = OnetimeAuth::new(key);
    auth.update(b"Cryptographic Forum ");
    auth.update(b"Research Group");
    auth.verify(&dryoc::onetimeauth::Mac::from(expected))
        .expect("verify failed");
}

#[wasm_bindgen_test]
fn hmac_rfc_4231_known_answer() {
    // RFC 4231 test case 1.
    let sha256 = HmacSha256::compute_to_vec(HmacSha256Key::from(rfc4231_key::<32>()), b"Hi There");
    assert_eq!(
        sha256,
        unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    let sha512 = HmacSha512::compute_to_vec(HmacSha512Key::from(rfc4231_key::<32>()), b"Hi There");
    assert_eq!(
        sha512,
        unhex(concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ))
    );

    let mut incremental = HmacSha256::new(HmacSha256Key::from(rfc4231_key::<32>()));
    incremental.update(b"Hi ");
    incremental.update(b"There");
    assert_eq!(incremental.finalize_to_vec(), sha256);
}

#[wasm_bindgen_test]
fn hkdf_rfc_5869_known_answer() {
    // RFC 5869 appendix A, test case 1.
    let ikm = [0x0bu8; 22];
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");

    let hkdf = HkdfSha256::extract(Some(&salt), &ikm);
    let okm = hkdf.expand_to_vec(42, &info).expect("expand failed");
    assert_eq!(
        okm,
        unhex(concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865",
        ))
    );

    let prk = hkdf.into_prk();
    assert_eq!(
        prk.as_slice(),
        &unhex_array::<32>("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    assert_eq!(
        HkdfSha256::from_prk(prk)
            .expand_to_vec(42, &info)
            .expect("expand failed"),
        okm
    );
}

#[wasm_bindgen_test]
fn generichash_keyed_known_answer() {
    // BLAKE2b keyed test vector: empty message, 64-byte key.
    let key = unhex_array::<64>(concat!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    ));
    let expected = unhex(concat!(
        "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786",
        "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
    ));

    let hash: [u8; 64] = GenericHash::<64, 64>::hash(b"", Some(&key)).expect("hash failed");
    assert_eq!(hash.to_vec(), expected);
}

#[cfg(feature = "base64")]
#[wasm_bindgen_test]
fn pwhash_string_parse_and_verify() {
    // Fixed Argon2id string with minimal cost parameters.
    let encoded = concat!(
        "$argon2id$v=19$m=8,t=1,p=1$9ekTPbzKHDiIpMlbQaGlhw$",
        "hNvEox1vwA2JfhZp1wZR15ZgoNTLZbWZo6XJcN6naXw",
    );

    let pwhash = VecPwHash::from_string(encoded).expect("valid string should parse");
    pwhash.verify(b"password").expect("verify failed");
    assert!(pwhash.verify(b"wrong").is_err());
    assert_eq!(
        pwhash.to_encoded_string().expect("re-encode failed"),
        encoded
    );

    assert!(VecPwHash::from_string("$argon2id$v=19$m=8,t=1,p=1$not-base64!$x").is_err());
}

#[wasm_bindgen_test]
fn xof_fips_202_shake_known_answer() {
    // FIPS 202 SHAKE outputs, checked against Python's `hashlib` (OpenSSL).
    // The empty-message outputs run two blocks and a byte past the rate
    // (168 bytes for SHAKE128, 136 for SHAKE256), so squeezing crosses
    // permutation boundaries.
    let shake128_empty = unhex(concat!(
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
        "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
        "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef",
        "aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
        "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
        "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619",
        "f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
        "1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f",
        "1368ec2967fc84ef2ae9aff268e0b1700a",
    ));
    let shake256_empty = unhex(concat!(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853",
        "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86",
        "f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6",
        "77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c",
        "aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2",
        "03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f",
        "5a1aaa96d313eacc890936c173cdcd0fab",
    ));
    assert_eq!(shake128_empty.len(), 2 * 168 + 1);
    assert_eq!(shake256_empty.len(), 2 * 136 + 1);

    assert_eq!(
        Shake128::compute_to_vec(b"abc", 32),
        unhex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")
    );
    assert_eq!(
        Shake128::compute_to_vec(b"", shake128_empty.len()),
        shake128_empty
    );
    // Squeezes that end on, before and after each block boundary continue
    // one output stream.
    let mut reader = Shake128::new().finalize();
    let mut streamed = Vec::new();
    for len in [1, 166, 2, 167, 1] {
        streamed.extend(reader.squeeze_to_vec(len));
    }
    assert_eq!(streamed, shake128_empty);

    let mut state = crypto_xof_shake256_init();
    crypto_xof_shake256_update(&mut state, b"ab").expect("update");
    crypto_xof_shake256_update(&mut state, b"c").expect("update");
    let mut abc = [0u8; 32];
    crypto_xof_shake256_squeeze(&mut state, &mut abc);
    assert_eq!(
        abc,
        unhex_array::<32>("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
    );
    assert!(crypto_xof_shake256_update(&mut state, b"more").is_err());

    let mut state = crypto_xof_shake256_init();
    let mut streamed = vec![0u8; shake256_empty.len()];
    let (first, rest) = streamed.split_at_mut(135);
    let (second, rest) = rest.split_at_mut(2);
    let (third, fourth) = rest.split_at_mut(135);
    for output in [first, second, third, fourth] {
        crypto_xof_shake256_squeeze(&mut state, output);
    }
    assert_eq!(streamed, shake256_empty);
}

#[wasm_bindgen_test]
fn xof_rfc_9861_turboshake_known_answer() {
    // RFC 9861 section 5; `ptn(n)` is `00 01 .. FA` repeated to `n` bytes.
    let ptn = |len: usize| (0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>();

    assert_eq!(
        TurboShake128::compute_to_vec(b"", 64),
        unhex(concat!(
            "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c",
            "3e8ccae2a4dae56c84a04c2385c03c15e8193bdf58737363321691c05462c8df",
        ))
    );
    // The last 32 of 10032 output bytes: 59 full blocks, then a partial one.
    let mut reader = TurboShake128::new().finalize();
    reader.squeeze_to_vec(10032 - 32);
    assert_eq!(
        reader.squeeze_to_vec(32),
        unhex("a3b9b0385900ce761f22aed548e754da10a5242d62e8c658e3f3a923a7555607")
    );
    // `ptn(17^2)` absorbs across a block boundary.
    let mut xof = TurboShake128::new();
    let message = ptn(17 * 17);
    xof.update(&message[..100]);
    xof.update(&message[100..]);
    assert_eq!(
        xof.finalize().squeeze_to_vec(32),
        unhex("96c77c279e0126f7fc07c9b07f5cdae1e0be60bdbe10620040e75d7223a624d2")
    );
    let mut state = crypto_xof_turboshake128_init_with_domain(0x06).expect("domain");
    crypto_xof_turboshake128_update(&mut state, &[0xff]).expect("update");
    let mut output = [0u8; 32];
    crypto_xof_turboshake128_squeeze(&mut state, &mut output);
    assert_eq!(
        output,
        unhex_array::<32>("8ec9c66465ed0d4a6c35d13506718d687a25cb05c74cca1e42501abd83874a67")
    );

    assert_eq!(
        TurboShake256::compute_to_vec(b"", 64),
        unhex(concat!(
            "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db",
            "11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0",
        ))
    );
    let mut reader = TurboShake256::new().finalize();
    reader.squeeze_to_vec(10032 - 32);
    assert_eq!(
        reader.squeeze_to_vec(32),
        unhex("abefa11630c661269249742685ec082f207265dccf2f43534e9c61ba0c9d1d75")
    );
    assert_eq!(
        TurboShake256::compute_to_vec(&ptn(17 * 17), 64),
        unhex(concat!(
            "66b810db8e90780424c0847372fdc95710882fde31c6df75beb9d4cd9305cfca",
            "e35e7b83e8b7e6eb4b78605880116316fe2c078a09b94ad7b8213c0a738b65c0",
        ))
    );
    let mut xof = TurboShake256::with_domain(0x0b).expect("domain");
    xof.update(&[0xff; 7]);
    assert_eq!(
        xof.finalize().squeeze_to_vec(64),
        unhex(concat!(
            "bb36764951ec97e9d85f7ee9a67a7718fc005cf42556be79ce12c0bde50e5736",
            "d6632b0d0dfb202d1bbb8ffe3dd74cb00834fa756cb03471bab13a1e2c16b3c0",
        ))
    );

    // Domain bytes must be in `0x01..=0x7f`.
    for domain in [0x00, 0x80] {
        assert!(TurboShake128::with_domain(domain).is_err());
        assert!(crypto_xof_turboshake256_init_with_domain(domain).is_err());
    }
}

#[wasm_bindgen_test]
fn mlkem768_acvp_known_answer() {
    use dryoc::kem::mlkem768::{self, StackKeyPair};

    // NIST ACVP vectors shared with the native ML-KEM tests.
    let keygen = &records(include_str!(
        "../src/mlkem/test-vectors/mlkem768_acvp_keygen.txt"
    ))[0];
    let seed: [u8; 64] = [unhex(keygen["d"]), unhex(keygen["z"])]
        .concat()
        .try_into()
        .expect("seed length");
    let keypair = StackKeyPair::from_seed(&seed);
    assert_eq!(keypair.public_key.as_slice(), unhex(keygen["ek"]));
    assert_eq!(keypair.secret_key.as_slice(), unhex(keygen["dk"]));

    let encap = &records(include_str!(
        "../src/mlkem/test-vectors/mlkem768_acvp_encap.txt"
    ))[0];
    let mut ciphertext = [0u8; CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES];
    let mut shared_secret = [0u8; 32];
    crypto_kem_mlkem768_enc_deterministic(
        &mut ciphertext,
        &mut shared_secret,
        &field(encap, "ek"),
        &field(encap, "m"),
    )
    .expect("encapsulate");
    assert_eq!(ciphertext.to_vec(), unhex(encap["c"]));
    assert_eq!(shared_secret.to_vec(), unhex(encap["k"]));

    // Valid ciphertexts decapsulate to the encapsulated key and modified
    // ones to the implicit-rejection key; neither is an error.
    for record in records(include_str!(
        "../src/mlkem/test-vectors/mlkem768_acvp_decap.txt"
    )) {
        let keypair = StackKeyPair::from_secret_key(StackByteArray::from(field(&record, "dk")));
        let received: mlkem768::SharedSecret = keypair
            .decapsulate(&field::<CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES>(&record, "c"))
            .expect("decapsulate");
        assert_eq!(
            received.as_slice(),
            unhex(record["k"]),
            "tcid {}",
            record["tcid"]
        );
    }

    // Encapsulation rejects keys that fail the FIPS 203 modulus check.
    for record in records(include_str!(
        "../src/mlkem/test-vectors/mlkem768_acvp_ek_check.txt"
    )) {
        let result: Result<(mlkem768::Ciphertext, mlkem768::SharedSecret), _> =
            mlkem768::encapsulate(&field::<1184>(&record, "ek"));
        assert_eq!(
            result.is_ok(),
            record["valid"] == "true",
            "tcid {}",
            record["tcid"]
        );
    }
}

#[wasm_bindgen_test]
fn xwing_known_answer() {
    use dryoc::kem::{SharedSecret, StackKeyPair};

    // draft-connolly-cfrg-xwing-kem Appendix C.
    for record in records(include_str!("../src/mlkem/test-vectors/xwing_draft.txt")) {
        let keypair = StackKeyPair::from_seed(&field::<32>(&record, "seed"));
        assert_eq!(keypair.public_key.as_slice(), unhex(record["pk"]));
        // The X-Wing secret key is the seed.
        assert_eq!(keypair.secret_key.as_slice(), unhex(record["seed"]));

        let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; 32];
        crypto_kem_xwing_enc_deterministic(
            &mut ciphertext,
            &mut shared_secret,
            keypair.public_key.as_array(),
            &field(&record, "eseed"),
        )
        .expect("encapsulate");
        assert_eq!(ciphertext.to_vec(), unhex(record["ct"]));
        assert_eq!(shared_secret.to_vec(), unhex(record["ss"]));
        let received: SharedSecret = keypair.decapsulate(&ciphertext).expect("decapsulate");
        assert_eq!(received.as_slice(), &shared_secret);

        // A modified ML-KEM part yields an unrelated secret, not an error.
        ciphertext[0] ^= 1;
        let rejected: SharedSecret = keypair.decapsulate(&ciphertext).expect("decapsulate");
        assert_ne!(rejected.as_slice(), &shared_secret);
    }

    // libsodium 1.0.22 results for invalid public keys and low-order or
    // non-canonical X25519 ciphertexts.
    for record in records(include_str!(
        "../src/mlkem/test-vectors/xwing_libsodium_edge.txt"
    )) {
        let mut ciphertext = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
        let mut shared_secret = [0u8; 32];
        let result = match record["op"] {
            "enc_deterministic" => crypto_kem_xwing_enc_deterministic(
                &mut ciphertext,
                &mut shared_secret,
                &field(&record, "pk"),
                &field(&record, "eseed"),
            ),
            "dec" => crypto_kem_xwing_dec(
                &mut shared_secret,
                &field(&record, "ct"),
                &field(&record, "sk"),
            ),
            op => panic!("unknown op {op}"),
        };
        assert_eq!(result.is_ok(), record["rc"] == "0", "{}", record["name"]);
        if let Some(expected) = record.get("ss") {
            assert_eq!(
                shared_secret.to_vec(),
                unhex(expected),
                "{}",
                record["name"]
            );
        }
    }
}

#[wasm_bindgen_test]
fn sealedbox_hpke_known_answer() {
    use dryoc::dryocsealedbox::{DryocSealedBox, SEALBYTES, StackKeyPair, VecBox};

    // draft-ietf-hpke-pq-05 Appendix A.5, shared with the native sealed-box
    // tests. It uses a non-empty `info` and associated data, so it checks
    // the key schedule helpers; sealed boxes use neither.
    let record = &records(include_str!(
        "../src/mlkem/test-vectors/hpke_xwing_hkdfsha256_chacha20poly1305.txt"
    ))[0];
    let recipient = StackKeyPair::from_secret_key(StackByteArray::from(field(record, "skRm")));
    assert_eq!(recipient.public_key.as_slice(), unhex(record["pkRm"]));

    let mut enc = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
    let mut shared_secret = [0u8; 32];
    crypto_kem_xwing_enc_deterministic(
        &mut enc,
        &mut shared_secret,
        recipient.public_key.as_array(),
        &field(record, "ikmE"),
    )
    .expect("encapsulate");
    assert_eq!(enc.to_vec(), unhex(record["enc"]));
    assert_eq!(shared_secret.to_vec(), unhex(record["shared_secret"]));
    let (key, nonce) = hpke_key_schedule(&shared_secret, &unhex(record["info"]));
    assert_eq!(key.to_vec(), unhex(record["key"]));
    assert_eq!(nonce.to_vec(), unhex(record["base_nonce"]));
    let plaintext = unhex(record["pt"]);
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    crypto_aead_chacha20poly1305_ietf_encrypt(
        &mut ciphertext,
        &plaintext,
        Some(&unhex(record["aad"])),
        &nonce,
        &key,
    )
    .expect("encrypt");
    assert_eq!(ciphertext, unhex(record["ct"]));

    // A sealed box is `enc || ciphertext || tag` for an empty `info` and no
    // associated data.
    let message = b"Beauty is truth, truth beauty";
    let (key, nonce) = hpke_key_schedule(&shared_secret, b"");
    let mut sealed = enc.to_vec();
    sealed.resize(SEALBYTES + message.len(), 0);
    crypto_aead_chacha20poly1305_ietf_encrypt(
        &mut sealed[CRYPTO_KEM_XWING_CIPHERTEXTBYTES..],
        message,
        None,
        &nonce,
        &key,
    )
    .expect("encrypt");
    let opened = VecBox::from_bytes(&sealed)
        .expect("parse")
        .unseal_to_vec(&recipient)
        .expect("unseal");
    assert_eq!(opened, message);

    // A box sealed by the crate opens with the HPKE receiver steps.
    let crate_sealed = DryocSealedBox::seal_to_vecbox(message, &recipient.public_key)
        .expect("seal")
        .to_vec();
    assert_eq!(crate_sealed.len(), SEALBYTES + message.len());
    let (enc, ciphertext) = crate_sealed.split_at(CRYPTO_KEM_XWING_CIPHERTEXTBYTES);
    let mut shared_secret = [0u8; 32];
    crypto_kem_xwing_dec(
        &mut shared_secret,
        enc.try_into().expect("enc length"),
        recipient.secret_key.as_array(),
    )
    .expect("decapsulate");
    let (key, nonce) = hpke_key_schedule(&shared_secret, b"");
    let mut opened = vec![0u8; message.len()];
    crypto_aead_chacha20poly1305_ietf_decrypt(&mut opened, ciphertext, None, &nonce, &key)
        .expect("decrypt");
    assert_eq!(opened, message);

    // Changing a byte of `enc`, the ciphertext or the tag fails to open, and
    // boxes shorter than the overhead are rejected.
    for index in [
        0,
        CRYPTO_KEM_XWING_CIPHERTEXTBYTES - 1,
        CRYPTO_KEM_XWING_CIPHERTEXTBYTES,
        sealed.len() - 1,
    ] {
        let mut tampered = sealed.clone();
        tampered[index] ^= 1;
        assert!(
            VecBox::from_bytes(&tampered)
                .expect("parse")
                .unseal_to_vec(&recipient)
                .is_err(),
            "byte {index}"
        );
    }
    assert!(VecBox::from_bytes(&sealed[..SEALBYTES - 1]).is_err());
}
