#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use dryoc::auth::Auth;
use dryoc::classic::crypto_generichash::crypto_generichash;
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
use dryoc::types::{Bytes, StackByteArray};
use wasm_bindgen_test::wasm_bindgen_test;

fn unhex(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("valid hex")
}

fn unhex_array<const N: usize>(hex: &str) -> [u8; N] {
    unhex(hex).try_into().expect("expected length")
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

    let subkey: Vec<u8> = kdf.derive_subkey::<16, _>(0).expect("derive failed");
    assert_eq!(subkey, unhex("f885a670a774b20d98fd80412dd3eb6c"));

    let subkey: Vec<u8> = kdf.derive_subkey::<32, _>(1).expect("derive failed");
    assert_eq!(
        subkey,
        unhex("a74d317a77e218b974eb6823b5e200dee5f9bec1af011a7d7ef6211a0c6835a5")
    );

    let subkey: Vec<u8> = kdf.derive_subkey::<64, _>(u64::MAX).expect("derive failed");
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

    let hash: Vec<u8> = GenericHash::<64, 64>::hash(b"", Some(&key)).expect("hash failed");
    assert_eq!(hash, expected);
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
