use std::vec;

#[test]
fn test_dryocbox() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = Nonce::gen();
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
}

#[test]
fn test_dryocsecretbox() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::gen();
    let nonce = Nonce::gen();
    let message = b"hey";

    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocbox_serde_json() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = Nonce::gen();
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

    let secret_key = Key::gen();
    let nonce = Nonce::gen();
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
fn test_dryocbox_serde_bincode() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = Nonce::gen();
    let message = b"hey friend";

    let dryocbox: VecBox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let encoded = bincode::serialize(&dryocbox).expect("doesn't serialize");

    let dryocbox: VecBox = bincode::deserialize(&encoded).unwrap();

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
fn test_dryocsecretbox_serde_bincode() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::gen();
    let nonce = Nonce::gen();
    let message = b"hey buddy bro";

    let dryocsecretbox: VecBox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let encoded = bincode::serialize(&dryocsecretbox).expect("doesn't serialize");

    let dryocsecretbox: VecBox = bincode::deserialize(&encoded).unwrap();

    let decrypted: Vec<u8> = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(all(feature = "serde", feature = "nightly"))]
#[test]
fn test_dryocsecretbox_serde_protected_bincode() {
    use dryoc::dryocsecretbox::protected::*;
    use dryoc::dryocsecretbox::*;

    let secret_key = protected::Key::gen_locked()
        .and_then(|s| s.mprotect_readonly())
        .expect("key failed");

    let nonce = protected::Nonce::gen_readonly_locked().expect("nonce failed");

    let message =
        HeapBytes::from_slice_into_readonly_locked(b"Secret message from the tooth fairy")
            .expect("message failed");

    let dryocsecretbox: protected::LockedBox =
        DryocSecretBox::encrypt(&message, &nonce, &secret_key);

    let encoded = bincode::serialize(&dryocsecretbox).expect("doesn't serialize");

    let dryocsecretbox: protected::LockedBox = bincode::deserialize(&encoded).unwrap();

    let decrypted: LockedBytes = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("decrypt failed");

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

    let key = Key::gen();

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

#[cfg(feature = "nightly")]
#[test]
fn test_dryocsecretbox_protected() {
    use dryoc::dryocsecretbox::protected::*;
    use dryoc::dryocsecretbox::*;

    let secret_key = protected::Key::gen_locked()
        .and_then(|s| s.mprotect_readonly())
        .expect("key failed");

    let nonce = protected::Nonce::gen_readonly_locked().expect("nonce failed");

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

#[cfg(feature = "nightly")]
#[test]
fn test_dryocbox_protected() {
    use dryoc::dryocbox::protected::*;
    use dryoc::dryocbox::DryocBox;

    let sender_keypair = LockedKeyPair::gen_locked_keypair().expect("keypair");
    let recipient_keypair = LockedKeyPair::gen_locked_keypair().expect("keypair");

    let nonce = Nonce::gen_readonly_locked().expect("nonce failed");

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
}

#[cfg(feature = "nightly")]
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

    let key = Key::gen_readonly_locked().expect("key failed");

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

    let recipient_keypair = KeyPair::gen();
    let message = b"juicybox";

    let dryocbox =
        DryocBox::seal_to_vecbox(message, &recipient_keypair.public_key).expect("unable to seal");

    let decrypted = dryocbox
        .unseal_to_vec(&recipient_keypair)
        .expect("unable to unseal");

    assert_eq!(message, decrypted.as_slice());
}
