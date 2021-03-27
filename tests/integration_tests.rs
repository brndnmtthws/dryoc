#[test]
fn test_dryocbox() {
    use dryoc::prelude::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = BoxNonce::gen();
    let message = "hey";

    let dryocbox = DryocBox::encrypt(
        &message.into(),
        &nonce,
        &recipient_keypair.public_key.clone(),
        &sender_keypair.secret_key.clone(),
    )
    .expect("unable to encrypt");

    let decrypted = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("unable to decrypt");

    assert_eq!(message.as_bytes(), decrypted.as_slice());
}

#[test]
fn test_dryocsecretbox() {
    use dryoc::prelude::*;

    let secret_key = SecretBoxKey::gen();
    let nonce = SecretBoxNonce::gen();
    let message = "hey";

    let dryocsecretbox = DryocSecretBox::encrypt(&message.into(), &nonce, &secret_key);

    let decrypted = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message.as_bytes(), decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocbox_serde() {
    use dryoc::prelude::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = BoxNonce::gen();
    let message = "hey";

    let dryocbox = DryocBox::encrypt(
        &message.into(),
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let json = serde_json::to_string(&dryocbox).expect("doesn't serialize");

    let dryocbox: DryocBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message.as_bytes(), decrypted);
}
#[cfg(feature = "serde")]
#[test]
fn test_dryocsecretbox_serde() {
    use dryoc::prelude::*;

    let secret_key = SecretBoxKey::gen();
    let nonce = SecretBoxNonce::gen();
    let message = "hey";

    let dryocsecretbox = DryocSecretBox::encrypt(&message.into(), &nonce, &secret_key);

    let json = serde_json::to_string(&dryocsecretbox).expect("doesn't serialize");

    let dryocsecretbox: DryocSecretBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message.as_bytes(), decrypted.as_slice());
}

#[test]
fn test_streams() {
    use dryoc::prelude::*;
    let message1 = b"Arbitrary data to encrypt";
    let message2 = b"split into";
    let message3 = b"three messages";

    // Generate a key
    let key = crypto_secretstream_xchacha20poly1305_keygen();

    // Create stream push state
    let mut state = SecretStreamXchacha20poly1305State::new();
    let header = crypto_secretstream_xchacha20poly1305_init_push(&mut state, &key);

    // Encrypt a series of messages
    let c1 =
        crypto_secretstream_xchacha20poly1305_push(&mut state, message1, None, StreamTag::MESSAGE)
            .expect("Encrypt failed");
    let c2 =
        crypto_secretstream_xchacha20poly1305_push(&mut state, message2, None, StreamTag::MESSAGE)
            .expect("Encrypt failed");
    let c3 =
        crypto_secretstream_xchacha20poly1305_push(&mut state, message3, None, StreamTag::FINAL)
            .expect("Encrypt failed");

    // Create stream pull state, using the same key as above with a new state.
    let mut state = SecretStreamXchacha20poly1305State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &&header, &key);

    // Decrypt the stream of messages
    let (m1, tag1) =
        crypto_secretstream_xchacha20poly1305_pull(&mut state, &c1, None).expect("Decrypt failed");
    let (m2, tag2) =
        crypto_secretstream_xchacha20poly1305_pull(&mut state, &c2, None).expect("Decrypt failed");
    let (m3, tag3) =
        crypto_secretstream_xchacha20poly1305_pull(&mut state, &c3, None).expect("Decrypt failed");

    assert_eq!(message1, m1.as_slice());
    assert_eq!(message2, m2.as_slice());
    assert_eq!(message3, m3.as_slice());

    assert_eq!(tag1, StreamTag::MESSAGE);
    assert_eq!(tag2, StreamTag::MESSAGE);
    assert_eq!(tag3, StreamTag::FINAL);
}
