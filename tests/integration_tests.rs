#[test]
fn test_dryocbox() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = Nonce::gen();
    let message = b"hey";

    let dryocbox = DryocBox::encrypt(
        message,
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

    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_dryocsecretbox() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::gen();
    let nonce = Nonce::gen();
    let message = b"hey";

    let dryocsecretbox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let decrypted = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocbox_serde() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = Nonce::gen();
    let message = b"hey friend";

    let dryocbox = DryocBox::encrypt(
        message,
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

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(feature = "serde")]
#[test]
fn test_dryocsecretbox_serde() {
    use dryoc::dryocsecretbox::*;

    let secret_key = Key::gen();
    let nonce = Nonce::gen();
    let message = b"hey buddy bro";

    let dryocsecretbox = DryocSecretBox::encrypt(message, &nonce, &secret_key);

    let json = serde_json::to_string(&dryocsecretbox).expect("doesn't serialize");

    let dryocsecretbox: DryocSecretBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message, decrypted.as_slice());
}

#[test]
fn test_streams() {
    use dryoc::crypto_secretstream_xchacha20poly1305::*;
    let message1 = b"Arbitrary data to encrypt";
    let message2 = b"split into";
    let message3 = b"three messages";

    // Generate a key
    let key = crypto_secretstream_xchacha20poly1305_keygen();

    // Create stream push state
    let mut state = State::new();
    let header = crypto_secretstream_xchacha20poly1305_init_push(&mut state, &key);

    // Encrypt a series of messages
    let c1 = crypto_secretstream_xchacha20poly1305_push(&mut state, message1, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c2 = crypto_secretstream_xchacha20poly1305_push(&mut state, message2, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c3 = crypto_secretstream_xchacha20poly1305_push(&mut state, message3, None, Tag::FINAL)
        .expect("Encrypt failed");

    // Create stream pull state, using the same key as above with a new state.
    let mut state = State::new();
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

    assert_eq!(tag1, Tag::MESSAGE);
    assert_eq!(tag2, Tag::MESSAGE);
    assert_eq!(tag3, Tag::FINAL);
}

#[test]
fn test_streams_rustaceous() {
    use dryoc::dryocstream::*;
    let message1 = b"Arbitrary data to encrypt";
    let message2 = b"split into";
    let message3 = b"three messages";

    let key = Key::gen();

    let (mut push_stream, header) = DryocStream::init_push(&key);
    let c1 = push_stream
        .encrypt(message1, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c2 = push_stream
        .encrypt(message2, None, Tag::MESSAGE)
        .expect("Encrypt failed");
    let c3 = push_stream
        .encrypt(message3, None, Tag::FINAL)
        .expect("Encrypt failed");

    let mut pull_stream = DryocStream::init_pull(&key, &header);

    let (m1, tag1) = pull_stream.decrypt(&c1, None).expect("Decrypt failed");
    let (m2, tag2) = pull_stream.decrypt(&c2, None).expect("Decrypt failed");
    let (m3, tag3) = pull_stream.decrypt(&c3, None).expect("Decrypt failed");

    assert_eq!(message1, m1.as_slice());
    assert_eq!(message2, m2.as_slice());
    assert_eq!(message3, m3.as_slice());

    assert_eq!(tag1, Tag::MESSAGE);
    assert_eq!(tag2, Tag::MESSAGE);
    assert_eq!(tag3, Tag::FINAL);
}

#[cfg(all(feature = "serde", not(feature = "base64")))]
#[test]
fn test_dryocbox_serde_known_good() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::from_slices(
        [
            19, 102, 68, 158, 243, 5, 191, 249, 31, 150, 224, 99, 131, 223, 250, 86, 183, 59, 12,
            207, 166, 197, 248, 213, 150, 17, 186, 94, 179, 184, 168, 31,
        ],
        [
            32, 93, 215, 217, 145, 250, 115, 60, 43, 161, 237, 154, 192, 46, 239, 131, 101, 167,
            229, 195, 16, 170, 88, 53, 253, 30, 21, 29, 150, 214, 140, 64,
        ],
    );
    let recipient_keypair = KeyPair::from_slices(
        [
            203, 213, 109, 27, 115, 197, 227, 35, 161, 27, 73, 179, 181, 104, 237, 253, 207, 206,
            186, 108, 254, 67, 246, 221, 47, 60, 68, 37, 148, 169, 242, 109,
        ],
        [
            0, 209, 170, 57, 221, 216, 185, 113, 114, 217, 32, 72, 65, 99, 132, 187, 137, 68, 72,
            19, 14, 237, 37, 220, 77, 172, 148, 163, 106, 5, 201, 101,
        ],
    );
    let nonce = Nonce::from_slice(&[
        52, 53, 237, 208, 81, 208, 57, 122, 253, 6, 222, 28, 25, 157, 13, 108, 28, 38, 41, 60, 242,
        45, 126, 101,
    ]);
    let message = b"hey friend";

    let dryocbox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let json = serde_json::to_string(&dryocbox).expect("doesn't serialize");

    assert_eq!(json, "{\"tag\":[105,111,140,72,164,126,195,203,17,25,161,50,61,65,22,82],\"data\":[183,35,105,8,103,239,207,9,37,137]}");

    let dryocbox: DryocBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}

#[cfg(all(feature = "serde", feature = "base64"))]
#[test]
fn test_dryocbox_serde_known_good() {
    use dryoc::dryocbox::*;

    let sender_keypair = KeyPair::from_slices(
        [
            19, 102, 68, 158, 243, 5, 191, 249, 31, 150, 224, 99, 131, 223, 250, 86, 183, 59, 12,
            207, 166, 197, 248, 213, 150, 17, 186, 94, 179, 184, 168, 31,
        ],
        [
            32, 93, 215, 217, 145, 250, 115, 60, 43, 161, 237, 154, 192, 46, 239, 131, 101, 167,
            229, 195, 16, 170, 88, 53, 253, 30, 21, 29, 150, 214, 140, 64,
        ],
    );
    let recipient_keypair = KeyPair::from_slices(
        [
            203, 213, 109, 27, 115, 197, 227, 35, 161, 27, 73, 179, 181, 104, 237, 253, 207, 206,
            186, 108, 254, 67, 246, 221, 47, 60, 68, 37, 148, 169, 242, 109,
        ],
        [
            0, 209, 170, 57, 221, 216, 185, 113, 114, 217, 32, 72, 65, 99, 132, 187, 137, 68, 72,
            19, 14, 237, 37, 220, 77, 172, 148, 163, 106, 5, 201, 101,
        ],
    );
    let nonce = Nonce::from_slice(&[
        52, 53, 237, 208, 81, 208, 57, 122, 253, 6, 222, 28, 25, 157, 13, 108, 28, 38, 41, 60, 242,
        45, 126, 101,
    ]);
    let message = b"hey friend";

    let dryocbox = DryocBox::encrypt(
        message,
        &nonce,
        &recipient_keypair.public_key,
        &sender_keypair.secret_key,
    )
    .expect("unable to encrypt");

    let json = serde_json::to_string(&dryocbox).expect("doesn't serialize");

    assert_eq!(
        json,
        "{\"tag\":\"aW+MSKR+w8sRGaEyPUEWUg==\",\"data\":\"tyNpCGfvzwkliQ==\"}"
    );

    let dryocbox: DryocBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocbox
        .decrypt(
            &nonce,
            &sender_keypair.public_key,
            &recipient_keypair.secret_key,
        )
        .expect("decrypt failed");

    assert_eq!(message, decrypted.as_slice());
}
