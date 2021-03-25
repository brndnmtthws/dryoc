#[test]
fn test_dryocbox() {
    use dryoc::prelude::*;

    let sender_keypair = KeyPair::gen();
    let recipient_keypair = KeyPair::gen();
    let nonce = Nonce::gen();
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
    let nonce = Nonce::gen();
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
    let nonce = Nonce::gen();
    let message = "hey";

    let dryocbox = DryocBox::encrypt(
        &message.into(),
        &nonce,
        &recipient_keypair.clone().into(),
        &sender_keypair.clone().into(),
    )
    .expect("unable to encrypt");

    let json = serde_json::to_string(&dryocbox).expect("doesn't serialize");

    let dryocbox: DryocBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocbox
        .decrypt(&nonce, &sender_keypair.into(), &recipient_keypair.into())
        .expect("unable to decrypt");

    assert_eq!(message.as_bytes(), decrypted.as_slice());
}
#[cfg(feature = "serde")]
#[test]
fn test_dryocsecretbox_serde() {
    use dryoc::prelude::*;

    let secret_key = SecretBoxKey::gen();
    let nonce = Nonce::gen();
    let message = "hey";

    let dryocsecretbox = DryocSecretBox::encrypt(&message.into(), &nonce, &secret_key);

    let json = serde_json::to_string(&dryocsecretbox).expect("doesn't serialize");

    let dryocsecretbox: DryocSecretBox = serde_json::from_str(&json).unwrap();

    let decrypted = dryocsecretbox
        .decrypt(&nonce, &secret_key)
        .expect("unable to decrypt");

    assert_eq!(message.as_bytes(), decrypted.as_slice());
}
