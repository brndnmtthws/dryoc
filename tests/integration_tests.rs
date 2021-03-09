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
        &recipient_keypair.clone().into(),
        &sender_keypair.clone().into(),
    )
    .expect("unable to encrypt");

    let decrypted = dryocbox
        .decrypt(&nonce, &sender_keypair.into(), &recipient_keypair.into())
        .expect("unable to decrypt");

    assert_eq!(message.as_bytes(), decrypted.as_slice());
}
