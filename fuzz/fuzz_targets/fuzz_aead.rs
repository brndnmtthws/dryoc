#![no_main]
use dryoc::classic::crypto_aead_xchacha20poly1305_ietf::{
    Mac, crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_decrypt_inplace,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_encrypt_inplace,
};
use dryoc::constants::{
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
};
use dryoc::dryocaead::{Key, Nonce, VecBox, VecEnvelope};
use dryoc::types::{ByteArray, Bytes};
use libfuzzer_sys::fuzz_target;

fn fill<const N: usize>(data: &mut &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = out.len().min(data.len());
    out[..n].copy_from_slice(&data[..n]);
    *data = &data[n..];
    out
}

fn take_len_prefixed(data: &mut &[u8]) -> Vec<u8> {
    let len = match data.split_first() {
        Some((len, rest)) => {
            *data = rest;
            (*len as usize).min(data.len())
        }
        None => 0,
    };
    let out = data[..len].to_vec();
    *data = &data[len..];
    out
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let key = fill::<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>(&mut data);
    let nonce = fill::<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>(&mut data);
    let aad = take_len_prefixed(&mut data);
    let message = take_len_prefixed(&mut data);
    let raw = data;
    let aad = if aad.is_empty() {
        None
    } else {
        Some(aad.as_slice())
    };

    let mut combined = vec![0u8; message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
    crypto_aead_xchacha20poly1305_ietf_encrypt(&mut combined, &message, aad, &nonce, &key)
        .expect("classic combined encrypt");

    let mut decrypted = vec![0u8; message.len()];
    crypto_aead_xchacha20poly1305_ietf_decrypt(&mut decrypted, &combined, aad, &nonce, &key)
        .expect("classic combined decrypt");
    assert_eq!(decrypted, message);

    let mut detached = vec![0u8; message.len()];
    let mut mac = Mac::default();
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        &mut detached,
        &mut mac,
        &message,
        aad,
        &nonce,
        &key,
    )
    .expect("classic detached encrypt");
    assert_eq!(detached, combined[..message.len()]);
    assert_eq!(mac.as_slice(), &combined[message.len()..]);

    let mut detached_decrypted = vec![0u8; message.len()];
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        &mut detached_decrypted,
        &detached,
        &mac,
        aad,
        &nonce,
        &key,
    )
    .expect("classic detached decrypt");
    assert_eq!(detached_decrypted, message);

    let mut inplace = message.clone();
    inplace.resize(message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, 0);
    crypto_aead_xchacha20poly1305_ietf_encrypt_inplace(&mut inplace, aad, &nonce, &key)
        .expect("classic inplace encrypt");
    assert_eq!(inplace, combined);

    crypto_aead_xchacha20poly1305_ietf_decrypt_inplace(&mut inplace, aad, &nonce, &key)
        .expect("classic inplace decrypt");
    assert_eq!(&inplace[..message.len()], message.as_slice());

    let rust_key = Key::from(key);
    let rust_nonce = Nonce::from(nonce);
    let aead = VecBox::encrypt_to_vecbox(&message, aad, &rust_nonce, &rust_key)
        .expect("rustaceous encrypt");
    assert_eq!(aead.to_vec(), combined);
    assert_eq!(
        aead.decrypt_to_vec(aad, &rust_nonce, &rust_key)
            .expect("rustaceous decrypt"),
        message
    );

    let mut envelope_bytes = rust_nonce.to_vec();
    envelope_bytes.extend_from_slice(&combined);
    let envelope = VecEnvelope::from_bytes(&envelope_bytes).expect("envelope parses");
    assert_eq!(envelope.to_vec(), envelope_bytes);
    assert_eq!(
        envelope
            .open_to_vec(aad, &rust_key)
            .expect("rustaceous envelope open"),
        message
    );

    if let Ok(parsed) = VecBox::from_bytes(raw) {
        let bytes = parsed.to_vec();
        let reparsed = VecBox::from_bytes(&bytes).expect("box reparses");
        assert_eq!(reparsed.to_vec(), bytes);

        let mut output = vec![0xa5; parsed.data().len()];
        let original = output.clone();
        match crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            &mut output,
            parsed.data().as_slice(),
            parsed.tag().as_array(),
            aad,
            &nonce,
            &key,
        ) {
            Ok(()) => {
                let mut encrypted = vec![
                    0u8;
                    output.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
                ];
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    &mut encrypted,
                    &output,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("re-encrypt parsed plaintext");
                assert_eq!(encrypted, bytes);
            }
            Err(_) => assert_eq!(output, original),
        }
    }

    if let Ok(parsed) = VecEnvelope::from_bytes(raw) {
        let bytes = parsed.to_vec();
        let reparsed = VecEnvelope::from_bytes(&bytes).expect("envelope reparses");
        assert_eq!(reparsed.to_vec(), bytes);
        let _ = parsed.open_to_vec(aad, &rust_key);
    }

    if raw.len() >= CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES {
        let mut output = vec![0xa5; raw.len() - CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        let original = output.clone();
        match crypto_aead_xchacha20poly1305_ietf_decrypt(&mut output, raw, aad, &nonce, &key) {
            Ok(()) => {
                let mut encrypted =
                    vec![0u8; output.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    &mut encrypted,
                    &output,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("re-encrypt raw plaintext");
                assert_eq!(encrypted, raw);
            }
            Err(_) => assert_eq!(output, original),
        }
    }
});
