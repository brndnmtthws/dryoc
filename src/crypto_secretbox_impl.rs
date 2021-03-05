use crate::constants::*;
use crate::error::Error;
use crate::types::*;

use generic_array::GenericArray;
use poly1305::{universal_hash::NewUniversalHash, Poly1305};
use salsa20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    XSalsa20,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub(crate) fn crypto_secretbox_detached_inplace(
    cryptobox: &mut CryptoBox,
    nonce: &Nonce,
    key: &SecretboxKey,
) {
    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut *mac_key);

    let mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    cipher.apply_keystream(cryptobox.data.as_mut_slice());

    cryptobox.mac = mac
        .compute_unpadded(cryptobox.data.as_slice())
        .into_bytes()
        .into();
}

pub(crate) fn crypto_secretbox_open_detached_inplace(
    cryptobox: &mut CryptoBox,
    nonce: &Nonce,
    key: &Input,
) -> Result<(), Error> {
    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut *mac_key);

    let mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    let mac: [u8; CRYPTO_SECRETBOX_MACBYTES] = mac
        .compute_unpadded(cryptobox.data.as_slice())
        .into_bytes()
        .into();

    cipher.apply_keystream(cryptobox.data.as_mut_slice());

    if mac.ct_eq(&cryptobox.mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("decryption error (authentication failure)"))
    }
}
