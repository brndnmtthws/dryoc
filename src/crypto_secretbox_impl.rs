use crate::constants::CRYPTO_SECRETBOX_MACBYTES;
use crate::error::Error;
use crate::nonce::Nonce;
use crate::types::{InputBase, MacBase, SecretBoxKeyBase};

use generic_array::GenericArray;
use poly1305::{universal_hash::NewUniversalHash, Poly1305};
use salsa20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    XSalsa20,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub(crate) fn crypto_secretbox_detached_inplace(
    mac: &mut MacBase,
    data: &mut Vec<u8>,
    nonce: &Nonce,
    key: &SecretBoxKeyBase,
) {
    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut *mac_key);

    let computed_mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    cipher.apply_keystream(data.as_mut_slice());

    let computed_mac = computed_mac.compute_unpadded(data.as_slice()).into_bytes();
    mac.copy_from_slice(&computed_mac);
}

pub(crate) fn crypto_secretbox_open_detached_inplace(
    mac: &MacBase,
    data: &mut Vec<u8>,
    nonce: &Nonce,
    key: &InputBase,
) -> Result<(), Error> {
    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut *mac_key);

    let computed_mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    let computed_mac: [u8; CRYPTO_SECRETBOX_MACBYTES] = computed_mac
        .compute_unpadded(data.as_slice())
        .into_bytes()
        .into();

    cipher.apply_keystream(data.as_mut_slice());

    if mac.ct_eq(&computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("decryption error (authentication failure)"))
    }
}
