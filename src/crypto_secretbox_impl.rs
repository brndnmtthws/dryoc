use crate::crypto_secretbox::{Key, Mac, Nonce};
use crate::error::Error;
use crate::poly1305::Poly1305;
use crate::types::*;

use generic_array::GenericArray;
use salsa20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    XSalsa20,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub(crate) fn crypto_secretbox_detached_inplace(
    mac: &mut Mac,
    data: &mut Vec<u8>,
    nonce: &Nonce,
    key: &Key,
) {
    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key.as_slice()),
        &GenericArray::from_slice(nonce.as_slice()),
    );

    let mut mac_key = crate::poly1305::Key::new();
    cipher.apply_keystream(&mut mac_key);

    let mut computed_mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    cipher.apply_keystream(data.as_mut_slice());

    computed_mac.update(data.as_slice());
    let computed_mac = computed_mac.finish();

    mac.copy_from_slice(&computed_mac);
}

pub(crate) fn crypto_secretbox_open_detached_inplace(
    mac: &Mac,
    data: &mut Vec<u8>,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let mut nonce_prefix: [u8; 16] = [0; 16];
    nonce_prefix.clone_from_slice(&nonce[..16]);

    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key.as_slice()),
        &GenericArray::from_slice(nonce.as_slice()),
    );

    let mut mac_key = crate::poly1305::Key::new();
    cipher.apply_keystream(&mut mac_key);

    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    computed_mac.update(data.as_slice());
    let computed_mac = computed_mac.finish();

    cipher.apply_keystream(data.as_mut_slice());

    if mac.as_slice().ct_eq(&computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("decryption error (authentication failure)"))
    }
}
