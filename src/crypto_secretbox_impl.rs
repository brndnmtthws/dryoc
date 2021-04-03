use generic_array::GenericArray;
use salsa20::cipher::{NewStreamCipher, SyncStreamCipher};
use salsa20::XSalsa20;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto_secretbox::{Key, Mac, Nonce};
use crate::error::Error;
use crate::poly1305::Poly1305;
use crate::types::*;

pub(crate) fn crypto_secretbox_detached_inplace(
    data: &mut [u8],
    mac: &mut Mac,
    nonce: &Nonce,
    key: &Key,
) {
    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = crate::poly1305::Key::new();
    cipher.apply_keystream(&mut mac_key);

    let mut computed_mac = Poly1305::new(&mac_key);

    mac_key.zeroize();

    cipher.apply_keystream(data);

    computed_mac.update(data);
    let computed_mac = computed_mac.finish();

    mac.copy_from_slice(&computed_mac);
}

pub(crate) fn crypto_secretbox_open_detached_inplace(
    data: &mut [u8],
    mac: &Mac,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let mut cipher = XSalsa20::new(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(nonce),
    );

    let mut mac_key = crate::poly1305::Key::new();
    cipher.apply_keystream(&mut mac_key);

    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    computed_mac.update(data);
    let computed_mac = computed_mac.finish();

    cipher.apply_keystream(data);

    if mac.ct_eq(&computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("decryption error (authentication failure)"))
    }
}
