use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::classic::crypto_secretbox::{Key, Mac, Nonce};
use crate::error::Error;
use crate::poly1305::{Key as Poly1305Key, Poly1305};
use crate::salsa20::XSalsa20;
use crate::utils::zeroize_bytes;

/// Bytes of the first keystream block that key the MAC; the message's
/// keystream starts at the block's remaining bytes.
const MAC_KEY_BYTES: usize = 32;

/// Encrypts `input` (or `output` in place when `input` is `None`) into
/// `output` and writes its MAC. The first keystream block (the MAC key and
/// the keystream of the message's first 32 bytes) is produced as the head
/// block of the message's keystream run, so that a vector kernel that
/// computes a scalar block beside its lane set gets it for a fraction of a
/// dependent scalar block.
fn seal(output: &mut [u8], input: Option<&[u8]>, mac: &mut Mac, nonce: &Nonce, key: &Key) {
    debug_assert!(input.is_none_or(|input| input.len() == output.len()));

    let mut mac_key = Poly1305Key::new();
    {
        let mut cipher = XSalsa20::new(key, nonce);
        let mut head = [0u8; 64];
        let split = output.len().min(64 - MAC_KEY_BYTES);
        let (front, rest) = output.split_at_mut(split);
        match input {
            Some(input) => {
                cipher.apply_keystream_b2b_with_head(&mut head, &input[split..], rest);
                for ((out, byte), ks) in front.iter_mut().zip(input).zip(&head[MAC_KEY_BYTES..]) {
                    *out = byte ^ ks;
                }
            }
            None => {
                cipher.apply_keystream_with_head(&mut head, rest);
                for (byte, ks) in front.iter_mut().zip(&head[MAC_KEY_BYTES..]) {
                    *byte ^= ks;
                }
            }
        }
        mac_key.copy_from_slice(&head[..MAC_KEY_BYTES]);
        zeroize_bytes(&mut head);
    }

    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    computed_mac.update(output);
    computed_mac.finalize(mac);
}

/// Verifies `mac` over `input` (or `output` when `input` is `None`) and, only
/// if it matches, decrypts into `output`.
fn open(
    output: &mut [u8],
    input: Option<&[u8]>,
    mac: &Mac,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    debug_assert!(input.is_none_or(|input| input.len() == output.len()));

    let mut cipher = XSalsa20::new(key, nonce);
    let mut mac_key = Poly1305Key::new();
    cipher.apply_keystream(&mut mac_key);

    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    computed_mac.update(input.unwrap_or(output));
    let computed_mac = computed_mac.finalize_to_array();

    if mac.ct_eq(&computed_mac).unwrap_u8() == 1 {
        match input {
            Some(input) => cipher.apply_keystream_b2b(input, output),
            None => cipher.apply_keystream(output),
        }
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

pub(crate) fn crypto_secretbox_detached_b2b(
    ciphertext: &mut [u8],
    mac: &mut Mac,
    message: &[u8],
    nonce: &Nonce,
    key: &Key,
) {
    seal(ciphertext, Some(message), mac, nonce, key);
}

pub(crate) fn crypto_secretbox_open_detached_b2b(
    message: &mut [u8],
    mac: &Mac,
    ciphertext: &[u8],
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    open(message, Some(ciphertext), mac, nonce, key)
}

pub(crate) fn crypto_secretbox_detached_inplace(
    data: &mut [u8],
    mac: &mut Mac,
    nonce: &Nonce,
    key: &Key,
) {
    seal(data, None, mac, nonce, key);
}

pub(crate) fn crypto_secretbox_open_detached_inplace(
    data: &mut [u8],
    mac: &Mac,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    open(data, None, mac, nonce, key)
}
