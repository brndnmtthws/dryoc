use zeroize::Zeroize;

use crate::classic::crypto_secretbox::{Key, Mac, Nonce};
use crate::error::Error;
use crate::poly1305::{Key as Poly1305Key, Poly1305};
use crate::salsa20::XSalsa20;
use crate::utils::{verify_ct, zeroize_bytes};

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

    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    if output.len() >= FRONT + 2 * XSalsa20::POLY_CHUNK && XSalsa20::poly_stitched() {
        return seal_stitched(output, input, mac, nonce, key);
    }
    seal_sequential(output, input, mac, nonce, key);
}

/// [`seal`] as the keystream then the MAC over the whole ciphertext.
fn seal_sequential(
    output: &mut [u8],
    input: Option<&[u8]>,
    mac: &mut Mac,
    nonce: &Nonce,
    key: &Key,
) {
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

/// Message bytes whose keystream is the second half of the first block.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
const FRONT: usize = 64 - MAC_KEY_BYTES;

/// [`seal`] with the stitched AArch64 kernel (SVE2): the first run gives the
/// MAC key block and the keystream of the first `FRONT + POLY_CHUNK` message
/// bytes; every later run of whole blocks also MACs a chunk of the
/// ciphertext before it ([`XSalsa20::apply_keystream_poly`]), and the rest
/// is MACed at the end. The output and tag are those of [`seal`].
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
fn seal_stitched(output: &mut [u8], input: Option<&[u8]>, mac: &mut Mac, nonce: &Nonce, key: &Key) {
    let first = FRONT + XSalsa20::POLY_CHUNK;
    let mut cipher = XSalsa20::new(key, nonce);
    let mut head = [0u8; 64];
    let (front, rest) = output[..first].split_at_mut(FRONT);
    match input {
        Some(input) => {
            cipher.apply_keystream_b2b_with_head(&mut head, &input[FRONT..first], rest);
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
    let mut mac_key = Poly1305Key::new();
    mac_key.copy_from_slice(&head[..MAC_KEY_BYTES]);
    zeroize_bytes(&mut head);
    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    let (done, mac_done) = cipher.apply_keystream_poly(input, output, first, 0, &mut computed_mac);
    match input {
        Some(input) => cipher.apply_keystream_b2b(&input[done..], &mut output[done..]),
        None => cipher.apply_keystream(&mut output[done..]),
    }
    computed_mac.update(&output[mac_done..]);
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

    // The MAC state drops (and wipes itself) at the end of this block,
    // before any decryption.
    let verified = {
        let mut computed_mac = Poly1305::new(&mac_key);
        mac_key.zeroize();

        computed_mac.update(input.unwrap_or(output));
        // The computed tag is the valid tag for this input, so wipe it even
        // when verification fails.
        let mut computed_tag = Mac::default();
        computed_mac.finalize(&mut computed_tag);

        let verified = verify_ct(mac, &computed_tag);
        zeroize_bytes(&mut computed_tag);
        verified
    };
    verified?;
    match input {
        Some(input) => cipher.apply_keystream_b2b(input, output),
        None => cipher.apply_keystream(output),
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_prelude::*;
    use crate::utils::test_util::XorShift64;

    /// [`seal`] (stitched on AArch64 with SVE2 from 672 bytes on) gives the
    /// ciphertext and tag of the sequential keystream-then-MAC path, buffer
    /// to buffer and in place, around the lengths where the stitched runs
    /// start, stop and leave a tail, and [`open`] takes them back.
    #[test]
    fn test_seal_matches_sequential() {
        let mut rng = XorShift64::new(0x9b05_688c_2b3e_6c1f);
        let key: Key = rng.next_bytes32();
        let nonce: Nonce = rng.next_bytes32()[..24].try_into().unwrap();
        for len in [
            0, 31, 32, 671, 672, 673, 991, 992, 993, 1024, 1056, 4099, 16384,
        ] {
            let message: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            let mut expected = vec![0u8; len];
            let mut expected_mac = Mac::default();
            seal_sequential(
                &mut expected,
                Some(&message),
                &mut expected_mac,
                &nonce,
                &key,
            );

            let mut ciphertext = vec![0u8; len];
            let mut mac = Mac::default();
            seal(&mut ciphertext, Some(&message), &mut mac, &nonce, &key);
            assert_eq!((&ciphertext, mac), (&expected, expected_mac), "len {len}");

            let mut data = message.clone();
            let mut mac = Mac::default();
            seal(&mut data, None, &mut mac, &nonce, &key);
            assert_eq!(
                (&data, mac),
                (&expected, expected_mac),
                "in place, len {len}"
            );

            open(&mut data, None, &mac, &nonce, &key).expect("open");
            assert_eq!(data, message, "len {len}");
        }
    }
}
