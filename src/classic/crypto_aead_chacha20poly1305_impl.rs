//! Shared orchestration for the ChaCha20-Poly1305-IETF and
//! XChaCha20-Poly1305-IETF AEAD constructions.
//!
//! The two constructions differ only in how the ChaCha20 stream is derived
//! from the nonce and key, and in the message size bound that follows from
//! that stream's counter width. Each public module supplies those two pieces
//! to [`impl_chacha20poly1305_aead!`]; everything that is independent of the
//! stream lives here as ordinary functions.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::chacha20::ChaCha20;
use crate::constants::{CRYPTO_ONETIMEAUTH_POLY1305_BYTES, CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES};
use crate::error::Error;
use crate::poly1305::{Key as Poly1305Key, Poly1305};
use crate::utils::{pad16, zeroize_bytes};

/// Poly1305 tag; the `Mac` of every ChaCha20-Poly1305 construction.
pub(crate) type Tag = [u8; CRYPTO_ONETIMEAUTH_POLY1305_BYTES];

const PAD0: [u8; 16] = [0u8; 16];

pub(crate) fn validate_output_len(
    output_len: usize,
    expected_len: usize,
    context: crate::ErrorContext,
) -> Result<(), Error> {
    if output_len != expected_len {
        Err(length_error!(context, output_len, exact expected_len))
    } else {
        Ok(())
    }
}

/// Takes the Poly1305 key from block 0 of `cipher`, which must be positioned
/// at block 0; the returned cipher is positioned at block 1 for the message.
pub(crate) fn poly1305_key(mut cipher: ChaCha20) -> (ChaCha20, Poly1305Key) {
    let mut mac_key = Poly1305Key::new();
    cipher.apply_keystream(&mut mac_key);
    (cipher, mac_key)
}

/// Encrypts `message` into `ciphertext` (in place when `message` is `None`)
/// with `cipher`, which must be positioned at block 0, and returns the
/// Poly1305 key from block 0. Both come out of the same keystream runs, so
/// the key costs no separate scalar block.
pub(crate) fn encrypt_with_poly1305_key(
    mut cipher: ChaCha20,
    message: Option<&[u8]>,
    ciphertext: &mut [u8],
) -> Poly1305Key {
    let mut block0 = [0u8; 64];
    match message {
        Some(message) => cipher.apply_keystream_b2b_with_head(&mut block0, message, ciphertext),
        None => cipher.apply_keystream_with_head(&mut block0, ciphertext),
    }
    let mut mac_key = Poly1305Key::new();
    mac_key.copy_from_slice(&block0[..CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES]);
    zeroize_bytes(&mut block0);
    mac_key
}

pub(crate) fn compute_mac(mac: &mut Tag, mac_key: &mut Poly1305Key, ciphertext: &[u8], ad: &[u8]) {
    let mut state = Poly1305::new(mac_key);
    mac_key.zeroize();

    state.update(ad);
    state.update(&PAD0[..pad16(ad.len())]);
    state.update(ciphertext);
    state.update(&PAD0[..pad16(ciphertext.len())]);
    state.update(&(ad.len() as u64).to_le_bytes());
    state.update(&(ciphertext.len() as u64).to_le_bytes());
    state.finalize(mac);
}

pub(crate) fn compute_mac_to_array(mac_key: &mut Poly1305Key, ciphertext: &[u8], ad: &[u8]) -> Tag {
    let mut mac = Tag::default();
    compute_mac(&mut mac, mac_key, ciphertext, ad);
    mac
}

pub(crate) fn verify_mac(mac: &Tag, computed_mac: &Tag) -> Result<(), Error> {
    if mac.ct_eq(computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

/// Generates the libsodium-shaped API of one ChaCha20-Poly1305-IETF
/// construction in the invoking module.
///
/// * `abytes` / `messagebytes_max`: the construction's `*_ABYTES` and
///   `*_MESSAGEBYTES_MAX` constants. The bound is deliberately not defaulted;
///   it must match the counter width of `stream`.
/// * `stream`: a closure `|nonce: &Nonce, key: &Key| -> ChaCha20` returning the
///   stream positioned at block 0. Block 0 becomes the Poly1305 key and the
///   message starts at block 1; `messagebytes_max` must keep the block counter
///   from wrapping over a message of that length plus block 0.
/// * `key` / `nonce` / `mac`: the module's `Key`, `Nonce`, and `Mac` aliases;
///   `mac` must be [`Tag`].
/// * The remaining entries name the generated functions. Attributes on an
///   entry, including doc comments, are applied to that function.
///
/// The invoking module must have `crate::types::*` in scope.
macro_rules! impl_chacha20poly1305_aead {
    (
        abytes: $abytes:expr,
        messagebytes_max: $messagebytes_max:expr,
        stream: $stream:expr,
        key: $key:ty,
        nonce: $nonce:ty,
        mac: $mac:ty,
        $(#[$keygen_inplace_meta:meta])*
        keygen_inplace: $keygen_inplace:ident,
        $(#[$keygen_meta:meta])*
        keygen: $keygen:ident,
        $(#[$encrypt_detached_meta:meta])*
        encrypt_detached: $encrypt_detached:ident,
        $(#[$encrypt_detached_inplace_meta:meta])*
        encrypt_detached_inplace: $encrypt_detached_inplace:ident,
        $(#[$decrypt_detached_meta:meta])*
        decrypt_detached: $decrypt_detached:ident,
        $(#[$decrypt_detached_inplace_meta:meta])*
        decrypt_detached_inplace: $decrypt_detached_inplace:ident,
        $(#[$encrypt_meta:meta])*
        encrypt: $encrypt:ident,
        $(#[$decrypt_meta:meta])*
        decrypt: $decrypt:ident,
        $(#[$encrypt_inplace_meta:meta])*
        encrypt_inplace: $encrypt_inplace:ident,
        $(#[$decrypt_inplace_meta:meta])*
        decrypt_inplace: $decrypt_inplace:ident,
    ) => {
        use $crate::classic::crypto_aead_chacha20poly1305_impl::{
            compute_mac, compute_mac_to_array, encrypt_with_poly1305_key, poly1305_key,
            validate_output_len, verify_mac,
        };

        $(#[$keygen_inplace_meta])*
        pub fn $keygen_inplace(key: &mut $key) {
            $crate::rng::copy_randombytes(key)
        }

        $(#[$keygen_meta])*
        pub fn $keygen() -> $key {
            <$key>::generate()
        }

        pub(super) fn validate_message_len(message_len: usize) -> Result<(), $crate::error::Error> {
            if message_len > $messagebytes_max {
                Err(length_error!(
                    $crate::ErrorContext::Message,
                    message_len,
                    max $messagebytes_max
                ))
            } else {
                Ok(())
            }
        }

        pub(super) fn message_len_from_combined_len(
            combined_len: usize,
            context: $crate::ErrorContext,
        ) -> Result<usize, $crate::error::Error> {
            if combined_len < $abytes {
                Err(length_error!(context, combined_len, min $abytes))
            } else {
                let message_len = combined_len - $abytes;
                validate_message_len(message_len)?;
                Ok(message_len)
            }
        }

        $(#[$encrypt_detached_meta])*
        pub fn $encrypt_detached(
            ciphertext: &mut [u8],
            mac: &mut $mac,
            message: &[u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_message_len(message.len())?;
            validate_output_len(
                ciphertext.len(),
                message.len(),
                $crate::ErrorContext::Ciphertext,
            )?;

            let associated_data = associated_data.unwrap_or(&[]);
            let mut mac_key =
                encrypt_with_poly1305_key(($stream)(nonce, key), Some(message), ciphertext);

            compute_mac(mac, &mut mac_key, ciphertext, associated_data);
            Ok(())
        }

        $(#[$encrypt_detached_inplace_meta])*
        pub fn $encrypt_detached_inplace(
            data: &mut [u8],
            mac: &mut $mac,
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_message_len(data.len())?;

            let associated_data = associated_data.unwrap_or(&[]);
            let mut mac_key = encrypt_with_poly1305_key(($stream)(nonce, key), None, data);

            compute_mac(mac, &mut mac_key, data, associated_data);
            Ok(())
        }

        $(#[$decrypt_detached_meta])*
        pub fn $decrypt_detached(
            message: &mut [u8],
            ciphertext: &[u8],
            mac: &$mac,
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_message_len(ciphertext.len())?;
            validate_output_len(
                message.len(),
                ciphertext.len(),
                $crate::ErrorContext::Message,
            )?;

            let associated_data = associated_data.unwrap_or(&[]);
            let (mut cipher, mut mac_key) = poly1305_key(($stream)(nonce, key));
            let computed_mac = compute_mac_to_array(&mut mac_key, ciphertext, associated_data);

            verify_mac(mac, &computed_mac)?;
            cipher.apply_keystream_b2b(ciphertext, message);
            Ok(())
        }

        $(#[$decrypt_detached_inplace_meta])*
        pub fn $decrypt_detached_inplace(
            data: &mut [u8],
            mac: &$mac,
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_message_len(data.len())?;

            let associated_data = associated_data.unwrap_or(&[]);
            let (mut cipher, mut mac_key) = poly1305_key(($stream)(nonce, key));
            let computed_mac = compute_mac_to_array(&mut mac_key, data, associated_data);

            verify_mac(mac, &computed_mac)?;
            cipher.apply_keystream(data);
            Ok(())
        }

        $(#[$encrypt_meta])*
        pub fn $encrypt(
            ciphertext: &mut [u8],
            message: &[u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_message_len(message.len())?;
            validate_output_len(
                ciphertext.len(),
                message.len() + $abytes,
                $crate::ErrorContext::Ciphertext,
            )?;

            let (ciphertext, mac) = ciphertext.split_at_mut(message.len());
            let mac = $crate::types::MutByteArray::as_mut_array(mac);
            $encrypt_detached(ciphertext, mac, message, associated_data, nonce, key)
        }

        $(#[$decrypt_meta])*
        pub fn $decrypt(
            message: &mut [u8],
            ciphertext: &[u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            let message_len =
                message_len_from_combined_len(ciphertext.len(), $crate::ErrorContext::Ciphertext)?;
            validate_output_len(message.len(), message_len, $crate::ErrorContext::Message)?;

            let (ciphertext, mac) = ciphertext.split_at(message_len);
            let mac = $crate::types::ByteArray::as_array(mac);
            $decrypt_detached(message, ciphertext, mac, associated_data, nonce, key)
        }

        $(#[$encrypt_inplace_meta])*
        pub fn $encrypt_inplace(
            data: &mut [u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            let message_len =
                message_len_from_combined_len(data.len(), $crate::ErrorContext::Data)?;
            let (data, mac) = data.split_at_mut(message_len);
            let mac = $crate::types::MutByteArray::as_mut_array(mac);
            $encrypt_detached_inplace(data, mac, associated_data, nonce, key)
        }

        $(#[$decrypt_inplace_meta])*
        pub fn $decrypt_inplace(
            data: &mut [u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            let message_len =
                message_len_from_combined_len(data.len(), $crate::ErrorContext::Data)?;
            let (data, mac) = data.split_at_mut(message_len);
            let mac = $crate::types::ByteArray::as_array(mac);
            $decrypt_detached_inplace(data, mac, associated_data, nonce, key)
        }
    };
}

pub(crate) use impl_chacha20poly1305_aead;
