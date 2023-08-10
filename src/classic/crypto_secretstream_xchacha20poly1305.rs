//! # Secret stream functions
//!
//! Implements authenticated encrypted streams as per
//! <https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream>.
//!
//! This API is compatible with libsodium's implementation.
//!
//! # Classic API example
//!
//! ```
//! use dryoc::classic::crypto_secretstream_xchacha20poly1305::*;
//! use dryoc::constants::{
//!     CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
//!     CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
//!     CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
//! };
//! let message1 = b"Arbitrary data to encrypt";
//! let message2 = b"split into";
//! let message3 = b"three messages";
//!
//! // Generate a key
//! let mut key = Key::default();
//! crypto_secretstream_xchacha20poly1305_keygen(&mut key);
//!
//! // Create stream push state
//! let mut state = State::new();
//! let mut header = Header::default();
//! crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &key);
//!
//! let (mut c1, mut c2, mut c3) = (
//!     vec![0u8; message1.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
//!     vec![0u8; message2.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
//!     vec![0u8; message3.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
//! );
//! // Encrypt a series of messages
//! crypto_secretstream_xchacha20poly1305_push(
//!     &mut state,
//!     &mut c1,
//!     message1,
//!     None,
//!     CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
//! )
//! .expect("Encrypt failed");
//! crypto_secretstream_xchacha20poly1305_push(
//!     &mut state,
//!     &mut c2,
//!     message2,
//!     None,
//!     CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
//! )
//! .expect("Encrypt failed");
//! crypto_secretstream_xchacha20poly1305_push(
//!     &mut state,
//!     &mut c3,
//!     message3,
//!     None,
//!     CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
//! )
//! .expect("Encrypt failed");
//!
//! // Create stream pull state, using the same key as above with a new state.
//! let mut state = State::new();
//! crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);
//!
//! let (mut m1, mut m2, mut m3) = (
//!     vec![0u8; message1.len()],
//!     vec![0u8; message2.len()],
//!     vec![0u8; message3.len()],
//! );
//! let (mut tag1, mut tag2, mut tag3) = (0u8, 0u8, 0u8);
//!
//! // Decrypt the stream of messages
//! crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut m1, &mut tag1, &c1, None)
//!     .expect("Decrypt failed");
//! crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut m2, &mut tag2, &c2, None)
//!     .expect("Decrypt failed");
//! crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut m3, &mut tag3, &c3, None)
//!     .expect("Decrypt failed");
//!
//! assert_eq!(message1, m1.as_slice());
//! assert_eq!(message2, m2.as_slice());
//! assert_eq!(message3, m3.as_slice());
//!
//! assert_eq!(tag1, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
//! assert_eq!(tag2, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
//! assert_eq!(tag3, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
//! ```

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_core::{crypto_core_hchacha20, HChaCha20Key};
use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY, CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES,
    CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES,
};
use crate::error::*;
use crate::rng::copy_randombytes;
use crate::types::*;
use crate::utils::{increment_bytes, xor_buf};

/// A secret for authenticated secret streams.
pub type Key = [u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES];
/// A nonce for authenticated secret streams.
pub type Nonce = [u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES];
/// Container for stream header data
pub type Header = [u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];

/// Stream state data
#[derive(PartialEq, Eq, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct State {
    k: Key,
    nonce: Nonce,
}

impl State {
    /// Returns a new stream state with an empty key and nonce.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Generates a random stream key using [crate::rng::copy_randombytes].
pub fn crypto_secretstream_xchacha20poly1305_keygen(key: &mut Key) {
    copy_randombytes(key);
}

fn state_counter(nonce: &mut Nonce) -> &mut [u8] {
    &mut nonce[..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
}

fn state_inonce(nonce: &mut Nonce) -> &mut [u8] {
    &mut nonce[CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES
        ..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
            + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
}

fn _crypto_secretstream_xchacha20poly1305_counter_reset(state: &mut State) {
    let counter = state_counter(&mut state.nonce);
    counter.fill(0);
    counter[0] = 1;
}

/// Initializes a push stream into `state` using `key` and returns a stream
/// header. The stream header can be used to initialize a pull stream using the
/// same key (i.e., using [crypto_secretstream_xchacha20poly1305_init_pull]).
///
/// Compatible with libsodium's
/// `crypto_secretstream_xchacha20poly1305_init_push`.
pub fn crypto_secretstream_xchacha20poly1305_init_push(
    state: &mut State,
    header: &mut Header,
    key: &Key,
) {
    copy_randombytes(header);

    let mut k = HChaCha20Key::default();
    crypto_core_hchacha20(k.as_mut_array(), header[..16].as_array(), key, None);
    // Copy key into state
    state.k.copy_from_slice(&k);
    _crypto_secretstream_xchacha20poly1305_counter_reset(state);

    let inonce = state_inonce(&mut state.nonce);
    inonce.copy_from_slice(
        &header[CRYPTO_CORE_HCHACHA20_INPUTBYTES
            ..(CRYPTO_CORE_HCHACHA20_INPUTBYTES
                + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES)],
    );
}

/// Initializes a pull stream from `header` into `state` using `key` and returns
/// a stream header. The stream header can be generated using
/// [crypto_secretstream_xchacha20poly1305_init_push].
///
/// Compatible with libsodium's
/// `crypto_secretstream_xchacha20poly1305_init_pull`.
pub fn crypto_secretstream_xchacha20poly1305_init_pull(
    state: &mut State,
    header: &Header,
    key: &Key,
) {
    let mut k = HChaCha20Key::default();
    crypto_core_hchacha20(k.as_mut_array(), header[0..16].as_array(), key, None);
    state.k.copy_from_slice(&k);

    _crypto_secretstream_xchacha20poly1305_counter_reset(state);

    let inonce = state_inonce(&mut state.nonce);
    inonce.copy_from_slice(
        &header[CRYPTO_CORE_HCHACHA20_INPUTBYTES
            ..(CRYPTO_CORE_HCHACHA20_INPUTBYTES
                + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES)],
    );
}

/// Manually rekeys a stream.
///
/// Compatible with libsodium's
/// `crypto_secretstream_xchacha20poly1305_init_push`.
pub fn crypto_secretstream_xchacha20poly1305_rekey(state: &mut State) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::{ChaCha20, Key, Nonce};

    let mut new_state = [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES
        + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES];

    new_state[..CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES].copy_from_slice(&state.k);
    new_state[CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES..]
        .copy_from_slice(state_inonce(&mut state.nonce));

    let key = Key::from_slice(&state.k);
    let nonce = Nonce::from_slice(&state.nonce);
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(&mut new_state);

    state
        .k
        .copy_from_slice(&new_state[0..CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES]);
    state_inonce(&mut state.nonce)
        .copy_from_slice(&new_state[CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES..]);

    _crypto_secretstream_xchacha20poly1305_counter_reset(state);
}

/// Encrypts `message` from the stream for `state`, with `tag` and optional
/// `associated_data`, placing the result into `ciphertext`.
///
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_push`.
///
/// NOTE: The libsodium version of this function contains an alignment bug which
/// was left in place, and is reflected in this implementation for compatibility
/// purposes. Refer to [commit
/// 290197ba3ee72245fdab5e971c8de43a82b19874](https://github.com/jedisct1/libsodium/commit/290197ba3ee72245fdab5e971c8de43a82b19874#diff-dbd9b6026ac3fd057df0ddf00e4d671af16e5df99b4cc7d08b73b61f193d10f5)
pub fn crypto_secretstream_xchacha20poly1305_push(
    state: &mut State,
    ciphertext: &mut [u8],
    message: &[u8],
    associated_data: Option<&[u8]>,
    tag: u8,
) -> Result<(), Error> {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::{ChaCha20, Key, Nonce};

    use crate::poly1305::Poly1305;

    let _pad0 = [0u8; 16];

    if ciphertext.len() != message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
        return Err(dryoc_error!(format!(
            "Ciphertext length was {}, should be {}",
            ciphertext.len(),
            message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES
        )));
    }

    if message.len() > CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX {
        return Err(dryoc_error!(format!(
            "Message length {} exceeds max length {}",
            message.len(),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
        )));
    }

    let associated_data = associated_data.unwrap_or(&[]);

    let mut mac_key = crate::poly1305::Key::new();
    let _pad0 = [0u8; 16];

    let key = Key::from_slice(&state.k);
    let nonce = Nonce::from_slice(&state.nonce);
    let mut cipher = ChaCha20::new(key, nonce);

    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    mac.update(associated_data);
    mac.update(&_pad0[..((0x10 - associated_data.len()) & 0xf)]);

    let mut block = [0u8; 64];
    block[0] = tag;
    cipher.seek(64);
    cipher.apply_keystream(&mut block);
    mac.update(&block);

    let mlen = message.len();
    ciphertext[0] = block[0];
    ciphertext[1..(1 + mlen)].copy_from_slice(message);

    cipher.seek(128);
    cipher.apply_keystream(&mut ciphertext[1..(1 + mlen)]);

    let mut size_data = [0u8; 16];
    size_data[..8].copy_from_slice(&associated_data.len().to_le_bytes());
    size_data[8..16].copy_from_slice(&(block.len() + mlen).to_le_bytes());

    mac.update(&ciphertext[1..(1 + mlen)]);
    // this is to workaround an unfortunate padding bug in libsodium, there's a
    // note in commit 290197ba3ee72245fdab5e971c8de43a82b19874. There's no
    // safety issue, so we can just pretend it's not a bug.
    let buffer_mac_pad = ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as usize;
    mac.update(&_pad0[0..buffer_mac_pad]);
    mac.update(&size_data);

    mac.finalize(&mut ciphertext[1 + mlen..]);

    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, &ciphertext[1 + mlen..]);

    let counter = state_counter(&mut state.nonce);
    increment_bytes(counter);

    if tag & CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
        == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
        || state_counter(&mut state.nonce)
            .ct_eq(&[0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES])
            .unwrap_u8()
            == 1
    {
        crypto_secretstream_xchacha20poly1305_rekey(state);
    }

    Ok(())
}

/// Decrypts `ciphertext` from the stream for `state` with optional
/// `additional_data`, placing the result into `message` (which must be manually
/// resized) and `tag`. Returns the length of the message.
///
/// Due to a quirk in libsodium's implementation, you need to manually resize
/// `message` to the message length after decrypting when using this function.
///
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_pull`.
///
/// NOTE: The libsodium version of this function contains an alignment bug which
/// was left in place, and is reflected in this implementation for compatibility
/// purposes. Refer to [commit
/// 290197ba3ee72245fdab5e971c8de43a82b19874](https://github.com/jedisct1/libsodium/commit/290197ba3ee72245fdab5e971c8de43a82b19874#diff-dbd9b6026ac3fd057df0ddf00e4d671af16e5df99b4cc7d08b73b61f193d10f5)
pub fn crypto_secretstream_xchacha20poly1305_pull(
    state: &mut State,
    message: &mut [u8],
    tag: &mut u8,
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<usize, Error> {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::{ChaCha20, Key, Nonce};

    use crate::poly1305::Poly1305;

    let _pad0 = [0u8; 16];

    if message.len() < ciphertext.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
        return Err(dryoc_error!(format!(
            "Message length was {}, should be at least {}",
            message.len(),
            ciphertext.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES
        )));
    }

    if ciphertext.len() > CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX {
        return Err(dryoc_error!(format!(
            "Message length {} exceeds max length {}",
            ciphertext.len(),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
        )));
    }

    let associated_data = associated_data.unwrap_or(&[]);

    let mut mac_key = crate::poly1305::Key::new();

    let key = Key::from_slice(&state.k);
    let nonce = Nonce::from_slice(&state.nonce);
    let mut cipher = ChaCha20::new(key, nonce);

    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    mac.update(associated_data);
    mac.update(&_pad0[..((0x10 - associated_data.len()) & 0xf)]);

    let mut block = [0u8; 64];
    block[0] = ciphertext[0];

    cipher.seek(64);
    cipher.apply_keystream(&mut block);

    *tag = block[0];
    block[0] = ciphertext[0];

    mac.update(&block);

    let mlen = ciphertext.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
    message[..mlen].copy_from_slice(&ciphertext[1..1 + mlen]);

    // this is to workaround an unfortunate padding bug in libsodium, there's a
    // note in commit 290197ba3ee72245fdab5e971c8de43a82b19874. There's no
    // safety issue, so we can just pretend it's not a bug.
    let buffer_mac_pad = ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as usize;
    mac.update(&message[..mlen]);
    mac.update(&_pad0[..buffer_mac_pad]);

    let mut size_data = [0u8; 16];
    size_data[..8].copy_from_slice(&associated_data.len().to_le_bytes());
    size_data[8..16].copy_from_slice(&(block.len() + mlen).to_le_bytes());
    mac.update(&size_data);
    let mac = mac.finalize_to_array();

    cipher.seek(128);
    cipher.apply_keystream(&mut message[..mlen]);

    if ciphertext[1 + mlen..].ct_eq(&mac).unwrap_u8() == 0 {
        return Err(dryoc_error!("Message authentication mismatch"));
    }

    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, &mac);

    let counter = state_counter(&mut state.nonce);
    increment_bytes(counter);

    if *tag & CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
        == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
        || state_counter(&mut state.nonce)
            .ct_eq(&[0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES])
            .unwrap_u8()
            == 1
    {
        crypto_secretstream_xchacha20poly1305_rekey(state);
    }

    Ok(mlen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sizes() {
        use static_assertions::*;

        use crate::constants::*;

        const_assert!(
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
                == CRYPTO_CORE_HCHACHA20_INPUTBYTES
                    + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
        );

        const_assert!(
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
                == CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        const_assert!(
            CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES
                == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
                    + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES
        );

        const_assert!(
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
                <= CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
        );

        const_assert!(
            CRYPTO_ONETIMEAUTH_POLY1305_BYTES >= CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
        );
    }

    #[test]
    fn test_secretstream_basic_push() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use crate::dryocstream::Tag;

        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut push_state = State::new();
        let mut push_header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut push_header, &key);
        let push_state_init = push_state.clone();

        let message = b"hello";
        let mut output = vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        let aad = b"";
        let tag = Tag::MESSAGE.bits();
        crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            &mut output,
            message,
            Some(aad),
            tag,
        )
        .expect("push failed");

        let mut so_output = output.clone();
        unsafe {
            use libc::{c_uchar, c_ulonglong};
            let mut so_state = crypto_secretstream_xchacha20poly1305_state {
                k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
                nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
                _pad: [0u8; 8],
            };
            so_state.k.copy_from_slice(&push_state_init.k);
            so_state.nonce.copy_from_slice(&push_state_init.nonce);
            let mut clen_p: c_ulonglong = 0;
            let ret = so_crypto_secretstream_xchacha20poly1305_push(
                &mut so_state,
                so_output.as_mut_ptr(),
                &mut clen_p,
                message.as_ptr(),
                message.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                0,
            );
            assert_eq!(ret, 0);
            so_output.resize(clen_p as usize, 0);
            assert_eq!(
                general_purpose::STANDARD.encode(&so_output),
                general_purpose::STANDARD.encode(&output)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(so_state.k),
                general_purpose::STANDARD.encode(push_state.k)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(so_state.nonce),
                general_purpose::STANDARD.encode(push_state.nonce)
            );

            let mut so_state = crypto_secretstream_xchacha20poly1305_state {
                k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
                nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
                _pad: [0u8; 8],
            };
            let mut mlen_p: c_ulonglong = 0;
            let mut tag_p: c_uchar = 0;
            let ret = so_crypto_secretstream_xchacha20poly1305_init_pull(
                &mut so_state,
                push_header.as_ptr(),
                key.as_ptr(),
            );
            assert_eq!(ret, 0);
            assert_eq!(
                general_purpose::STANDARD.encode(so_state.k),
                general_purpose::STANDARD.encode(push_state_init.k)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(so_state.nonce),
                general_purpose::STANDARD.encode(push_state_init.nonce)
            );
            assert!(so_output.len() >= CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            let ret = so_crypto_secretstream_xchacha20poly1305_pull(
                &mut so_state,
                so_output.as_mut_ptr(),
                &mut mlen_p,
                &mut tag_p,
                output.as_ptr(),
                output.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
            );
            assert_eq!(ret, 0);
            so_output.resize(mlen_p as usize, 0);
        }
        assert_eq!(
            general_purpose::STANDARD.encode(message),
            general_purpose::STANDARD.encode(&so_output)
        );

        let mut pull_state = State::default();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &push_header, &key);

        assert_eq!(
            general_purpose::STANDARD.encode(pull_state.k),
            general_purpose::STANDARD.encode(push_state_init.k)
        );
        assert_eq!(
            general_purpose::STANDARD.encode(pull_state.nonce),
            general_purpose::STANDARD.encode(push_state_init.nonce)
        );

        let mut pull_result_message =
            vec![0u8; output.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        let mut pull_result_tag = 0u8;
        crypto_secretstream_xchacha20poly1305_pull(
            &mut pull_state,
            &mut pull_result_message,
            &mut pull_result_tag,
            &output,
            Some(&[]),
        )
        .expect("pull failed");

        assert_eq!(Tag::MESSAGE, Tag::from_bits(tag).expect("tag"));
        assert_eq!(
            general_purpose::STANDARD.encode(&pull_result_message),
            general_purpose::STANDARD.encode(message)
        );
    }

    #[test]
    fn test_rekey() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_rekey as so_crypto_secretstream_xchacha20poly1305_rekey,
            crypto_secretstream_xchacha20poly1305_state,
        };

        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;

        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut push_state = State::default();
        let mut push_header: Header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut push_header, &key);
        let push_state_init = push_state.clone();

        crypto_secretstream_xchacha20poly1305_rekey(&mut push_state);

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        so_state.k.copy_from_slice(&push_state_init.k);
        so_state.nonce.copy_from_slice(&push_state_init.nonce);
        unsafe {
            so_crypto_secretstream_xchacha20poly1305_rekey(&mut so_state);
        }
        assert_eq!(
            general_purpose::STANDARD.encode(so_state.k),
            general_purpose::STANDARD.encode(push_state.k)
        );
        assert_eq!(
            general_purpose::STANDARD.encode(so_state.nonce),
            general_purpose::STANDARD.encode(push_state.nonce)
        );
    }

    #[test]
    fn test_secretstream_lots_of_messages_push() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libc::{c_uchar, c_ulonglong};
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_state,
        };

        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use crate::dryocstream::Tag;

        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut push_state = State::new();
        let mut push_header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut push_header, &key);
        let push_state_init = push_state.clone();

        let mut pull_state = State::default();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &push_header, &key);

        assert_eq!(
            general_purpose::STANDARD.encode(pull_state.k),
            general_purpose::STANDARD.encode(push_state_init.k)
        );
        assert_eq!(
            general_purpose::STANDARD.encode(pull_state.nonce),
            general_purpose::STANDARD.encode(push_state_init.nonce)
        );

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        so_state.k.copy_from_slice(&push_state_init.k);
        so_state.nonce.copy_from_slice(&push_state_init.nonce);

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        let mut mlen_p: c_ulonglong = 0;
        let mut tag_p: c_uchar = 0;
        unsafe {
            let ret = so_crypto_secretstream_xchacha20poly1305_init_pull(
                &mut so_state,
                push_header.as_ptr(),
                key.as_ptr(),
            );
            assert_eq!(ret, 0);
        }
        assert_eq!(
            general_purpose::STANDARD.encode(so_state.k),
            general_purpose::STANDARD.encode(push_state_init.k)
        );
        assert_eq!(
            general_purpose::STANDARD.encode(so_state.nonce),
            general_purpose::STANDARD.encode(push_state_init.nonce)
        );

        for i in 0..100 {
            let message = format!("hello {}", i);
            let aad = format!("aad {}", i);
            let tag = if i % 7 == 0 { Tag::REKEY } else { Tag::MESSAGE };

            let mut output =
                vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            crypto_secretstream_xchacha20poly1305_push(
                &mut push_state,
                &mut output,
                message.as_bytes(),
                Some(aad.as_bytes()),
                tag.bits(),
            )
            .expect("push failed");

            let mut so_output = output.clone();
            unsafe {
                assert!(so_output.len() >= CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
                let ret = so_crypto_secretstream_xchacha20poly1305_pull(
                    &mut so_state,
                    so_output.as_mut_ptr(),
                    &mut mlen_p,
                    &mut tag_p,
                    output.as_ptr(),
                    output.len() as u64,
                    aad.as_ptr(),
                    aad.len() as u64,
                );
                assert_eq!(ret, 0);
                so_output.resize(mlen_p as usize, 0);
            }
            assert_eq!(
                general_purpose::STANDARD.encode(&message),
                general_purpose::STANDARD.encode(&so_output)
            );

            let mut pull_result_message =
                vec![0u8; output.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            let mut pull_result_tag = 0u8;
            crypto_secretstream_xchacha20poly1305_pull(
                &mut pull_state,
                &mut pull_result_message,
                &mut pull_result_tag,
                &output,
                Some(aad.as_bytes()),
            )
            .expect("pull failed");

            assert_eq!(tag, Tag::from_bits(pull_result_tag).expect("tag"));
            assert_eq!(
                general_purpose::STANDARD.encode(&pull_result_message),
                general_purpose::STANDARD.encode(&message)
            );
        }
    }

    #[test]
    fn test_secretstream_basic_pull() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libc::c_ulonglong;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_push as so_crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;

        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        let mut so_header = Header::default();
        unsafe {
            so_crypto_secretstream_xchacha20poly1305_init_push(
                &mut so_state,
                so_header.as_mut_ptr(),
                key.as_ptr(),
            );
        }

        let mut pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &so_header, &key);

        let message = b"hello";
        let aad = b"aad";
        let mut so_output = vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        let mut clen_p: c_ulonglong = 0;

        unsafe {
            let ret = so_crypto_secretstream_xchacha20poly1305_push(
                &mut so_state,
                so_output.as_mut_ptr(),
                &mut clen_p,
                message.as_ptr(),
                message.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                0,
            );
            assert_eq!(ret, 0);
            so_output.resize(clen_p as usize, 0);
        }

        let mut output = vec![0u8; so_output.len()];
        let mut tag = 0u8;
        let mlen = crypto_secretstream_xchacha20poly1305_pull(
            &mut pull_state,
            &mut output,
            &mut tag,
            &so_output,
            Some(aad),
        )
        .expect("decrypt failed");
        output.resize(mlen, 0);

        assert_eq!(
            general_purpose::STANDARD.encode(&output),
            general_purpose::STANDARD.encode(message)
        );
        assert_eq!(tag, 0);
    }

    #[test]
    fn test_secretstream_lots_of_messages_pull() {
        use base64::engine::general_purpose;
        use base64::Engine as _;
        use libc::c_ulonglong;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_push as so_crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use crate::dryocstream::Tag;

        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        let mut so_header = Header::default();
        unsafe {
            so_crypto_secretstream_xchacha20poly1305_init_push(
                &mut so_state,
                so_header.as_mut_ptr(),
                key.as_ptr(),
            );
        }

        let mut pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &so_header, &key);

        for i in 0..100 {
            let message = format!("hello {}", i);
            let aad = format!("aad {}", i);
            let mut so_output =
                vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            let mut clen_p: c_ulonglong = 0;

            let tag = if i % 7 == 0 { Tag::REKEY } else { Tag::MESSAGE };

            unsafe {
                let ret = so_crypto_secretstream_xchacha20poly1305_push(
                    &mut so_state,
                    so_output.as_mut_ptr(),
                    &mut clen_p,
                    message.as_ptr(),
                    message.len() as u64,
                    aad.as_ptr(),
                    aad.len() as u64,
                    tag.bits(),
                );
                assert_eq!(ret, 0);
                so_output.resize(clen_p as usize, 0);
            }

            let mut output =
                vec![0u8; so_output.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            let mut outtag = 0u8;
            crypto_secretstream_xchacha20poly1305_pull(
                &mut pull_state,
                &mut output,
                &mut outtag,
                &so_output,
                Some(aad.as_bytes()),
            )
            .expect("decrypt failed");

            assert_eq!(
                general_purpose::STANDARD.encode(so_state.k),
                general_purpose::STANDARD.encode(pull_state.k)
            );
            assert_eq!(
                general_purpose::STANDARD.encode(so_state.nonce),
                general_purpose::STANDARD.encode(pull_state.nonce)
            );

            assert_eq!(
                general_purpose::STANDARD.encode(&output),
                general_purpose::STANDARD.encode(message)
            );
            assert_eq!(outtag, tag.bits());
        }
    }
}
