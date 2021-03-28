/*!
# Secret stream functions

Implements authenticated encrypted streams as per
[https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream).

This API is compatible with libsodium's implementation.

# Classic API example

```
use dryoc::crypto_secretstream_xchacha20poly1305::*;
let message1 = b"Arbitrary data to encrypt";
let message2 = b"split into";
let message3 = b"three messages";

// Generate a key
let key = crypto_secretstream_xchacha20poly1305_keygen();

// Create stream push state
let mut state = State::new();
let header = crypto_secretstream_xchacha20poly1305_init_push(&mut state, &key);

// Encrypt a series of messages
let c1 =
    crypto_secretstream_xchacha20poly1305_push(&mut state, message1, None, Tag::MESSAGE)
        .expect("Encrypt failed");
let c2 =
    crypto_secretstream_xchacha20poly1305_push(&mut state, message2, None, Tag::MESSAGE)
        .expect("Encrypt failed");
let c3 =
    crypto_secretstream_xchacha20poly1305_push(&mut state, message3, None, Tag::FINAL)
        .expect("Encrypt failed");

// Create stream pull state, using the same key as above with a new state.
let mut state = State::new();
crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);

// Decrypt the stream of messages
let (m1, tag1) =
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &c1, None).expect("Decrypt failed");
let (m2, tag2) =
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &c2, None).expect("Decrypt failed");
let (m3, tag3) =
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &c3, None).expect("Decrypt failed");

assert_eq!(message1, m1.as_slice());
assert_eq!(message2, m2.as_slice());
assert_eq!(message3, m3.as_slice());

assert_eq!(tag1, Tag::MESSAGE);
assert_eq!(tag2, Tag::MESSAGE);
assert_eq!(tag3, Tag::FINAL);
```
*/

use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY, CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES,
    CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES,
};
use crate::crypto_core::crypto_core_hchacha20;
use crate::error::*;
use crate::types::{ByteArray, InputBase, OutputBase};
use crate::utils::{increment_bytes, xor_buf};

use bitflags::bitflags;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A secret for authenticated secret streams.
pub type Key = ByteArray<CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES>;
/// A nonce for authenticated secret streams.
pub type Nonce = ByteArray<CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES>;

bitflags! {
    /// Message tag definitions
    pub struct Tag: u8 {
        /// Describes a normal message in a stream.
        const MESSAGE = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
        /// Indicates the message marks the end of a series of messages in a
        /// stream, but not the end of the stream.
        const PUSH = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH;
        /// Derives a new key for the stream.
        const REKEY = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY;
        /// Indicates the end of the stream.
        const FINAL = Self::PUSH.bits | Self::REKEY.bits;
    }
}

impl From<u8> for Tag {
    fn from(other: u8) -> Self {
        Self::from_bits(other).expect("Unable to parse tag")
    }
}

/// Stream state data
#[derive(PartialEq, Clone, Zeroize)]
#[zeroize(drop)]
pub struct State {
    k: Key,
    nonce: Nonce,
}

impl State {
    /// Returns a new stream state with an empty key and a randomly generated
    /// nonce.
    pub fn new() -> Self {
        Self {
            k: Key::new(),
            nonce: Nonce::gen(),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// Generates a random stream key using [crate::rng::copy_randombytes].
pub fn crypto_secretstream_xchacha20poly1305_keygen() -> Key {
    Key::gen()
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

/// Initializes a push stream into `state` using `key` and returns a stream header.
/// The stream header can be used to initialize a pull stream using the same key
/// (i.e., using [crypto_secretstream_xchacha20poly1305_init_pull]).
///
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_init_push`.
pub fn crypto_secretstream_xchacha20poly1305_init_push(state: &mut State, key: &Key) -> OutputBase {
    use crate::rng::copy_randombytes;

    let mut out: OutputBase = vec![0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];
    copy_randombytes(&mut out);

    let key = crypto_core_hchacha20(&out[..16], key.as_slice(), None);
    // Copy key into state
    state.k.copy_from_slice(&key);
    _crypto_secretstream_xchacha20poly1305_counter_reset(state);

    let inonce = state_inonce(&mut state.nonce);
    inonce.copy_from_slice(
        &out[CRYPTO_CORE_HCHACHA20_INPUTBYTES
            ..(CRYPTO_CORE_HCHACHA20_INPUTBYTES
                + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES)],
    );

    out
}

/// Initializes a pull stream from `header` into `state` using `key` and returns a stream header.
/// The stream header can be generated using [crypto_secretstream_xchacha20poly1305_init_push].
///
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_init_pull`.
pub fn crypto_secretstream_xchacha20poly1305_init_pull(
    state: &mut State,
    header: &InputBase,
    key: &Key,
) {
    let k = crypto_core_hchacha20(&header[0..16], key.as_slice(), None);
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
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_init_push`.
pub fn crypto_secretstream_xchacha20poly1305_rekey(state: &mut State) {
    use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
    use chacha20::{ChaCha20, Key, Nonce};

    let mut new_state = [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES
        + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES];

    new_state[..CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES].copy_from_slice(state.k.as_slice());
    new_state[CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES..]
        .copy_from_slice(state_inonce(&mut state.nonce));

    let key = Key::from_slice(state.k.as_slice());
    let nonce = Nonce::from_slice(state.nonce.as_slice());
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
/// `associated_data`.
///
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_push`.
///
/// NOTE: The libsodium version of this function contains an alignment bug which
/// was left in place, and is reflected in this implementation for compatibility
/// purposes. Refer to [commit
/// 290197ba3ee72245fdab5e971c8de43a82b19874](https://github.com/jedisct1/libsodium/commit/290197ba3ee72245fdab5e971c8de43a82b19874#diff-dbd9b6026ac3fd057df0ddf00e4d671af16e5df99b4cc7d08b73b61f193d10f5)
pub fn crypto_secretstream_xchacha20poly1305_push(
    state: &mut State,
    message: &InputBase,
    associated_data: Option<&InputBase>,
    tag: Tag,
) -> Result<OutputBase, Error> {
    use chacha20::cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use chacha20::{ChaCha20, Key, Nonce};
    use poly1305::{
        universal_hash::{NewUniversalHash, UniversalHash},
        Key as Poly1305Key, Poly1305,
    };

    if message.len() > CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX {
        return Err(dryoc_error!(format!(
            "Message length {} exceeds max length {}",
            message.len(),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
        )));
    }

    let associated_data = associated_data.unwrap_or(&[]);

    let mut mac_key = [0u8; 64];
    let _pad0 = [0u8; 16];

    let key = Key::from_slice(state.k.as_slice());
    let nonce = Nonce::from_slice(state.nonce.as_slice());
    let mut cipher = ChaCha20::new(key, nonce);

    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&Poly1305Key::from_slice(&mac_key[0..32]));
    mac_key.zeroize();

    mac.update_padded(&associated_data);

    let mut block = [0u8; 64];
    block[0] = tag.bits();
    cipher.seek(64);
    cipher.apply_keystream(&mut block);
    mac.update_padded(&block);

    let mlen = message.len();
    let mut buffer: Vec<u8> = vec![0u8; block.len() + mlen];
    buffer[0] = block[0];
    buffer[1..(1 + mlen)].copy_from_slice(&message);

    cipher.seek(128);
    cipher.apply_keystream(&mut buffer[1..(1 + mlen)]);

    let mut size_data = [0u8; 16];
    size_data[..8].copy_from_slice(&associated_data.len().to_le_bytes());
    size_data[8..16].copy_from_slice(&(block.len() + mlen).to_le_bytes());

    // this is to workaround an unfortunate padding bug in libsodium, there's a
    // note in commit 290197ba3ee72245fdab5e971c8de43a82b19874. There's no
    // safety issue, so we can just pretend it's not a bug.
    let buffer_mac_pad = ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as usize;
    let size_data_start = 1 + mlen + buffer_mac_pad;
    let size_data_end = 1 + mlen + buffer_mac_pad + size_data.len();
    buffer[1 + mlen..].fill(0);
    buffer[size_data_start..size_data_end].copy_from_slice(&size_data);
    buffer.resize(size_data_end, 0);
    let mac = mac.compute_unpadded(&buffer[1..]).into_bytes();

    buffer.resize(mlen + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES, 0);
    buffer[1 + mlen..].copy_from_slice(&mac);

    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, &mac);

    let counter = state_counter(&mut state.nonce);
    increment_bytes(counter);

    if tag & Tag::REKEY == Tag::REKEY
        || state_counter(&mut state.nonce)
            .ct_eq(&[0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES])
            .unwrap_u8()
            == 1
    {
        crypto_secretstream_xchacha20poly1305_rekey(state);
    }

    Ok(buffer)
}

/// Decrypts `ciphertext` from the stream for `state` with optional
/// `additional_data`, returning the message and tag as a tuple upon success.
///
/// Compatible with libsodium's `crypto_secretstream_xchacha20poly1305_pull`.
///
/// NOTE: The libsodium version of this function contains an alignment bug which
/// was left in place, and is reflected in this implementation for compatibility
/// purposes. Refer to [commit
/// 290197ba3ee72245fdab5e971c8de43a82b19874](https://github.com/jedisct1/libsodium/commit/290197ba3ee72245fdab5e971c8de43a82b19874#diff-dbd9b6026ac3fd057df0ddf00e4d671af16e5df99b4cc7d08b73b61f193d10f5)
pub fn crypto_secretstream_xchacha20poly1305_pull(
    state: &mut State,
    ciphertext: &InputBase,
    associated_data: Option<&InputBase>,
) -> Result<(OutputBase, Tag), Error> {
    use chacha20::cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use chacha20::{ChaCha20, Key, Nonce};
    use poly1305::{
        universal_hash::{NewUniversalHash, UniversalHash},
        Key as Poly1305Key, Poly1305,
    };

    if ciphertext.len() > CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX {
        return Err(dryoc_error!(format!(
            "Message length {} exceeds max length {}",
            ciphertext.len(),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
        )));
    }

    let associated_data = associated_data.unwrap_or(&[]);

    let mut mac_key = [0u8; 64];

    let key = Key::from_slice(state.k.as_slice());
    let nonce = Nonce::from_slice(state.nonce.as_slice());
    let mut cipher = ChaCha20::new(key, nonce);

    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&Poly1305Key::from_slice(&mac_key[0..32]));
    mac_key.zeroize();

    mac.update_padded(&associated_data);

    let mut block = [0u8; 64];
    block[0] = ciphertext[0];

    cipher.seek(64);
    cipher.apply_keystream(&mut block);

    let tag = Tag::from_bits(block[0]).expect("Failed to decode tag");
    block[0] = ciphertext[0];

    mac.update_padded(&block);

    let mlen = ciphertext.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
    let mut buffer: Vec<u8> = vec![0u8; mlen + block.len()];
    buffer[..mlen].copy_from_slice(&ciphertext[1..1 + mlen]);

    let mut size_data = [0u8; 16];
    size_data[..8].copy_from_slice(&associated_data.len().to_le_bytes());
    size_data[8..16].copy_from_slice(&(block.len() + mlen).to_le_bytes());

    // this is to workaround an unfortunate padding bug in libsodium, there's a
    // note in commit 290197ba3ee72245fdab5e971c8de43a82b19874. There's no
    // safety issue, so we can just pretend it's not a bug.
    let buffer_mac_pad = ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as usize;
    let size_data_start = mlen + buffer_mac_pad;
    let size_data_end = mlen + buffer_mac_pad + size_data.len();
    buffer[mlen..].fill(0);
    buffer[size_data_start..size_data_end].copy_from_slice(&size_data);
    buffer.resize(size_data_end, 0);
    let mac = mac.compute_unpadded(&buffer).into_bytes();

    cipher.seek(128);
    cipher.apply_keystream(&mut buffer[..mlen]);

    buffer.resize(mlen, 0);

    if ciphertext[1 + mlen..].ct_eq(&mac).unwrap_u8() == 0 {
        return Err(dryoc_error!("Message authentication mismatch"));
    }

    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, &mac);

    let counter = state_counter(&mut state.nonce);
    increment_bytes(counter);

    if tag & Tag::REKEY == Tag::REKEY
        || state_counter(&mut state.nonce)
            .ct_eq(&[0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES])
            .unwrap_u8()
            == 1
    {
        crypto_secretstream_xchacha20poly1305_rekey(state);
    }

    Ok((buffer, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sizes() {
        use crate::constants::*;
        use static_assertions::*;

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
            std::mem::size_of::<Nonce>()
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
        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use base64::encode;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let mut push_state = State::default();
        let push_header = crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &key);
        let push_state_init = push_state.clone();

        let message = b"hello";
        let aad = b"";
        let output = crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            message,
            Some(aad),
            Tag::MESSAGE,
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
            so_state.k.copy_from_slice(push_state_init.k.as_slice());
            so_state
                .nonce
                .copy_from_slice(push_state_init.nonce.as_slice());
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
            assert_eq!(encode(&so_output), encode(&output));
            assert_eq!(encode(&so_state.k), encode(push_state.k.as_slice()));
            assert_eq!(encode(&so_state.nonce), encode(push_state.nonce.as_slice()));

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
                key.as_slice().as_ptr(),
            );
            assert_eq!(ret, 0);
            assert_eq!(encode(&so_state.k), encode(push_state_init.k.as_slice()));
            assert_eq!(
                encode(&so_state.nonce),
                encode(push_state_init.nonce.as_slice())
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
        assert_eq!(encode(&message), encode(&so_output));

        let mut pull_state = State::default();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut &mut pull_state, &&push_header, &key);

        assert_eq!(
            encode(pull_state.k.as_slice()),
            encode(push_state_init.k.as_slice())
        );
        assert_eq!(
            encode(pull_state.nonce.as_slice()),
            encode(push_state_init.nonce.as_slice())
        );

        let (pull_result_message, pull_result_tag) =
            crypto_secretstream_xchacha20poly1305_pull(&mut pull_state, &&output, Some(&[]))
                .expect("pull failed");

        assert_eq!(Tag::MESSAGE, pull_result_tag);
        assert_eq!(encode(&pull_result_message), encode(&message));
    }

    #[test]
    fn test_rekey() {
        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use base64::encode;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_rekey as so_crypto_secretstream_xchacha20poly1305_rekey,
            crypto_secretstream_xchacha20poly1305_state,
        };

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let mut push_state = State::default();
        let _push_header = crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &key);
        let push_state_init = push_state.clone();

        crypto_secretstream_xchacha20poly1305_rekey(&mut push_state);

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        so_state.k.copy_from_slice(push_state_init.k.as_slice());
        so_state
            .nonce
            .copy_from_slice(push_state_init.nonce.as_slice());
        unsafe {
            so_crypto_secretstream_xchacha20poly1305_rekey(&mut so_state);
        }
        assert_eq!(encode(&so_state.k), encode(push_state.k.as_slice()));
        assert_eq!(encode(&so_state.nonce), encode(push_state.nonce.as_slice()));
    }

    #[test]
    fn test_secretstream_lots_of_messages_push() {
        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use base64::encode;
        use libc::{c_uchar, c_ulonglong};
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_state,
        };

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let mut push_state = State::default();
        let push_header = crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &key);
        let push_state_init = push_state.clone();

        let mut pull_state = State::default();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut &mut pull_state, &&push_header, &key);

        assert_eq!(
            encode(pull_state.k.as_slice()),
            encode(push_state_init.k.as_slice())
        );
        assert_eq!(
            encode(pull_state.nonce.as_slice()),
            encode(push_state_init.nonce.as_slice())
        );

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        so_state.k.copy_from_slice(push_state_init.k.as_slice());
        so_state
            .nonce
            .copy_from_slice(push_state_init.nonce.as_slice());

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
                key.as_slice().as_ptr(),
            );
            assert_eq!(ret, 0);
        }
        assert_eq!(encode(&so_state.k), encode(push_state_init.k.as_slice()));
        assert_eq!(
            encode(&so_state.nonce),
            encode(push_state_init.nonce.as_slice())
        );

        for i in 0..100 {
            let message = format!("hello {}", i);
            let aad = format!("aad {}", i);
            let tag = if i % 7 == 0 { Tag::REKEY } else { Tag::MESSAGE };

            let output = crypto_secretstream_xchacha20poly1305_push(
                &mut push_state,
                message.as_bytes(),
                Some(aad.as_bytes()),
                tag,
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
            assert_eq!(encode(&message), encode(&so_output));

            let (pull_result_message, pull_result_tag) =
                crypto_secretstream_xchacha20poly1305_pull(
                    &mut pull_state,
                    &output,
                    Some(aad.as_bytes()),
                )
                .expect("pull failed");

            assert_eq!(tag, pull_result_tag);
            assert_eq!(encode(&pull_result_message), encode(&message));
        }
    }

    #[test]
    fn test_secretstream_basic_pull() {
        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use base64::encode;
        use libc::c_ulonglong;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_push as so_crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        let mut so_header = [0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];
        unsafe {
            so_crypto_secretstream_xchacha20poly1305_init_push(
                &mut so_state,
                so_header.as_mut_ptr(),
                key.as_slice().as_ptr(),
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

        let (output, tag) =
            crypto_secretstream_xchacha20poly1305_pull(&mut pull_state, &so_output, Some(aad))
                .expect("decrypt failed");

        assert_eq!(encode(&output), encode(message));
        assert_eq!(tag.bits(), 0);
    }

    #[test]
    fn test_secretstream_lots_of_messages_pull() {
        use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
        use base64::encode;
        use libc::c_ulonglong;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_push as so_crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let mut so_state = crypto_secretstream_xchacha20poly1305_state {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; 8],
        };
        let mut so_header = [0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];
        unsafe {
            so_crypto_secretstream_xchacha20poly1305_init_push(
                &mut so_state,
                so_header.as_mut_ptr(),
                key.as_slice().as_ptr(),
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

            let (output, outtag) = crypto_secretstream_xchacha20poly1305_pull(
                &mut pull_state,
                &so_output,
                Some(aad.as_bytes()),
            )
            .expect("decrypt failed");

            assert_eq!(encode(&so_state.k), encode(pull_state.k.as_slice()));
            assert_eq!(encode(&so_state.nonce), encode(pull_state.nonce.as_slice()));

            assert_eq!(encode(&output), encode(message));
            assert_eq!(outtag, tag);
        }
    }
}
