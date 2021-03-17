use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX, CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES,
    CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES,
};
use crate::crypto_core::crypto_core_hchacha20;
use crate::error::*;
use crate::rng::copy_randombytes;
use crate::types::{InputBase, OutputBase, SecretStreamKeyBase};

const PADBYTES: usize = 8;
type SecretStreamKey = [u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES];
type SecretstreamNonce = [u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES];
type SecretStreamPad = [u8; PADBYTES];

pub struct SecretstreamXchacha20poly1305State {
    k: SecretStreamKey,
    nonce: SecretstreamNonce,
    _pad: SecretStreamPad,
}

impl SecretstreamXchacha20poly1305State {
    pub fn new() -> Self {
        Self {
            k: [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES],
            _pad: [0u8; PADBYTES],
        }
    }
}

impl Default for SecretstreamXchacha20poly1305State {
    fn default() -> Self {
        Self::new()
    }
}

/// Generates a random key using [copy_randombytes]
pub fn crypto_secretstream_xchacha20poly1305_keygen() -> SecretStreamKeyBase {
    let mut key: SecretStreamKeyBase = [0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES];
    copy_randombytes(&mut key);
    key
}

fn crypto_secretstream_xchacha20poly1305_counter_reset(
    state: &mut SecretstreamXchacha20poly1305State,
) {
    state.nonce.fill(0);
    state.nonce[0] = 1;
}

pub fn crypto_secretstream_xchacha20poly1305_init_push(
    state: &mut SecretstreamXchacha20poly1305State,
    key: &SecretStreamKeyBase,
) -> OutputBase {
    use crate::rng::copy_randombytes;

    let mut out: OutputBase = vec![0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];

    copy_randombytes(&mut out);
    let mut out = crypto_core_hchacha20(&state.k[0..16], key);

    state.nonce[CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES..].copy_from_slice(
        &out[CRYPTO_CORE_HCHACHA20_INPUTBYTES
            ..(CRYPTO_CORE_HCHACHA20_INPUTBYTES
                + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES)],
    );

    state._pad.fill(0);

    out
}

pub fn crypto_secretstream_xchacha20poly1305_init_pull() {}

pub fn crypto_secretstream_xchacha20poly1305_rekey() {}

pub fn crypto_secretstream_xchacha20poly1305_push(message: &InputBase) -> Result<(), Error> {
    if message.len() > CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX {
        return Err(dryoc_error!(format!(
            "Message length {} exceeds max length {}",
            message.len(),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
        )));
    }

    Ok(())
}

pub fn crypto_secretstream_xchacha20poly1305_pull() {}
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
            std::mem::size_of::<SecretstreamNonce>()
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
    fn test_secretstream_basic() {
        use sodiumoxide::crypto::secretstream::{gen_key, Key, Stream, Tag};

        let msg1 = "message 1";

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let so_key = Key::from_slice(&key).expect("failed to get key");
        let (mut enc_stream, header) = Stream::init_push(&so_key).expect("failed to init stream");

        let mut state = SecretstreamXchacha20poly1305State::default();
        let mut stream = crypto_secretstream_xchacha20poly1305_init_push(&mut state, &key);
    }
}
