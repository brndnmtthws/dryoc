use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE, CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES,
    CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES,
};
use crate::crypto_core::crypto_core_hchacha20;
use crate::error::*;
use crate::types::{InputBase, OutputBase, SecretStreamKey, SecretStreamPad, SecretstreamNonce};
use crate::utils::{increment_bytes, xor_buf};

use libsodium_sys::crypto_onetimeauth_final;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[repr(u8)]
pub enum Tag {
    Message = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    Final = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
}

impl From<u8> for Tag {
    fn from(other: u8) -> Self {
        match other {
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL => Tag::Final,
            _ => Tag::Message,
        }
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretstreamXchacha20poly1305State {
    k: SecretStreamKey,
    nonce: SecretstreamNonce,
}

impl SecretstreamXchacha20poly1305State {
    pub fn new() -> Self {
        Self {
            k: SecretStreamKey::new(),
            nonce: SecretstreamNonce::gen(),
        }
    }
}

impl Default for SecretstreamXchacha20poly1305State {
    fn default() -> Self {
        Self::new()
    }
}

/// Generates a random key using [copy_randombytes]
pub fn crypto_secretstream_xchacha20poly1305_keygen() -> SecretStreamKey {
    SecretStreamKey::gen()
}

fn state_counter(nonce: &mut SecretstreamNonce) -> &mut [u8] {
    &mut nonce.0[0..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
}

fn state_inonce(nonce: &mut SecretstreamNonce) -> &mut [u8] {
    &mut nonce.0[CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES
        ..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
            + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
}

fn _crypto_secretstream_xchacha20poly1305_counter_reset(
    state: &mut SecretstreamXchacha20poly1305State,
) {
    let counter = state_counter(&mut state.nonce);
    counter.fill(0);
    counter[0] = 1;
}

/// Init push
pub fn crypto_secretstream_xchacha20poly1305_init_push(
    state: &mut SecretstreamXchacha20poly1305State,
    key: &SecretStreamKey,
) -> OutputBase {
    use crate::rng::copy_randombytes;

    let mut out: OutputBase = vec![0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];
    copy_randombytes(&mut out);

    let key = crypto_core_hchacha20(&out[..16], &key.0, None);
    // Copy key into state
    state.k.0.copy_from_slice(&key);
    _crypto_secretstream_xchacha20poly1305_counter_reset(state);

    let inonce = state_inonce(&mut state.nonce);
    inonce.copy_from_slice(
        &out[CRYPTO_CORE_HCHACHA20_INPUTBYTES
            ..(CRYPTO_CORE_HCHACHA20_INPUTBYTES
                + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES)],
    );

    out
}

/// Init pull
pub fn crypto_secretstream_xchacha20poly1305_init_pull(
    state: &mut SecretstreamXchacha20poly1305State,
    header: &InputBase,
    key: &SecretStreamKey,
) {
    let mut k = crypto_core_hchacha20(&header[0..16], &key.0, None);
    state.k.0.copy_from_slice(&k);

    _crypto_secretstream_xchacha20poly1305_counter_reset(state);

    let mut inonce = state_inonce(&mut state.nonce);
    inonce.copy_from_slice(
        &header[CRYPTO_CORE_HCHACHA20_INPUTBYTES
            ..(CRYPTO_CORE_HCHACHA20_INPUTBYTES
                + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES)],
    );
}

pub fn crypto_secretstream_xchacha20poly1305_rekey() {
    unimplemented!();
}

/// Push to stream
pub fn crypto_secretstream_xchacha20poly1305_push(
    state: &mut SecretstreamXchacha20poly1305State,
    message: &InputBase,
    associated_data: Option<&InputBase>,
    tag: Tag,
) -> Result<OutputBase, Error> {
    use base64::encode;
    use chacha20::cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use chacha20::{ChaCha20, Key, Nonce};
    use libsodium_sys::{
        crypto_onetimeauth_poly1305_final, crypto_onetimeauth_poly1305_init,
        crypto_onetimeauth_poly1305_state, crypto_onetimeauth_poly1305_update,
        crypto_stream_chacha20_ietf, crypto_stream_chacha20_ietf_xor_ic,
    };
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

    let key = Key::from_slice(&state.k.0);
    let nonce = Nonce::from_slice(&state.nonce.0);
    let mut cipher = ChaCha20::new(key, nonce);

    let mut mac_key_so = [0u8; 64];
    let key_so = state.k.0.clone();
    let nonce_so = state.nonce.0.clone();

    unsafe {
        crypto_stream_chacha20_ietf(
            mac_key_so.as_mut_ptr(),
            64,
            nonce_so.as_ptr(),
            key_so.as_ptr(),
        );
    }

    cipher.apply_keystream(&mut mac_key);
    assert_eq!(encode(&mac_key), encode(&mac_key_so));
    let mut mac = Poly1305::new(&Poly1305Key::from_slice(&mac_key[0..32]));
    let mut so_mac_state = crypto_onetimeauth_poly1305_state { opaque: [0; 256] };
    unsafe {
        crypto_onetimeauth_poly1305_init(&mut so_mac_state, mac_key.as_ptr());
    }
    mac_key.zeroize();

    mac.update_padded(&associated_data);
    unsafe {
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            associated_data.as_ptr(),
            associated_data.len() as u64,
        );
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            _pad0.as_ptr(),
            ((0x10 - associated_data.len()) & 0xf) as u64,
        );
        let mut so_mac_state_final = so_mac_state.clone();
        let mut mac_out = [0u8; 16];
        crypto_onetimeauth_poly1305_final(&mut so_mac_state_final, mac_out.as_mut_ptr());
        let mac_final = mac.clone().finalize().into_bytes();
        assert_eq!(encode(&mac_out), encode(&mac_final));
    }

    let mut block = [0u8; 64];
    block[0] = tag as u8;
    let mut block_so = block.clone();
    cipher.seek(64);
    cipher.apply_keystream(&mut block);
    mac.update_padded(&block);

    unsafe {
        crypto_stream_chacha20_ietf_xor_ic(
            block_so.as_mut_ptr(),
            block_so.as_ptr(),
            block.len() as u64,
            nonce_so.as_ptr(),
            1,
            key_so.as_ptr(),
        );
        crypto_onetimeauth_poly1305_update(&mut so_mac_state, block.as_ptr(), block.len() as u64);
        let mut so_mac_state_final = so_mac_state.clone();
        let mut mac_out = [0u8; 16];
        crypto_onetimeauth_poly1305_final(&mut so_mac_state_final, mac_out.as_mut_ptr());
        let mac_final = mac.clone().finalize().into_bytes();
        assert_eq!(encode(&mac_out), encode(&mac_final));
    }

    assert_eq!(encode(&block), encode(&block_so));

    let mlen = message.len();
    let mut buffer: Vec<u8> = vec![0u8; block.len() + mlen];
    buffer[0] = block[0];
    buffer[1..(1 + mlen)].copy_from_slice(&message);
    let mut buffer_so = buffer.clone();

    cipher.seek(128);
    cipher.apply_keystream(&mut buffer[1..(1 + mlen)]);

    let message_so = &mut buffer_so[1..(1 + mlen)];
    unsafe {
        crypto_stream_chacha20_ietf_xor_ic(
            message_so.as_mut_ptr(),
            message_so.as_ptr(),
            mlen as u64,
            nonce_so.as_ptr(),
            2,
            key_so.as_ptr(),
        );
        crypto_stream_chacha20_ietf_xor_ic(
            block_so.as_mut_ptr(),
            block_so.as_ptr(),
            block.len() as u64,
            nonce_so.as_ptr(),
            1,
            key_so.as_ptr(),
        );
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            buffer[1..(1 + mlen)].as_ptr(),
            mlen as u64,
        );
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            _pad0.as_ptr(),
            ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as u64,
        );
    }

    assert_eq!(encode(&buffer[1..(1 + mlen)]), encode(&message_so));

    let mut size_data = [0u8; 16];
    size_data[..8].copy_from_slice(&associated_data.len().to_le_bytes());
    size_data[8..16].copy_from_slice(&(block.len() + mlen).to_le_bytes());

    unsafe {
        crypto_onetimeauth_poly1305_update(&mut so_mac_state, size_data.as_ptr(), 16);
    }

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

    let mut mac_out = [0u8; 16];
    unsafe {
        let mut so_mac_state_final = so_mac_state.clone();
        crypto_onetimeauth_poly1305_final(&mut so_mac_state_final, mac_out.as_mut_ptr());
        assert_eq!(encode(&mac_out), encode(&mac));
    }

    buffer.resize(mlen + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES, 0);
    buffer[1 + mlen..].copy_from_slice(&mac_out);

    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, &mac_out);

    let counter = state_counter(&mut state.nonce);
    increment_bytes(counter);

    Ok(buffer)
}

/// Pull the guy
pub fn crypto_secretstream_xchacha20poly1305_pull(
    state: &mut SecretstreamXchacha20poly1305State,
    input: &InputBase,
    associated_data: Option<&InputBase>,
) -> Result<(OutputBase, Tag), Error> {
    use base64::encode;
    use chacha20::cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use chacha20::{ChaCha20, Key, Nonce};
    use libsodium_sys::{
        crypto_onetimeauth_poly1305_final, crypto_onetimeauth_poly1305_init,
        crypto_onetimeauth_poly1305_state, crypto_onetimeauth_poly1305_update,
        crypto_stream_chacha20_ietf, crypto_stream_chacha20_ietf_xor_ic,
    };
    use poly1305::{
        universal_hash::{NewUniversalHash, UniversalHash},
        Key as Poly1305Key, Poly1305,
    };

    if input.len() > CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX {
        return Err(dryoc_error!(format!(
            "Message length {} exceeds max length {}",
            input.len(),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
        )));
    }

    let associated_data = associated_data.unwrap_or(&[]);

    let mut mac_key = [0u8; 64];
    let _pad0 = [0u8; 16];

    let key = Key::from_slice(&state.k.0);
    let nonce = Nonce::from_slice(&state.nonce.0);
    let mut cipher = ChaCha20::new(key, nonce);

    let mut mac_key_so = [0u8; 64];
    let key_so = state.k.0.clone();
    let nonce_so = state.nonce.0.clone();

    unsafe {
        crypto_stream_chacha20_ietf(
            mac_key_so.as_mut_ptr(),
            64,
            nonce_so.as_ptr(),
            key_so.as_ptr(),
        );
    }

    cipher.apply_keystream(&mut mac_key);
    assert_eq!(encode(&mac_key), encode(&mac_key_so));
    let mut mac = Poly1305::new(&Poly1305Key::from_slice(&mac_key[0..32]));
    let mut so_mac_state = crypto_onetimeauth_poly1305_state { opaque: [0; 256] };
    unsafe {
        crypto_onetimeauth_poly1305_init(&mut so_mac_state, mac_key.as_ptr());
    }
    mac_key.zeroize();

    mac.update_padded(&associated_data);
    unsafe {
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            associated_data.as_ptr(),
            associated_data.len() as u64,
        );
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            _pad0.as_ptr(),
            ((0x10 - associated_data.len()) & 0xf) as u64,
        );
        let mut so_mac_state_final = so_mac_state.clone();
        let mut mac_out = [0u8; 16];
        crypto_onetimeauth_poly1305_final(&mut so_mac_state_final, mac_out.as_mut_ptr());
        let mac_final = mac.clone().finalize().into_bytes();
        assert_eq!(encode(&mac_out), encode(&mac_final));
    }

    let mut block = [0u8; 64];
    block[0] = input[0];
    let mut block_so = block.clone();
    cipher.seek(64);
    cipher.apply_keystream(&mut block);
    mac.update_padded(&block);
    let tag = block[0].into();

    unsafe {
        crypto_stream_chacha20_ietf_xor_ic(
            block_so.as_mut_ptr(),
            block_so.as_ptr(),
            block.len() as u64,
            nonce_so.as_ptr(),
            1,
            key_so.as_ptr(),
        );
        crypto_onetimeauth_poly1305_update(&mut so_mac_state, block.as_ptr(), block.len() as u64);
        let mut so_mac_state_final = so_mac_state.clone();
        let mut mac_out = [0u8; 16];
        crypto_onetimeauth_poly1305_final(&mut so_mac_state_final, mac_out.as_mut_ptr());
        let mac_final = mac.clone().finalize().into_bytes();
        assert_eq!(encode(&mac_out), encode(&mac_final));
    }

    assert_eq!(encode(&block), encode(&block_so));

    let mlen = input.len();
    let mut buffer: Vec<u8> = vec![0u8; block.len() + mlen];
    buffer[0] = block[0];
    buffer[1..(1 + mlen)].copy_from_slice(&input);
    let mut buffer_so = buffer.clone();

    cipher.seek(128);
    cipher.apply_keystream(&mut buffer[1..(1 + mlen)]);

    let message_so = &mut buffer_so[1..(1 + mlen)];
    unsafe {
        crypto_stream_chacha20_ietf_xor_ic(
            message_so.as_mut_ptr(),
            message_so.as_ptr(),
            mlen as u64,
            nonce_so.as_ptr(),
            2,
            key_so.as_ptr(),
        );
        crypto_stream_chacha20_ietf_xor_ic(
            block_so.as_mut_ptr(),
            block_so.as_ptr(),
            block.len() as u64,
            nonce_so.as_ptr(),
            1,
            key_so.as_ptr(),
        );
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            buffer[1..(1 + mlen)].as_ptr(),
            mlen as u64,
        );
        crypto_onetimeauth_poly1305_update(
            &mut so_mac_state,
            _pad0.as_ptr(),
            ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as u64,
        );
    }

    assert_eq!(encode(&buffer[1..(1 + mlen)]), encode(&message_so));

    let mut size_data = [0u8; 16];
    size_data[..8].copy_from_slice(&associated_data.len().to_le_bytes());
    size_data[8..16].copy_from_slice(&(block.len() + mlen).to_le_bytes());

    unsafe {
        crypto_onetimeauth_poly1305_update(&mut so_mac_state, size_data.as_ptr(), 16);
    }

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

    let mut mac_out = [0u8; 16];
    unsafe {
        let mut so_mac_state_final = so_mac_state.clone();
        crypto_onetimeauth_poly1305_final(&mut so_mac_state_final, mac_out.as_mut_ptr());
        assert_eq!(encode(&mac_out), encode(&mac));
    }

    buffer.resize(mlen + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES, 0);
    buffer[1 + mlen..].copy_from_slice(&mac_out);

    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, &mac_out);

    let counter = state_counter(&mut state.nonce);
    increment_bytes(counter);

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
        use base64::encode;
        use libsodium_sys::{
            crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_state,
        };

        let key = crypto_secretstream_xchacha20poly1305_keygen();

        let mut push_state = SecretstreamXchacha20poly1305State::default();
        let push_header = crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &key);
        let push_state_init = push_state.clone();

        let message = b"hello";
        let aad = b"";
        let output = crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            message,
            Some(aad),
            Tag::Message,
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
            so_state.k.copy_from_slice(&push_state_init.k.0);
            so_state.nonce.copy_from_slice(&push_state_init.nonce.0);
            let mut clen_p: c_ulonglong = 0;
            let ret = so_crypto_secretstream_xchacha20poly1305_push(
                &mut so_state,
                so_output.as_mut_ptr(),
                &mut clen_p,
                message.as_ptr(),
                message.len() as u64,
                aad.as_ptr(),
                0,
                0,
            );
            assert_eq!(ret, 0);
            so_output.resize(clen_p as usize, 0);
            assert_eq!(encode(&so_output), encode(&output));
            assert_eq!(encode(&so_state.k), encode(&push_state.k.0));
            assert_eq!(encode(&so_state.nonce), encode(&push_state.nonce.0));

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
                key.0.as_ptr(),
            );
            assert_eq!(ret, 0);
            assert_eq!(encode(&so_state.k), encode(&push_state_init.k.0));
            assert_eq!(encode(&so_state.nonce), encode(&push_state_init.nonce.0));
            assert!(so_output.len() >= CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            let ret = so_crypto_secretstream_xchacha20poly1305_pull(
                &mut so_state,
                so_output.as_mut_ptr(),
                &mut mlen_p,
                &mut tag_p,
                output.as_ptr(),
                output.len() as u64,
                aad.as_ptr(),
                0 as u64,
            );
            assert_eq!(ret, 0);
            so_output.resize(mlen_p as usize, 0);
        }
        assert_eq!(encode(&message), encode(&so_output));

        let mut pull_state = SecretstreamXchacha20poly1305State::default();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut &mut pull_state, &&push_header, &key);

        assert_eq!(encode(&pull_state.k.0), encode(&push_state_init.k.0));
        assert_eq!(
            encode(&pull_state.nonce.0),
            encode(&push_state_init.nonce.0)
        );
    }
}
