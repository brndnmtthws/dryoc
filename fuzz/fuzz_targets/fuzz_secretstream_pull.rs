#![no_main]
use dryoc::classic::crypto_secretstream_xchacha20poly1305::{
    State, crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_pull,
};
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
};
use dryoc::dryocstream::{DryocStream, Header, Key, Pull};
use dryoc::types::ByteArray;
use libfuzzer_sys::fuzz_target;

fn fill<const N: usize>(data: &mut &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = out.len().min(data.len());
    out[..n].copy_from_slice(&data[..n]);
    *data = &data[n..];
    out
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let key = Key::from(fill::<CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES>(
        &mut data,
    ));
    let header = Header::from(fill::<CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES>(
        &mut data,
    ));
    let aad_len = match data.split_first() {
        Some((aad_len, rest)) => {
            data = rest;
            (*aad_len as usize).min(data.len())
        }
        None => 0,
    };
    let aad = data[..aad_len].to_vec();
    let ciphertext = data[aad_len..].to_vec();
    let aad = if aad.is_empty() { None } else { Some(&aad) };

    let mut stream: DryocStream<Pull> = DryocStream::init_pull(&key, &header);
    let _ = stream.pull_to_vec(&ciphertext, aad);

    let mut state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut state, header.as_array(), key.as_array());
    let output_len = ciphertext
        .len()
        .saturating_sub(CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    let mut output = vec![0u8; output_len];
    let mut tag = 0u8;
    let _ = crypto_secretstream_xchacha20poly1305_pull(
        &mut state,
        &mut output,
        &mut tag,
        &ciphertext,
        aad.map(|aad| aad.as_slice()),
    );
});
