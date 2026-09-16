#![no_main]
//! Secretstream push/pull sequences: every message the fuzzer describes (tag,
//! length, associated data, optional explicit rekey) is pushed with the
//! classic API and pulled back with both the classic API and `DryocStream`,
//! asserting message, tag and lockstep push/pull state. Before each valid
//! pull one input-selected mutation (ciphertext, tag byte, MAC, associated
//! data, truncation) and one replay are rejected without touching the output
//! buffer, the tag or the pull state.
use dryoc::classic::crypto_secretstream_xchacha20poly1305::{
    State, crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_pull, crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_rekey,
};
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
};
use dryoc::dryocstream::{DryocStream, Header, Key, Pull};
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;
use common::fill;

/// Longest message in a sequence; covers the 64-byte block boundaries the
/// stream cipher and Poly1305 care about several times over.
const MAX_MESSAGE_LEN: usize = 1024;
/// Longest associated data.
const MAX_AAD_LEN: usize = 255;
/// Messages per sequence.
const MAX_MESSAGES: usize = 8;

const TAGS: [u8; 4] = [
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
];

/// Takes `len` bytes from `data`, cycling what is left when the input runs
/// short (zeros when it is empty), so long messages need short inputs.
fn take_cycled(data: &mut &[u8], len: usize) -> Vec<u8> {
    let n = len.min(data.len());
    let (head, rest) = data.split_at(n);
    *data = rest;
    if head.is_empty() {
        vec![0u8; len]
    } else {
        head.iter().copied().cycle().take(len).collect()
    }
}

struct Step {
    tag: u8,
    rekey_before: bool,
    message: Vec<u8>,
    aad: Option<Vec<u8>>,
    /// Which corruption to try before the valid pull.
    mutation: u8,
    /// Bit position for the corruption.
    bit: u16,
}

fn take_step(data: &mut &[u8]) -> Step {
    let ctl = fill::<1>(data)[0];
    let len = usize::from(u16::from_le_bytes(fill::<2>(data))) % (MAX_MESSAGE_LEN + 1);
    let bit = u16::from_le_bytes(fill::<2>(data));
    let aad = (ctl & 0x04 != 0).then(|| {
        let aad_len = usize::from(fill::<1>(data)[0]) % (MAX_AAD_LEN + 1);
        take_cycled(data, aad_len)
    });
    Step {
        tag: TAGS[usize::from(ctl & 0x03)],
        rekey_before: ctl & 0x08 != 0,
        message: take_cycled(data, len),
        aad,
        mutation: (ctl >> 4) % 6,
        bit,
    }
}

/// Returns a corrupted `(ciphertext, aad)` pair for `step`, or `None` when
/// the selected mutation is a no-op for this message (nothing to flip).
fn corrupt(step: &Step, ciphertext: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let bit = usize::from(step.bit);
    let mut ct = ciphertext.to_vec();
    let mut aad = step.aad.clone();
    match step.mutation {
        // Encrypted tag byte.
        0 => ct[0] ^= 1 << (bit % 8),
        // Ciphertext body.
        1 => {
            if step.message.is_empty() {
                return None;
            }
            let idx = 1 + bit % step.message.len();
            ct[idx] ^= 1 << (bit % 8);
        }
        // MAC.
        2 => {
            let idx = ct.len() - 16 + bit % 16;
            ct[idx] ^= 1 << (bit % 8);
        }
        // Associated data: flip a bit, or present some when there was none.
        3 => match &mut aad {
            Some(aad) if !aad.is_empty() => {
                let idx = bit % aad.len();
                aad[idx] ^= 1 << (bit % 8);
            }
            _ => aad = Some(vec![step.bit as u8; 1 + bit % 4]),
        },
        // Drop the associated data, or truncate it.
        4 => match &mut aad {
            Some(aad) if !aad.is_empty() => {
                aad.pop();
            }
            Some(_) => return None,
            None => aad = Some(vec![0u8]),
        },
        // Truncate the ciphertext (possibly below the overhead).
        _ => {
            ct.pop();
        }
    }
    Some((ct, aad))
}

/// Asserts that pulling `ciphertext` with `aad` fails and leaves the output,
/// the tag and the pull state untouched.
fn assert_rejected(pull_state: &State, ciphertext: &[u8], aad: Option<&[u8]>) {
    let mut state = pull_state.clone();
    let mut output = vec![0xa5u8; ciphertext.len()];
    let mut tag = 0xa5u8;
    let result = crypto_secretstream_xchacha20poly1305_pull(
        &mut state,
        &mut output,
        &mut tag,
        ciphertext,
        aad,
    );
    assert!(result.is_err(), "corrupted ciphertext authenticated");
    assert!(
        output.iter().all(|&b| b == 0xa5),
        "failed pull wrote output"
    );
    assert_eq!(tag, 0xa5, "failed pull wrote tag");
    assert!(state == *pull_state, "failed pull advanced state");
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let key = fill::<CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES>(&mut data);
    let header = fill::<CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES>(&mut data);
    let count = 1 + usize::from(fill::<1>(&mut data)[0]) % MAX_MESSAGES;
    let steps: Vec<Step> = (0..count).map(|_| take_step(&mut data)).collect();

    // Both directions start from the same header (the push side would
    // otherwise draw a random one), so the run is reproducible.
    let mut push_state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut push_state, &header, &key);
    let mut pull_state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &header, &key);
    let mut stream: DryocStream<Pull> =
        DryocStream::init_pull(&Key::from(key), &Header::from(header));
    assert!(push_state == pull_state);

    for step in &steps {
        if step.rekey_before {
            crypto_secretstream_xchacha20poly1305_rekey(&mut push_state);
            crypto_secretstream_xchacha20poly1305_rekey(&mut pull_state);
            stream.rekey();
        }
        let aad = step.aad.as_deref();

        let mut ciphertext =
            vec![0u8; step.message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            &mut ciphertext,
            &step.message,
            aad,
            step.tag,
        )
        .expect("push");

        // Corruption and replay-from-the-future are rejected atomically.
        if let Some((bad_ct, bad_aad)) = corrupt(step, &ciphertext) {
            assert_rejected(&pull_state, &bad_ct, bad_aad.as_deref());
            // The valid pull below proves the stream did not advance here.
            let bad_ct: &[u8] = &bad_ct;
            let bad_aad = bad_aad.as_deref();
            assert!(stream.pull_to_vec(&bad_ct, bad_aad.as_ref()).is_err());
        }
        assert_rejected(&push_state, &ciphertext, aad);

        // Classic pull.
        let mut message = vec![0xa5u8; step.message.len()];
        let mut tag = 0xa5u8;
        let len = crypto_secretstream_xchacha20poly1305_pull(
            &mut pull_state,
            &mut message,
            &mut tag,
            &ciphertext,
            aad,
        )
        .expect("pull");
        assert_eq!(len, step.message.len());
        assert_eq!(message, step.message);
        assert_eq!(tag, step.tag);
        assert!(push_state == pull_state, "push and pull states diverged");

        // Rustaceous pull sees the same message and tag.
        let ciphertext_ref: &[u8] = &ciphertext;
        let (pulled, pulled_tag) = stream
            .pull_to_vec(&ciphertext_ref, aad.as_ref())
            .expect("stream pull");
        assert_eq!(pulled, step.message);
        assert_eq!(pulled_tag.bits(), step.tag);

        // Replay: the same ciphertext no longer authenticates once consumed.
        assert_rejected(&pull_state, &ciphertext, aad);
    }
});
