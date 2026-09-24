//! # Secret streams
//!
//! Implements libsodium's `crypto_secretstream_xchacha20poly1305_*` functions
//! for encrypting an ordered sequence of messages with a shared secret key.
//! See the [libsodium documentation](https://doc.libsodium.org/secret-key_cryptography/secretstream)
//! for details.
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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::chacha20::ChaCha20;
use crate::classic::crypto_core::crypto_core_hchacha20;
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
use crate::poly1305::Poly1305;
use crate::rng::copy_randombytes;
use crate::types::*;
use crate::utils::{increment_bytes, pad16, verify_ct, xor_buf};

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

/// The ciphertext length for a `message_len`-byte message, which must not
/// exceed [`CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX`].
pub(crate) fn ciphertext_len_from_message_len(message_len: usize) -> Result<usize, Error> {
    validate_length!(
        max CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX,
        message_len,
        crate::ErrorContext::Message
    );
    Ok(message_len + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES)
}

/// The message length carried by a `ciphertext_len`-byte ciphertext, which
/// must hold the overhead and at most
/// [`CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX`] message bytes.
pub(crate) fn message_len_from_ciphertext_len(ciphertext_len: usize) -> Result<usize, Error> {
    validate_length!(
        min CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
        ciphertext_len,
        crate::ErrorContext::Ciphertext
    );
    validate_length!(
        max CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
            + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
        ciphertext_len,
        crate::ErrorContext::Ciphertext
    );
    Ok(ciphertext_len - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES)
}

fn secretstream_length_block(associated_data_len: usize, message_len: usize) -> [u8; 16] {
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(associated_data_len as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(64u64 + message_len as u64).to_le_bytes());
    lengths
}

/// Runs keystream blocks 0 and 1 for the current `state`: block 0 keys the
/// Poly1305 MAC (and is zeroized here), block 1 is XORed into `block`, whose
/// first byte the caller has set to the tag byte to encrypt or decrypt. The
/// returned MAC has absorbed `associated_data` and its padding. The cipher is
/// left positioned at block 2, where the message starts. Nothing in `state` is
/// touched.
#[inline]
fn secretstream_init_mac(
    state: &State,
    block: &mut [u8; 64],
    associated_data: &[u8],
) -> (ChaCha20, Zeroizing<Poly1305>) {
    let mut cipher = ChaCha20::ietf(&state.k, &state.nonce, 0);

    // Blocks 0 and 1 come out of one keystream run.
    let mut block0 = Zeroizing::new([0u8; 64]);
    cipher.apply_keystream_with_head(&mut block0, block);
    let mut mac_key = crate::poly1305::Key::new();
    mac_key.copy_from_slice(&block0[..mac_key.len()]);
    let mut mac = Zeroizing::new(Poly1305::new(&mac_key));
    mac_key.zeroize();
    drop(block0);

    mac.update(associated_data);
    mac.update(&[0u8; 16][..pad16(associated_data.len())]);

    (cipher, mac)
}

/// Advances `state` past an authenticated message: XORs `mac` into the
/// implicit nonce, increments the counter, and rekeys when `tag` requests it
/// or the counter wrapped to zero.
#[inline]
fn secretstream_advance(state: &mut State, mac: &[u8], tag: u8) {
    let inonce = state_inonce(&mut state.nonce);
    xor_buf(inonce, mac);

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
}

fn _crypto_secretstream_xchacha20poly1305_counter_reset(state: &mut State) {
    let counter = state_counter(&mut state.nonce);
    counter.fill(0);
    counter[0] = 1;
}

/// Initializes a push stream for streaming encryption.
///
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
    secretstream_init(state, header, key);
}

/// Initializes a pull stream for streaming decryption.
///
/// Initializes `state` using `key` and a `header` returned by
/// [`crypto_secretstream_xchacha20poly1305_init_push`].
///
/// Compatible with libsodium's
/// `crypto_secretstream_xchacha20poly1305_init_pull`.
pub fn crypto_secretstream_xchacha20poly1305_init_pull(
    state: &mut State,
    header: &Header,
    key: &Key,
) {
    secretstream_init(state, header, key);
}

fn secretstream_init(state: &mut State, header: &Header, key: &Key) {
    crypto_core_hchacha20(&mut state.k, ByteArray::as_array(&header[..16]), key, None);
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
/// `crypto_secretstream_xchacha20poly1305_rekey`.
pub fn crypto_secretstream_xchacha20poly1305_rekey(state: &mut State) {
    let mut new_state = Zeroizing::new(
        [0u8; CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES
            + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES],
    );

    new_state[..CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES].copy_from_slice(&state.k);
    new_state[CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES..]
        .copy_from_slice(state_inonce(&mut state.nonce));

    ChaCha20::ietf(&state.k, &state.nonce, 0).apply_keystream(&mut *new_state);

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
///
/// # Errors
///
/// Returns an error if `message` exceeds the maximum supported length or
/// `ciphertext` is not exactly one authentication tag longer than `message`.
pub fn crypto_secretstream_xchacha20poly1305_push(
    state: &mut State,
    ciphertext: &mut [u8],
    message: &[u8],
    associated_data: Option<&[u8]>,
    tag: u8,
) -> Result<(), Error> {
    let expected_ciphertext_len = ciphertext_len_from_message_len(message.len())?;
    validate_length!(
        exact expected_ciphertext_len,
        ciphertext.len(),
        crate::ErrorContext::Ciphertext
    );

    let associated_data = associated_data.unwrap_or(&[]);
    let _pad0 = [0u8; 16];

    // Block 0 keys the MAC, block 1 carries the tag, the message starts at
    // block 2; each call below consumes whole blocks.
    let mut block = Zeroizing::new([0u8; 64]);
    block[0] = tag;
    let (mut cipher, mut mac) = secretstream_init_mac(state, &mut block, associated_data);
    mac.update(&*block);

    let mlen = message.len();
    ciphertext[0] = block[0];
    cipher.apply_keystream_b2b(message, &mut ciphertext[1..(1 + mlen)]);

    let size_data = secretstream_length_block(associated_data.len(), mlen);

    mac.update(&ciphertext[1..(1 + mlen)]);
    // this is to workaround an unfortunate padding bug in libsodium, there's a
    // note in commit 290197ba3ee72245fdab5e971c8de43a82b19874. There's no
    // safety issue, so we can just pretend it's not a bug.
    let buffer_mac_pad = ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as usize;
    mac.update(&_pad0[0..buffer_mac_pad]);
    mac.update(&size_data);

    mac.finalize(&mut ciphertext[1 + mlen..]);

    secretstream_advance(state, &ciphertext[1 + mlen..], tag);

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
///
/// # Errors
///
/// Returns an error if `ciphertext` is too short or too long, `message` lacks
/// space for the plaintext, or authentication fails.
pub fn crypto_secretstream_xchacha20poly1305_pull(
    state: &mut State,
    message: &mut [u8],
    tag: &mut u8,
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<usize, Error> {
    let _pad0 = [0u8; 16];

    let mlen = message_len_from_ciphertext_len(ciphertext.len())?;

    validate_length!(min mlen, message.len(), crate::ErrorContext::Message);

    let associated_data = associated_data.unwrap_or(&[]);

    // Block 0 keys the MAC, block 1 carries the tag, the message starts at
    // block 2; each call below consumes whole blocks.
    let mut block = Zeroizing::new([0u8; 64]);
    block[0] = ciphertext[0];
    let (mut cipher, mut mac) = secretstream_init_mac(state, &mut block, associated_data);

    let decrypted_tag = block[0];
    block[0] = ciphertext[0];

    mac.update(&*block);

    // this is to workaround an unfortunate padding bug in libsodium, there's a
    // note in commit 290197ba3ee72245fdab5e971c8de43a82b19874. There's no
    // safety issue, so we can just pretend it's not a bug.
    let buffer_mac_pad = ((0x10 - block.len() as i64 + mlen as i64) & 0xf) as usize;
    mac.update(&ciphertext[1..1 + mlen]);
    mac.update(&_pad0[..buffer_mac_pad]);

    let size_data = secretstream_length_block(associated_data.len(), mlen);
    mac.update(&size_data);
    let mac = Zeroizing::new(mac.finalize_to_array());

    verify_ct(&ciphertext[1 + mlen..], mac.as_slice())?;

    cipher.apply_keystream_b2b(&ciphertext[1..1 + mlen], &mut message[..mlen]);
    *tag = decrypted_tag;

    secretstream_advance(state, &*mac, decrypted_tag);

    Ok(mlen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dryocstream::Tag;

    /// The length checks shared by Classic and Rustaceous push and pull
    /// accept exactly `MESSAGEBYTES_MAX` message bytes (libsodium's
    /// `64 * (2^32 - 2)`, capped so the ciphertext length fits a `usize`) and
    /// reject one more, checked on lengths since no test can allocate such a
    /// buffer.
    #[test]
    fn length_checks_accept_exactly_messagebytes_max() {
        const MAX: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX;
        const ABYTES: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        #[cfg(target_pointer_width = "64")]
        assert_eq!(MAX, 64 * ((1 << 32) - 2));
        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(MAX, usize::MAX - ABYTES);

        assert!(matches!(ciphertext_len_from_message_len(0), Ok(ABYTES)));
        assert!(matches!(
            ciphertext_len_from_message_len(MAX),
            Ok(len) if len == MAX + ABYTES
        ));
        assert!(matches!(
            ciphertext_len_from_message_len(MAX + 1),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Message,
                actual,
                constraint: LengthConstraint::AtMost(max),
            }) if actual == MAX + 1 && max == MAX
        ));

        assert!(matches!(
            message_len_from_ciphertext_len(ABYTES - 1),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Ciphertext,
                actual,
                constraint: LengthConstraint::AtLeast(ABYTES),
            }) if actual == ABYTES - 1
        ));
        assert!(matches!(message_len_from_ciphertext_len(ABYTES), Ok(0)));
        assert!(matches!(
            message_len_from_ciphertext_len(MAX + ABYTES),
            Ok(len) if len == MAX
        ));
        // On 32-bit targets `MAX + ABYTES` is `usize::MAX`, so no longer
        // ciphertext length exists.
        if let Some(too_long) = (MAX + ABYTES).checked_add(1) {
            assert!(matches!(
                message_len_from_ciphertext_len(too_long),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::Ciphertext,
                    actual,
                    constraint: LengthConstraint::AtMost(max),
                }) if actual == too_long && max == MAX + ABYTES
            ));
        }
    }

    /// Push and pull must reject wrong buffer lengths with the right error
    /// and leave the sentinel output, the tag and the (cloned) state exactly
    /// as they were, and the state must remain usable afterwards. Neither
    /// libsodium nor this implementation validates the tag byte itself.
    #[test]
    fn push_and_pull_reject_invalid_buffer_lengths_without_mutation() {
        let key = Key::default();
        let mut state = State::new();
        let mut header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &key);
        let original_state = state.clone();
        let message = b"message";

        for len in [
            0,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
            message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES - 1,
            message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES + 1,
        ] {
            let mut ciphertext = vec![0xa5u8; len];
            let error = crypto_secretstream_xchacha20poly1305_push(
                &mut state,
                &mut ciphertext,
                message,
                None,
                Tag::MESSAGE.bits(),
            )
            .expect_err("ciphertext must be exactly the message plus overhead");
            assert!(
                matches!(
                    error,
                    Error::InvalidLength {
                        context: crate::ErrorContext::Ciphertext,
                        ..
                    }
                ),
                "push into {len} bytes"
            );
            assert_eq!(ciphertext, vec![0xa5u8; len], "push into {len} bytes");
            assert!(state == original_state, "push into {len} bytes");
        }

        let mut ciphertext =
            vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        crypto_secretstream_xchacha20poly1305_push(
            &mut state,
            &mut ciphertext,
            message,
            None,
            Tag::MESSAGE.bits(),
        )
        .expect("state must remain usable");

        let mut state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);
        let original_state = state.clone();
        let mut tag = 0x5a;

        let short_ciphertext = [0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES - 1];
        let mut output = [0xa5u8; 8];
        let error = crypto_secretstream_xchacha20poly1305_pull(
            &mut state,
            &mut output,
            &mut tag,
            &short_ciphertext,
            None,
        )
        .expect_err("ciphertext must include secretstream overhead");
        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::Ciphertext,
                ..
            }
        ));
        assert_eq!((output, tag), ([0xa5u8; 8], 0x5a));
        assert!(state == original_state);

        let mut output = vec![0xa5u8; message.len() - 1];
        let error = crypto_secretstream_xchacha20poly1305_pull(
            &mut state,
            &mut output,
            &mut tag,
            &ciphertext,
            None,
        )
        .expect_err("the message buffer must hold the plaintext");
        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::Message,
                ..
            }
        ));
        assert_eq!(output, vec![0xa5u8; message.len() - 1]);
        assert_eq!(tag, 0x5a);
        assert!(state == original_state);

        let mut output = vec![0u8; message.len()];
        crypto_secretstream_xchacha20poly1305_pull(
            &mut state,
            &mut output,
            &mut tag,
            &ciphertext,
            None,
        )
        .expect("state must remain usable");
        assert_eq!(
            (output.as_slice(), tag),
            (&message[..], Tag::MESSAGE.bits())
        );
    }

    #[test]
    fn pull_authenticates_before_mutating_outputs_or_state() {
        let key = Key::default();
        let mut push_state = State::new();
        let mut header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut header, &key);

        let plaintext = b"do not publish unauthenticated plaintext";
        let mut ciphertext =
            vec![0u8; plaintext.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            &mut ciphertext,
            plaintext,
            Some(b"associated data"),
            Tag::FINAL.bits(),
        )
        .expect("push failed");

        let mut pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &header, &key);
        let original_state = pull_state.clone();
        let mut tampered = ciphertext.clone();
        *tampered.last_mut().expect("authentication tag") ^= 1;
        let mut output = vec![0xa5; plaintext.len()];
        let original_output = output.clone();
        let mut tag = 0x5a;

        assert!(matches!(
            crypto_secretstream_xchacha20poly1305_pull(
                &mut pull_state,
                &mut output,
                &mut tag,
                &tampered,
                Some(b"associated data"),
            ),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(output, original_output);
        assert_eq!(tag, 0x5a);
        assert!(pull_state == original_state);

        crypto_secretstream_xchacha20poly1305_pull(
            &mut pull_state,
            &mut output,
            &mut tag,
            &ciphertext,
            Some(b"associated data"),
        )
        .expect("state must remain usable after authentication failure");
        assert_eq!(output, plaintext);
        assert_eq!(tag, Tag::FINAL.bits());
    }

    #[test]
    fn length_block_uses_fixed_width_little_endian_values() {
        let lengths = secretstream_length_block(0x0102_0304, 0x0506_0708);

        assert_eq!(&lengths[..8], &0x0102_0304u64.to_le_bytes());
        assert_eq!(&lengths[8..], &(64u64 + 0x0506_0708).to_le_bytes());
    }

    #[test]
    fn test_sizes() {
        use crate::constants::*;

        const _: () = assert!(
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
                == CRYPTO_CORE_HCHACHA20_INPUTBYTES
                    + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
        );

        const _: () = assert!(
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
                == CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        const _: () = assert!(
            CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES
                == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
                    + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES
        );

        const _: () = assert!(
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
                <= CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
        );

        const _: () = assert!(
            CRYPTO_ONETIMEAUTH_POLY1305_BYTES >= CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES
        );

        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(
                CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX,
                usize::MAX - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES
            );
            assert_eq!(
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX,
                usize::MAX - CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
            );
            assert_eq!(
                CRYPTO_SECRETBOX_MESSAGEBYTES_MAX,
                usize::MAX - CRYPTO_SECRETBOX_MACBYTES
            );
        }
    }

    #[test]
    fn test_secretstream_large_aad() {
        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut push_state = State::new();
        let mut push_header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut push_header, &key);

        let message = b"hello world";
        let large_aad = vec![0x42u8; 328]; // 328 bytes of 0x42

        let mut ciphertext =
            vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            &mut ciphertext,
            message,
            Some(&large_aad),
            Tag::MESSAGE.bits(),
        )
        .expect("push failed");

        let mut pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &push_header, &key);

        let mut decrypted = vec![0u8; message.len()];
        let mut tag = 0u8;

        crypto_secretstream_xchacha20poly1305_pull(
            &mut pull_state,
            &mut decrypted,
            &mut tag,
            &ciphertext,
            Some(&large_aad),
        )
        .expect("pull failed");

        assert_eq!(message.as_slice(), decrypted.as_slice());
        assert_eq!(tag, Tag::MESSAGE.bits());

        // Test with wrong AAD should fail
        let mut wrong_aad = large_aad.clone();
        wrong_aad[100] = 0x43; // Change one byte

        let mut wrong_aad_pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(
            &mut wrong_aad_pull_state,
            &push_header,
            &key,
        );

        let mut decrypted = vec![0u8; message.len()];
        let mut tag = 0u8;

        assert!(
            crypto_secretstream_xchacha20poly1305_pull(
                &mut wrong_aad_pull_state,
                &mut decrypted,
                &mut tag,
                &ciphertext,
                Some(&wrong_aad),
            )
            .is_err()
        );
    }

    #[test]
    fn test_secretstream_small_aad() {
        let mut key = Key::default();
        crypto_secretstream_xchacha20poly1305_keygen(&mut key);

        let mut push_state = State::new();
        let mut push_header = Header::default();
        crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut push_header, &key);

        let message = b"hello world";
        let small_aad = b"abc"; // 3 bytes of AAD

        let mut ciphertext =
            vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        crypto_secretstream_xchacha20poly1305_push(
            &mut push_state,
            &mut ciphertext,
            message,
            Some(small_aad),
            Tag::MESSAGE.bits(),
        )
        .expect("push failed");

        let mut pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &push_header, &key);

        let mut decrypted = vec![0u8; message.len()];
        let mut tag = 0u8;

        crypto_secretstream_xchacha20poly1305_pull(
            &mut pull_state,
            &mut decrypted,
            &mut tag,
            &ciphertext,
            Some(small_aad),
        )
        .expect("pull failed");

        assert_eq!(message.as_slice(), decrypted.as_slice());
        assert_eq!(tag, Tag::MESSAGE.bits());

        // Test with wrong AAD should fail
        let wrong_aad = b"xyz"; // Different 3 byte AAD

        let mut wrong_aad_pull_state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(
            &mut wrong_aad_pull_state,
            &push_header,
            &key,
        );

        let mut decrypted = vec![0u8; message.len()];
        let mut tag = 0u8;

        assert!(
            crypto_secretstream_xchacha20poly1305_pull(
                &mut wrong_aad_pull_state,
                &mut decrypted,
                &mut tag,
                &ciphertext,
                Some(wrong_aad),
            )
            .is_err()
        );
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;
        use crate::constants::{
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
        };

        /// libsodium's state mirroring `state`.
        fn so_state(state: &State) -> libsodium_sys::crypto_secretstream_xchacha20poly1305_state {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_state {
                k: state.k,
                nonce: state.nonce,
                _pad: [0u8; 8],
            }
        }

        fn assert_same_state(
            so: &libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
            state: &State,
            ctx: &str,
        ) {
            assert_eq!((so.k, so.nonce), (state.k, state.nonce), "{ctx}: state");
        }

        /// libsodium's push, returning the ciphertext.
        fn so_push(
            so: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
            message: &[u8],
            ad: &[u8],
            tag: u8,
        ) -> Vec<u8> {
            crate::native_test_util::init();
            let mut ciphertext =
                vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            let mut clen: libc::c_ulonglong = 0;
            // SAFETY: every pointer comes from a live buffer of the length
            // passed beside it; `ciphertext` has room for the message and
            // the overhead.
            let rc = unsafe {
                libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
                    so,
                    ciphertext.as_mut_ptr(),
                    &mut clen,
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    ad.as_ptr(),
                    ad.len() as libc::c_ulonglong,
                    tag,
                )
            };
            assert_eq!((rc, clen as usize), (0, ciphertext.len()));
            ciphertext
        }

        /// libsodium's pull, returning the message and tag.
        fn so_pull(
            so: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
            ciphertext: &[u8],
            ad: &[u8],
        ) -> (Vec<u8>, u8) {
            crate::native_test_util::init();
            let mut message =
                vec![0u8; ciphertext.len() - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            let mut mlen: libc::c_ulonglong = 0;
            let mut tag: libc::c_uchar = 0;
            // SAFETY: as in `so_push`; `message` has room for the plaintext.
            let rc = unsafe {
                libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
                    so,
                    message.as_mut_ptr(),
                    &mut mlen,
                    &mut tag,
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    ad.as_ptr(),
                    ad.len() as libc::c_ulonglong,
                )
            };
            assert_eq!((rc, mlen as usize), (0, message.len()));
            (message, tag)
        }

        /// Pushes `message` with both implementations from equal states and
        /// checks the ciphertexts and the advanced states agree, then pulls
        /// it with both from equal pull states and checks the message, tag
        /// and advanced states agree.
        #[allow(clippy::too_many_arguments)]
        fn check_push_pull_match_libsodium(
            push_state: &mut State,
            so_push_state: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
            pull_state: &mut State,
            so_pull_state: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
            message: &[u8],
            ad: &[u8],
            tag: u8,
            ctx: &str,
        ) {
            let expected = so_push(so_push_state, message, ad, tag);
            let mut ciphertext =
                vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
            crypto_secretstream_xchacha20poly1305_push(
                push_state,
                &mut ciphertext,
                message,
                Some(ad),
                tag,
            )
            .expect("push");
            assert_eq!(ciphertext, expected, "{ctx}: ciphertext");
            assert_same_state(so_push_state, push_state, &format!("{ctx}: push"));

            let (expected_message, expected_tag) = so_pull(so_pull_state, &ciphertext, ad);
            let mut output = vec![0u8; message.len()];
            let mut pulled_tag = 0xa5;
            let mlen = crypto_secretstream_xchacha20poly1305_pull(
                pull_state,
                &mut output,
                &mut pulled_tag,
                &ciphertext,
                Some(ad),
            )
            .expect("pull");
            assert_eq!(mlen, message.len(), "{ctx}: pulled length");
            assert_eq!(
                (&output, pulled_tag),
                (&expected_message, expected_tag),
                "{ctx}: pull"
            );
            assert_eq!(
                (&output, pulled_tag),
                (&message.to_vec(), tag),
                "{ctx}: round trip"
            );
            assert_same_state(so_pull_state, pull_state, &format!("{ctx}: pull"));
        }

        /// Message lengths around the ChaCha20 block (the message starts at
        /// block 2, after the MAC key and tag blocks) and around the vector
        /// kernels' 8-, 9- and 16-block chunks.
        fn boundary_lens() -> Vec<usize> {
            let mut lens = vec![0, 1, 63, 64, 65, 127, 128, 129];
            for chunk in [8 * 64, 9 * 64, 16 * 64] {
                lens.extend([
                    chunk - 129,
                    chunk - 128,
                    chunk - 127,
                    chunk - 1,
                    chunk,
                    chunk + 1,
                ]);
            }
            lens.sort_unstable();
            lens.dedup();
            lens
        }

        /// One stream carrying every tag (MESSAGE, PUSH, REKEY, FINAL, and an
        /// arbitrary byte, which both implementations pass through and rekey
        /// on because its REKEY bit is set) over every message length in
        /// [`boundary_lens`] with empty, partial-block and whole-block
        /// associated data, against libsodium at every step.
        #[test]
        fn test_every_tag_and_length_matches_libsodium() {
            let mut rng = crate::utils::test_util::XorShift64::new(0x7f4a_7c15_9e37_79b9);
            let key: Key = rng.next_bytes32();
            let mut push_state = State::new();
            let mut header = Header::default();
            crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut header, &key);
            let mut pull_state = State::new();
            crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &header, &key);
            let mut so_push_state = so_state(&push_state);
            let mut so_pull_state = so_state(&pull_state);

            let tags = [
                CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
                CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
                CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
                0x42,
            ];
            let ads: [&[u8]; 3] = [b"", b"aad", &[0x5a; 16]];
            for len in boundary_lens() {
                let message: Vec<u8> = (0..len.div_ceil(8))
                    .flat_map(|_| rng.next_u64().to_le_bytes())
                    .take(len)
                    .collect();
                for tag in tags {
                    for ad in ads {
                        check_push_pull_match_libsodium(
                            &mut push_state,
                            &mut so_push_state,
                            &mut pull_state,
                            &mut so_pull_state,
                            &message,
                            ad,
                            tag,
                            &format!("len {len}, tag {tag:#04x}, ad {}", ad.len()),
                        );
                    }
                }
            }
        }

        /// With the counter set to its last values, the pushes that carry it
        /// through `ff ff ff ff` to zero must rekey automatically exactly as
        /// libsodium does (a MESSAGE tag, so only the wrap triggers it), and
        /// the stream must continue in step afterwards, on both sides.
        #[test]
        fn test_counter_wrap_rekeys_like_libsodium() {
            let mut rng = crate::utils::test_util::XorShift64::new(0x2545_f491_4f6c_dd1d);
            let key: Key = rng.next_bytes32();
            for start in [
                [0xfd, 0xff, 0xff, 0xff],
                [0xfe, 0xff, 0xff, 0xff],
                [0xff; 4],
            ] {
                let mut push_state = State::new();
                let mut header = Header::default();
                crypto_secretstream_xchacha20poly1305_init_push(&mut push_state, &mut header, &key);
                let mut pull_state = State::new();
                crypto_secretstream_xchacha20poly1305_init_pull(&mut pull_state, &header, &key);
                push_state.nonce[..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
                    .copy_from_slice(&start);
                pull_state.nonce[..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
                    .copy_from_slice(&start);
                let mut so_push_state = so_state(&push_state);
                let mut so_pull_state = so_state(&pull_state);

                let before_wrap = push_state.clone();
                for step in 0..5 {
                    let message: Vec<u8> = (0..37 * step).map(|i| i as u8).collect();
                    check_push_pull_match_libsodium(
                        &mut push_state,
                        &mut so_push_state,
                        &mut pull_state,
                        &mut so_pull_state,
                        &message,
                        b"counter",
                        CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                        &format!("start {start:02x?}, step {step}"),
                    );
                    let counter = u32::from_le_bytes(
                        push_state.nonce[..CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES]
                            .try_into()
                            .unwrap(),
                    );
                    let wrapped = u32::from_le_bytes(start).checked_add(step + 1).is_none();
                    if wrapped {
                        // Rekeyed: fresh key, counter reset to 1.
                        assert_ne!(
                            push_state.k, before_wrap.k,
                            "start {start:02x?}, step {step}"
                        );
                        assert_eq!(
                            counter,
                            (step + 1) - (u32::MAX - u32::from_le_bytes(start)),
                            "start {start:02x?}, step {step}"
                        );
                    } else {
                        assert_eq!(
                            push_state.k, before_wrap.k,
                            "start {start:02x?}, step {step}"
                        );
                        assert_eq!(
                            counter,
                            u32::from_le_bytes(start) + step + 1,
                            "start {start:02x?}, step {step}"
                        );
                    }
                }
            }
        }

        #[test]
        fn test_secretstream_basic_push() {
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use libsodium_sys::{
                crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
                crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
                crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
                crypto_secretstream_xchacha20poly1305_state,
            };

            use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
            use crate::dryocstream::Tag;

            crate::native_test_util::init();

            let mut key = Key::default();
            crypto_secretstream_xchacha20poly1305_keygen(&mut key);

            let mut push_state = State::new();
            let mut push_header = Header::default();
            crypto_secretstream_xchacha20poly1305_init_push(
                &mut push_state,
                &mut push_header,
                &key,
            );
            let push_state_init = push_state.clone();

            let message = b"hello";
            let mut output =
                vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
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
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use libsodium_sys::{
                crypto_secretstream_xchacha20poly1305_rekey as so_crypto_secretstream_xchacha20poly1305_rekey,
                crypto_secretstream_xchacha20poly1305_state,
            };

            use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;

            crate::native_test_util::init();

            let mut key = Key::default();
            crypto_secretstream_xchacha20poly1305_keygen(&mut key);

            let mut push_state = State::default();
            let mut push_header: Header = Header::default();
            crypto_secretstream_xchacha20poly1305_init_push(
                &mut push_state,
                &mut push_header,
                &key,
            );
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
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use libc::{c_uchar, c_ulonglong};
            use libsodium_sys::{
                crypto_secretstream_xchacha20poly1305_init_pull as so_crypto_secretstream_xchacha20poly1305_init_pull,
                crypto_secretstream_xchacha20poly1305_pull as so_crypto_secretstream_xchacha20poly1305_pull,
                crypto_secretstream_xchacha20poly1305_state,
            };

            use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
            use crate::dryocstream::Tag;

            crate::native_test_util::init();

            let mut key = Key::default();
            crypto_secretstream_xchacha20poly1305_keygen(&mut key);

            let mut push_state = State::new();
            let mut push_header = Header::default();
            crypto_secretstream_xchacha20poly1305_init_push(
                &mut push_state,
                &mut push_header,
                &key,
            );
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
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use libc::c_ulonglong;
            use libsodium_sys::{
                crypto_secretstream_xchacha20poly1305_init_push as so_crypto_secretstream_xchacha20poly1305_init_push,
                crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
                crypto_secretstream_xchacha20poly1305_state,
            };

            use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;

            crate::native_test_util::init();

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
            let mut so_output =
                vec![0u8; message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
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
            use base64::Engine as _;
            use base64::engine::general_purpose;
            use libc::c_ulonglong;
            use libsodium_sys::{
                crypto_secretstream_xchacha20poly1305_init_push as so_crypto_secretstream_xchacha20poly1305_init_push,
                crypto_secretstream_xchacha20poly1305_push as so_crypto_secretstream_xchacha20poly1305_push,
                crypto_secretstream_xchacha20poly1305_state,
            };

            use crate::constants::CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
            use crate::dryocstream::Tag;

            crate::native_test_util::init();

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
                    general_purpose::STANDARD.encode(&message)
                );
                assert_eq!(outtag, tag.bits());
            }
        }
    }
}
