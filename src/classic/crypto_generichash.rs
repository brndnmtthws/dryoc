//! # Generic hashing
//!
//! Implements libsodium's generic hashing functions with BLAKE2b. With a secret
//! key, BLAKE2b acts as a message authentication code (MAC) or pseudorandom
//! function (PRF); it is not HMAC.
//!
//! See the [libsodium documentation](https://doc.libsodium.org/hashing/generic_hashing)
//! for details.
//!
//! # Classic API example, single-part interface
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::classic::crypto_generichash::*;
//! use dryoc::constants::CRYPTO_GENERICHASH_BYTES;
//!
//! // Use the default hash length
//! let mut output = [0u8; CRYPTO_GENERICHASH_BYTES];
//! // Compute the hash using the single-part interface
//! crypto_generichash(&mut output, b"a string of bytes", None).ok();
//!
//! assert_eq!(
//!     general_purpose::STANDARD.encode(output),
//!     "GdztjR9nU/rLh8VJt8e74+/seKTUnHgBexhGSpxLau0="
//! );
//! ```
//!
//! # Classic API example, incremental interface
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::classic::crypto_generichash::*;
//! use dryoc::constants::CRYPTO_GENERICHASH_BYTES;
//!
//! // Use the default hash length
//! let mut output = [0u8; CRYPTO_GENERICHASH_BYTES];
//! // Initialize the state for the incremental interface
//! let mut state = crypto_generichash_init(None, CRYPTO_GENERICHASH_BYTES).expect("state");
//! // Update the hash
//! crypto_generichash_update(&mut state, b"a string of bytes");
//! // Finalize, compute the hash and copy it into `output`
//! crypto_generichash_final(state, &mut output).expect("final failed");
//!
//! assert_eq!(
//!     general_purpose::STANDARD.encode(output),
//!     "GdztjR9nU/rLh8VJt8e74+/seKTUnHgBexhGSpxLau0="
//! );
//! ```
use super::generichash_blake2b::*;
use crate::blake2b;
use crate::constants::CRYPTO_GENERICHASH_KEYBYTES;
use crate::error::Error;

/**
Computes a hash from `input` and `key`, copying the result into `output`.

| Parameter | Typical length | Recommended minimum | Accepted lengths |
|-|-|-|-|
| `output` | [`CRYPTO_GENERICHASH_BYTES`](crate::constants::CRYPTO_GENERICHASH_BYTES) | [`CRYPTO_GENERICHASH_BYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_BYTES_MIN) | 1 to [`CRYPTO_GENERICHASH_BYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_BYTES_MAX) |
| `key` | [`CRYPTO_GENERICHASH_KEYBYTES`] | [`CRYPTO_GENERICHASH_KEYBYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MIN) | 0 to [`CRYPTO_GENERICHASH_KEYBYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX) |

As in libsodium, the `*_MIN` constants are recommendations rather than
limits, and an empty key (`Some(&[])`) computes the same unkeyed hash as
`None`.

Compatible with libsodium's `crypto_generichash`.

# Errors

Returns an error if the output or key length is outside the accepted range.
*/
#[inline]
pub fn crypto_generichash(
    output: &mut [u8],
    input: &[u8],
    key: Option<&[u8]>,
) -> Result<(), Error> {
    crypto_generichash_blake2b(output, input, key)
}

/// State struct for the generic hash algorithm, based on BLAKE2B.
pub struct GenericHashState {
    state: blake2b::State,
}

/**
Initializes the state for the generic hash function using `outlen` for the expected hash output length, and optional `key`, returning it upon success.

| Parameter | Typical length | Recommended minimum | Accepted lengths |
|-|-|-|-|
| `outlen` | [`CRYPTO_GENERICHASH_BYTES`](crate::constants::CRYPTO_GENERICHASH_BYTES) | [`CRYPTO_GENERICHASH_BYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_BYTES_MIN) | 1 to [`CRYPTO_GENERICHASH_BYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_BYTES_MAX) |
| `key` | [`CRYPTO_GENERICHASH_KEYBYTES`] | [`CRYPTO_GENERICHASH_KEYBYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MIN) | 0 to [`CRYPTO_GENERICHASH_KEYBYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX) |

As in libsodium, the `*_MIN` constants are recommendations rather than
limits, and an empty key (`Some(&[])`) is the same as `None`.

Equivalent to libsodium's `crypto_generichash_init`.

# Errors

Returns an error if `outlen` or the key length is outside the accepted range.
*/
#[inline]
pub fn crypto_generichash_init(
    key: Option<&[u8]>,
    outlen: usize,
) -> Result<GenericHashState, Error> {
    let state = crypto_generichash_blake2b_init(key, outlen, None, None)?;
    Ok(GenericHashState { state })
}

/// Updates the internal hash state with `input`.
///
/// Equivalent to libsodium's `crypto_generichash_update`
#[inline]
pub fn crypto_generichash_update(state: &mut GenericHashState, input: &[u8]) {
    crypto_generichash_blake2b_update(&mut state.state, input)
}

/// Finalizes the hash computation, copying the result into `output`, whose
/// length should equal `outlen` from the call to [`crypto_generichash_init`].
///
/// As in libsodium, a different length is not rejected: `output` receives its
/// length's worth (1 to 64 bytes) of the BLAKE2b chaining value computed for
/// the `init` length, so a shorter `output` truncates the digest and a longer
/// one appends chaining-value bytes that are not part of it.
///
/// Equivalent to libsodium's `crypto_generichash_final`
///
/// # Errors
///
/// Returns an error if `output` is empty or longer than 64 bytes, lengths
/// for which libsodium aborts.
#[inline]
pub fn crypto_generichash_final(state: GenericHashState, output: &mut [u8]) -> Result<(), Error> {
    crypto_generichash_blake2b_final(state.state, output)
}

/// Generates a random hash key using the OS's random number source.
///
/// Equivalent to libsodium's `crypto_generichash_keygen`
pub fn crypto_generichash_keygen() -> [u8; CRYPTO_GENERICHASH_KEYBYTES] {
    let mut key = [0u8; CRYPTO_GENERICHASH_KEYBYTES];
    crate::rng::copy_randombytes(&mut key);
    key
}

#[cfg(all(test, dryoc_native_tests))]
mod tests {
    use super::*;
    use crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX;
    use crate::native_test_util;
    use crate::test_prelude::*;

    /// Output lengths around libsodium's accepted range (1 to 64) and the
    /// recommended minimum (16).
    const OUTLENS: [usize; 6] = [0, 1, 15, 16, 64, 65];
    /// Key lengths around libsodium's accepted range (0 to 64) and the
    /// recommended minimum (16).
    const KEYLENS: [usize; 6] = [0, 1, 15, 16, 64, 65];

    fn message(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// `None` and keys of every length in [`KEYLENS`].
    fn keys(key: &[u8]) -> impl Iterator<Item = Option<&[u8]>> {
        core::iter::once(None).chain(KEYLENS.into_iter().map(|len| Some(&key[..len])))
    }

    /// `input` cut at the BLAKE2b block boundaries, with empty updates
    /// between the pieces.
    fn parts(input: &[u8]) -> Vec<&[u8]> {
        let mut parts = Vec::new();
        let mut start = 0;
        for cut in [0usize, 1, 127, 128, 129, input.len()] {
            let cut = cut.clamp(start, input.len());
            parts.push(&input[start..cut]);
            parts.push(&[][..]);
            start = cut;
        }
        parts
    }

    fn ours_incremental(
        key: Option<&[u8]>,
        init_outlen: usize,
        parts: &[&[u8]],
        final_outlen: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut state = crypto_generichash_init(key, init_outlen)?;
        for part in parts {
            crypto_generichash_update(&mut state, part);
        }
        let mut output = vec![0u8; final_outlen];
        crypto_generichash_final(state, &mut output)?;
        Ok(output)
    }

    /// One-shot and incremental hashing accept exactly the output and key
    /// lengths libsodium accepts (below the recommended minimums included),
    /// treat an empty key as no key, and produce libsodium's digests,
    /// including across BLAKE2b block boundaries.
    #[test]
    fn output_and_key_lengths_match_libsodium() {
        let key: Vec<u8> = (0..=CRYPTO_GENERICHASH_KEYBYTES_MAX as u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        for len in [0usize, 1, 127, 128, 129, 300] {
            let input = message(len);
            let parts = parts(&input);
            for outlen in OUTLENS {
                for key in keys(&key) {
                    let context =
                        format!("len {len}, outlen {outlen}, key {:?}", key.map(<[u8]>::len));
                    let expected = native_test_util::generichash(outlen, &input, key);

                    let mut one_shot = vec![0u8; outlen];
                    let actual = crypto_generichash(&mut one_shot, &input, key).map(|()| one_shot);
                    assert_eq!(actual.map_err(drop), expected, "one-shot {context}");

                    // libsodium aborts on an out-of-range final length, so the
                    // incremental oracle finalizes with a valid one; `init`
                    // rejects the same lengths as the one-shot call.
                    let expected = native_test_util::generichash_multipart(
                        key,
                        outlen,
                        &parts,
                        outlen.clamp(1, 64),
                    );
                    let actual = ours_incremental(key, outlen, &parts, outlen);
                    assert_eq!(actual.map_err(drop), expected, "incremental {context}");
                }
            }
        }
    }

    /// Like libsodium, `crypto_generichash_final` does not check the output
    /// length against the one given to `crypto_generichash_init`: it writes
    /// the first `output.len()` bytes (1 to 64) of the BLAKE2b chaining value,
    /// which is parameterized by the `init` length. dryoc rejects final
    /// lengths outside 1 to 64 with an error, where libsodium aborts.
    #[test]
    fn final_with_mismatched_output_length_matches_libsodium() {
        let input = message(200);
        let parts = parts(&input);
        let key = message(32);
        for key in [None, Some(&key[..])] {
            for (init_outlen, final_outlen) in [(32, 64), (64, 16), (16, 1), (1, 64), (15, 16)] {
                let expected =
                    native_test_util::generichash_multipart(key, init_outlen, &parts, final_outlen)
                        .expect("libsodium final");
                let actual =
                    ours_incremental(key, init_outlen, &parts, final_outlen).expect("final");
                assert_eq!(actual, expected, "init {init_outlen}, final {final_outlen}");
            }
            for final_outlen in [0, 65] {
                assert!(matches!(
                    ours_incremental(key, 32, &parts, final_outlen),
                    Err(Error::InvalidLength { actual, .. }) if actual == final_outlen
                ));
            }
        }
    }
}
