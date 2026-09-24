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

| Parameter | Typical length | Minimum length | Maximum length |
|-|-|-|-|
| `output` | [`CRYPTO_GENERICHASH_BYTES`](crate::constants::CRYPTO_GENERICHASH_BYTES) | [`CRYPTO_GENERICHASH_BYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_BYTES_MIN) | [ `CRYPTO_GENERICHASH_BYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_BYTES_MAX) |
| `key` | [`CRYPTO_GENERICHASH_KEYBYTES`] | [`CRYPTO_GENERICHASH_KEYBYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MIN) | [ `CRYPTO_GENERICHASH_KEYBYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX) |

Compatible with libsodium's `crypto_generichash`.

# Errors

Returns an error if the output or key length is outside the supported range.
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

| Parameter | Typical length | Minimum length | Maximum length |
|-|-|-|-|
| `outlen` | [`CRYPTO_GENERICHASH_BYTES`](crate::constants::CRYPTO_GENERICHASH_BYTES) | [`CRYPTO_GENERICHASH_BYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_BYTES_MIN) | [`CRYPTO_GENERICHASH_BYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_BYTES_MAX) |
| `key` | [`CRYPTO_GENERICHASH_KEYBYTES`] | [`CRYPTO_GENERICHASH_KEYBYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MIN) | [ `CRYPTO_GENERICHASH_KEYBYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX) |

Equivalent to libsodium's `crypto_generichash_init`.

# Errors

Returns an error if `outlen` or the key length is outside the supported range.
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
/// Equivalent to libsodium's `crypto_generichash_final`
#[inline]
pub fn crypto_generichash_update(state: &mut GenericHashState, input: &[u8]) {
    crypto_generichash_blake2b_update(&mut state.state, input)
}

/// Finalizes the hash computation, copying the result into `output`. The length
/// of `output` should match `outlen` from the call to
/// [`crypto_generichash_init`].
///
/// Equivalent to libsodium's `crypto_generichash_final`
///
/// # Errors
///
/// Returns an error if `output` is empty or longer than the maximum supported
/// digest.
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
    use crate::constants::{
        CRYPTO_GENERICHASH_BYTES_MAX, CRYPTO_GENERICHASH_BYTES_MIN,
        CRYPTO_GENERICHASH_KEYBYTES_MAX, CRYPTO_GENERICHASH_KEYBYTES_MIN,
    };

    fn message(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn sodium_hash(input: &[u8], key: Option<&[u8]>, outlen: usize) -> Vec<u8> {
        crate::native_test_util::init();
        let mut output = vec![0u8; outlen];
        let rc = unsafe {
            libsodium_sys::crypto_generichash(
                output.as_mut_ptr(),
                output.len(),
                input.as_ptr(),
                input.len() as u64,
                key.map_or(std::ptr::null(), <[u8]>::as_ptr),
                key.map_or(0, <[u8]>::len),
            )
        };
        assert_eq!(rc, 0);
        output
    }

    /// One-shot and incremental dryoc paths against one-shot and incremental
    /// libsodium at the BLAKE2b block boundaries. Includes the inclusive API
    /// maxima that the former `% (max-min)` random tests could never select.
    #[test]
    fn test_generichash_parameter_boundaries_match_libsodium() {
        crate::native_test_util::init();
        let key: Vec<u8> = (0..CRYPTO_GENERICHASH_KEYBYTES_MAX as u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        for len in [127usize, 128, 129] {
            let input = message(len);
            for outlen in [CRYPTO_GENERICHASH_BYTES_MIN, CRYPTO_GENERICHASH_BYTES_MAX] {
                for key in [
                    None,
                    Some(&key[..CRYPTO_GENERICHASH_KEYBYTES_MIN]),
                    Some(&key[..CRYPTO_GENERICHASH_KEYBYTES_MAX]),
                ] {
                    let expected = sodium_hash(&input, key, outlen);

                    let mut one_shot = vec![0u8; outlen];
                    crypto_generichash(&mut one_shot, &input, key).expect("one-shot");
                    assert_eq!(
                        one_shot, expected,
                        "len {len}, outlen {outlen}, key {key:?}"
                    );

                    let mut ours = crypto_generichash_init(key, outlen).expect("init");
                    let mut sodium = libsodium_sys::crypto_generichash_state { opaque: [0u8; 384] };
                    let rc = unsafe {
                        libsodium_sys::crypto_generichash_init(
                            &mut sodium,
                            key.map_or(std::ptr::null(), <[u8]>::as_ptr),
                            key.map_or(0, <[u8]>::len),
                            outlen,
                        )
                    };
                    assert_eq!(rc, 0);

                    let cuts = [0usize, 1, 127, 128, 129, len];
                    let mut start = 0;
                    for cut in cuts.into_iter().filter(|&cut| cut <= len) {
                        let cut = cut.max(start);
                        crypto_generichash_update(&mut ours, &input[start..cut]);
                        crypto_generichash_update(&mut ours, b"");
                        assert_eq!(
                            unsafe {
                                libsodium_sys::crypto_generichash_update(
                                    &mut sodium,
                                    input[start..cut].as_ptr(),
                                    (cut - start) as u64,
                                )
                            },
                            0
                        );
                        assert_eq!(
                            unsafe {
                                libsodium_sys::crypto_generichash_update(
                                    &mut sodium,
                                    std::ptr::null(),
                                    0,
                                )
                            },
                            0
                        );
                        start = cut;
                    }

                    let mut ours_out = vec![0u8; outlen];
                    crypto_generichash_final(ours, &mut ours_out).expect("final");
                    let mut sodium_out = vec![0u8; outlen];
                    assert_eq!(
                        unsafe {
                            libsodium_sys::crypto_generichash_final(
                                &mut sodium,
                                sodium_out.as_mut_ptr(),
                                outlen,
                            )
                        },
                        0
                    );
                    assert_eq!(ours_out, sodium_out);
                    assert_eq!(ours_out, expected);
                }
            }
        }
    }
}
