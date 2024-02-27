//! # Generic hashing
//!
//! Implements libsodium's generic hashing functions, based on blake2b. Can also
//! be used as an HMAC function, if a key is provided.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/hashing/generic_hashing).
//!
//! # Classic API example, one-time interface
//!
//! ```
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::classic::crypto_generichash::*;
//! use dryoc::constants::CRYPTO_GENERICHASH_BYTES;
//!
//! // Use the default hash length
//! let mut output = [0u8; CRYPTO_GENERICHASH_BYTES];
//! // Compute the hash using the one-time interface
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
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
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
| `key` | [`CRYPTO_GENERICHASH_KEYBYTES`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES) | [`CRYPTO_GENERICHASH_KEYBYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MIN) | [ `CRYPTO_GENERICHASH_KEYBYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX) |

Compatible with libsodium's `crypto_generichash_final`
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
| `outlen` | [`CRYPTO_GENERICHASH_BYTES`](crate::constants::CRYPTO_GENERICHASH_BYTES) | [`CRYPTO_GENERICHASH_BYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_BYTES_MIN) | [ `CRYPTO_GENERICHASH_BYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_BYTES_MAX) |
| `key` | [`CRYPTO_GENERICHASH_KEYBYTES`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES) | [`CRYPTO_GENERICHASH_KEYBYTES_MIN`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MIN) | [ `CRYPTO_GENERICHASH_KEYBYTES_MAX`](crate::constants::CRYPTO_GENERICHASH_KEYBYTES_MAX) |

Equivalent to libsodium's `crypto_generichash_final`
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generichash() {
        use libsodium_sys::crypto_generichash as so_crypto_generichash;
        use rand_core::{OsRng, RngCore};

        use crate::constants::{CRYPTO_GENERICHASH_BYTES_MAX, CRYPTO_GENERICHASH_BYTES_MIN};
        use crate::rng::copy_randombytes;

        for _ in 0..20 {
            let outlen = CRYPTO_GENERICHASH_BYTES_MIN
                + (OsRng.next_u32() as usize
                    % (CRYPTO_GENERICHASH_BYTES_MAX - CRYPTO_GENERICHASH_BYTES_MIN));
            let mut output = vec![0u8; outlen];

            let mut input = vec![0u8; (OsRng.next_u32() % 5000) as usize];

            copy_randombytes(&mut input);

            let mut so_output = output.clone();

            crypto_generichash(&mut output, &input, None).ok();

            unsafe {
                so_crypto_generichash(
                    so_output.as_mut_ptr(),
                    so_output.len(),
                    input.as_ptr(),
                    input.len() as u64,
                    std::ptr::null(),
                    0,
                );
            }

            assert_eq!(output, so_output);
        }
    }

    #[test]
    fn test_generichash_key() {
        use libsodium_sys::crypto_generichash as so_crypto_generichash;
        use rand_core::{OsRng, RngCore};

        use crate::constants::{
            CRYPTO_GENERICHASH_BYTES_MAX, CRYPTO_GENERICHASH_BYTES_MIN,
            CRYPTO_GENERICHASH_KEYBYTES_MAX, CRYPTO_GENERICHASH_KEYBYTES_MIN,
        };
        use crate::rng::copy_randombytes;

        for _ in 0..20 {
            let outlen = CRYPTO_GENERICHASH_BYTES_MIN
                + (OsRng.next_u32() as usize
                    % (CRYPTO_GENERICHASH_BYTES_MAX - CRYPTO_GENERICHASH_BYTES_MIN));
            let mut output = vec![0u8; outlen];

            let mut input = vec![0u8; (OsRng.next_u32() % 5000) as usize];

            let keylen = CRYPTO_GENERICHASH_KEYBYTES_MIN
                + (OsRng.next_u32() as usize
                    % (CRYPTO_GENERICHASH_KEYBYTES_MAX - CRYPTO_GENERICHASH_KEYBYTES_MIN));
            let mut key = vec![0u8; keylen];

            copy_randombytes(&mut input);
            copy_randombytes(&mut key);

            let mut so_output = output.clone();

            crypto_generichash(&mut output, &input, Some(&key)).ok();

            unsafe {
                so_crypto_generichash(
                    so_output.as_mut_ptr(),
                    so_output.len(),
                    input.as_ptr(),
                    input.len() as u64,
                    key.as_ptr(),
                    key.len(),
                );
            }

            assert_eq!(output, so_output);
        }
    }
}
