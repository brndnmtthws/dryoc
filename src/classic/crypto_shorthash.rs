//! # Short-input hashing
//!
//! This module implements libsodium's short input hashing, based on
//! SipHash-2-4.
//!
//! You may want to use short input hashing when:
//!
//! * you need to construct hash tables in a fashion that is collision resistant
//!   (i.e., it's hard for other parties to guess when there may be a hash key
//!   collision, which could lead to DoS or timing attacks)
//! * you want to construct probabilistic data structures, such as bloom filters
//! * you want to perform basic integrity checks on data
//! * you have relatively short inputs
//!
//! The key used with this function should be treated as a secret. If used for
//! constructing hash tables, it's recommended the table size be a prime number
//! to ensure all bits from the output are used.
//!
//! For details, refer to [libsodium docs](https://libsodium.gitbook.io/doc/hashing/short-input_hashing).
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_shorthash::*;
//! use dryoc::rng::copy_randombytes;
//!
//! // Generate a random key
//! let key = crypto_shorthash_keygen();
//!
//! // Generate some random input data
//! let mut input = vec![0u8; 69];
//! copy_randombytes(&mut input);
//!
//! // Compute the hash, put result into `output`
//! let mut output = Hash::default();
//! crypto_shorthash(&mut output, &input, &key);
//! ```
use crate::constants::{CRYPTO_SHORTHASH_BYTES, CRYPTO_SHORTHASH_KEYBYTES};
use crate::rng::copy_randombytes;
use crate::siphash24::siphash24;

/// Hash type alias for short input hashing.
pub type Hash = [u8; CRYPTO_SHORTHASH_BYTES];
/// Key type alias for short input hashing.
pub type Key = [u8; CRYPTO_SHORTHASH_KEYBYTES];

/// Generates a random key for short input hashing.
pub fn crypto_shorthash_keygen() -> Key {
    let mut key = Key::default();
    copy_randombytes(&mut key);
    key
}

/// Computes a short input hash for `input` and `key`, placing the result into
/// `output`, using SipHash-2-4.
pub fn crypto_shorthash(output: &mut Hash, input: &[u8], key: &Key) {
    siphash24(output, input, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shorthash() {
        use rand_core::{OsRng, RngCore};
        use sodiumoxide::crypto::shorthash;

        for _ in 0..20 {
            let key = crypto_shorthash_keygen();
            let mut input = vec![0u8; (OsRng.next_u32() % 69) as usize];
            copy_randombytes(&mut input);
            let mut output = Hash::default();

            crypto_shorthash(&mut output, &input, &key);

            let so_output = shorthash::shorthash(
                &input,
                &shorthash::Key::from_slice(&key).expect("so key failed"),
            );

            assert_eq!(output, so_output.0);
        }
    }
}
