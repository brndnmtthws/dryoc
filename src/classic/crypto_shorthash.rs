//! # Short-input hashing
//!
//! Implements libsodium's SipHash-2-4 function for short inputs. It produces a
//! compact, keyed hash that can protect hash tables against attacker-chosen
//! collision patterns.
//!
//! This function is intended for short, keyed inputs. It is not a
//! general-purpose hash or an encryption primitive. Use
//! [`crate::classic::crypto_auth`] for message authentication, or
//! [`crate::classic::crypto_generichash`] for general-purpose hashing.
//!
//! Treat the key as secret and generate it randomly. See the
//! [libsodium documentation](https://doc.libsodium.org/hashing/short-input_hashing)
//! for details.
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
    use crate::test_prelude::*;

    /// The SipHash-2-4 reference vectors (key `00..0f`, message `00..n-1`)
    /// at the word boundaries: 0, 7, 8, 9, 15 and 16 bytes.
    #[test]
    fn test_shorthash_reference_vectors() {
        let key: Key = core::array::from_fn(|i| i as u8);
        for (len, expected) in [
            (0usize, [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72]),
            (7, [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab]),
            (8, [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93]),
            (9, [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e]),
            (15, [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1]),
            (16, [0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f]),
        ] {
            let input: Vec<u8> = (0..len as u8).collect();
            let mut output = Hash::default();
            crypto_shorthash(&mut output, &input, &key);
            assert_eq!(output, expected, "len {len}");
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_shorthash_matches_libsodium() {
        use crate::native_test_util::shorthash_siphash24;

        let key: Key = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for len in [0usize, 1, 7, 8, 9, 63, 64, 65] {
            let input: Vec<u8> = (0..len as u32).map(|i| (i * 31 % 251) as u8).collect();
            let mut output = Hash::default();
            crypto_shorthash(&mut output, &input, &key);
            let so_output = shorthash_siphash24(&input, &key);
            assert_eq!(output, so_output, "len {len}");
        }
    }
}
