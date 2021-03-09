//! # dryoc: Don't Roll Your Own Crypto™️
//!
//! A pure-Rust implementation of [libsodium](https://libsodium.gitbook.io/doc/),
//! intended to be 100% compatible with a mostly interchangeable API, and have
//! limited dependencies.
//!
//! This library includes both a _classic_ API, which is very similar to the
//! original libsodium API, and _Rustaceous_ API with Rust-specific features.
//! Both APIs can be used together interchangeably, according to your
//! preferences. The Rustaceous API is a wrapper around the underlying classic
//! API.
//!
//! It's recommended that you use the Rustaceous API unless you have strong
//! feelings about using the Classic API.
//!
//! To get started with the Rustaceous API, refer to [dryocbox] and [dryocsecretbox].
//!
//! To get started, with the classic (libsodium) API, refer to [crypto_box] and
//! [crypto_secretbox].
//!
//! # Security notes
//!
//! This crate has NOT been audited, but some of the underlying implementations
//! have received some auditing, such as the [poly1305] crate. Notably, only the
//! non-AVX2 backend has been audited. Thus, don't enable AVX2 if you're
//! paranoid, and avoid non-ARM and non-Intel microarchitectures.

#![warn(missing_docs)]
#![warn(missing_crate_level_docs)]
#![warn(missing_doc_code_examples)]

#[cfg(feature = "serde")]
extern crate serde;

#[macro_use]
mod error;
mod crypto_box_impl;
mod crypto_secretbox_impl;
mod hsalsa20;
mod scalarmult_curve25519;
mod types;

/// Ciphertext wrapper
pub mod ciphertext;
/// Constant value definitions
pub mod constants;
pub mod crypto_box;
/// Core cryptography functions
pub mod crypto_core;
/// Hash functions
pub mod crypto_hash;
pub mod crypto_secretbox;
pub mod dryocbox;
pub mod dryocsecretbox;
/// Public-key tools
pub mod keypair;
/// Message wrapper
pub mod message;
/// Nonce wrapper
pub mod nonce;
pub mod prelude;
/// Random number generation utilities
pub mod rng;
/// Secret-key box key wrapper
pub mod secretboxkey;
/// Public traits
pub mod traits;

#[cfg(test)]
mod tests {

    #[test]
    fn test_randombytes_buf() {
        use crate::rng::*;
        let r = randombytes_buf(5);
        assert_eq!(r.len(), 5);
        let sum = r.into_iter().fold(0u64, |acc, n| acc + n as u64);
        assert_ne!(sum, 0);
    }
}
