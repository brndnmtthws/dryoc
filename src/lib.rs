//! # dryoc: Don't Roll Your Own Crypto™️
//!
//! A pure-Rust implementation of [libsodium](https://libsodium.gitbook.io/doc/),
//! intended to be 100% compatible with a mostly interchangeable API, and have
//! limited dependencies.
//!
//! To get started, refer to [crypto_box] and [crypto_secretbox].
//!
//! # Security notes
//!
//! This crate has not been audited, but some of the underlying implementations
//! have received some auditing, such as the [poly1305] crate. Notably, only the
//! non-AVX2 backend has been audited. Thus, don't enable AVX2 if you're
//! paranoid, and avoid non-ARM and non-Intel microarchitectures.

#![warn(missing_docs)]
#![warn(missing_crate_level_docs)]
#![warn(missing_doc_code_examples)]

#[macro_use]
mod error;
mod crypto_box_impl;
mod crypto_core;
mod crypto_secretbox_impl;
mod hsalsa20;
mod scalarmult_curve25519;
mod types;

/// Constant value definitions
pub mod constants;
pub mod crypto_box;
/// Hash functions
pub mod crypto_hash;
pub mod crypto_secretbox;
/// Random number generation utilities
pub mod rng;

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
