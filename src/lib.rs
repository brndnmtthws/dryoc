//! # dryoc: Don't Roll Your Own Crypto™[^1]
//!
//! dryoc is a pure-Rust, general purpose cryptography library. It's also an
//! implementation of [libsodium](https://libsodium.gitbook.io/doc/), and designed to be 100%
//! compatible with a interchangeable with libsodium's API.
//!
//! Minimum supported Rust version (MSRV): Requires **Rust 1.51** or newer.
//!
//! ## Features
//!
//! * 100% pure Rust
//! * mostly free of unsafe code[^2]
//! * free of corporate and governmental influence
//! * automatic safety features such as zeroization of data structures (via
//!   [Drop] and [Zeroize](https://crates.io/crates/zeroize))
//! * protected memory support, with an API designed such that it's hard to
//!   accidentally unprotect your memory
//! * designed to be especially difficult to use incorrectly[^3]
//! * provides full compatibility with libsodium, and implements most of its
//!   functions
//! * covers common use cases for safe encryption
//! * available under the [LGPL-3.0 license](https://www.gnu.org/licenses/lgpl-3.0.en.html)
//!
//! # APIs
//!
//! This library includes both a _Classic_ API, which is very similar to the
//! original libsodium API, and _Rustaceous_ API with Rust-specific features.
//! Both APIs can be used together interchangeably, according to your
//! preferences. The Rustaceous API is a wrapper around the underlying classic
//! API.
//!
//! It's recommended that you use the Rustaceous API unless you have strong
//! feelings about using the Classic API. The classic API includes some pitfalls
//! and traps that are also present in the original libsodium API, and unless
//! you're extra careful you could make mistakes. With the Rustaceous API, it's
//! harder to make mistakes thanks to strict safety features.
//!
//! | Feature | Rustaceous API | Classic API | Libsodium Docs |
//! |-|-|-|-|
//! | Secret-key authenticated boxes | [`DryocSecretBox`](dryocsecretbox) | [`crypto_secretbox`](classic::crypto_secretbox) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox) |
//! | Public-key authenticated boxes | [`DryocBox`](dryocbox) | [`crypto_box`](classic::crypto_box) | [Link](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption) |
//! | Streaming encryption | [`DryocStream`](dryocstream) | [`crypto_secretstream_xchacha20poly1305`](classic::crypto_secretstream_xchacha20poly1305) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) |
//! | Generic hashing | [`GenericHash`](generichash) | [`crypto_generichash`](classic::crypto_generichash) | [Link](https://doc.libsodium.org/hashing/generic_hashing) |
//! | One-time authentication | [`OnetimeAuth`](onetimeauth) | [`crypto_onetimeauth`](classic::crypto_onetimeauth) | [Link](https://doc.libsodium.org/advanced/poly1305) |
//! | Protected memory[^4] | [protected] | N/A | [Link](https://doc.libsodium.org/memory_management) |
//!
//! # Using Serde
//!
//! This crate includes optional [Serde](https://serde.rs/) support which can be
//! enabled with the `serde` feature flag. When enabled, the
//! [`Serialize`](serde::ser::Serialize) and
//! [`Deserialize`](serde::de::Deserialize) traits are provided for data
//! structures.
//!
//! # Security notes
//!
//! This crate has not been audited by any 3rd parties.
//!
//! With that out of the way, the deterministic nature of cryptography and
//! extensive testing used in this crate means it's relatively safe to use,
//! provided the underlying algorithms remain safe. Arguably, this crate is
//! _incredibly_ safe (as far as cryptography libraries go) thanks to the
//! features provided by the API of this crate, and those provided by the Rust
//! language itself.
//!
//! [^1]: Not actually trademarked.
//!
//! [^2]: The protected memory features described in the [protected] mod require
//! custom memory allocation, system calls, and pointer arithmetic, which are
//! unsafe in Rust.
//!
//! [^3]: The Rustaceous API is designed to protect users of this library from
//! making mistakes, however the Classic API allows one to do as one pleases.
//!
//! [^4]: Currently only available on nightly Rust, with the `nightly` feature
//! flag enabled.

#![warn(missing_docs)]
#![cfg_attr(
    any(feature = "nightly", all(feature = "nightly", doc)),
    feature(allocator_api, doc_cfg)
)]
#[macro_use]
mod error;
#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
#[macro_use]
pub mod protected;

mod blake2b;
#[cfg(feature = "serde")]
mod bytes_serde;
mod poly1305;
mod scalarmult_curve25519;

pub mod classic {
    //! # Classic API
    //!
    //! The Classic API contains functions designed to match the interface of
    //! libsodium as closely as possible. It's provided to make it easier to
    //! switch code from using libsodium directly over to dryoc, and also to
    //! provide a familiar interface for anyone already comfortable with
    //! libsodium.
    mod crypto_box_impl;
    mod crypto_secretbox_impl;

    pub mod crypto_box;
    /// # Core cryptography functions
    pub mod crypto_core;
    pub mod crypto_generichash;
    /// Hash functions
    pub mod crypto_hash;
    pub mod crypto_onetimeauth;
    pub mod crypto_secretbox;
    pub mod crypto_secretstream_xchacha20poly1305;
}

/// # Constant value definitions
pub mod constants;

pub mod dryocbox;
pub mod dryocsecretbox;
pub mod dryocstream;
pub mod generichash;
/// # Public-key tools
pub mod keypair;
pub mod onetimeauth;
/// # Random number generation utilities
pub mod rng;
/// # Base type definitions
pub mod types;
/// # Various utility functions
pub mod utils;

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
