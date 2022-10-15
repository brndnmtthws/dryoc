//! # dryoc: Don't Roll Your Own Crypto™[^1]
//!
//! dryoc is a pure-Rust, general-purpose cryptography library. It's also an
//! implementation of [libsodium](https://libsodium.gitbook.io/doc/), and
//! designed to be 100% compatible with, and interchangeable with, libsodium's
//! API.
//!
//! Doing cryptography properly is _hard_. While no human is infallible,
//! computers are pretty good at following instructions. Humans are bad at
//! following instructions, but they do a decent job of giving instructions,
//! provided they can effectively communicate intent. Thus, if the instructions
//! humans give the computer are correct, we can be reasonably assured
//! that the operations the computer does are correct too.
//!
//! This library tries to make it easy to give the computer the correct
//! instructions, and it does so by providing well-known implementations of
//! general-purpose cryptography functions, in an API that's relatively easy to
//! use, type safe, and hard to use incorrectly.
//!
//! As the name of this library implies, one should avoid trying to "roll their
//! own crypto", as it often results in avoidable mistakes. In the context of
//! cryptography, mistakes can be very costly.
//!
//! The minimum supported Rust version (MSRV) for this crate is **Rust 1.51** or
//! newer.
//!
//! ## Features
//!
//! * 100% pure Rust, no hidden C libraries
//! * mostly free of unsafe code[^2]
//! * Hard to misuse, helping you avoid common costly cryptography mistakes
//! * Many libsodium features implemented with both Classic and Rustaceous API
//! * Protected memory handling (`mprotect()` + `mlock()`, along with Windows
//!   equivalents)
//! * [Serde](https://serde.rs/) support (with `features = ["serde"]`)
//! * [_Portable_ SIMD](https://doc.rust-lang.org/std/simd/index.html)
//!   implementation for Blake2b (used by generic hashing, password hashing, and
//!   key derivation) on nightly, with `features = ["simd_backend", "nightly"]`
//! * SIMD backend for Curve25519 (used by public/private key functions) on
//!   nightly with `features = ["simd_backend", "nightly"]`
//! * [SHA2](https://github.com/RustCrypto/hashes/tree/master/sha2) (used by
//!   sealed boxes) includes SIMD implementation for AVX2
//! * [ChaCha20](https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20)
//!   (used by streaming interface) includes SIMD implementations for Neon,
//!   AVX2, and SSE2
//!
//! To enable all the SIMD backends through 3rd party crates, you'll need to
//! also set `RUSTFLAGS`:
//! * For AVX2 set `RUSTFLAGS=-Ctarget-cpu=haswell -Ctarget-feature=+avx2`
//! * For SSE2 set `RUSTFLAGS=-Ctarget-feature=+sse2`
//! * For Neon set `RUSTFLAGS=-Ctarget-feature=+neon`
//!
//! _Note that eventually this project will converge on portable SIMD
//! implementations for all the core algos which will work across all platforms
//! supported by LLVM, rather than relying on hand-coded assembly or intrinsics,
//! but his is a work in progress_.
//!
//! ## APIs
//!
//! This library includes both a _Classic_ API, which is very similar to the
//! original libsodium API, and _Rustaceous_ API with Rust-specific features.
//! Both APIs can be used together interchangeably, according to your
//! preferences. The Rustaceous API is a wrapper around the underlying classic
//! API.
//!
//! It's recommended that you use the Rustaceous API unless you have strong
//! feelings about using the Classic API. The Classic API includes some pitfalls
//! and traps that are also present in the original libsodium API, and unless
//! you're extra careful you could make mistakes. With the Rustaceous API, it's
//! harder to make mistakes thanks to strict type and safety features.
//!
//! The Rustaceous API is, arguably, somewhat trickier to use, especially if
//! you're new to Rust. The Rustaceous API requires knowing and specifying the
//! desired type in many cases. For your convenience, type aliases are provided
//! for common types within each module. The Classic API only uses base types
//! (fixed length byte arrays and byte slices).
//!
//! | Feature | Rustaceous API | Classic API | Libsodium Docs |
//! |-|-|-|-|
//! | Public-key authenticated boxes | [`DryocBox`](dryocbox) | [`crypto_box`](classic::crypto_box) | [Link](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption) |
//! | Secret-key authenticated boxes | [`DryocSecretBox`](dryocsecretbox) | [`crypto_secretbox`](classic::crypto_secretbox) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox) |
//! | Streaming encryption | [`DryocStream`](dryocstream) | [`crypto_secretstream_xchacha20poly1305`](classic::crypto_secretstream_xchacha20poly1305) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) |
//! | Generic hashing, HMAC | [`GenericHash`](generichash) | [`crypto_generichash`](classic::crypto_generichash) | [Link](https://doc.libsodium.org/hashing/generic_hashing) |
//! | Secret-key authentication | [`Auth`](auth) | [`crypto_auth`](classic::crypto_auth) | [Link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) |
//! | One-time authentication | [`OnetimeAuth`](onetimeauth) | [`crypto_onetimeauth`](classic::crypto_onetimeauth) | [Link](https://doc.libsodium.org/advanced/poly1305) |
//! | Key derivation | [`Kdf`](kdf) | [`crypto_kdf`](classic::crypto_kdf) | [Link](https://doc.libsodium.org/key_derivation) |
//! | Key exchange | [`Session`](kx) | [`crypto_kx`](classic::crypto_kx) | [Link](https://doc.libsodium.org/key_exchange) |
//! | Public-key signatures | [`SigningKeyPair`](sign) | [`crypto_sign`](classic::crypto_sign) | [Link](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures) |
//! | Password hashing | [`PwHash`](pwhash) | [`crypto_pwhash`](classic::crypto_pwhash) | [Link](https://libsodium.gitbook.io/doc/password_hashing/default_phf) |
//! | Protected memory[^4] | [protected] | N/A | [Link](https://doc.libsodium.org/memory_management) |
//! | Short-input hashing | N/A | [`crypto_shorthash`](classic::crypto_shorthash) | [Link](https://libsodium.gitbook.io/doc/hashing/short-input_hashing) |
//!
//! ## Using Serde
//!
//! This crate includes optional [Serde](https://serde.rs/) support which can be
//! enabled with the `serde` feature flag. When enabled, the
//! [`Serialize`](serde::ser::Serialize) and
//! [`Deserialize`](serde::de::Deserialize) traits are provided for data
//! structures.
//!
//! ## Security notes
//!
//! This crate has not been audited by any 3rd parties. It uses well-known
//! implementations of the underlying algorithms which have been previously
//! verified as using constant-time operations.
//!
//! With that out of the way, the deterministic nature of cryptography and
//! extensive testing used in this crate means it's relatively safe to use,
//! provided the underlying algorithms remain safe. Arguably, this crate is
//! _incredibly_ safe (as far as cryptography libraries go) thanks to the
//! features provided by the API of this crate, and those provided by the Rust
//! language itself.
//!
//! ## Acknowledgements
//!
//! Big ups to the authors and contributors of [NaCl](https://nacl.cr.yp.to/) and [libsodium](https://github.com/jedisct1/libsodium) for paving the
//! way toward better cryptography libraries.
//!
//! [^1]: Not actually trademarked.
//!
//! [^2]: The protected memory features described in the [protected] mod require
//! custom memory allocation, system calls, and pointer arithmetic, which are
//! unsafe in Rust. Some of the 3rd party libraries used by this crate, such as
//! those with SIMD, may contain unsafe code. In particular, most SIMD
//! implementations are considered "unsafe" due to their use of assembly or
//! intrinsics, however without SIMD-based cryptography you may be exposed to
//! timing attacks.
//!
//! [^3]: The Rustaceous API is designed to protect users of this library from
//! making mistakes, however the Classic API allows one to do as one pleases.
//!
//! [^4]: Currently only available on nightly Rust, with the `nightly` feature
//! flag enabled.

#![cfg_attr(
    any(feature = "nightly", all(feature = "nightly", doc)),
    feature(allocator_api, doc_cfg)
)]
#![cfg_attr(
    all(feature = "simd_backend", feature = "nightly"),
    feature(portable_simd)
)]
#![cfg_attr(feature = "nightly", feature(test))]
#[macro_use]
mod error;
#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
#[macro_use]
pub mod protected;

mod argon2;
mod blake2b;
#[cfg(feature = "serde")]
mod bytes_serde;
mod poly1305;
mod scalarmult_curve25519;
mod siphash24;

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
    mod generichash_blake2b;

    pub mod crypto_auth;
    pub mod crypto_box;
    /// # Core cryptography functions
    pub mod crypto_core;
    pub mod crypto_generichash;
    /// Hash functions
    pub mod crypto_hash;
    pub mod crypto_kdf;
    pub mod crypto_kx;
    pub mod crypto_onetimeauth;
    pub mod crypto_pwhash;
    pub mod crypto_secretbox;
    pub mod crypto_secretstream_xchacha20poly1305;
    pub mod crypto_shorthash;
    pub mod crypto_sign;
    pub mod crypto_sign_ed25519;
}

pub mod auth;
/// # Constant value definitions
pub mod constants;
pub mod dryocbox;
pub mod dryocsecretbox;
pub mod dryocstream;
pub mod generichash;
pub mod kdf;
pub mod keypair;
pub mod kx;
pub mod onetimeauth;
pub mod pwhash;
/// # Random number generation utilities
pub mod rng;
pub mod sha512;
pub mod sign;
/// # Base type definitions
pub mod types;
/// # Various utility functions
pub mod utils;

pub use error::Error;

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
