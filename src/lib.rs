/*!
# dryoc: Don't Roll Your Own Crypto™[^1]

dryoc is a pure-Rust implementation of
[libsodium](https://libsodium.gitbook.io/doc/), intended to be 100%
compatible with a interchangeable with the libsodium API, and have limited
dependencies.

## Features

The importart features of dryoc are:
* it's 100% pure Rust
* free of unsafe code (except when some optimizations are enabled, which are disabled by default)
* automatic safety features such as zeroization of data structures
* covers most common use cases for safe encryption
* provides full compatibility with libsodium and implements most of its key functions
* it's designed to be difficult to use incorrectly (with the Rustaceous API)

# APIs

This library includes both a _classic_ API, which is very similar to the
original libsodium API, and _Rustaceous_ API with Rust-specific features.
Both APIs can be used together interchangeably, according to your
preferences. The Rustaceous API is a wrapper around the underlying classic
API.

It's recommended that you use the Rustaceous API unless you have strong
feelings about using the Classic API.

| Feature                      | Rustaceous API   | Classic API                             | Libsodium Docs                                                                            |
|------------------------------|------------------|-----------------------------------------|-------------------------------------------------------------------------------------------|
| Secret-key authenticated box | [dryocsecretbox] | [crypto_secretbox]                      | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox)                |
| Streaming encryption         | [dryocstream]    | [crypto_secretstream_xchacha20poly1305] | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)             |
| Public-key authenticated box | [dryocbox]       | [crypto_box]                            | [Link](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption) |

# Using Serde

This crate includes optional [Serde](https://serde.rs/) support which can be
enabled with the `serde` feature flag. When using text-based formats, such as
JSON or YAML, it's recommended you enable the `base64` feature as well, which
encodes binary fields as base64. For binary formats, this may not be
necessary if they already include optimized storage for binary types.

# Security notes

This crate has not been audited, but some of the underlying implementations
have received some auditing, such as the [poly1305] crate. Notably, only the
non-AVX2 backend has been audited. Thus, don't enable AVX2 if you're
paranoid, and avoid non-ARM and non-Intel microarchitectures.

With that out of the way, the deterministic nature of cryptography and
extensive testing used in this crate means it's relatively safe to use,
provided the underlying algorithms remain safe. Arguably, this crate is
_incredibly_ safe (as far as cryptography libraries go) thanks to the
features provided by the Rust language.

[^1]: Not actually trademarked.

*/

#![warn(missing_docs)]

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(all(feature = "serde", feature = "base64"))]
extern crate base64;

#[macro_use]
mod error;
#[cfg(all(feature = "serde", feature = "base64"))]
mod b64;
mod crypto_box_impl;
mod crypto_secretbox_impl;
mod scalarmult_curve25519;

/// # Ciphertext wrapper
pub mod ciphertext;
/// # Constant value definitions
pub mod constants;
pub mod crypto_box;
/// # Core cryptography functions
pub mod crypto_core;
/// Hash functions
pub mod crypto_hash;
/// # Provides one-time authentication using Poly1305
pub mod crypto_onetimeauth;
pub mod crypto_secretbox;
pub mod crypto_secretstream_xchacha20poly1305;
pub mod dryocbox;
pub mod dryocsecretbox;
pub mod dryocstream;
/// # Public-key tools
pub mod keypair;
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
