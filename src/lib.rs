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
//! This crate uses the Rust 2024 edition. The minimum supported Rust version
//! (MSRV) is **Rust 1.89** or newer.
//!
//! Rust 2024 reserves `gen` as a keyword. Prefer generation APIs such as
//! `Key::generate()`. Existing `gen` APIs remain available through raw
//! identifier syntax, such as `Key::r#gen()`, for compatibility and are
//! deprecated.
//!
//! ## Features
//!
//! * 100% pure Rust, no hidden C libraries
//! * mostly free of unsafe code[^2]
//! * Hard to misuse, helping you avoid common costly cryptography mistakes
//! * Many libsodium features implemented with both Classic and Rustaceous API
//! * Protected memory handling (`mprotect()` + `mlock()`, along with Windows
//!   equivalents) on stable Rust for Unix and Windows targets, enabled by
//!   default with the `protected` feature
//! * Password-hash string helpers enabled by default with the `base64` feature
//! * [Serde](https://serde.rs/) support (with `features = ["serde"]`)
//! * [wincode](https://crates.io/crates/wincode) support for direct binary
//!   serialization of Rustaceous box types (with `features = ["wincode"]`)
//! * [_Portable_ SIMD](https://doc.rust-lang.org/std/simd/index.html)
//!   implementations on nightly, with `features = ["simd_backend", "nightly"]`:
//!   * Blake2b (used by generic hashing, password hashing, and key derivation)
//!   * Argon2 block mixing (used by password hashing)
//!   * Salsa20 (used by XSalsa20-Poly1305 secretbox)
//!   * Poly1305 (used by one-time authentication and secret boxes), except on
//!     AArch64 where dryoc keeps the soft backend because the portable-SIMD
//!     path is slower there
//! * [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
//!   (used by public/private key functions) selects its own serial or x86_64
//!   vector backend at build time
//! * [SHA2](https://github.com/RustCrypto/hashes/tree/master/sha2) (used by
//!   sealed boxes) includes SIMD implementation for AVX2
//! * [ChaCha20](https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20)
//!   (used by streaming interface) includes SIMD implementations for NEON,
//!   AVX2, and SSE2
//!
//! The `simd_backend` and `nightly` features enable dryoc's portable SIMD
//! backends. CPU-specific dependency backends and local benchmarking may also
//! benefit from target-specific `RUSTFLAGS`:
//! * For AVX2 set `RUSTFLAGS=-Ctarget-cpu=haswell -Ctarget-feature=+avx2`
//! * For SSE2 set `RUSTFLAGS=-Ctarget-feature=+sse2`
//! * For NEON set `RUSTFLAGS=-Ctarget-feature=+neon`
//! * For local Apple Silicon benchmarks, use `RUSTFLAGS=-Ctarget-cpu=native`.
//!   NEON is part of the AArch64 macOS baseline target, so adding
//!   `-Ctarget-feature=+neon` is not expected to change native results.
//!
//! The Curve25519 backend is selected by `curve25519-dalek`, not by dryoc's
//! `simd_backend` feature.
//!
//! Poly1305 is a special exception on AArch64: even with `simd_backend` and
//! `nightly` enabled, dryoc uses the soft Poly1305 backend because profiling
//! shows the portable-SIMD implementation is slower on that architecture.
//!
//! _Note that eventually this project will converge on portable SIMD
//! implementations for all the core algos which will work across all platforms
//! supported by LLVM, rather than relying on hand-coded assembly or intrinsics,
//! but this is a work in progress_.
//!
//! See [BENCHMARKS.md](https://github.com/brndnmtthws/dryoc/blob/main/BENCHMARKS.md)
//! for side-by-side software and SIMD benchmark results.
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
//! | Feature | Rustaceous API | Classic API | Reference |
//! |-|-|-|-|
//! | Public-key authenticated boxes | [`DryocBox`](dryocbox) | [`crypto_box`](classic::crypto_box) | [Link](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption) |
//! | Secret-key authenticated boxes | [`DryocSecretBox`](dryocsecretbox) | [`crypto_secretbox`](classic::crypto_secretbox) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox) |
//! | Authenticated encryption with additional data | [`DryocAead`](dryocaead) | [`crypto_aead_xchacha20poly1305_ietf`](classic::crypto_aead_xchacha20poly1305_ietf) | [Link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) |
//! | Streaming encryption | [`DryocStream`](dryocstream) | [`crypto_secretstream_xchacha20poly1305`](classic::crypto_secretstream_xchacha20poly1305) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) |
//! | Generic hashing, HMAC | [`GenericHash`](generichash) | [`crypto_generichash`](classic::crypto_generichash) | [Link](https://doc.libsodium.org/hashing/generic_hashing) |
//! | SHA-3 hashing | [`Sha3256`](sha3::Sha3256), [`Sha3512`](sha3::Sha3512) | [`crypto_hash`](classic::crypto_hash) | [Link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) |
//! | Secret-key authentication | [`Auth`](auth) | [`crypto_auth`](classic::crypto_auth) | [Link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) |
//! | Direct HMAC authentication | [`Hmac`](hmac) | [`crypto_auth_hmacsha256`](classic::crypto_auth_hmacsha256), [`crypto_auth_hmacsha512`](classic::crypto_auth_hmacsha512), [`crypto_auth_hmacsha512256`](classic::crypto_auth_hmacsha512256) | [Link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) |
//! | One-time authentication | [`OnetimeAuth`](onetimeauth) | [`crypto_onetimeauth`](classic::crypto_onetimeauth) | [Link](https://doc.libsodium.org/advanced/poly1305) |
//! | Key derivation | [`Kdf`](kdf) | [`crypto_kdf`](classic::crypto_kdf) | [Link](https://doc.libsodium.org/key_derivation) |
//! | HKDF key derivation | [`Hkdf`](hkdf) | [`crypto_kdf`](classic::crypto_kdf) | [Link](https://doc.libsodium.org/key_derivation/hkdf) |
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
//! ## Using wincode
//!
//! This crate includes optional [wincode](https://crates.io/crates/wincode)
//! support which can be enabled with the `wincode` feature flag. When enabled,
//! [`wincode::SchemaWrite`] and [`wincode::SchemaRead`] are provided for
//! supported Rustaceous box types, including
//! [`DryocBox`](dryocbox::DryocBox),
//! [`DryocSecretBox`](dryocsecretbox::DryocSecretBox), and
//! [`AeadBox`](dryocaead::AeadBox).
//!
//! ## Unsafe code
//!
//! Non-test `unsafe` code is limited to these areas:
//!
//! | Area | Feature gate | Why `unsafe` is required |
//! |-|-|-|
//! | `src/types.rs` fixed-size byte views | Always available | Converts validated byte slices and vectors into `[u8; N]` references without copying. Each cast is guarded by a length check or an exact-size wrapper invariant. |
//! | `src/dryocbox.rs`, `src/dryocsecretbox.rs`, and `src/dryocaead.rs` wincode impls | `wincode` | Implements `unsafe` wincode schema traits for the Rustaceous box wire formats. The implementations write and read initialized fields in the same order. |
//! | `src/blake2b/blake2b_soft.rs` and `src/blake2b/blake2b_simd.rs` parameter blocks | Always available for the soft backend; `simd_backend,nightly` for SIMD | Views a `repr(C, packed)` BLAKE2b parameter block as bytes so the initialization vector is mixed exactly as specified. The parameter type contains only initialized byte fields. |
//! | `src/protected.rs` protected memory | `protected` on Unix/Windows | Calls OS APIs such as `mlock`, `mprotect`, `VirtualLock`, and `VirtualProtect`, implements page-aligned guarded heap buffers, and exposes exact-size byte-array views over protected heap buffers. |
//! | `src/classic/salsa20_simd.rs` Salsa20 SIMD backend | `simd_backend,nightly` | Performs little-endian unaligned in-place and buffer-to-buffer word XOR in 256-byte chunks, plus volatile zeroization of cached SIMD lanes containing derived key material. |
//!
//! Test-only unsafe code is used for libsodium and Argon2 compatibility checks
//! and protected-memory platform probes; it is not part of the runtime crate
//! API.
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
//! [^2]: The protected memory features described in the [protected] mod are
//! available on Unix and Windows targets with the default `protected` feature.
//! Unsupported targets do not expose the protected-memory API. These features
//! require custom memory allocation, system calls, and pointer arithmetic,
//! which are unsafe in Rust. Some optional SIMD code, including
//! dependency-provided SIMD implementations and small internal helpers, may
//! contain unsafe code. In particular, many SIMD implementations are considered
//! "unsafe" due to their use of assembly or intrinsics, however without
//! SIMD-based cryptography you may be exposed to timing attacks. See the unsafe
//! code section above for the non-test unsafe inventory in this crate.
//!
//! [^3]: The Rustaceous API is designed to protect users of this library from
//! making mistakes, however the Classic API allows one to do as one pleases.
//!
//! [^4]: Available on Unix and Windows targets with the `protected` feature
//! flag enabled. The `protected` feature is enabled by default.

#![cfg_attr(feature = "nightly", feature(allocator_api, doc_cfg))]
#![cfg_attr(
    all(feature = "simd_backend", feature = "nightly"),
    feature(portable_simd)
)]
#![cfg_attr(all(test, feature = "nightly"), feature(test))]
#[macro_use]
mod error;
#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
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
    mod crypto_auth_hmac_impl;
    mod crypto_box_impl;
    mod crypto_secretbox_impl;
    mod generichash_blake2b;
    #[cfg(all(feature = "simd_backend", feature = "nightly"))]
    mod salsa20_simd;

    pub mod crypto_aead_xchacha20poly1305_ietf;
    pub mod crypto_auth;
    pub mod crypto_auth_hmacsha256;
    pub mod crypto_auth_hmacsha512;
    pub mod crypto_auth_hmacsha512256;
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
pub mod dryocaead;
pub mod dryocbox;
pub mod dryocsecretbox;
pub mod dryocstream;
pub mod generichash;
pub mod hkdf;
pub mod hmac;
pub mod kdf;
pub mod keypair;
pub mod kx;
pub mod onetimeauth;
pub mod precalc;
pub mod pwhash;
/// # Random number generation utilities
pub mod rng;
pub mod sha256;
pub mod sha3;
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
