//! # dryoc: Don't Roll Your Own Crypto™[^1]
//!
//! **dryoc** is a high-performance, pure-Rust cryptography library. It provides
//! both a type-safe Rustaceous API and a Classic compatibility surface
//! interoperative with libsodium wire formats.
//!
//! ## Highlights
//!
//! * **High Performance:** Native SIMD and assembly kernels (AVX-512, AVX2,
//!   NEON, SVE2) with automatic runtime CPU detection.
//! * **Post-Quantum Cryptography:** ML-KEM-768 (FIPS 203), X-Wing hybrid
//!   (ML-KEM
//!   + X25519), and RFC 9180 HPKE sealed boxes.
//! * **Type-Safe Rustaceous API:** Strongly-typed fixed-size keys, nonces, and
//!   containers prevent length and type misuse at compile time.
//! * **Classic Compatibility:** Drop-in libsodium-compatible functions
//!   (`crypto_*`) and wire formats.
//! * **Hardened Memory:** Protected memory allocations (page-aligned, locked,
//!   guard pages) on Unix and Windows, plus automatic secret zeroization via
//!   [`zeroize`](https://crates.io/crates/zeroize).
//! * **Flexible & `#![no_std]`:** Fully functional without `std` or `alloc`
//!   using fixed-size stack arrays; opt-in `alloc`, `serde`, and `wincode`
//!   support.
//!
//! Requires Rust 1.89 or newer (Rust 2024 edition).
//!
//! ## APIs
//!
//! `dryoc` provides two complementary API surfaces built on the same underlying
//! cryptographic kernels:
//!
//! * **Rustaceous API (Recommended):** Uses strongly-typed, fixed-size array
//!   wrappers (e.g., [`Key`](dryocsecretbox::Key),
//!   [`Nonce`](dryocsecretbox::Nonce),
//!   [`DryocSecretBox`](dryocsecretbox::DryocSecretBox)). Ensures correct key
//!   and nonce sizes at compile time and provides convenient helper methods.
//! * **Classic API:** Low-level byte-slice and array functions matching
//!   libsodium standard signatures (`crypto_box_*`, `crypto_secretbox_*`,
//!   etc.).
//!
//! ### Rustaceous Quick Start
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use dryoc::dryocsecretbox::*;
//! use dryoc::types::*;
//!
//! let key = Key::generate();
//! let nonce = Nonce::generate();
//! let message = b"Hello, post-quantum world!";
//!
//! let box_ = DryocSecretBox::encrypt_to_vecbox(message, &nonce, &key).expect("encryption failed");
//! let decrypted = box_
//!     .decrypt_to_vec(&nonce, &key)
//!     .expect("authentication failed");
//! assert_eq!(message, &decrypted[..]);
//! # }
//! ```
//!
//! ## Feature & API Overview
//!
//! | Primitive / Operation | Rustaceous API | Classic API |
//! |-|-|-|
//! | Public-key authenticated boxes | [`DryocBox`](dryocbox) | [`crypto_box`](classic::crypto_box) |
//! | Secret-key authenticated boxes | [`DryocSecretBox`](dryocsecretbox) | [`crypto_secretbox`](classic::crypto_secretbox) |
//! | Post-quantum key encapsulation | [`kem`], [`kem::mlkem768`] | [`crypto_kem`](classic::crypto_kem) |
//! | Post-quantum sealed boxes (HPKE) | [`DryocSealedBox`](dryocsealedbox) | N/A |
//! | AEAD (ChaCha20-Poly1305-IETF / XChaCha20) | [`DryocAead`](dryocaead) | [`crypto_aead_xchacha20poly1305_ietf`](classic::crypto_aead_xchacha20poly1305_ietf) |
//! | Streaming encryption | [`DryocStream`](dryocstream) | [`crypto_secretstream_xchacha20poly1305`](classic::crypto_secretstream_xchacha20poly1305) |
//! | Generic hashing (BLAKE2b) | [`GenericHash`](generichash) | [`crypto_generichash`](classic::crypto_generichash) |
//! | SHA-2 & SHA-3 hashing | [`Sha256`](sha256::Sha256), [`Sha3256`](sha3::Sha3256) | [`crypto_hash`](classic::crypto_hash) |
//! | XOF (SHAKE128/256, TurboSHAKE) | [`Shake128`](xof::Shake128) | [`crypto_xof`](classic::crypto_xof) |
//! | Secret-key & HMAC authentication | [`Auth`](auth), [`Hmac`](hmac) | [`crypto_auth`](classic::crypto_auth) |
//! | Key derivation (KDF & HKDF) | [`Kdf`](kdf), [`Hkdf`](hkdf) | [`crypto_kdf`](classic::crypto_kdf) |
//! | Key exchange | [`Session`](kx) | [`crypto_kx`](classic::crypto_kx) |
//! | Public-key signatures (Ed25519) | [`SigningKeyPair`](sign) | [`crypto_sign`](classic::crypto_sign) |
//! | Password hashing (Argon2id) | [`PwHash`](pwhash) | [`crypto_pwhash`](classic::crypto_pwhash) |
//! | Protected memory | [`protected`] | N/A |
//!
//! ## Cargo Features
//!
//! | Feature | Default | Description |
//! |-|-|-|
//! | `std` | Yes | Enables `alloc`, runtime CPU detection, and `Error::Io`. |
//! | `alloc` | With `std` | Heap-allocating APIs (`Vec<u8>` conversions, `VecBox` types, `pwhash`). |
//! | `protected` | Yes | Page-aligned, locked memory allocations on Unix/Windows. |
//! | `base64` | Yes | Password-hash string formatting helpers. |
//! | `serde` | Yes | Serde serialization support for keys, nonces, and containers. |
//! | `wincode_0_6` | No | Direct binary serialization via `wincode 0.6`. |
//! | `simd_backend` | No | Portable SIMD implementation (requires `nightly`). |
//! | `nightly` | No | Nightly compiler features (`portable_simd`, `Allocator` impls). |
//!
//! ## Security Notes
//!
//! `dryoc` has not undergone a third-party security audit. Defect surface is
//! minimized through type safety, comprehensive compatibility test suites, and
//! minimal `unsafe` usage confined to SIMD/assembly kernels and protected
//! memory. See [`unsafe_code`] for the full unsafe code inventory.
//!
//! [^1]: Not actually trademarked.
#![no_std]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
#![cfg_attr(
    all(feature = "simd_backend", feature = "nightly"),
    feature(portable_simd)
)]
#![cfg_attr(all(test, feature = "nightly"), feature(test))]

#[cfg(any(feature = "alloc", test))]
#[macro_use]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

/// Whether an x86-64 CPU feature is available: detected at runtime with the
/// `std` feature, and taken from the compile-time target features (for
/// example `-C target-feature=+avx2`) without it. A `true` result therefore
/// always means the running CPU supports the feature.
#[cfg(target_arch = "x86_64")]
macro_rules! has_x86_feature {
    ($feature:tt) => {{
        #[cfg(feature = "std")]
        let detected = std::arch::is_x86_feature_detected!($feature);
        #[cfg(not(feature = "std"))]
        let detected = cfg!(target_feature = $feature);
        detected
    }};
}

/// Whether an AArch64 CPU feature is available, detected the same way as
/// `has_x86_feature!`.
#[cfg(target_arch = "aarch64")]
macro_rules! has_aarch64_feature {
    ($feature:tt) => {{
        #[cfg(feature = "std")]
        let detected = std::arch::is_aarch64_feature_detected!($feature);
        #[cfg(not(feature = "std"))]
        let detected = cfg!(target_feature = $feature);
        detected
    }};
}

#[macro_use]
mod error;
#[cfg(feature = "wincode_0_6")]
#[macro_use]
mod wincode_schema;

/// The `alloc` prelude items that the standard prelude would provide, for
/// unit tests in this `no_std` crate.
#[cfg(test)]
mod test_prelude {
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec::Vec;
}
#[cfg(any(
    all(feature = "protected", any(unix, windows)),
    all(doc, not(doctest), feature = "std")
))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
#[macro_use]
pub mod protected;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64;
#[cfg(feature = "alloc")]
mod argon2;
mod blake2b;
#[cfg(feature = "serde")]
mod bytes_serde;
mod chacha20;
mod edwards25519;
mod fe25519;
mod keccak;
mod mlkem;
#[cfg(all(test, dryoc_native_tests))]
mod native_test_util;
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
mod neon;
mod poly1305;
mod salsa20;
mod scalarmult_curve25519;
mod sha2_impl;
mod siphash24;
mod stream;
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod wasm32;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub mod classic {
    //! # Classic API
    //!
    //! The Classic API follows libsodium's interface closely. Use it to port
    //! libsodium code or when fixed-size byte arrays and byte slices are a
    //! better fit than the Rustaceous types.
    mod crypto_aead_chacha20poly1305_impl;
    pub(crate) mod crypto_auth_hmac_impl;
    mod crypto_box_impl;
    mod crypto_secretbox_impl;
    mod generichash_blake2b;

    pub mod crypto_aead_chacha20poly1305_ietf;
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
    pub mod crypto_kem;
    pub mod crypto_kem_mlkem768;
    pub mod crypto_kem_xwing;
    pub mod crypto_kx;
    pub mod crypto_onetimeauth;
    #[cfg(feature = "alloc")]
    #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "alloc")))]
    pub mod crypto_pwhash;
    pub mod crypto_secretbox;
    pub mod crypto_secretstream_xchacha20poly1305;
    pub mod crypto_shorthash;
    pub mod crypto_sign;
    pub mod crypto_sign_ed25519;
    pub mod crypto_xof;
}

pub mod auth;
/// # Constant value definitions
pub mod constants;
pub mod dryocaead;
pub mod dryocbox;
pub mod dryocsealedbox;
pub mod dryocsecretbox;
pub mod dryocstream;
pub mod generichash;
pub mod hkdf;
pub mod hmac;
pub mod kdf;
pub mod kem;
pub mod keypair;
pub mod kx;
pub mod onetimeauth;
pub mod precalc;
#[cfg(feature = "alloc")]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "alloc")))]
pub mod pwhash;
/// # Random number generation utilities
pub mod rng;
pub mod sha256;
pub mod sha3;
pub mod sha512;
pub mod sign;
/// # Base type definitions
pub mod types;
pub mod unsafe_code;
/// # Various utility functions
pub mod utils;
pub mod xof;

pub use error::{Error, ErrorContext, LengthConstraint, ValueConstraint};
