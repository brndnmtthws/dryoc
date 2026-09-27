//! # dryoc: Don't Roll Your Own Crypto™[^1]
//!
//! dryoc is a pure-Rust cryptography library compatible with
//! [libsodium](https://doc.libsodium.org/) where it matters: same algorithms,
//! same wire formats, so supported operations interoperate.
//!
//! Two APIs, one implementation. _Classic_ mirrors libsodium's functions and
//! types for porting existing code. _Rustaceous_ is typed Rust: keys, nonces,
//! and outputs have fixed-size types. Both use the same implementations and
//! work together.
//!
//! This crate uses the Rust 2024 edition and requires Rust 1.89 or newer.
//!
//! ## Features
//!
//! * Pure Rust, no bundled C
//! * Little unsafe code[^2]
//! * Classic and typed Rustaceous APIs for many libsodium operations
//! * ML-KEM-768, the X-Wing hybrid (ML-KEM-768 + X25519), and sealed boxes on
//!   X-Wing
//! * WebAssembly via `wasm32-unknown-unknown`, with opt-in `simd128` builds
//! * `no_std`, with or without `alloc`; see [Cargo features](#cargo-features)
//! * Protected memory on Unix and Windows (`protected`, on by default)
//! * Password-hash string helpers (`base64`, on by default)
//! * [Serde](https://serde.rs/) support (`serde`, on by default), plus optional
//!   [wincode](https://crates.io/crates/wincode) support
//! * Built-in AArch64 and x86-64 kernels; ones needing extra CPU extensions are
//!   picked at runtime (from compile-time target features without `std`), the
//!   rest run portable code
//! * Opt-in [portable SIMD](https://doc.rust-lang.org/std/simd/index.html) on
//!   nightly Rust with `features = ["simd_backend", "nightly"]`
//! * Curve25519 and Ed25519 group arithmetic in dryoc; [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
//!   for scalar arithmetic modulo the group order
//! * Portable SHA-256 and SHA-512 compression and the Keccak permutation from
//!   the [RustCrypto](https://github.com/RustCrypto) project
//!
//! Portable SIMD needs nightly Rust with `--features simd_backend,nightly`:
//! `simd_backend` picks those implementations, `nightly` enables
//! `portable_simd`.
//!
//! With `protected`, `nightly` also implements `Allocator` for
//! `PageAlignedAllocator`. That needs `nightly-2026-09-24` or later (API
//! ungated there); older nightlies don't compile with `--features nightly`.
//!
//! The built-in AArch64 and x86-64 kernels don't need `simd_backend`. Ones
//! needing extra extensions (NEON, SVE2, SHA-2/SHA-3, AVX2, AVX-512, BMI2) are
//! picked at runtime with `std`, or from compile-time target features without
//! it (see [Cargo features](#cargo-features)). The AArch64 `asm!` BLAKE2b
//! rounds, scalar ChaCha20 rounds, and Curve25519 field code are baseline
//! instructions, used outside Miri; Miri falls back to portable code where
//! assembly or intrinsics don't apply. Curve25519/Ed25519 group ops also ignore
//! `simd_backend`.
//!
//! WebAssembly can't detect features at runtime, so the ChaCha20, XSalsa20,
//! Poly1305, ML-KEM, and 2-way Keccak SIMD builds only compile in with the
//! `simd128` target feature (e.g. `RUSTFLAGS=-Ctarget-feature=+simd128 cargo
//! build --target wasm32-unknown-unknown`). That module needs a SIMD-capable
//! engine; without the flag, wasm builds use portable code. BLAKE2b and Argon2
//! stay portable in both — measured faster.
//!
//! ## Cargo features
//!
//! | Feature | Default | Enables |
//! |-|-|-|
//! | `std` | Yes | `alloc`, runtime CPU detection, `Error::Io`. |
//! | `alloc` | With `std` | Allocating APIs: `Vec<u8>` byte-trait impls, `VecBox`/`VecEnvelope`/`VecSignedMessage`/`VecPwHash`, `*_to_vec`/`*_to_vecbox`, `rng::randombytes_buf`, `pwhash`/`classic::crypto_pwhash` (Argon2 working memory is heap). |
//! | `protected` | Yes | Protected memory on Unix and Windows; implies `std`. |
//! | `base64` | Yes | Password-hash string helpers; implies `alloc`. |
//! | `serde` | Yes | Serde support; the `Vec`-based types also need `alloc`. |
//! | `wincode_0_6` | No | wincode 0.6 support for the `Vec`-based boxes; implies `alloc`. |
//! | `simd_backend` | No | Portable SIMD implementations; requires `nightly`. |
//! | `nightly` | No | Nightly-only APIs described above; the `Allocator` implementation also needs `protected`. |
//!
//! The crate is `#![no_std]`. With no features, everything over fixed arrays
//! and caller slices works: the Classic API except `crypto_pwhash`, the
//! stack-allocated Rustaceous types, and the primitives. For the `Vec` APIs on
//! a target with an allocator, enable `alloc`.
//!
//! Without `std`, extra-extension kernels follow the compile-time target
//! features (e.g. `-C target-feature=+avx2`), same priority as runtime
//! detection; otherwise portable code.
//!
//! Randomness comes from [getrandom](https://docs.rs/getrandom), no `std` needed.
//! Bare-metal targets (`thumbv7em-none-eabihf`, `aarch64-unknown-none`) have no
//! entropy source: build with `RUSTFLAGS='--cfg getrandom_backend="custom"'`
//! and supply a [custom backend](https://docs.rs/getrandom/latest/getrandom/#custom-backend).
//!
//! Upgrading from 1.x: `default-features = false` used to keep everything but
//! protected memory and hash strings. Add `features = ["std"]` (or `["alloc"]`
//! without `std`) to keep it.
//!
//! ## Performance
//!
//! Same process, same buffers, one thread, `-Ctarget-cpu=native` — against
//! libsodium 1.0.22 on a Xeon 6975P-C and a Neoverse V3, Poly1305 at 1 MiB is
//! `4.29x`/`3.61x` faster, secretbox `2.71x`/`4.00x`, BLAKE2b `1.17x`/`1.42x`.
//! Argon2id varies more by machine, flags, and libsodium release. ML-KEM-768
//! keygen/encaps/decaps: `1.61x`/`1.93x`/`2.15x` on the Xeon,
//! `2.99x`/`3.40x`/`3.80x` on the Neoverse V3; X-Wing `1.49x`–`1.71x` and
//! `1.95x`–`2.32x`. See
//! [BENCHMARKS.md](https://github.com/brndnmtthws/dryoc/blob/main/BENCHMARKS.md).
//!
//! ## APIs
//!
//! _Classic_ mirrors libsodium's functions and types. _Rustaceous_ is the typed
//! Rust interface to the same operations.
//!
//! ## Error handling
//!
//! Fallible operations return [`Error`]: auth failures, bad lengths or values,
//! bad encodings, bad keys, protected-memory failures, bad operation state.
//!
//! Prefer the Rustaceous API for new code. Use the Classic API when porting
//! libsodium code or when its byte-array interface is a better fit.
//!
//! Rustaceous functions sometimes require an explicit output type. Each module
//! provides type aliases for its common key, nonce, and output types. The
//! Classic API instead uses fixed-size byte arrays and byte slices.
//!
//! The byte-array traits behind those aliases, such as
//! [`NewByteArray::generate`](types::NewByteArray::generate) and
//! [`Bytes::as_slice`](types::Bytes::as_slice), live in [`types`]. Algorithm
//! modules do not re-export them, so import them next to the module:
//!
//! ```
//! use dryoc::dryocsecretbox::*;
//! use dryoc::types::*;
//!
//! let key = Key::generate();
//! ```
//!
//! Each `protected` module re-exports [`protected`], which
//! includes the traits.
//!
//! | Feature | Rustaceous API | Classic API | Reference |
//! |-|-|-|-|
//! | Public-key authenticated boxes | [`DryocBox`](dryocbox) | [`crypto_box`](classic::crypto_box) | [Link](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption) |
//! | Post-quantum sealed boxes (HPKE with X-Wing) | [`DryocSealedBox`](dryocsealedbox) | N/A | [Link](https://www.rfc-editor.org/rfc/rfc9180.html) |
//! | Secret-key authenticated boxes | [`DryocSecretBox`](dryocsecretbox) | [`crypto_secretbox`](classic::crypto_secretbox) | [Link](https://doc.libsodium.org/secret-key_cryptography/secretbox) |
//! | ChaCha20-Poly1305-IETF authenticated encryption | [`chacha20poly1305_ietf`](dryocaead::chacha20poly1305_ietf) | [`crypto_aead_chacha20poly1305_ietf`](classic::crypto_aead_chacha20poly1305_ietf) | [Link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction) |
//! | Authenticated encryption with additional data | [`DryocAead`](dryocaead) | [`crypto_aead_xchacha20poly1305_ietf`](classic::crypto_aead_xchacha20poly1305_ietf) | [Link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) |
//! | Streaming encryption | [`DryocStream`](dryocstream) | [`crypto_secretstream_xchacha20poly1305`](classic::crypto_secretstream_xchacha20poly1305) | [Link](https://doc.libsodium.org/secret-key_cryptography/secretstream) |
//! | Generic hashing and keyed hashing | [`GenericHash`](generichash) | [`crypto_generichash`](classic::crypto_generichash) | [Link](https://doc.libsodium.org/hashing/generic_hashing) |
//! | SHA-2 hashing | [`Sha256`](sha256::Sha256), [`Sha512`](sha512::Sha512) | [`crypto_hash`](classic::crypto_hash) | [Link](https://doc.libsodium.org/advanced/sha-2_hash_function) |
//! | SHA-3 hashing | [`Sha3256`](sha3::Sha3256), [`Sha3512`](sha3::Sha3512) | [`crypto_hash`](classic::crypto_hash) | [Link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) |
//! | Extendable-output functions | [`Shake128`](xof::Shake128), [`TurboShake128`](xof::TurboShake128) | [`crypto_xof`](classic::crypto_xof) | [Link](https://doc.libsodium.org/hashing/xof) |
//! | Secret-key authentication | [`Auth`](auth) | [`crypto_auth`](classic::crypto_auth) | [Link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) |
//! | Direct HMAC authentication | [`Hmac`](hmac) | [`crypto_auth_hmacsha256`](classic::crypto_auth_hmacsha256), [`crypto_auth_hmacsha512`](classic::crypto_auth_hmacsha512), [`crypto_auth_hmacsha512256`](classic::crypto_auth_hmacsha512256) | [Link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) |
//! | One-time authentication | [`OnetimeAuth`](onetimeauth) | [`crypto_onetimeauth`](classic::crypto_onetimeauth) | [Link](https://doc.libsodium.org/advanced/poly1305) |
//! | Key derivation | [`Kdf`](kdf) | [`crypto_kdf`](classic::crypto_kdf) | [Link](https://doc.libsodium.org/key_derivation) |
//! | HKDF key derivation | [`Hkdf`](hkdf) | [`crypto_kdf`](classic::crypto_kdf) | [Link](https://doc.libsodium.org/key_derivation/hkdf) |
//! | Key exchange | [`Session`](kx) | [`crypto_kx`](classic::crypto_kx) | [Link](https://doc.libsodium.org/key_exchange) |
//! | Post-quantum key encapsulation | [`kem`], [`kem::mlkem768`] | [`crypto_kem`](classic::crypto_kem), [`crypto_kem_xwing`](classic::crypto_kem_xwing), [`crypto_kem_mlkem768`](classic::crypto_kem_mlkem768) | [Link](https://doc.libsodium.org/public-key_cryptography/key_encapsulation) |
//! | Public-key signatures | [`SigningKeyPair`](sign) | [`crypto_sign`](classic::crypto_sign) | [Link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) |
//! | Password hashing | [`PwHash`](pwhash) | [`crypto_pwhash`](classic::crypto_pwhash) | [Link](https://doc.libsodium.org/password_hashing/default_phf) |
//! | Protected memory[^4] | [protected] | N/A | [Link](https://doc.libsodium.org/memory_management) |
//! | Short-input hashing | N/A | [`crypto_shorthash`](classic::crypto_shorthash) | [Link](https://doc.libsodium.org/hashing/short-input_hashing) |
//!
//! ## Using Serde
//!
//! Default `serde` derives `Serialize`/`Deserialize` for supported types.
//!
//! ## Using wincode
//!
//! `wincode_0_6` implements wincode 0.6 `SchemaWrite`/`SchemaRead` for the
//! `VecBox` aliases in [`dryocbox`]/[`dryocsecretbox`] and the
//! `VecBox`/`VecEnvelope` aliases in [`dryocaead`]. wincode is pre-1.0 and its
//! traits are public API, so the feature carries its version — future releases
//! add new features (e.g. `wincode_0_7`), never a breaking rename.
//!
//! ## Security notes
//!
//! No third-party audit. Compatibility tests, Rust types, and little unsafe
//! code reduce some defect classes but don't guarantee a secure application:
//! still follow the key/nonce rules, protect secrets, check errors, and pick
//! primitives that fit the protocol.
//!
//! ## Acknowledgements
//!
//! Thanks to the authors and contributors of [NaCl](https://nacl.cr.yp.to/) and
//! [libsodium](https://github.com/jedisct1/libsodium).
//!
//! [^1]: Not actually trademarked.
//!
//! [^2]: The protected memory features described in the [protected] mod are
//! available on Unix and Windows targets with the default `protected` feature.
//! Unsupported targets do not expose the protected-memory API. These features
//! require custom memory allocation, system calls, and pointer arithmetic,
//! which are unsafe in Rust. Some optional SIMD code, including
//! dependency-provided SIMD implementations and small internal helpers, may
//! contain unsafe code. [`unsafe_code`] lists every non-test use of unsafe
//! code in this crate.
//!
//! [^4]: Available on Unix and Windows targets with the `protected` feature
//! flag enabled. The `protected` feature is enabled by default.

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
