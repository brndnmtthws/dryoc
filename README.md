[![Docs](https://docs.rs/dryoc/badge.svg)](https://docs.rs/dryoc) [![Crates.io](https://img.shields.io/crates/v/dryoc)](https://crates.io/crates/dryoc) [![Build & test](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml) [![Codecov](https://img.shields.io/codecov/c/github/brndnmtthws/dryoc)](https://app.codecov.io/gh/brndnmtthws/dryoc/)

[💬 Join the Matrix chat](https://matrix.to/#/#dryoc:frens.io)

# dryoc: Don't Roll Your Own Crypto™<sup>[^1]</sup>

dryoc is a pure-Rust, general-purpose cryptography library that's hard to misuse. It's based on the excellent
[libsodium](https://github.com/jedisct1/libsodium) library, but in _pure_ Rust. It
also includes protected memory features throughout, which makes it dead simple
to build secure, robust, and safe cryptographic software. The original goal of this library was to provide a pure-Rust alternative to libsodium.

![Granny says no](dryoc.png)

The purpose of this project is to provide a pure-Rust, mostly drop-in
replacement for libsodium. This library has nearly the same ergonomics as
libsodium (referred to in dryoc as the _Classic_ API), such that people
familiar with libsodium can use this library nearly interchangeably. While
the API is not 100% identical to libsodium, most functions have the same or
very similar signatures.

In addition to the Classic API, there's a _Rustaceous_ API which aims to bring
an idiomatic Rust implementation of libsodium's core features: public and
secret key authenticated cryptography and general-purpose cryptography tools.

Not all features from libsodium are implemented here, either because there
exist better implementations in other crates, or because they aren't
necessary as part of this crate.

Additionally, this crate provides exceptionally safe cryptography thanks to
Rust's safety features. The Rustaceous API is designed designed to make it
difficult to shoot yourself in the foot. It's worth noting, however, you
certainly can still shoot yourself if you choose (either by leaking private
data, using insecure hardware, OPSEC issues, etc).

For example usage, refer to the
[official docs](https://docs.rs/dryoc/latest/dryoc/) or the
[integration tests](/tests/integration_tests.rs).

## Features

* 100% pure Rust, no hidden C libraries
* mostly free of unsafe code[^2]
* Hard to misuse, helping you avoid common costly cryptography mistakes
* Many libsodium features implemented with both Classic and Rustaceous API
* Protected memory handling (`mprotect()` + `mlock()`, along with Windows equivalents)
* [Serde](https://serde.rs/) support (with `features = ["serde"]`)
* [_Portable_ SIMD](https://doc.rust-lang.org/std/simd/index.html) implementation for Blake2b (used by generic hashing, password hashing, and key derivation) on nightly, with `features = ["simd_backend", "nightly"]`
* SIMD backend for Curve25519 (used by public/private key functions) on nightly with `features = ["simd_backend", "nightly"]`
* [SHA2](https://github.com/RustCrypto/hashes/tree/master/sha2) (used by sealed boxes) includes SIMD implementation for AVX2
* [ChaCha20](https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20) (used by streaming interface) includes SIMD implementations for Neon, AVX2, and SSE2

To enable all the SIMD backends through 3rd party crates, you'll need to also
set `RUSTFLAGS`:
* For AVX2 set `RUSTFLAGS=-Ctarget-cpu=haswell -Ctarget-feature=+avx2`
* For SSE2 set `RUSTFLAGS=-Ctarget-feature=+sse2`
* For Neon set `RUSTFLAGS=-Ctarget-feature=+neon`

_Note that eventually this project will converge on portable SIMD implementations
for all the core algos which will work across all platforms supported by LLVM,
rather than relying on hand-coded assembly or intrinsics, but this is a work in
progress_.

## Project status

The following libsodium features are currently implemented, or awaiting
implementation:

* [x] [Public-key cryptography](https://docs.rs/dryoc/latest/dryoc/dryocbox/index.html) (`crypto_box_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography)
* [x] [Secret-key cryptography](https://docs.rs/dryoc/latest/dryoc/dryocsecretbox/index.html) (`crypto_secretbox_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography)
* [x] [Point*scalar multiplication](https://docs.rs/dryoc/latest/dryoc/classic/crypto_core/index.html) (`crypto_scalarmult*`) [libsodium link](https://doc.libsodium.org/advanced/scalar_multiplication)
* [x] Zeroing memory (`sodium_memzero`) with [zeroize](https://crates.io/crates/zeroize) [libsodium link](https://doc.libsodium.org/memory_management)
* [x] [Generating random data](https://docs.rs/dryoc/latest/dryoc/rng/index.html) (`randombytes_buf`) [libsodium link](https://doc.libsodium.org/generating_random_data)
* [x] [Encrypted streams](https://docs.rs/dryoc/latest/dryoc/dryocstream/index.html) (`crypto_secretstream_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secretstream)
* [x] [Memory locking](https://docs.rs/dryoc/latest/dryoc/protected/index.html) (`sodium_mlock`, `sodium_munlock`, `sodium_mprotect_*`) [libsodium link](https://doc.libsodium.org/memory_management)
* [x] [Encrypting related messages](https://docs.rs/dryoc/latest/dryoc/utils/fn.increment_bytes.html) (`sodium_increment`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/encrypted-messages)
* [x] [Generic hashing](https://docs.rs/dryoc/latest/dryoc/generichash/index.html) (`crypto_generichash_*`) [libsodium link](https://doc.libsodium.org/hashing/generic_hashing)
* [x] [Secret-key authentication](https://docs.rs/dryoc/latest/dryoc/auth/index.html) (`crypto_auth*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)
* [x] [One-time authentication](https://docs.rs/dryoc/latest/dryoc/onetimeauth/index.html) (`crypto_onetimeauth_*`) [libsodium link](https://doc.libsodium.org/advanced/poly1305)
* [x] [Sealed boxes](https://docs.rs/dryoc/latest/dryoc/dryocbox/struct.DryocBox.html#method.seal) (`crypto_box_seal*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
* [x] [Key derivation](https://docs.rs/dryoc/latest/dryoc/kdf/index.html) (`crypto_kdf_*`) [libsodium link](https://doc.libsodium.org/key_derivation)
* [x] [Key exchange](https://docs.rs/dryoc/latest/dryoc/kx/index.html) (`crypto_kx_*`) [libsodium link](https://doc.libsodium.org/key_exchange)
* [x] [Public-key signatures](https://docs.rs/dryoc/latest/dryoc/sign/index.html) (`crypto_sign_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [x] [Ed25519 to Curve25519](https://docs.rs/dryoc/latest/dryoc/classic/crypto_sign_ed25519/index.html) (`crypto_sign_ed25519_*`) [libsodium link](https://doc.libsodium.org/advanced/ed25519-curve25519)
* [x] [Short-input hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_shorthash/index.html) (`crypto_shorthash`) [libsodium link](https://doc.libsodium.org/hashing/short-input_hashing)
* [x] [Password hashing](https://docs.rs/dryoc/latest/dryoc/pwhash/index.html) (`crypto_pwhash_*`) [libsodium link](https://doc.libsodium.org/password_hashing/default_phf)

The following libsodium features are either incomplete, not exposed as public
APIs, or not implemented; you may find equivalent functionality in other
crates:

* [Stream ciphers](https://doc.libsodium.org/advanced/stream_ciphers) (use [salsa20](https://crates.io/crates/salsa20) crate directly instead)
* [Helpers](https://doc.libsodium.org/helpers) and [padding](https://doc.libsodium.org/padding) utilities
* [Advanced features](https://doc.libsodium.org/advanced):
  * [Scrypt](https://doc.libsodium.org/advanced/scrypt) (use [scrypt](https://crates.io/crates/scrypt) crate directly instead)
  * [Finite field arithmetic](https://doc.libsodium.org/advanced/point-arithmetic) (try the [curve25519-dalek](https://crates.io/crates/curve25519-dalek) crate)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/brndnmtthws/dryoc.svg)](https://starchart.cc/brndnmtthws/dryoc)

## Other NaCl-related Rust implementations worth mentioning

* [sodiumoxide](https://crates.io/crates/sodiumoxide)
* [crypto_box](https://crates.io/crates/crypto_box)

[^1]: Not actually trademarked.

[^2]: The protected memory features described in the [protected] mod require
custom memory allocation, system calls, and pointer arithmetic, which are unsafe
in Rust. Some of the 3rd party libraries used by this crate, such as those with
SIMD, may contain unsafe code. In particular, most SIMD implementations are
considered "unsafe" due to their use of assembly or intrinsics, however without
SIMD-based cryptography you may be exposed to timing attacks.
