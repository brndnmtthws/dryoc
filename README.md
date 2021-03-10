[![Docs](https://docs.rs/dryoc/badge.svg)](https://docs.rs/dryoc) [![Crates.io](https://img.shields.io/crates/v/dryoc)](https://crates.io/crates/dryoc) [![Build & test](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml) [![Codecov](https://img.shields.io/codecov/c/github/brndnmtthws/dryoc)](https://app.codecov.io/gh/brndnmtthws/dryoc/)

# dryoc: Don't Roll Your Own Crypto

dryoc is a pure-Rust implementation of the excellent
[libsodium](https://github.com/jedisct1/libsodium) library.

The purpose of this project is to provide a pure-Rust, mostly drop-in
replacement for libsodium. This library has nearly the same ergonomics as
libsodium (referred to in dryoc as the _Classic_ API), so that people
familiar with libsodium can use this library nearly interchangeably. While
the API is not 100% identical to libsodium, most functions have the same or
very similar signatures.

In addition to the Classic API, there's a Rustaceous API which aims to bring
an idiomatic Rust implementation of libsodium's core features: public and
secret key authenticated cryptography.

Not all features from libsodium are implemented here, such as advanced "under
the hood" features of libsodium. For those specific features, it's
recommended you rely on other crates directly.

This project prefers to rely on existing well-known implementations of
cryptographic functions where possible, rather than succumbing to NIH
syndrome. This library leverages existing vetted projects in the Rust
ecosystem to provide high quality and easy to use cryptography.

## Usage

In `cargo.toml`:

```toml
[dependencies]
dryoc = "0.2"
```

With optional features:

```toml
[dependencies]
dryoc = {version = "0.2", features = ["serde", "base64", "simd_backend"]
```

## Features

* Many libsodium implemented with both Classic and Rustaceous API
* [Serde](https://serde.rs/) support, including optional base64 encoding (with `dryoc = {version = "0.2", features = ["serde", "base64"]}`)
* SIMD optimizations, nightly only (with `dryoc = {version = "0.2", features = ["simd_backend"]}`)

## Project status

The following libsodium features are currently implemented, or awaiting
implementation:

* [x] [Public-key cryptography](https://doc.libsodium.org/public-key_cryptography) (`crypto_box_*`)
* [x] [Secret-key cryptography](https://doc.libsodium.org/secret-key_cryptography) (`crypto_secretbox_*`)
* [x] [Point*scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)
* [x] [Zeroing memory](https://doc.libsodium.org/memory_management) with [zeroize](https://crates.io/crates/zeroize)
* [ ] [Encrypted streams](https://doc.libsodium.org/secret-key_cryptography/secretstream)
* [ ] [Encrypting related message](https://doc.libsodium.org/secret-key_cryptography/encrypted-messages)
* [ ] [Generating random data](https://doc.libsodium.org/generating_random_data)
* [ ] [Key derivation](https://doc.libsodium.org/key_derivation)
* [ ] [Generic hashing](https://doc.libsodium.org/hashing/generic_hashing)
* [ ] [Short-input hashing](https://doc.libsodium.org/hashing/short-input_hashing)
* [ ] [Password hashing](https://doc.libsodium.org/password_hashing/default_phf)
* [ ] [Key exchange](https://doc.libsodium.org/key_exchange)
* [ ] [One-time authentication](https://doc.libsodium.org/advanced/poly1305)
* [ ] [Public-key signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [ ] [Sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
* [ ] [Authentication](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)

The following libsodium features are not implemented, and there's no
plan to implement them:

* [Stream ciphers](https://doc.libsodium.org/advanced/stream_ciphers) (use [salsa20](https://crates.io/crates/salsa20) crate)
* [Helpers](https://doc.libsodium.org/helpers) and [padding](https://doc.libsodium.org/padding) utilities
* [Memory locking](https://doc.libsodium.org/memory_management)
* [Advanced features](https://doc.libsodium.org/advanced):
  * [SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function) (use [sha2](https://crates.io/crates/sha2) crate)
  * [HMAC-SHA-2](https://doc.libsodium.org/advanced/hmac-sha2) (use [hmac](https://crates.io/crates/hmac) crate)
  * [Scrypt](https://doc.libsodium.org/advanced/scrypt) (use [scrypt](https://crates.io/crates/scrypt) crate)
  * [Ed25519 to Curve25519](https://doc.libsodium.org/advanced/ed25519-curve25519) (use [dalek.rs](https://dalek.rs/))
  * [Finite field arithmetic](https://doc.libsodium.org/advanced/point-arithmetic) (use [dalek.rs](https://dalek.rs/))

## Stargazers over time

[![Stargazers over time](https://starchart.cc/brndnmtthws/dryoc.svg)](https://starchart.cc/brndnmtthws/dryoc)

## Other Rust implementations worth mentioning

* [sodiumoxide](https://crates.io/crates/sodiumoxide)
* [crypto_box](https://crates.io/crates/crypto_box)
