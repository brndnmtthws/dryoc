[![Docs](https://docs.rs/dryoc/badge.svg)](https://docs.rs/crate/dryoc) [![Crates.io](https://img.shields.io/crates/v/dryoc)](https://crates.io/crates/dryoc) [![Build & test](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml) [![Codecov](https://img.shields.io/codecov/c/github/brndnmtthws/dryoc)](https://app.codecov.io/gh/brndnmtthws/dryoc/)

# dryoc: Don't Roll Your Own Crypto

dryoc is a pure-Rust implementation of the excellent
[libsodium](https://github.com/jedisct1/libsodium) library.

The purpose of this project is to provide a mostly drop-in replacement for
libsodium, with nearly the same ergonomics as libsodium, so that people
familiar with libsodium can use this library nearly interchangeably. While
the API is not 100% identical to libsodium, most functions have the same or
very similar signatures.

Not all features from libsodium are implemented here, namely the more
advanced "under the hood" features, such as raw cryptography functions. For
that, it's recommended you rely on other Rust crates directly, as this
library would only serve as a shim on top of those.

This project prefers to rely on existing well-known implementations of
cryptographic functions from other crates where possible. This library
leverages existing vetted projects in the Rust ecosystem to provide high
quality and easy to use cryptography.

## Project status

The following features are currently implemented, or awaiting implementation:

* [x] [Public-key cryptography](https://doc.libsodium.org/public-key_cryptography) (crypto_box_*)
* [x] [Secret-key cryptography](https://doc.libsodium.org/secret-key_cryptography) (crypto_secretbox_*)
* [x] [Point*scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)
* [ ] [Generating random data](https://doc.libsodium.org/generating_random_data)
* [ ] [Key derivation](https://doc.libsodium.org/key_derivation)
* [ ] [Generic hashing](https://doc.libsodium.org/hashing/generic_hashing)
* [ ] [Short-input hashing](https://doc.libsodium.org/hashing/short-input_hashing)
* [ ] [Password hashing](https://doc.libsodium.org/password_hashing/default_phf)
* [ ] [Key exchange](https://doc.libsodium.org/key_exchange)
* [ ] [One-time authentication](https://doc.libsodium.org/advanced/poly1305)

The following libsodium features are not implemented, and there's no
plan to implement them:

* [Stream ciphers](https://doc.libsodium.org/advanced/stream_ciphers) (use [salsa20](https://crates.io/crates/salsa20) crate)
* [Helpers](https://doc.libsodium.org/helpers) and [padding](https://doc.libsodium.org/padding) utilities
* [Zeroing memory](https://doc.libsodium.org/memory_management) (use [zeroize](https://crates.io/crates/zeroize) crate)
* [Memory locking](https://doc.libsodium.org/memory_management)
* [Advanced features](https://doc.libsodium.org/advanced):
  * [SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function) (use [sha2](https://crates.io/crates/sha2) crate)
  * [HMAC-SHA-2](https://doc.libsodium.org/advanced/hmac-sha2) (use [hmac](https://crates.io/crates/hmac) crate)
  * [Scrypt](https://doc.libsodium.org/advanced/scrypt) (use [scrypt](https://crates.io/crates/scrypt) crate)
  * [Ed25519 to Curve25519](https://doc.libsodium.org/advanced/ed25519-curve25519) (use [dalek.rs](https://dalek.rs/))
  * [Finite field arithmetic](https://doc.libsodium.org/advanced/point-arithmetic) (use [dalek.rs](https://dalek.rs/))

## Stargazers over time

[![Stargazers over time](https://starchart.cc/brndnmtthws/dryoc.svg)](https://starchart.cc/brndnmtthws/dryoc)
