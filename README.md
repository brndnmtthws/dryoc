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

* [x] Public-key cryptography (crypto_box_*)
* [x] Secret-key cryptography (crypto_secretbox_*)
* [ ] Generic hashing
* [ ] Short-input hashing
* [ ] Password hashing
* [ ] Generating random data
* [ ] Key derivation
* [ ] Key exchange
* [ ] One-time authentication
* [ ] Stream ciphers

The following libsodium features are not implemented, and there's no
plan to implement them:

* Padding
* Zeroing memory
* Memory locking
* Advanced features:
  * SHA-2
  * HMAC-SHA-2
  * Scrypt
  * Point*scalar multiplication
  * Ed25519 to Curve25519
  * Finite field arithmetic
