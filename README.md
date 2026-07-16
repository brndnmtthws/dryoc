[![Docs](https://docs.rs/dryoc/badge.svg)](https://docs.rs/dryoc) [![Crates.io](https://img.shields.io/crates/v/dryoc)](https://crates.io/crates/dryoc) [![Build & test](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml) [![Codecov](https://img.shields.io/codecov/c/github/brndnmtthws/dryoc)](https://app.codecov.io/gh/brndnmtthws/dryoc/)

[💬 Join the Matrix chat](https://matrix.to/#/#dryoc:frens.io)

# dryoc: Don't Roll Your Own Crypto™<sup>[^1]</sup>

dryoc is a pure-Rust, general-purpose cryptography library based on
[libsodium](https://github.com/jedisct1/libsodium). Many supported operations
use libsodium-compatible algorithms and wire formats, allowing dryoc and
libsodium applications to interoperate.

![Granny says no](dryoc.png)

The _Classic_ API closely follows libsodium's functions and types. It is not
identical to libsodium, but most implemented functions have the same or similar
signatures.

The _Rustaceous_ API wraps the same operations in Rust types that make key,
nonce, and output sizes explicit. The two APIs can be used together.

dryoc does not implement every libsodium feature. See [Project status](#project-status)
for current coverage.

See the [API documentation](https://docs.rs/dryoc/latest/dryoc/) and
[integration tests](tests/integration_tests.rs) for examples.

## Features

* Pure Rust, with no hidden C libraries
* Limited use of unsafe code[^2]
* Typed Rustaceous APIs for keys, nonces, and outputs
* Classic and Rustaceous APIs for many libsodium operations
* WebAssembly support via the `wasm32-unknown-unknown` target
* Protected memory handling (`mprotect()` + `mlock()`, along with Windows
  equivalents) on stable Rust for Unix and Windows targets, enabled by default
  with the `protected` feature
* Password-hash string helpers enabled by default with the `base64` feature
* [Serde](https://serde.rs/) support (with `features = ["serde"]`)
* [wincode](https://crates.io/crates/wincode) support for direct binary serialization of Rustaceous box types (with `features = ["wincode"]`)
* [_Portable_ SIMD](https://doc.rust-lang.org/std/simd/index.html) implementations on nightly, with `features = ["simd_backend", "nightly"]`:
  * Blake2b (used by generic hashing, password hashing, and key derivation)
  * Argon2 block mixing (used by password hashing)
  * Salsa20 (used by XSalsa20-Poly1305 secretbox)
  * Poly1305 (used by one-time authentication and secret boxes), except on
    AArch64 where dryoc keeps the soft backend because the portable-SIMD path
    is slower there
* [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) (used by public/private key functions) selects its own serial or x86_64 vector backend
* [SHA2](https://github.com/RustCrypto/hashes/tree/master/sha2) (used for SHA-256
  and SHA-512 hashing and seeded box key generation) includes an AVX2 backend
* [SHA3](https://github.com/RustCrypto/hashes/tree/master/sha3) (used by SHA-3 compatibility hashing)
* [ChaCha20](https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20) (used by streaming interface) includes SIMD implementations for NEON, AVX2, and SSE2

## Rust version

dryoc uses the Rust 2024 edition and requires Rust 1.89 or newer, as declared
by `rust-version` in `Cargo.toml`.

Enable both `simd_backend` and `nightly` to use dryoc's portable SIMD backends.
No target-specific `RUSTFLAGS` are required; CPU-specific dependencies select
supported implementations independently.

The Curve25519 backend is selected by `curve25519-dalek`, not by dryoc's
`simd_backend` feature.

Poly1305 is a special exception on AArch64: even with `simd_backend` and
`nightly` enabled, dryoc uses the soft Poly1305 backend because profiling shows
the portable-SIMD implementation is slower on that architecture.

See [BENCHMARKS.md](BENCHMARKS.md) for side-by-side software and SIMD benchmark
results.

## Optional serialization

Enable `serde` to derive [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html)
and [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html)
for supported data structures.

Enable `wincode` to derive [`wincode::SchemaWrite`](https://docs.rs/wincode/latest/wincode/trait.SchemaWrite.html)
and [`wincode::SchemaRead`](https://docs.rs/wincode/latest/wincode/trait.SchemaRead.html)
for supported Rustaceous box types, including `DryocBox` and
`DryocSecretBox`, plus AEAD boxes and envelopes from `dryocaead`.

## Security

dryoc has not undergone a third-party security audit. Its compatibility tests,
Rust types, and limited use of unsafe code reduce some classes of defects, but
do not guarantee that an application is secure. Applications must still follow
the documented key and nonce rules, protect secret material, handle errors, and
choose primitives appropriate for their protocol.

## Project status

The following features are implemented. The libsodium-compatible entries have
been reviewed against [libsodium 1.0.22](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE):

* [x] [Public-key cryptography](https://docs.rs/dryoc/latest/dryoc/dryocbox/index.html) (`crypto_box_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography)
* [x] [Secret-key cryptography](https://docs.rs/dryoc/latest/dryoc/dryocsecretbox/index.html) (`crypto_secretbox_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography)
* [x] [Curve25519 point*scalar multiplication](https://docs.rs/dryoc/latest/dryoc/classic/crypto_core/index.html) (`crypto_scalarmult*`) [libsodium link](https://doc.libsodium.org/advanced/scalar_multiplication)
* [x] Zeroing memory (`sodium_memzero`) with [zeroize](https://crates.io/crates/zeroize) [libsodium link](https://doc.libsodium.org/memory_management)
* [x] [Generating random data](https://docs.rs/dryoc/latest/dryoc/rng/index.html) (`randombytes_buf`) [libsodium link](https://doc.libsodium.org/generating_random_data)
* [x] [Encrypted streams](https://docs.rs/dryoc/latest/dryoc/dryocstream/index.html) (`crypto_secretstream_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secretstream)
* [x] [XChaCha20-Poly1305-IETF AEAD](https://docs.rs/dryoc/latest/dryoc/dryocaead/index.html) (`crypto_aead_xchacha20poly1305_ietf_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
* [x] [ChaCha20-Poly1305-IETF AEAD](https://docs.rs/dryoc/latest/dryoc/dryocaead/chacha20poly1305_ietf/index.html) (`crypto_aead_chacha20poly1305_ietf_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction)
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
* [x] [Signature secret-key extraction helpers](https://docs.rs/dryoc/latest/dryoc/classic/crypto_sign_ed25519/index.html) (`crypto_sign_ed25519_sk_to_seed`, `crypto_sign_ed25519_sk_to_pk`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [x] [SHA-2 hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_hash/index.html) (`crypto_hash_sha256_*`, `crypto_hash_sha512_*`) [libsodium link](https://doc.libsodium.org/advanced/sha-2_hash_function)
* [x] [SHA-3 hashing](https://docs.rs/dryoc/latest/dryoc/sha3/index.html) (`crypto_hash_sha3256_*`, `crypto_hash_sha3512_*`; dryoc extension) [NIST FIPS 202 link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf)
* [x] [Short-input hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_shorthash/index.html) (`crypto_shorthash`) [libsodium link](https://doc.libsodium.org/hashing/short-input_hashing)
* [x] [Password hashing](https://docs.rs/dryoc/latest/dryoc/pwhash/index.html) (`crypto_pwhash_*`) [libsodium link](https://doc.libsodium.org/password_hashing/default_phf)
* [x] [HKDF key derivation variants](https://docs.rs/dryoc/latest/dryoc/hkdf/index.html) (`crypto_kdf_hkdf_sha256_*`, `crypto_kdf_hkdf_sha512_*`) [libsodium link](https://doc.libsodium.org/key_derivation/hkdf)
* [x] [Direct HMAC authentication variants](https://docs.rs/dryoc/latest/dryoc/hmac/index.html) (`crypto_auth_hmacsha256_*`, `crypto_auth_hmacsha512_*`, `crypto_auth_hmacsha512256_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)

The following libsodium features are either incomplete, not exposed as public
APIs, or not implemented; you may find equivalent functionality in other
crates:

* [ ] [AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead) beyond the ChaCha20-Poly1305-IETF variants, including AEGIS-128L/256, AES256-GCM, and the legacy 64-bit-nonce ChaCha20-Poly1305 construction
* [ ] XChaCha20-Poly1305 box and secretbox variants (`crypto_box_curve25519xchacha20poly1305_*`, `crypto_secretbox_xchacha20poly1305_*`)
* [ ] Extendable-output functions (`crypto_xof_shake*`, `crypto_xof_turboshake*`), added in libsodium 1.0.21
* [ ] [Key encapsulation](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE) (`crypto_kem_*`, `crypto_kem_mlkem768_*`, `crypto_kem_xwing_*`), added in libsodium 1.0.22
* [ ] Deterministic random data for reproducible tests (`randombytes_buf_deterministic`)
* [ ] Short-input hash variants beyond SipHash-2-4 with 64-bit output (`crypto_shorthash_siphashx24_*`)
* [ ] [IP address encryption](https://doc.libsodium.org/secret-key_cryptography/ip_address_encryption) (`crypto_ipcrypt_*`, `sodium_ip2bin`, `sodium_bin2ip`), added in libsodium 1.0.21
* [ ] [Helpers](https://doc.libsodium.org/helpers), [padding](https://doc.libsodium.org/padding), and constant-time verify utilities (`sodium_*`, `crypto_verify_*`)
* [ ] Standalone [stream cipher](https://doc.libsodium.org/advanced/stream_ciphers) APIs (`crypto_stream_*`; use the [salsa20](https://crates.io/crates/salsa20) or [chacha20](https://crates.io/crates/chacha20) crates directly instead)
* [ ] [Advanced features](https://doc.libsodium.org/advanced):
  * [ ] Keccak-f[1600] core permutation (`crypto_core_keccak1600_*`)
  * [ ] [Scrypt](https://doc.libsodium.org/advanced/scrypt) (`crypto_pwhash_scryptsalsa208sha256_*`; use the [scrypt](https://crates.io/crates/scrypt) crate directly instead)
  * [ ] [Finite field and group arithmetic](https://doc.libsodium.org/advanced/point-arithmetic) (`crypto_core_ed25519_*`, `crypto_core_ristretto255_*`; try the [curve25519-dalek](https://crates.io/crates/curve25519-dalek) crate)
  * [ ] Ed25519 and Ristretto255 scalar multiplication variants (`crypto_scalarmult_ed25519_*`, `crypto_scalarmult_ristretto255_*`)

## Other NaCl-related Rust implementations

* [sodiumoxide](https://crates.io/crates/sodiumoxide)
* [crypto_box](https://crates.io/crates/crypto_box)

[^1]: Not actually trademarked.

[^2]: The protected memory features described in the [protected] mod are
available on Unix and Windows targets with the default `protected` feature.
Unsupported targets do not expose the protected-memory API. These features
require custom memory allocation, system calls, and pointer arithmetic, which
are unsafe in Rust. Some optional SIMD code, including dependency-provided SIMD
implementations and small internal helpers, may contain unsafe code. The
in-crate unsafe inventory includes fixed-size
byte views, optional wincode schema impls for Rustaceous boxes and both AEAD
envelope nonce sizes, BLAKE2b parameter byte views, protected memory guarded
heap buffers and OS protection calls, and Salsa20 SIMD unaligned in-place and
buffer-to-buffer XOR.
See the [rustdoc unsafe code summary](https://docs.rs/dryoc/latest/dryoc/#unsafe-code)
for the full non-test unsafe inventory in this crate.
