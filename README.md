[![Docs](https://docs.rs/dryoc/badge.svg)](https://docs.rs/dryoc) [![Crates.io](https://img.shields.io/crates/v/dryoc)](https://crates.io/crates/dryoc) [![Build & test](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml) [![Codecov](https://img.shields.io/codecov/c/github/brndnmtthws/dryoc)](https://app.codecov.io/gh/brndnmtthws/dryoc/)

[💬 Join the Matrix chat](https://matrix.to/#/#dryoc:frens.io)

# dryoc: Don't Roll Your Own Crypto™<sup>[^1]</sup>

dryoc is a general-purpose cryptography library written in pure Rust. It
implements many of the same algorithms and wire formats as
[libsodium](https://doc.libsodium.org/), so supported operations can
interoperate with libsodium.

![Granny says no](dryoc.png)

The _Classic_ API closely follows libsodium's functions and types, which makes
it useful when porting existing code. The _Rustaceous_ API provides typed Rust
interfaces that make key, nonce, and output sizes explicit. Both APIs use the
same implementations and can be used together.

dryoc does not implement every libsodium feature. See [Project status](#project-status)
for current coverage.

See the [API documentation](https://docs.rs/dryoc/latest/dryoc/) and
[integration tests](tests/integration_tests.rs) for examples.

## Features

* Pure Rust, with no hidden C libraries
* Limited use of unsafe code[^2]
* Classic and typed Rustaceous APIs for many libsodium operations
* WebAssembly support through the `wasm32-unknown-unknown` target
* Protected memory on Unix and Windows, enabled by default with the
  `protected` feature
* Password-hash string helpers, enabled by default with the `base64` feature
* Optional [Serde](https://serde.rs/) and
  [wincode](https://crates.io/crates/wincode) serialization
* Optimized implementations selected at runtime on AArch64 and x86-64; CPUs
  without the required extensions use portable code
* Optional [portable SIMD](https://doc.rust-lang.org/std/simd/index.html)
  implementations on nightly Rust with `features = ["simd_backend", "nightly"]`
* Curve25519 and Ed25519 group arithmetic implemented in dryoc;
  [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
  provides scalar arithmetic modulo the group order
* Portable SHA-256, SHA-512, and SHA-3 implementations from the
  [RustCrypto](https://github.com/RustCrypto) project

## Performance

On the optimized workloads shown below, dryoc is faster than libsodium 1.0.18
on both x86-64 and AArch64. Each result compares the two libraries in the same
process, using the same buffers, one thread, and `-Ctarget-cpu=native`:

| Workload | Intel Xeon 6975P-C (AVX-512) | Arm Neoverse V3 (NEON/SVE2) |
| --- | ---: | ---: |
| Poly1305, 1 MiB | `5.85x faster` | `3.28x faster` |
| Poly1305, 16 KiB | `5.59x faster` | `3.14x faster` |
| XSalsa20-Poly1305 secretbox, 1 MiB | `3.07x faster` | `2.84x faster` |
| XSalsa20-Poly1305 secretbox, 1 KiB | `3.16x faster` | `2.04x faster` |
| BLAKE2b, 694,200 B | `1.19x faster` | `1.43x faster` |

![dryoc speedup over libsodium by workload](benchmarks/speedup.svg)

The optimized Poly1305, Salsa20, and BLAKE2b implementations are selected
automatically at runtime. They do not require `-Ctarget-cpu=native`; omitting
that flag changes the results above by no more than 6%. Argon2id results vary
more with the machine and build flags. See [BENCHMARKS.md](BENCHMARKS.md) for
the full results, test environment, builds without CPU-specific flags, and
workloads where libsodium is as fast or faster.

## Rust version

dryoc uses the Rust 2024 edition and requires Rust 1.89 or newer, as declared
by `rust-version` in `Cargo.toml`.

The optional portable SIMD implementations require nightly Rust and
`--features simd_backend,nightly`. The `simd_backend` feature selects those
implementations, while `nightly` enables Rust's unstable `portable_simd` API.

Optimized AArch64 and x86-64 implementations are built in and selected at
runtime when the CPU supports them. They do not require the `simd_backend`
feature. Curve25519 and Ed25519 group operations are also unaffected by that
feature.

## Optional serialization

Enable `serde` to derive [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html)
and [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html)
for supported data structures.

Enable `wincode` to derive [`wincode::SchemaWrite`](https://docs.rs/wincode/latest/wincode/trait.SchemaWrite.html)
and [`wincode::SchemaRead`](https://docs.rs/wincode/latest/wincode/trait.SchemaRead.html)
for the `VecBox` aliases in `dryocbox` and `dryocsecretbox`, and for the
`VecBox` and `VecEnvelope` aliases in `dryocaead`.

## Security

dryoc has not undergone a third-party security audit. Its compatibility tests,
Rust types, and limited use of unsafe code reduce some classes of defects, but
do not guarantee that an application is secure. Applications must still follow
the documented key and nonce rules, protect secret material, handle errors, and
choose primitives appropriate for their protocol.

## Project status

The following features are implemented. Entries that mirror libsodium have
been checked against [libsodium 1.0.22](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE):

* [x] [Public-key authenticated encryption](https://docs.rs/dryoc/latest/dryoc/dryocbox/index.html) (`crypto_box_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
* [x] [Secret-key authenticated encryption](https://docs.rs/dryoc/latest/dryoc/dryocsecretbox/index.html) (`crypto_secretbox_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secretbox)
* [x] [Curve25519 scalar multiplication](https://docs.rs/dryoc/latest/dryoc/classic/crypto_core/index.html) (`crypto_scalarmult*`) [libsodium link](https://doc.libsodium.org/advanced/scalar_multiplication)
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

The following libsodium features are incomplete, internal only, or not
implemented. Other crates may provide equivalent functionality:

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

[^2]: Protected memory is available on Unix and Windows with the default
`protected` feature. It requires custom allocation, system calls, and pointer
arithmetic, which are unsafe in Rust. Some optimized implementations also use
small, carefully bounded unsafe blocks. The in-crate unsafe inventory includes
fixed-size byte views, wincode schema implementations for vector-backed boxes
and AEAD envelopes, BLAKE2b
parameter byte views, protected memory guarded heap buffers and OS protection
calls, 16-byte volatile zeroization of secret buffers, the x86-64 backends
(runtime-detected AVX2, AVX-512 and AVX-512 IFMA entry points for ChaCha20,
XSalsa20, Poly1305, the Argon2 block compression and the BLAKE2b compression,
`asm!` scalar ChaCha20 and Salsa20 double rounds that run beside the AVX-512
lane sets, an AVX-512
Ed25519 basepoint table lookup, and BMI2-compiled copies of the Curve25519
scalar multiplication, inversion and square-root loops), and the AArch64
backends: runtime-detected NEON entry points for Poly1305, XSalsa20, ChaCha20,
and the Ed25519 basepoint table lookup, register-only SVE2 `asm!` blocks for
the ChaCha20 and XSalsa20 rounds, scalar `asm!` blocks for the ChaCha20 and
BLAKE2b rounds and the Curve25519 field products, and runtime-detected
`sha2`/`sha3` instruction `asm!` loops for the SHA-256 and SHA-512
compression functions.
The [rustdoc unsafe code summary](https://docs.rs/dryoc/latest/dryoc/#unsafe-code)
lists every non-test use of unsafe code in this crate.
