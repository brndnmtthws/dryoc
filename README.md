[![Docs](https://docs.rs/dryoc/badge.svg)](https://docs.rs/dryoc) [![Crates.io](https://img.shields.io/crates/v/dryoc)](https://crates.io/crates/dryoc) [![Build & test](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/brndnmtthws/dryoc/actions/workflows/build-and-test.yml) [![Codecov](https://img.shields.io/codecov/c/github/brndnmtthws/dryoc)](https://app.codecov.io/gh/brndnmtthws/dryoc/)

[💬 Join the Matrix chat](https://matrix.to/#/#dryoc:frens.io)

# dryoc: Don't Roll Your Own Crypto™<sup>[^1]</sup>

dryoc is a pure-Rust cryptography library compatible with
[libsodium](https://doc.libsodium.org/) where it matters: same algorithms,
same wire formats, so supported operations interoperate.

![Granny says no](dryoc.png)

Two APIs, one implementation. _Classic_ mirrors libsodium's functions and
types for porting existing code. _Rustaceous_ is typed Rust: keys, nonces,
and outputs have fixed-size types, so convert runtime bytes with `try_into()`
and the wrong length fails. Use them together.

Not every libsodium feature is covered; see [Project status](#project-status).
Examples: [API docs](https://docs.rs/dryoc/latest/dryoc/),
[integration tests](tests/integration_tests.rs).

## Features

* Pure Rust, no bundled C
* Little unsafe code[^2]
* Classic and typed Rustaceous APIs for many libsodium operations
* ML-KEM-768, the X-Wing hybrid (ML-KEM-768 + X25519), and sealed boxes on X-Wing
* WebAssembly via `wasm32-unknown-unknown`, with opt-in `simd128` builds
* `no_std`, with or without `alloc`; see [Cargo features](#cargo-features)
* Protected memory on Unix and Windows (`protected`, on by default)
* Password-hash string helpers (`base64`, on by default)
* [Serde](https://serde.rs/) support (`serde`, on by default), plus optional
  [wincode](https://crates.io/crates/wincode) support
* Built-in AArch64 and x86-64 kernels; ones needing extra CPU extensions are
  picked at runtime (from compile-time target features without `std`), the rest
  run portable code
* Opt-in [portable SIMD](https://doc.rust-lang.org/std/simd/index.html) on nightly
  Rust with `features = ["simd_backend", "nightly"]`
* Curve25519 and Ed25519 group arithmetic in dryoc;
  [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
  for scalar arithmetic modulo the group order
* Portable SHA-256 and SHA-512 compression and the Keccak permutation from the
  [RustCrypto](https://github.com/RustCrypto) project

## Performance

Same process, same buffers, one thread, `-Ctarget-cpu=native` — dryoc vs
libsodium 1.0.22:

| Workload | Intel Xeon 6975P-C (AVX-512) | Arm Neoverse V3 (NEON/SVE2) |
| --- | ---: | ---: |
| Poly1305, 1 MiB | `4.29x faster` | `3.61x faster` |
| Poly1305, 16 KiB | `4.07x faster` | `3.51x faster` |
| XSalsa20-Poly1305 secretbox, 1 MiB | `2.71x faster` | `4.00x faster` |
| XSalsa20-Poly1305 secretbox, 1 KiB | `3.27x faster` | `2.60x faster` |
| BLAKE2b, 694,200 B | `1.17x faster` | `1.42x faster` |

![dryoc speedup over libsodium by workload](benchmarks/speedup.svg)

No special flags needed: extensions are detected at runtime, and the AArch64
Poly1305 and BLAKE2b code is baseline instructions. Dropping the flag moves
these numbers by at most 6% on the Xeon, 2.4% on the Neoverse V3. Argon2id
varies more by machine, flags, and libsodium release.

ML-KEM-768 key generation, encapsulation, decapsulation: `1.61x`/`1.93x`/`2.15x`
on the Xeon, `2.99x`/`3.40x`/`3.80x` on the Neoverse V3; X-Wing:
`1.49x`–`1.71x` and `1.95x`–`2.32x`. Full results, setup, no-flag builds, and
rows where libsodium holds its own: [BENCHMARKS.md](BENCHMARKS.md).

## Rust version

Requires Rust 1.89 or newer (Rust 2024 edition, per `rust-version` in `Cargo.toml`).

Portable SIMD needs nightly Rust with `--features simd_backend,nightly`:
`simd_backend` picks those implementations, `nightly` enables `portable_simd`.

With `protected`, `nightly` also implements `Allocator` for
`PageAlignedAllocator`. That needs `nightly-2026-09-24` or later (API ungated
there); older nightlies don't compile with `--features nightly`.

The built-in AArch64 and x86-64 kernels don't need `simd_backend`. Ones needing
extra extensions (NEON, SVE2, SHA-2/SHA-3, AVX2, AVX-512, BMI2) are picked at
runtime with `std`, or from compile-time target features without it (see
[Cargo features](#cargo-features)). The AArch64 `asm!` Poly1305 loops, BLAKE2b
rounds, scalar ChaCha20 rounds, and Curve25519 field code are baseline
instructions, used outside Miri. Curve25519/Ed25519 group ops also ignore
`simd_backend`.

### WebAssembly SIMD

WebAssembly can't detect features at runtime, so the ChaCha20, XSalsa20,
Poly1305, ML-KEM, and 2-way Keccak SIMD builds only compile in with the
`simd128` target feature:

```sh
RUSTFLAGS=-Ctarget-feature=+simd128 cargo build --target wasm32-unknown-unknown
```

That module needs a SIMD-capable engine. Without the flag, wasm builds use the
portable code. BLAKE2b and Argon2 stay portable in both — measured faster.

## Cargo features

| Feature | Default | Enables |
| --- | --- | --- |
| `std` | Yes | `alloc`, runtime CPU detection, `Error::Io` |
| `alloc` | With `std` | Allocating APIs: `Vec<u8>` byte-trait impls, `VecBox`/`VecEnvelope`/`VecSignedMessage`/`VecPwHash`, `*_to_vec`/`*_to_vecbox`, `randombytes_buf`, `pwhash`/`crypto_pwhash` |
| `protected` | Yes | Protected memory on Unix/Windows; implies `std` |
| `base64` | Yes | Password-hash strings; implies `alloc` |
| `serde` | Yes | Serde support; `Vec` types also need `alloc` |
| `wincode_0_6` | No | wincode 0.6 for the `Vec` boxes; implies `alloc` |
| `simd_backend` | No | Portable SIMD; requires `nightly` |
| `nightly` | No | Nightly-only APIs (see [Rust version](#rust-version)); `Allocator` also needs `protected` |

dryoc is `#![no_std]`. With no features, everything over fixed arrays and
caller slices works: the Classic API except `crypto_pwhash`, the
stack-allocated Rustaceous types, and the primitives. For the `Vec` APIs on a
target with an allocator:

```toml
dryoc = { version = "2", default-features = false, features = ["alloc"] }
```

Without `std`, extra-extension kernels follow the compile-time target features
(e.g. `-C target-feature=+avx2`), same priority as runtime detection;
otherwise portable code.

Randomness comes from [getrandom](https://docs.rs/getrandom), no `std` needed.
Bare-metal targets (`thumbv7em-none-eabihf`, `aarch64-unknown-none`) have no
entropy source: build with `RUSTFLAGS='--cfg getrandom_backend="custom"'` and
supply a [custom backend](https://docs.rs/getrandom/latest/getrandom/#custom-backend).

Upgrading from 1.x: `default-features = false` used to keep everything but
protected memory and hash strings. Add `features = ["std"]` (or `["alloc"]`
without `std`) to keep it.

## Serialization

Default `serde` derives `Serialize`/`Deserialize` for supported types.
`wincode_0_6` implements wincode 0.6 `SchemaWrite`/`SchemaRead` for the
`VecBox` aliases in `dryocbox`/`dryocsecretbox` and the `VecBox`/`VecEnvelope`
aliases in `dryocaead`. wincode is pre-1.0 and its traits are public API, so
the feature carries its version — future releases add new features (e.g.
`wincode_0_7`), never a breaking rename.

## Python

Bindings on PyPI as [`dryoc`](https://pypi.org/project/dryoc/)
(`uv add dryoc` / `pip install dryoc`): Pythonic typed API, CPython 3.11+,
free-threaded builds included. See [python/README.md](python/README.md).

## Security

No third-party audit. Compatibility tests, Rust types, and little unsafe code
reduce some defect classes but don't guarantee a secure application: still
follow the key/nonce rules, protect secrets, check errors, and pick primitives
that fit the protocol.

## Project status

Implemented below, libsodium mirrors checked against [1.0.22](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE):

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
* [x] [Post-quantum key encapsulation](https://docs.rs/dryoc/latest/dryoc/kem/index.html) with X-Wing and ML-KEM-768 (`crypto_kem_*`, `crypto_kem_xwing_*`, `crypto_kem_mlkem768_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/key_encapsulation)
* [x] [Post-quantum sealed boxes](https://docs.rs/dryoc/latest/dryoc/dryocsealedbox/index.html): HPKE (RFC 9180) with X-Wing, HKDF-SHA256 and ChaCha20-Poly1305 (dryoc extension) [RFC 9180 link](https://www.rfc-editor.org/rfc/rfc9180.html)
* [x] [Public-key signatures](https://docs.rs/dryoc/latest/dryoc/sign/index.html) (`crypto_sign_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [x] [Ed25519 to Curve25519](https://docs.rs/dryoc/latest/dryoc/classic/crypto_sign_ed25519/index.html) (`crypto_sign_ed25519_*`) [libsodium link](https://doc.libsodium.org/advanced/ed25519-curve25519)
* [x] [Signature secret-key extraction helpers](https://docs.rs/dryoc/latest/dryoc/classic/crypto_sign_ed25519/index.html) (`crypto_sign_ed25519_sk_to_seed`, `crypto_sign_ed25519_sk_to_pk`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [x] [SHA-2 hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_hash/index.html) (`crypto_hash_sha256_*`, `crypto_hash_sha512_*`) [libsodium link](https://doc.libsodium.org/advanced/sha-2_hash_function)
* [x] [SHA-3 hashing](https://docs.rs/dryoc/latest/dryoc/sha3/index.html) (`crypto_hash_sha3256_*`, `crypto_hash_sha3512_*`) [NIST FIPS 202 link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf)
* [x] [Extendable-output functions](https://docs.rs/dryoc/latest/dryoc/xof/index.html) (`crypto_xof_shake128_*`, `crypto_xof_shake256_*`, `crypto_xof_turboshake128_*`, `crypto_xof_turboshake256_*`) [libsodium link](https://doc.libsodium.org/hashing/xof)
* [x] [Short-input hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_shorthash/index.html) (`crypto_shorthash`) [libsodium link](https://doc.libsodium.org/hashing/short-input_hashing)
* [x] [Password hashing](https://docs.rs/dryoc/latest/dryoc/pwhash/index.html) (`crypto_pwhash_*`) [libsodium link](https://doc.libsodium.org/password_hashing/default_phf)
* [x] [HKDF key derivation variants](https://docs.rs/dryoc/latest/dryoc/hkdf/index.html) (`crypto_kdf_hkdf_sha256_*`, `crypto_kdf_hkdf_sha512_*`) [libsodium link](https://doc.libsodium.org/key_derivation/hkdf)
* [x] [Direct HMAC authentication variants](https://docs.rs/dryoc/latest/dryoc/hmac/index.html) (`crypto_auth_hmacsha256_*`, `crypto_auth_hmacsha512_*`, `crypto_auth_hmacsha512256_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)

The following libsodium features are incomplete, internal only, or not
implemented. Other crates may provide equivalent functionality:

* [ ] [AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead) beyond the ChaCha20-Poly1305-IETF variants, including AEGIS-128L/256, AES256-GCM, and the legacy 64-bit-nonce ChaCha20-Poly1305 construction
* [ ] XChaCha20-Poly1305 box and secretbox variants (`crypto_box_curve25519xchacha20poly1305_*`, `crypto_secretbox_xchacha20poly1305_*`)
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
wincode schema implementations for vector-backed boxes and AEAD envelopes,
BLAKE2b parameter byte views, protected memory guarded heap buffers with their
fixed-size byte views and OS protection calls (made on recorded address
ranges, so no-access pages are never referenced), 16-byte volatile zeroization of
secret buffers, the x86-64 backends
(detected AVX2, AVX-512 and AVX-512 IFMA entry points for ChaCha20,
XSalsa20, Poly1305, the Argon2 block compression, the BLAKE2b compression,
the ML-KEM polynomial arithmetic and the 4-way Keccak permutation,
`asm!` scalar ChaCha20 and Salsa20 double rounds that run beside the AVX-512
lane sets, an AVX-512
Ed25519 basepoint table lookup, and BMI2-compiled copies of the Curve25519
scalar multiplication, inversion and square-root loops), and the AArch64
backends: detected NEON entry points for XSalsa20, ChaCha20,
the Ed25519 basepoint table lookup (with 16-byte table loads) and the ML-KEM
polynomial arithmetic, message encoding, ciphertext decompression and matrix rejection
sampling (with 16-byte
coefficient-row and input loads and
stores), register-only SVE2 `asm!` blocks for
the ChaCha20 and XSalsa20 rounds (a variant of each also runs Poly1305
over the preceding ciphertext, reading only that input), SVE2 `asm!` passes
of the Argon2 block permutation (reading and writing only the block), scalar `asm!`
blocks for the ChaCha20 and
BLAKE2b rounds, the Poly1305 block loops (one lane, or four each reading a
quarter of the input), the Curve25519 field products and the divstep loop of the
Curve25519 inversion, a `.p2align` directive that
pins the Ed25519 basepoint multiplication loops' alignment, and detected
`sha2`/`sha3` instruction `asm!` loops for the SHA-256 and SHA-512
compression functions, the detected SHA3-extension Keccak permutation (and
a generated `asm!` block running it on two states beside a third on the
integer registers in a three-pass loop, reading its round-constant table
and reading and writing only an 80-byte stack frame of spill slots and its
pass counter, which it wipes and releases), and
single rotated-operand `eor`/`bic` instructions in the scalar Keccak rounds
and the Argon2 `G` function.
`PwHash::into_parts` moves fields out of a value with
a zeroizing `Drop` (`ManuallyDrop` + `ptr::read`). CPU features are detected
at runtime with the `std` feature and taken from the compile-time target
features without it. Each detected kernel is entered through one safe wrapper
that takes a zero-sized CPU feature token, which only that feature detection
can construct, so the kernel's single `unsafe` call sits next to that proof
rather than at every call site. The WebAssembly `simd128` backends (ChaCha20,
XSalsa20 and the ML-KEM polynomial arithmetic) use unsafe 16-byte vector loads
and stores, and `simd128` builds store the portable Argon2 round outputs with
volatile writes that keep LLVM from vectorizing them.
The [rustdoc unsafe code summary](https://docs.rs/dryoc/latest/dryoc/#unsafe-code)
lists every non-test use of unsafe code in this crate.
