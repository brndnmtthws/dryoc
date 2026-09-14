//! # dryoc: Don't Roll Your Own Crypto™[^1]
//!
//! dryoc is a pure-Rust, general-purpose cryptography library. It implements
//! many [libsodium](https://libsodium.gitbook.io/doc/)-compatible APIs and wire
//! formats, so supported operations can interoperate with libsodium across
//! languages.
//!
//! dryoc provides a libsodium-like Classic API and a typed Rustaceous API. The
//! Rustaceous types make key, nonce, and output sizes explicit; the Classic API
//! eases migration from libsodium. Both APIs use the same implementations and
//! can be used together.
//!
//! This crate uses the Rust 2024 edition. The minimum supported Rust version
//! (MSRV) is **Rust 1.89** or newer.
//!
//! ## Features
//!
//! * Pure Rust, with no hidden C libraries
//! * Limited use of unsafe code[^2]
//! * Typed Rustaceous APIs for keys, nonces, and outputs
//! * Classic and Rustaceous APIs for many libsodium operations
//! * WebAssembly support via the `wasm32-unknown-unknown` target
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
//!   * Argon2 block mixing (used by password hashing), except on x86-64 where
//!     the runtime-detected AVX2/AVX-512 backend below is used instead
//!   * Salsa20 (used by XSalsa20-Poly1305 secretbox), except on little-endian
//!     AArch64 and on x86-64 where the runtime-detected backends below are used
//!     instead
//!   * Poly1305 (used by one-time authentication and secret boxes), except on
//!     AArch64 and x86-64 where dryoc keeps the soft backend with its
//!     runtime-detected bulk path because the portable-SIMD path is slower
//! * Runtime-detected AArch64 backends on stable Rust, always built in on that
//!   architecture: NEON and SVE2 keystream kernels for Salsa20 and ChaCha20, a
//!   NEON Poly1305, `sha2`/`sha3` instruction SHA-256 and SHA-512 compression,
//!   and a NEON Ed25519 basepoint table lookup
//! * AArch64 `asm!` on stable Rust, built in on that architecture: the
//!   Curve25519 field multiply and square, register-scheduled scalar ChaCha20
//!   rounds, and (little-endian, default BLAKE2b backend) register-scheduled
//!   BLAKE2b rounds
//! * Runtime-detected x86-64 backends on stable Rust, always built in on that
//!   architecture: AVX2 and AVX-512 keystream kernels for Salsa20 and ChaCha20,
//!   AVX2, AVX-512 and AVX-512 IFMA Poly1305 bulk paths, AVX2 and AVX-512
//!   Argon2 block compression, and AVX2 and AVX-512VL BLAKE2b compression; CPUs
//!   without AVX2 use the portable code
//! * Curve25519 and Ed25519 group arithmetic implemented in-crate; [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
//!   supplies the scalar arithmetic modulo the group order
//! * [SHA2](https://github.com/RustCrypto/hashes/tree/master/sha2) provides the
//!   portable SHA-256 and SHA-512 compression functions used where no hardware
//!   path is detected
//! * [SHA3](https://github.com/RustCrypto/hashes/tree/master/sha3) (used by
//!   SHA-3 compatibility hashing)
//!
//! Dryoc's portable SIMD backends require a nightly Rust toolchain and
//! `--features simd_backend,nightly`. `simd_backend` selects the SIMD code;
//! `nightly` enables Rust's unstable `portable_simd` API.
//!
//! The Curve25519 and Ed25519 group arithmetic is dryoc's own (a radix-2^51
//! field with register-only AArch64 `asm!` products, an X25519 ladder and an
//! edwards25519 point implementation); `curve25519-dalek` supplies the scalar
//! arithmetic modulo the group order. None of it is affected by dryoc's
//! `simd_backend` feature.
//!
//! Poly1305, Salsa20 and (on x86-64) Argon2 are special exceptions. Even with
//! `simd_backend` and `nightly` enabled, dryoc keeps the soft Poly1305 backend
//! with its runtime-detected bulk path on AArch64 and x86-64 because profiling
//! shows the portable-SIMD implementation is slower; on AArch64 it uses the
//! runtime-detected NEON Salsa20 kernels, which run about 2.5x faster than the
//! portable-SIMD lane set on Neoverse cores, and on x86-64 it uses its
//! runtime-detected AVX2/AVX-512 Salsa20 and Argon2 kernels. The default (soft)
//! BLAKE2b backend likewise compresses through a runtime-detected AVX2 or
//! AVX-512VL kernel on x86-64.
//!
//! ## Performance
//!
//! Measured against libsodium 1.0.18 in the same process on the same buffers
//! (single thread, `-Ctarget-cpu=native`; the Neoverse V3 figures are medians
//! of three core-pinned runs), dryoc's Poly1305 is `5.85x` (Intel Xeon
//! 6975P-C) and `3.28x` (Arm Neoverse V3) faster on 1 MiB messages,
//! XSalsa20-Poly1305 secretbox `3.07x` and
//! `2.84x`, and BLAKE2b `1.19x` and `1.43x`; Argon2id ranges from `1.06x`
//! slower to `1.55x` faster depending on the machine and target flags. See
//! [BENCHMARKS.md](https://github.com/brndnmtthws/dryoc/blob/main/BENCHMARKS.md)
//! for the full tables on both machines, the no-flags and portable-SIMD
//! builds, and the environment.
//!
//! ## APIs
//!
//! The _Classic_ API closely follows libsodium's functions and types. The
//! _Rustaceous_ API wraps the same operations in Rust types.
//!
//! ## Error handling
//!
//! Fallible cryptographic operations return [`Error`]. Its structured variants
//! let callers distinguish authentication failures, invalid lengths or values,
//! malformed encodings, invalid keys, protected-memory failures, and invalid
//! operation state.
//!
//! Prefer the Rustaceous API for new code. Use the Classic API when porting
//! libsodium code or when its byte-array interface is a better fit.
//!
//! Rustaceous functions sometimes require an explicit output type. Each module
//! provides type aliases for its common key, nonce, and output types. The
//! Classic API instead uses fixed-size byte arrays and byte slices.
//!
//! | Feature | Rustaceous API | Classic API | Reference |
//! |-|-|-|-|
//! | Public-key authenticated boxes | [`DryocBox`](dryocbox) | [`crypto_box`](classic::crypto_box) | [Link](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption) |
//! | Secret-key authenticated boxes | [`DryocSecretBox`](dryocsecretbox) | [`crypto_secretbox`](classic::crypto_secretbox) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox) |
//! | ChaCha20-Poly1305-IETF authenticated encryption | [`chacha20poly1305_ietf`](dryocaead::chacha20poly1305_ietf) | [`crypto_aead_chacha20poly1305_ietf`](classic::crypto_aead_chacha20poly1305_ietf) | [Link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction) |
//! | Authenticated encryption with additional data | [`DryocAead`](dryocaead) | [`crypto_aead_xchacha20poly1305_ietf`](classic::crypto_aead_xchacha20poly1305_ietf) | [Link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) |
//! | Streaming encryption | [`DryocStream`](dryocstream) | [`crypto_secretstream_xchacha20poly1305`](classic::crypto_secretstream_xchacha20poly1305) | [Link](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) |
//! | Generic hashing and keyed hashing | [`GenericHash`](generichash) | [`crypto_generichash`](classic::crypto_generichash) | [Link](https://doc.libsodium.org/hashing/generic_hashing) |
//! | SHA-2 hashing | [`Sha256`](sha256::Sha256), [`Sha512`](sha512::Sha512) | [`crypto_hash`](classic::crypto_hash) | [Link](https://doc.libsodium.org/advanced/sha-2_hash_function) |
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
//! [`Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) and
//! [`Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) traits are provided
//! for data structures.
//!
//! ## Using wincode
//!
//! This crate includes optional [wincode](https://crates.io/crates/wincode)
//! support which can be enabled with the `wincode` feature flag. When enabled,
//! [`wincode::SchemaWrite`](https://docs.rs/wincode/latest/wincode/trait.SchemaWrite.html) and
//! [`wincode::SchemaRead`](https://docs.rs/wincode/latest/wincode/trait.SchemaRead.html) are
//! provided for supported Rustaceous box types, including
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
//! | `src/dryocbox.rs`, `src/dryocsecretbox.rs`, and `src/dryocaead.rs` wincode impls | `wincode` | Implements `unsafe` wincode schema traits for the Rustaceous box wire formats, including both AEAD nonce sizes. The implementations write and read initialized fields in the same order. |
//! | `src/blake2b/mod.rs` parameter block | Always available | `Params::as_bytes` views the `repr(C, packed)` BLAKE2b parameter block as a `[u8; 64]` so the initialization vector is mixed exactly as specified; both backends call it. The parameter type contains only initialized byte fields, has alignment 1, and its size is checked at compile time. |
//! | `src/protected.rs` protected memory | `protected` on Unix/Windows | Calls OS APIs such as `mlock`, `mprotect`, `VirtualLock`, and `VirtualProtect`, implements page-aligned guarded heap buffers, and exposes exact-size byte-array views over protected heap buffers. |
//! | `src/poly1305/poly1305_soft.rs` with `src/poly1305/poly1305_neon.rs` and `src/poly1305/poly1305_x86_64.rs` Poly1305 bulk backends | Always available on little-endian `aarch64` and `x86_64` | Calls a `#[target_feature(enable = "neon")]` (AArch64) block function, or through `poly1305_x86_64::full_blocks` a `#[target_feature(enable = "avx2")]`, `#[target_feature(enable = "avx512f")]` or `#[target_feature(enable = "avx512f,avx512ifma")]` (x86-64) one, after `is_aarch64_feature_detected!("neon")`, `is_x86_feature_detected!("avx2")`, `is_x86_feature_detected!("avx512f")` or both `is_x86_feature_detected!("avx512f")` and `is_x86_feature_detected!("avx512ifma")` succeed at runtime. The kernels use only safe value intrinsics and safe slice loads; the x86-64 ones load message blocks through `x86_64::load`/`load512` (`_mm256_loadu_si256`/`_mm512_loadu_si512` on `&[u8; 32]`/`&[u8; 64]`) and key-power lanes through `x86_64::load_words`/`load_words512` (the same intrinsics on `&[u64; 4]`/`&[u64; 8]`). |
//! | `src/salsa20/salsa20_neon.rs` XSalsa20 NEON and SVE2 backends | Always available on little-endian `aarch64` | Calls `#[target_feature(enable = "neon")]`, `#[target_feature(enable = "neon,sha3")]` and `#[target_feature(enable = "neon,sve2")]` keystream kernels through a `Kernel` handle that can only be constructed after `is_aarch64_feature_detected!` confirms the required features. The NEON kernels use only safe intrinsics and safe slice loads and stores. The SVE2 kernel additionally runs the Salsa20 rounds of one vector set and one scalar block in one `asm!` block of `add`/`xar`/`eor` instructions on registers bound as `inout` operands, with no memory access. |
//! | `src/chacha20/chacha20_neon.rs` ChaCha20 NEON and SVE2 backends | Always available on little-endian `aarch64` | Calls a `#[target_feature(enable = "neon")]` keystream kernel through a `Kernel` handle that can only be constructed after `is_aarch64_feature_detected!("neon")` (or `"sve2"`) succeeds at runtime. The NEON kernel uses only safe intrinsics and safe slice loads and stores. The SVE2 kernels additionally run the ChaCha20 rounds in `asm!` blocks of `add`/`xar` instructions — one over the 32 vector registers for full chunks, one over the 16 low registers for runs of up to four blocks — with the registers bound as `inout` operands and no memory access, called only when `"sve2"` was detected. |
//! | `src/chacha20/chacha20_x86_64.rs` and `src/salsa20/salsa20_x86_64.rs` ChaCha20 and XSalsa20 AVX2/AVX-512 backends, with the `src/x86_64.rs` helpers | Always available on `x86_64` | Each calls a `#[target_feature(enable = "avx2")]`, `#[target_feature(enable = "avx512f")]` or `#[target_feature(enable = "avx2,avx512f,avx512vl")]` keystream kernel through a `Kernel` handle wrapping an `x86_64::LaneSet`, which can only be constructed after `is_x86_feature_detected!` confirms those features at runtime. The kernels and the shared helpers use safe value intrinsics; the only pointer intrinsics are `_mm256_loadu_si256`/`_mm256_storeu_si256` and `_mm512_loadu_si512`/`_mm512_storeu_si512` in `x86_64::load`/`store`/`load512`/`store512` on `&[u8; 32]`/`&[u8; 64]` references (shared or exclusive as the operation needs), which guarantee exactly that many readable or writable bytes and need no alignment. |
//! | `src/scalarmult_curve25519.rs`, `src/edwards25519/mod.rs` and `src/fe25519/mod.rs` Curve25519 BMI2 roots | Always available on `x86_64` | The X25519 ladder, `mul_base`, `double_scalar_mul_basepoint_vartime`, `Fe::invert` and `Fe::sqrt_ratio_i` each call a `#[target_feature(enable = "bmi2")]` copy of the same safe, inlined arithmetic after `is_x86_feature_detected!("bmi2")` succeeds at runtime, so the `u128` field products compile to `mulx`. These functions contain no intrinsics or `asm!`; the only unsafe operation is the call itself. |
//! | `src/chacha20/chacha20_x86_64.rs` and `src/salsa20/salsa20_x86_64.rs` scalar double rounds beside the AVX-512 lane sets | Always available on `x86_64` | Each `scalar_double_round` is an `asm!` block of base x86-64 `add`/`xor`/`rol`/`mov` instructions: ten (ChaCha20) or nine (Salsa20) state words are `inout` registers and the rest are 4-byte loads and stores at fixed offsets within a `&mut [u32; 6]` / `&mut [u32; 7]` whose pointer is passed in (`nostack`). They keep the companion block of `xor_chunk_avx512_with_block` on the integer ports, where the compiler would otherwise SLP-vectorise it onto the ports the lane set occupies; called only from that `#[target_feature(enable = "avx512f")]` kernel, which the AVX-512 `Kernel` handle reaches after `is_x86_feature_detected!("avx512f")`. |
//! | `src/argon2/argon2_x86_64.rs` Argon2 AVX2 and AVX-512 block compression | Always available on `x86_64` | Calls a `#[target_feature(enable = "avx2")]` or `#[target_feature(enable = "avx512f")]` `fill_block` through a `Kernel` handle that can only be constructed after `is_x86_feature_detected!` confirms that feature at runtime. The kernels use safe value intrinsics; block words are loaded and stored through `x86_64::load_words`/`store_words`/`load_words512`/`store_words512` (`_mm256_loadu_si256`/`_mm256_storeu_si256`/`_mm512_loadu_si512`/`_mm512_storeu_si512` on `&[u64; 4]`/`&[u64; 8]` references, shared or exclusive as the operation needs, which guarantee exactly 32 or 64 readable or writable bytes and need no alignment). |
//! | `src/blake2b/blake2b_x86_64.rs` BLAKE2b AVX2 and AVX-512VL compression | Always available on `x86_64` (soft backend) | Calls a `#[target_feature(enable = "avx2")]` or `#[target_feature(enable = "avx2,avx512f,avx512vl")]` `compress` through a `Kernel` handle that can only be constructed after `is_x86_feature_detected!` confirms those features at runtime. The kernels use safe value intrinsics; the block and chaining state are loaded and stored through `x86_64::load`/`load_words`/`store_words` (`_mm256_loadu_si256`/`_mm256_storeu_si256` on `&[u8; 32]`/`&[u64; 4]` references, which guarantee exactly 32 readable or writable bytes and need no alignment). |
//! | `src/blake2b/blake2b_aarch64.rs` BLAKE2b rounds | Always available on little-endian `aarch64` (soft backend) | `rounds` is an `asm!` block of base A64 `ldr`/`add`/`ror`/`eor` instructions: the sixteen working-state words are `inout` registers, and the only memory accesses are 192 8-byte loads (two per `G`) at immediate offsets within the 128-byte block whose pointer is passed in (`readonly`, `nostack`, `preserves_flags`). It pins the two-instruction-deep `G` step schedule that LLVM folds back into three. |
//! | `src/chacha20/chacha20_aarch64.rs` scalar ChaCha20 rounds | Always available on `aarch64` | `rounds` is a register-only `asm!` block of base A64 `add`/`ror`/`eor` instructions over the 16 state words, bound as `inout` operands with no memory access (`nomem`, `nostack`); it exists to pin the two-instruction-deep quarter-round schedule that LLVM folds back into three. Used by HChaCha20 and the scalar block function. |
//! | `src/sha256/sha256_aarch64.rs` SHA-256 hardware compression | Always available on little-endian `aarch64` | `Sha256` calls the `#[target_feature(enable = "sha2")]` function `compress` only after `is_aarch64_feature_detected!("sha2")` succeeds. That function runs the whole block loop in one `asm!` block that reads the caller's `&[[u8; 64]]` blocks and the `K32` table, and reads and writes the eight-word state through its `&mut` pointer; only the listed registers are clobbered and it touches no stack. |
//! | `src/sha512/sha512_aarch64.rs` SHA-512 hardware compression | Always available on little-endian `aarch64` | `Sha512` calls the `#[target_feature(enable = "sha3")]` function `compress` only after `is_aarch64_feature_detected!("sha3")` succeeds. That function runs the whole block loop in one `asm!` block that reads the caller's `&[[u8; 128]]` blocks and the `K64` table, and reads and writes the eight-word state through its `&mut` pointer; only the listed registers are clobbered and it touches no stack. |
//! | `src/sha512/sha512_aarch64.rs` SHA-512 two-state hardware compression | Always available on little-endian `aarch64` | `Sha512::from_blocks` calls the `#[target_feature(enable = "sha3")]` function `compress2` only after `is_aarch64_feature_detected!("sha3")` succeeds. Its single `asm!` block compresses one block into each of two independent states with the two round sequences interleaved (the HMAC inner and outer key blocks); it reads the two `&[u8; 128]` blocks and the `K64` table, reads and writes both eight-word states through their `&mut` pointers, clobbers every vector register and `x3`, and touches no stack. |
//! | `src/edwards25519/edwards25519_x86_64.rs` basepoint table lookup | Always available on `x86_64` | `select_row` calls the `#[target_feature(enable = "avx512f")]` function `edwards25519_x86_64::select_row` only after `is_x86_feature_detected!("avx512f")` succeeds; the function uses safe value intrinsics (a vector compare of the digit and masked blends over every entry) and writes its result through `x86_64::store_words512`, reading every table entry regardless of the digit. |
//! | `src/edwards25519/edwards25519_neon.rs` basepoint table lookup | Always available on `aarch64` | `select_row` calls the `#[target_feature(enable = "neon")]` function `edwards25519_neon::select_row` only after `is_aarch64_feature_detected!("neon")` succeeds; the function uses only safe value intrinsics (`and`/`orr` on vectors built from limbs) and reads every table entry regardless of the digit. |
//! | `src/fe25519/fe25519_aarch64.rs` Curve25519 field multiply and square | Always available on `aarch64` | `mul`, `square`, `square_chain` and `mul_121666` are register-only `asm!` blocks of base A64 integer instructions (`mul`, `umulh`, `adds`/`adc`, `extr`, `madd`, `and`) computing one radix-2^51 field product; every written register is a declared output or scratch operand and the blocks are `pure`, `nomem`, `nostack`. |
//! | `src/utils.rs` word-wise zeroization | Always available | `zeroize_bytes` and `zeroize_u64s` view the 16-byte-aligned middle of a byte or `u64` slice as `u128`s (`align_to_mut`) and clear each with a volatile store, so wiping a buffer costs one store per sixteen bytes instead of one per byte or word. Unaligned ends use the `zeroize` crate. |
//!
//! Test-only unsafe code is used for libsodium and Argon2 compatibility checks
//! and protected-memory platform probes; it is not part of the runtime crate
//! API.
//!
//! ## Security notes
//!
//! dryoc has not undergone a third-party security audit. Its compatibility
//! tests, Rust types, and limited use of unsafe code reduce some classes of
//! defects, but do not guarantee that an application is secure. Applications
//! must still follow the documented key and nonce rules, protect secret
//! material, handle errors, and choose primitives appropriate for their
//! protocol.
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
//! contain unsafe code. See the unsafe code section above for the non-test
//! unsafe inventory in this crate.
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
mod chacha20;
mod edwards25519;
mod fe25519;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod neon;
mod poly1305;
mod salsa20;
mod scalarmult_curve25519;
mod sha2_impl;
mod siphash24;
mod stream;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub mod classic {
    //! # Classic API
    //!
    //! The Classic API follows libsodium's interface closely. Use it to port
    //! libsodium code or when fixed-size byte arrays and byte slices are a
    //! better fit than the Rustaceous types.
    mod crypto_aead_chacha20poly1305_impl;
    mod crypto_auth_hmac_impl;
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

pub use error::{Error, ErrorContext, LengthConstraint, ValueConstraint};

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
