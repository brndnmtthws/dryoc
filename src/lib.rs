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
//! ## Unsafe code
//!
//! Miri uses portable code where AArch64 assembly or NEON intrinsics don't
//! apply. Protected-memory OS calls are native-only: Miri can't enforce page
//! permissions.
//!
//! Kernels below run only after `has_x86_feature!`/`has_aarch64_feature!`
//! confirms their features — runtime detection with `std`, compile-time target
//! features without it. Either way `true` means the CPU has it.
//!
//! Non-test `unsafe` code is limited to these areas:
//!
//! | Area | Feature gate | Why `unsafe` is required |
//! |-|-|-|
//! | `src/dryocbox.rs`, `src/dryocsecretbox.rs`, and `src/dryocaead.rs` wincode impls | `wincode_0_6` | Implements `unsafe` wincode schema traits for the Rustaceous box wire formats, including both AEAD nonce sizes. The implementations write and read initialized fields in the same order. |
//! | `src/blake2b/mod.rs` parameter block | Always available | `Params::as_bytes` views the `repr(C, packed)` BLAKE2b parameter block as a `[u8; 64]` so the initialization vector is mixed exactly as specified; both backends call it. The parameter type contains only initialized byte fields, has alignment 1, and its size is checked at compile time. |
//! | `src/protected.rs` protected memory | `protected` on Unix/Windows | Calls OS APIs such as `mlock`, `mprotect`, `VirtualLock`, and `VirtualProtect`, implements page-aligned guarded heap buffers, and exposes exact-size byte-array views over protected heap buffers. Each allocation is initialized through its raw pointer before any slice over it exists, and the OS calls take recorded address ranges rather than slices, so no reference is ever created to no-access pages. |
//! | `src/x86_64.rs` and `src/aarch64.rs` CPU feature tokens | Always available on `x86_64` / little-endian `aarch64` | Not `unsafe` themselves: the zero-sized tokens `Avx2`, `Avx512`, `Avx512Vl`, `Avx512Ifma`, `Bmi2` (x86-64) and `Neon`, `Sve2`, `Sha2`, `Sha3` (AArch64) have a private field, and their only constructors are `new` functions that return a token when `has_x86_feature!`/`has_aarch64_feature!` reports every feature it names (runtime detection with `std`, the compile-time target features without it) (plus `Avx2::avx512vl`/`Avx512::avx512vl`, which detect the rest of the `Avx512Vl` set). `Avx512` and `Avx512Ifma` also require `avx2`: rustc's `avx512f` target feature implies it, but std's `avx512f` detection does not check the CPUID `avx2` bit. Every `#[target_feature]` kernel in the rows below is entered through a safe `#[inline(always)]` wrapper that takes its token by value and makes the one `unsafe` call into the `*_unchecked` kernel, whose features the token proves; `sve2` and `sha3` imply `neon`, so `Sve2` and `Sha3` also cover the `"neon,sve2"` and `"neon,sha3"` kernels. The dispatch enums (`Kernel`, `x86_64::LaneSet`) hold the tokens, so the calls into the wrappers are safe. |
//! | `src/poly1305/poly1305_soft.rs` with `src/poly1305/poly1305_x86_64.rs` Poly1305 bulk backends | Always available on `x86_64` | Calls, through `poly1305_x86_64::full_blocks`, a `#[target_feature(enable = "avx2")]`, `#[target_feature(enable = "avx512f")]` or `#[target_feature(enable = "avx512f,avx512ifma")]` (x86-64) one, through the token wrappers of an `Avx2`, `Avx512` or `Avx512Ifma` token. The kernels use only safe value intrinsics and safe slice loads; the x86-64 ones load message blocks through `x86_64::load`/`load512` (`_mm256_loadu_si256`/`_mm512_loadu_si512` on `&[u8; 32]`/`&[u8; 64]`) and key-power lanes through `x86_64::load_words`/`load_words512` (the same intrinsics on `&[u64; 4]`/`&[u64; 8]`). |
//! | `src/poly1305/poly1305_aarch64.rs` Poly1305 block loops | Always available on little-endian `aarch64` | Two `asm!` loops of `poly_block` text (Poly1305-donna-64 in radix 2^64) on the integer registers: `blocks` over four lanes, each reading its contiguous quarter of the caller's input through a post-incremented pointer (the loop runs exactly `len / 64` times, 16 bytes per lane per iteration), and `blocks1` over one lane (exactly `len / 16` iterations of 16 bytes). Every load is therefore in bounds; otherwise register-only, no stack, flags clobbered. |
//! | `src/salsa20/salsa20_neon.rs` XSalsa20 NEON and SVE2 backends | Always available on little-endian `aarch64` | Calls `#[target_feature(enable = "neon")]`, `#[target_feature(enable = "neon,sha3")]` and `#[target_feature(enable = "neon,sve2")]` keystream kernels through the token wrappers of the `Neon`, `Sha3` or `Sve2` token held by its `Kernel` handle. The NEON kernels use only safe intrinsics and safe slice loads and stores. The SVE2 kernel additionally runs the Salsa20 rounds of one vector set and one scalar block in one `asm!` block (or of half the set's rounds and one scalar block in each of two) of `add`/`xar`/`eor` instructions on registers bound as `inout` operands, with no memory access; a second variant also runs a Poly1305 lane beside the scalar block (`mul`/`umulh`/`adds`/`adcs` on general-purpose registers), whose only memory access is `ldp` loads of its 320 bytes of MAC input through a pointer bound as an `inout` operand and advanced 16 bytes at a time. |
//! | `src/chacha20/chacha20_neon.rs` ChaCha20 NEON and SVE2 backends | Always available on little-endian `aarch64` | Calls a `#[target_feature(enable = "neon")]` or `#[target_feature(enable = "neon,sve2")]` keystream kernel through the token wrappers of the `Neon` or `Sve2` token held by its `Kernel` handle. The NEON kernel uses only safe intrinsics and safe slice loads and stores. The SVE2 kernels additionally run the ChaCha20 rounds in `asm!` blocks of `add`/`xar` instructions — one over the 32 vector registers for full chunks (in a second variant also running a companion block's rounds with `add`/`eor`/`ror` on 16 general-purpose registers, and in a third two Poly1305 lanes over 512 bytes of MAC input with `mul`/`umulh`/`adds`/`adcs` on general-purpose registers, whose only memory access is `ldp` loads of those 512 bytes through two pointers bound as `inout` operands and advanced 16 bytes at a time), one over the 16 low registers for runs of up to four blocks — with the registers bound as `inout` operands and no memory access (the full-chunk and four-block blocks loop twice over five double rounds, on a general-purpose counter operand), called only from the `"neon,sve2"` kernels. |
//! | `src/chacha20/chacha20_x86_64.rs` and `src/salsa20/salsa20_x86_64.rs` ChaCha20 and XSalsa20 AVX2/AVX-512 backends, with the `src/x86_64.rs` helpers | Always available on `x86_64` | Each calls a `#[target_feature(enable = "avx2")]`, `#[target_feature(enable = "avx512f")]` or `#[target_feature(enable = "avx2,avx512f,avx512vl")]` keystream kernel through the token wrappers of the `Avx2`, `Avx512` or `Avx512Vl` token held by the `x86_64::LaneSet` in its `Kernel` handle. The kernels and the shared helpers use safe value intrinsics; the only pointer intrinsics are `_mm256_loadu_si256`/`_mm256_storeu_si256` and `_mm512_loadu_si512`/`_mm512_storeu_si512` in `x86_64::load`/`store`/`load512`/`store512` on `&[u8; 32]`/`&[u8; 64]` references (shared or exclusive as the operation needs), which guarantee exactly that many readable or writable bytes and need no alignment. |
//! | `src/scalarmult_curve25519.rs`, `src/edwards25519/mod.rs` and `src/fe25519/mod.rs` Curve25519 BMI2 roots | Always available on `x86_64` | The X25519 ladder (whole, and the projective `ladder_xz` that X-Wing pairs with the base point under one inversion), `mul_base`, `double_scalar_mul_basepoint_vartime`, `Fe::invert` and `Fe::sqrt_ratio_i` each call a `#[target_feature(enable = "bmi2")]` copy of the same safe, inlined arithmetic through its token wrapper when a `Bmi2` token can be constructed, so the `u128` field products compile to `mulx`. These functions contain no intrinsics or `asm!`; the only unsafe operation is the wrapper's call. |
//! | `src/chacha20/chacha20_x86_64.rs` and `src/salsa20/salsa20_x86_64.rs` scalar double rounds beside the AVX-512 lane sets | Always available on `x86_64` | Each `scalar_double_round` is an `asm!` block of base x86-64 `add`/`xor`/`rol`/`mov` instructions: ten (ChaCha20) or nine (Salsa20) state words are `inout` registers and the rest are 4-byte loads and stores at fixed offsets within a `&mut [u32; 6]` / `&mut [u32; 7]` whose pointer is passed in (`nostack`). They keep the companion block of `xor_chunk_avx512_with_block` on the integer ports, where the compiler would otherwise SLP-vectorise it onto the ports the lane set occupies; called only from that `#[target_feature(enable = "avx512f")]` kernel, which the AVX-512 `Kernel` handles reach through the wrapper of their `Avx512` token. |
//! | `src/argon2/argon2_x86_64.rs` Argon2 AVX2 and AVX-512 block compression | `alloc` on `x86_64` | The safe `Kernel::fill_block` runs the permutation `P` in place on the block by calling the `#[target_feature(enable = "avx2")]` function `permute_avx2_unchecked` or the `#[target_feature(enable = "avx512f")]` function `permute_avx512_unchecked` through the token wrapper of the `Avx2` or `Avx512` token held by its `Kernel` handle. The kernels use safe value intrinsics; block words are loaded and stored through `x86_64::load_words`/`store_words`/`load_words512`/`store_words512` (`_mm256_loadu_si256`/`_mm256_storeu_si256`/`_mm512_loadu_si512`/`_mm512_storeu_si512` on `&[u64; 4]`/`&[u64; 8]` references, shared or exclusive as the operation needs, which guarantee exactly 32 or 64 readable or writable bytes and need no alignment). |
//! | `src/argon2/argon2_neon.rs` Argon2 SVE2 block compression | `alloc` on little-endian `aarch64` (outside Miri) | The safe `Kernel::fill_block` runs the permutation `P` in place on the block by calling the `#[target_feature(enable = "neon,sve2")]` function `permute_unchecked` through the token wrapper of the `Sve2` token held by its `Kernel` handle. Each of its two `asm!` passes (rows, then columns) loads, permutes and stores three 16-word states on the vector registers and five on the integer registers, through pointers derived from the block's one `&mut` borrow and advanced only over the words of those eight states, which are in the block and each belong to one state; it uses no stack and declares every register it writes. |
//! | `src/mlkem/mlkem_x86_64.rs` ML-KEM AVX2 polynomial arithmetic | Always available on `x86_64` | Calls the `#[target_feature(enable = "avx2")]` NTT, inverse NTT and base-multiplication kernels through the token wrappers of the `Avx2` token held by its `Kernel` handle. The kernels use safe value intrinsics; coefficients and twiddle tables are loaded and stored through `x86_64::load_i16s`/`store_i16s` (`_mm256_loadu_si256`/`_mm256_storeu_si256` on `&[i16; 16]` references, shared or exclusive as the operation needs, which guarantee exactly 32 readable or writable bytes and need no alignment). |
//! | `src/keccak/keccak_x86_64.rs` 4-way Keccak-p\[1600\] AVX2 permutation | Always available on `x86_64` | `permute_lanes` (behind `ParSponge`) calls the `#[target_feature(enable = "avx2")]` function `permute4_avx2_unchecked` through the token wrapper of the `Avx2` token held by its `Kernel` handle. The kernel uses safe value intrinsics; the four states (disjoint `&mut [u64; 25]` references from `get_disjoint_mut`) are loaded and stored through `x86_64::load_words`/`store_words` (`_mm256_loadu_si256`/`_mm256_storeu_si256` on `&[u64; 4]` references, which guarantee exactly 32 readable or writable bytes and need no alignment). |
//! | `src/keccak/keccak_aarch64.rs` 2-way Keccak-p\[1600\] SHA3-extension permutation | Always available on little-endian `aarch64` | `ParSponge` and `permute_lanes` call the `#[target_feature(enable = "neon,sha3")]` function `permute2_sha3_unchecked` through the token wrapper of the `Sha3` token held by its `Kernel` handle. The kernel uses only safe value intrinsics and reads and writes the states through their `&mut [u64; 25]` references (disjoint ones from `get_disjoint_mut` for lanes of one array). |
//! | `src/keccak/keccak3_aarch64.rs` 3-way Keccak-p\[1600, 24\] permutation (generated by `keccak3_aarch64.py`) | Always available on little-endian `aarch64` | `Kernel::permute_selected` in `keccak_aarch64.rs` calls the `#[target_feature(enable = "neon,sha3")]` function `permute3_unchecked` through the `permute3` wrapper of the `Sha3` token held by its `Kernel` handle. The function is one `asm!` block with every register it writes an output operand; its only memory accesses are 48 post-incremented loads of the static round-constant table `RC` over its three loop passes and loads and stores in an 80-byte stack frame it allocates below the stack pointer (eight spill slots and the pass counter), which it wipes and releases before it ends. The states are loaded into and stored from its operands through their `&mut [u64; 25]` references (disjoint ones from `get_disjoint_mut` for lanes of one array). |
//! | `src/keccak/keccak_soft.rs` lazy-rotation scalar Keccak-p\[1600\] | Always available on `aarch64` (outside Miri) | `xor_rol` and `bic_rol` are each one register-only `asm!` instruction (`eor` or `bic` with a rotated second operand) on two `u64` inputs and one output, with no memory, stack or flag access (`pure`, `nomem`, `nostack`, `preserves_flags`); the rotation amount is a `const` operand. Under Miri they are the plain Rust expressions. |
//! | `src/blake2b/blake2b_x86_64.rs` BLAKE2b AVX2 and AVX-512VL compression | Always available on `x86_64` (soft backend) | Calls a `#[target_feature(enable = "avx2")]` or `#[target_feature(enable = "avx2,avx512f,avx512vl")]` `compress` through the token wrapper of the `Avx2` or `Avx512Vl` token held by its `Kernel` handle. The kernels use safe value intrinsics; the block and chaining state are loaded and stored through `x86_64::load`/`load_words`/`store_words` (`_mm256_loadu_si256`/`_mm256_storeu_si256` on `&[u8; 32]`/`&[u64; 4]` references, which guarantee exactly 32 readable or writable bytes and need no alignment). |
//! | `src/blake2b/blake2b_aarch64.rs` BLAKE2b rounds | Always available on little-endian `aarch64` (soft backend) | `rounds` is an `asm!` block of base A64 `ldr`/`add`/`ror`/`eor` instructions: the sixteen working-state words are `inout` registers, and the only memory accesses are 192 8-byte loads (two per `G`) at immediate offsets within the 128-byte block whose pointer is passed in (`readonly`, `nostack`, `preserves_flags`). It pins the two-instruction-deep `G` step schedule that LLVM folds back into three. |
//! | `src/chacha20/chacha20_aarch64.rs` scalar ChaCha20 rounds | Always available on `aarch64` | `rounds` is a register-only `asm!` block of base A64 `add`/`ror`/`eor` instructions over the 16 state words, bound as `inout` operands with no memory access (`nomem`, `nostack`); it exists to pin the two-instruction-deep quarter-round schedule that LLVM folds back into three. Used by HChaCha20 and the scalar block function. |
//! | `src/sha256/sha256_aarch64.rs` SHA-256 hardware compression | Always available on little-endian `aarch64` | `Sha256` calls the `#[target_feature(enable = "sha2")]` function `compress_unchecked` through the token wrapper of a `Sha2` token. That function runs the whole block loop in one `asm!` block that reads the caller's `&[[u8; 64]]` blocks and the `K32` table, and reads and writes the eight-word state through its `&mut` pointer; only the listed registers are clobbered and it touches no stack. |
//! | `src/sha512/sha512_aarch64.rs` SHA-512 hardware compression | Always available on little-endian `aarch64` | `Sha512` calls the `#[target_feature(enable = "sha3")]` function `compress_unchecked` through the token wrapper of a `Sha3` token. That function runs the whole block loop in one `asm!` block that reads the caller's `&[[u8; 128]]` blocks and the `K64` table, and reads and writes the eight-word state through its `&mut` pointer; only the listed registers are clobbered and it touches no stack. |
//! | `src/sha512/sha512_aarch64.rs` SHA-512 two-state hardware compression | Always available on little-endian `aarch64` | `Sha512::absorb_key_blocks` calls the `#[target_feature(enable = "sha3")]` function `compress2_unchecked` through the token wrapper of a `Sha3` token. Its single `asm!` block compresses one block into each of two independent states with the two round sequences interleaved (the HMAC inner and outer key blocks); it reads the two `&[u8; 128]` blocks and the `K64` table, reads and writes both eight-word states through their `&mut` pointers, clobbers every vector register and `x3`, and touches no stack. |
//! | `src/edwards25519/edwards25519_x86_64.rs` basepoint table lookup | Always available on `x86_64` | `select_row` calls the `#[target_feature(enable = "avx512f")]` function `edwards25519_x86_64::select_row_unchecked` through the token wrapper of an `Avx512` token. The function uses safe value intrinsics (a vector compare of the digit and masked blends over every entry), reads every table entry regardless of the digit, assembles its result through `x86_64::store_words512`, and writes it into caller-owned storage that `mul_base` wipes. |
//! | `src/edwards25519/edwards25519_neon.rs` basepoint table lookup | `aarch64` with `neon` enabled at build time (every std AArch64 target) | The module is compiled only under `cfg(target_feature = "neon")`. Its `select_row` and `select_row64` (the four-limb table copy) are `#[inline(always)]` functions whose bodies are each one `unsafe` block of NEON intrinsics (`and`/`orr` on vectors built from limbs; `select_row64` loads its limb pairs with `vld1q_u64` from two-element subslices of the table, in bounds and `u64`-aligned); the block is valid because the feature is statically enabled. Each reads every entry of its row regardless of the digit; `select_row` writes the result into caller-owned storage and `select_row64` returns it. |
//! | `src/mlkem/mlkem_neon.rs` ML-KEM NEON polynomial arithmetic and matrix rejection sampling | Always available on little-endian `aarch64` | Calls the `#[target_feature(enable = "neon")]` forward NTT, inverse NTT, NTT-domain multiply-add, reduction, message encoding, ciphertext decompression and rejection-sampling kernels through the token wrappers of the `Neon` token held by its `Kernel` handle. The kernels use safe value intrinsics; the only pointer intrinsics are `vld1q_s16`/`vst1q_s16` in `load`/`store` on `&[i16; 8]`/`&mut [i16; 8]` rows of the polynomials and twiddle tables, and `vld1q_u8`/`vld1q_u16` in `load_u8`/`load_u16` on `&[u8; 16]`/`&[u16; 8]` sampler input bytes and constant tables, which guarantee exactly 16 readable or writable bytes and need no alignment beyond the element type's. |
//! | `src/edwards25519/mod.rs` `mul_base` loop alignment | Always available on `aarch64` | Each of the two loop bodies starts with an `asm!` block holding only a `.p2align 6` directive, which emits `nop` padding and touches no register, memory or flag (`nomem`, `nostack`, `preserves_flags`); it pins the loops' alignment, whose drift with unrelated code cost up to 12%. |
//! | `src/fe25519/fe25519_aarch64.rs` Curve25519 field multiply and square | Always available on `aarch64` | `mul`, `square` and `square_chain` are register-only `asm!` blocks of base A64 integer instructions (`mul`, `umulh`, `adds`/`adc`, `extr`, `madd`, `and`) computing one radix-2^51 field product; every written register is a declared output or scratch operand and the blocks are `pure`, `nomem`, `nostack`. |
//! | `src/fe25519/safegcd.rs` divsteps of the Curve25519 inversion | Always available on `aarch64` (outside Miri) | `divsteps_59` is one register-only `asm!` loop of base A64 integer instructions (`csel`, `cinv`, `ccmp`, `tst`, `and`, `add`, shifts) running the 59 branch-free divsteps of one inversion batch; every written register is a declared output or scratch operand, the flags are clobbered, the only branch is the fixed-count loop, and the block is `pure`, `nomem`, `nostack`. |
//! | `src/fe25519/fe64_aarch64.rs` four-limb Curve25519 field arithmetic for the X25519 ladder and the basepoint multiplication | Always available on `aarch64` | `Fe64::add`, `sub`, `mul`, `square` and `mul_121666_add` are register-only `asm!` blocks of base A64 integer instructions (`mul`, `umulh`, `adds`/`adcs`/`adc`, `subs`/`sbcs`, `csel`, `add`/`sub`) computing one result modulo `2^256 - 38`; every written register is a declared output or scratch operand and the blocks are `pure`, `nomem`, `nostack`. |
//! | `src/wasm32.rs` WebAssembly `simd128` loads and stores, used by the `src/chacha20/chacha20_wasm32.rs`, `src/salsa20/salsa20_wasm32.rs` and `src/mlkem/mlkem_wasm32.rs` kernels | `wasm32` built with the `simd128` target feature | `load`/`store` and `load_i16s`/`store_i16s` call `v128_load`/`v128_store` on `&[u8; 16]`/`&mut [u8; 16]` and `&[i16; 8]`/`&mut [i16; 8]` references, which guarantee exactly 16 initialized readable or writable bytes; both instructions are unaligned (align 1) accesses. The kernels, and the Poly1305 and Keccak `simd128` kernels, otherwise use only safe value intrinsics. `simd128` is a compile-time target feature, so there is no runtime check or `#[target_feature]` call to justify. |
//! | `src/argon2/argon2_soft.rs` round output stores | `wasm32` built with the `simd128` target feature | `store_word` writes each of a round's sixteen output words with `core::ptr::write_volatile` through a `&mut u64` into the block, so the pointer is valid, aligned and initialized. A volatile store is not a seed for LLVM's SLP vectorizer, which would otherwise pair the four `G` columns into `i64x2` lanes whose multiply engines emulate at half the scalar speed; other builds use a plain assignment. |
//! | `src/argon2/argon2_soft.rs` `G` XOR-rotations | Always available on `aarch64` (outside Miri) | `xor_ror` is one register-only `asm!` instruction (`eor` with a rotated second operand) on two `u64` inputs and one output, with no memory, stack or flag access (`pure`, `nomem`, `nostack`, `preserves_flags`); the rotation amount is a `const` operand. Other targets and Miri use the plain Rust expression. |
//! | `src/utils.rs` word-wise zeroization | Always available | `zeroize_bytes`, `zeroize_u32s`, `zeroize_u64s` and `zeroize_i16s` (behind `WideZeroizing`) view the 16-byte-aligned middle of a byte, `u32`, `u64` or `i16` slice as `u128`s (`align_to_mut`) and clear each with a volatile store, so wiping a buffer costs one store per sixteen bytes instead of one per element. Unaligned ends use the `zeroize` crate. |
//! | `src/pwhash.rs` `PwHash::into_parts` | `alloc` | Uses `ManuallyDrop` and reads each owned field exactly once so the hash's drop-time zeroization does not erase the value while transferring ownership to the caller. |
//!
//! Test-only unsafe (libsodium/Argon2 checks, protected-memory probes) isn't
//! part of the runtime API.
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
//! contain unsafe code. See the unsafe code section above for the non-test
//! unsafe inventory in this crate.
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
/// # Various utility functions
pub mod utils;
pub mod xof;

pub use error::{Error, ErrorContext, LengthConstraint, ValueConstraint};
