# Repository Guidelines

## Project Overview

`dryoc` is a pure-Rust cryptography crate intended to be mostly compatible with
libsodium while also offering a more idiomatic Rust API. The public API has two
main surfaces:

- `src/classic/`: libsodium-like functions and type aliases.
- Top-level modules such as `dryocbox`, `dryocsecretbox`, `dryocstream`, `kdf`,
  `kx`, `pwhash`, and `sign`: the Rustaceous API.

Keep changes conservative. This is security-sensitive code, so compatibility,
constant-time behavior, memory zeroing, and feature-gated API shape matter more
than convenience refactors.

## Toolchain And Features

- The crate uses Rust 2024. `Cargo.toml` declares `rust-version = "1.89"`;
  avoid newer language features unless the MSRV is intentionally changed.
- Rust 2024 reserves `gen` as a keyword. Random generation APIs are named
  `generate` (for example, `Key::generate()`); the legacy `gen`/`r#gen`
  aliases were removed.
- Default features are `base64`, `u64_backend`, and `protected`.
- Optional features:
  - `serde`: serialization support for supported types.
  - `base64`: password-hash string helpers; enabled by default and does not add
    a dependency.
  - `wincode`: direct binary serialization support for Rustaceous box types.
  - `protected`: protected memory APIs on Unix/Windows; enabled by default and
    does not add a dependency beyond target OS bindings already used by the
    crate.
  - `nightly`: extra doc cfg support and nightly-only allocator APIs for
    protected memory.
  - `simd_backend`: SIMD-backed internals; in CI this is used with `nightly`.
- Do not commit a `Cargo.lock` for routine library changes unless the project
  policy changes.

## Common Commands

Use focused commands while developing, then broaden coverage before handing off:

```sh
cargo check
cargo test
cargo test --features serde
cargo test --features base64
cargo test --features wincode
cargo +nightly test --features serde,nightly
cargo +nightly test --features simd_backend,nightly
cargo clippy --features default -- -D warnings
cargo +nightly fmt --all -- --check
```

CI uses `cargo nextest` when available:

```sh
cargo nextest run --features default
cargo nextest run --features serde
cargo nextest run --features base64
cargo nextest run --features wincode
cargo +nightly nextest run --features simd_backend,nightly
```

Coverage is generated on nightly with:

```sh
cargo +nightly tarpaulin --features serde,nightly,wincode --out Xml
```

Fuzzing lives in `fuzz/` and is isolated as its own workspace:

```sh
cargo fuzz run fuzz_hashes
```

## Formatting And Lints

- Follow `.rustfmt.toml`; it uses unstable rustfmt options, so formatting checks
  may require nightly rustfmt.
- Keep `cargo clippy -- -D warnings` clean for any feature combination you touch.
- Prefer existing local types and aliases over new wrappers.
- Keep documentation examples compiling under the feature gates they require.

## Testing Expectations

- Add or update unit tests next to the module for implementation details.
- Add integration tests in `tests/integration_tests.rs` for public API behavior,
  feature-gated serde/base64 behavior, and Classic/Rustaceous interoperability.
- For cryptographic primitives, prefer known-answer tests and libsodium
  compatibility checks over tests that only round-trip random data.
- When changing a feature-gated area, test both the enabled and relevant disabled
  configurations.
- For protected memory changes, test the default `protected` feature on
  Unix/Windows; also test with `+nightly --features nightly` when touching
  nightly-only allocator APIs.

## Crypto-Specific Rules

- Do not introduce new algorithms, modes, nonce handling, key derivation rules,
  or wire formats without explicit design review.
- Preserve libsodium-compatible constants, buffer sizes, error behavior, and
  function semantics in `src/classic/`.
- Avoid data-dependent branches or memory access patterns in code that handles
  secrets.
- Use `subtle` or existing constant-time helpers for equality and selection.
- Ensure secret material is zeroized where existing types expect that behavior.
- Treat nonce generation and reuse rules as part of the API contract; do not
  silently change them.
- Any new `unsafe` must be small, documented by surrounding invariants, and
  covered by tests. Prefer existing unsafe wrappers and allocation helpers.
- Put a `// SAFETY:` comment immediately before every non-test `unsafe` block,
  `unsafe impl`, `unsafe extern`, or `unsafe fn`; explain the concrete pointer,
  aliasing, initialization, layout, or OS-call invariant that makes it valid.
- When adding, removing, or materially changing non-test `unsafe`, update the
  unsafe code inventory in `src/lib.rs` and `README.md`.
- Test-only `unsafe` should stay confined to compatibility checks or platform
  probes, and it does not need to be listed in the unsafe inventory.

## Module Map

- `src/lib.rs`: crate-level docs, feature gates, and public module exports.
- `src/types.rs`: fixed-size byte-array traits and helper types.
- `src/rng.rs`: random byte generation.
- `src/protected.rs`: protected memory allocation, locking, guard pages, and
  locked bytes; nightly-only allocator APIs are additionally gated by `nightly`.
- `src/stream.rs`: keystream sinks shared by the ChaCha20 and Salsa20 drivers
  (`Sink`, `InPlace`, `BufferToBuffer`, `Dest`).
- `src/neon.rs`: AArch64 NEON load/store/transpose/XOR helpers shared by the
  `*_neon.rs` kernels.
- `src/x86_64.rs`: AVX2/AVX-512 load/store/transpose/XOR helpers shared by the
  `*_x86_64.rs` kernels.
- `src/sha2_impl.rs`: the `sha2_hasher!` macro that generates the SHA-256 and
  SHA-512 hasher types; each `sha*/mod.rs` supplies its IV and `compress`.
- `src/classic/crypto_*_impl.rs`: shared bodies behind pairs of classic
  modules (HMAC, secretbox/box, ChaCha20-Poly1305 and XChaCha20-Poly1305).
- `src/classic/`: libsodium-compatible API modules.
- `src/blake2b/`, `src/poly1305/`, `src/argon2/`, `src/salsa20/`,
  `src/chacha20/`, `src/sha256/`, `src/sha512/`, `src/fe25519/`,
  `src/edwards25519/`, `src/scalarmult_curve25519.rs`: primitive
  implementations and backend selection. An algorithm directory holds a
  `mod.rs` that selects the backend, plus one file per backend it has, named
  `<algo>_soft.rs` (portable Rust), `<algo>_simd.rs` (nightly portable SIMD),
  `<algo>_neon.rs` (runtime-detected AArch64 NEON/SVE2 intrinsics),
  `<algo>_x86_64.rs` (runtime-detected AVX2/AVX-512 intrinsics), or
  `<algo>_aarch64.rs` (AArch64 `asm!` blocks: base integer instructions or
  the runtime-detected `sha2`/`sha3` extensions).
- `BENCHMARKS.md` and `benchmarks/`: libsodium comparison results per machine
  (`results-<arch>.dat`) and the gnuplot script that renders the charts.
- `tests/integration_tests.rs`: public behavior and feature integration.
- `fuzz/`: cargo-fuzz target workspace.

## Dependency Policy

- Avoid adding dependencies unless they replace a substantial local maintenance
  burden or are standard, audited choices in Rust cryptography.
- Dependency changes should be justified in the PR description and tested across
  the relevant feature matrix.
- Keep optional dependencies feature-gated when they only support optional APIs.

## Documentation

- Public API changes need rustdoc updates in the affected module.
- Keep Classic API docs aligned with the corresponding libsodium concept.
- README changes should reflect only user-visible behavior, feature flags, or
  support status.
