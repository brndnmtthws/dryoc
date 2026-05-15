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
- Rust 2024 reserves `gen` as a keyword. Existing generation APIs retain their
  public name through raw identifier syntax; define and call them as `r#gen`
  (for example, `Key::r#gen()`).
- Default features are `u64_backend`.
- Optional features:
  - `serde`: serialization support for supported types.
  - `base64`: password-hash string helpers.
  - `wincode`: direct binary serialization support for Rustaceous box types.
  - `nightly`: protected memory APIs and extra doc cfg support.
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
cargo fuzz run fuzz_target_1
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
- For protected memory changes, test with `+nightly --features nightly` and be
  mindful of platform-specific Unix/Windows behavior.

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
- `src/protected.rs`: nightly-only protected memory allocator and locked bytes.
- `src/classic/`: libsodium-compatible API modules.
- `src/blake2b/`, `src/poly1305/`, `src/argon2.rs`,
  `src/scalarmult_curve25519.rs`: primitive implementations and backend
  selection.
- `src/classic/salsa20_simd.rs`: nightly-only portable SIMD Salsa20 backend
  used internally by `crypto_secretbox` when `simd_backend` is enabled.
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
