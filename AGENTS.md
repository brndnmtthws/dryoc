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
- The crate is `#![no_std]`. Default features are `base64`, `protected`,
  `serde`, and `std`: defaults cover what most users want, and opt-in
  features are limited to pre-1.0 dependencies (`wincode_*`), nightly-only
  code, and `no_std` builds.
- Core features:
  - `std`: implies `alloc`; runtime CPU feature detection and `Error::Io`.
    Without it, `has_x86_feature!`/`has_aarch64_feature!` (in `src/lib.rs`)
    fall back to compile-time `cfg!(target_feature = ...)`; only the feature
    tokens' constructors call them, never `std::arch::is_*_feature_detected!`
    directly.
  - `alloc`: every API that allocates (`Vec<u8>` byte-trait impls, `Vec*`
    aliases, `*_to_vec`/`*_to_vecbox`, `randombytes_buf`, password hashing).
    Gate such items with `#[cfg(feature = "alloc")]` and import
    `alloc::vec::Vec`/`alloc::string::String` explicitly; APIs over arrays and
    caller-provided slices must build with no features.
  - Unit tests may use `std`; import the `Vec`/`String` prelude items with
    `use crate::test_prelude::*;` and gate tests that call `alloc` APIs.
- Optional features:
  - `serde`: serialization support for supported types; enabled by default.
  - `base64`: password-hash string helpers; implies `alloc`, enabled by
    default, and does not add a dependency.
  - `wincode_0_6`: direct binary serialization support for Rustaceous box
    types with wincode 0.6; implies `alloc`. wincode is pre-1.0 and public
    API, so each supported wincode version gets its own
    `wincode_<major>_<minor>` feature; add new versions alongside, never rename
    or repoint an existing one.
  - `protected`: protected memory APIs on Unix/Windows; implies `std`, enabled
    by default, and does not add a dependency beyond target OS bindings already
    used by the crate.
  - `nightly`: extra doc cfg support, portable SIMD for `simd_backend`, and
    the `Allocator` implementation for protected memory (with `protected`);
    it does not imply `protected` or `std`, so `simd_backend,nightly` works
    in `no_std`. Requires `nightly-2026-09-24` or later (the allocator API is
    ungated there).
  - `simd_backend`: SIMD-backed internals; in CI this is used with `nightly`.
- Do not commit a `Cargo.lock` for routine library changes unless the project
  policy changes. The one exception is `python/Cargo.lock`, which is committed
  because it pins the dependencies of the shipped binary wheels
  (`python/.gitignore` un-ignores it).

## Common Commands

Use focused commands while developing, then broaden coverage before handing off:

```sh
cargo check
cargo check --no-default-features
cargo check --no-default-features --features alloc
RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build --target thumbv7em-none-eabihf --no-default-features --features alloc
cargo test
cargo test --no-default-features
cargo test --no-default-features --features std
cargo test --no-default-features --features std,serde
cargo test --features base64
cargo test --features wincode_0_6
cargo +nightly test --features nightly
cargo +nightly test --features simd_backend,nightly
cargo clippy --features default -- -D warnings
cargo +nightly fmt --all -- --check
```

CI uses `cargo nextest` when available:

```sh
cargo nextest run --features default
cargo nextest run --no-default-features
cargo nextest run --no-default-features --features alloc
cargo nextest run --no-default-features --features std,serde
cargo nextest run --features base64
cargo nextest run --features wincode_0_6
cargo +nightly nextest run --features simd_backend,nightly
```

The wasm tests run through `wasm-bindgen-test-runner` (from the
`wasm-bindgen-cli` version matching the `wasm-bindgen` in `cargo tree`), once
without and once with the `simd128` kernels. Use `cargo test --tests`, not
nextest: nextest starts one runner (a wasm-bindgen pass plus Node) per test.
`--tests` skips doctests, which are not run on wasm. CI also sets
`CARGO_PROFILE_TEST_OPT_LEVEL=1` and `CARGO_PROFILE_TEST_DEBUG=0` for these
runs (debug assertions and overflow checks stay on):

```sh
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export CARGO_PROFILE_TEST_OPT_LEVEL=1 CARGO_PROFILE_TEST_DEBUG=0
cargo test --target wasm32-unknown-unknown --tests --no-default-features --features std,serde,base64,wincode_0_6
RUSTFLAGS=-Ctarget-feature=+simd128 cargo test --target wasm32-unknown-unknown --tests --no-default-features --features std,serde,base64,wincode_0_6
```

Coverage is generated on nightly with:

```sh
cargo +nightly tarpaulin --features serde,nightly,wincode_0_6 --out Xml
```

Fuzzing lives in `fuzz/` and is isolated as its own workspace:

```sh
cargo fuzz run fuzz-hashes
```

The Python bindings live in `python/`, also an isolated workspace. Run these
from `python/` (CI runs the same checks against the built wheel):

```sh
uv sync                  # .venv with the dev group; builds the extension (release)
uv run pytest
uv run python -m mypy.stubtest dryoc
uv run mypy --strict python/dryoc tests
uv run pyright --verifytypes dryoc --ignoreexternal
cargo clippy --locked --all-targets -- -D warnings
cargo +nightly fmt --check
uv run maturin build --release --locked --out dist    # abi3 wheel, CPython >= 3.11
uv run maturin sdist --out dist
```

`uv sync` and `uv run` rebuild the extension whenever a file listed in
`[tool.uv] cache-keys` in `python/pyproject.toml` changes (the Rust sources of
both crates and the manifests); add new build inputs there. `python/uv.lock`
is committed and CI installs with `uv sync --locked`, so any change to
`[dependency-groups]` or `requires-python` needs `uv lock` and the updated
lockfile in the same change.

`python/Cargo.toml`'s `version` must equal the root crate's `version`: the
wheel takes its version from it, and `publish.yml` refuses a release tag when
the two differ. Bump both together.

`python/Cargo.lock` records the root crate's version and its whole dependency
graph, and every Python build is locked (`--locked` on the command line,
`[tool.maturin] locked = true` for `uv sync`, `uv run` and sdist builds).
Any change to the root version or root dependencies therefore requires
`cargo update -p dryoc --manifest-path python/Cargo.toml` and committing the
updated `python/Cargo.lock` in the same change. `publish.yml` checks this with
`cargo metadata --locked --manifest-path python/Cargo.toml` before anything
is published.

Releases are cut with `./release.py` (a stdlib-only `uv run --script`).
First merge a bump PR that sets both `Cargo.toml` versions, runs
`cargo update -p dryoc --manifest-path python/Cargo.toml` and `uv lock` (in
`python/`), and commits both lockfiles. Then, on an up-to-date `main`, run
`./release.py --dry-run` and `./release.py`. It checks that `git`, `cargo`,
`uv` and `gh` are installed; that `main` is clean and equal to `origin/main`;
that both manifests carry the release version, which must be SemVer, newer
than every crates.io version, and a prerelease only as `-alpha.N`, `-beta.N`
or `-rc.N` (maturin maps these to PEP 440 `aN`/`bN`/`rcN`); that both
lockfiles are fresh; that the `vX.Y.Z` tag exists neither locally nor on
`origin`; that the version is on neither crates.io nor PyPI; and that
Build & test passed on `HEAD`. It then asks before creating and pushing the
annotated tag, which starts `publish.yml`.

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
- Native compatibility tests run in parallel threads, and libsodium's lazy
  RNG setup and `sodium_init`'s dispatch selection are unsynchronized
  globals. Prefer the `src/native_test_util.rs` wrappers, which call
  `native_test_util::init()`; any test that calls `libsodium_sys` (or a
  libsodium symbol declared in `extern "C"`) directly must call it first.
- Python tests (`python/tests/`) use PyNaCl as a test-only libsodium oracle.
  PyNaCl must never become a runtime dependency. The interop module skips
  itself with an explicit reason when PyNaCl is unavailable.

## Crypto-Specific Rules

- Do not introduce new algorithms, modes, nonce handling, key derivation rules,
  or wire formats without explicit design review.
- Preserve libsodium-compatible constants, buffer sizes, error behavior, and
  function semantics in `src/classic/`.
- Avoid data-dependent branches or memory access patterns in code that handles
  secrets.
- Use `subtle` or existing constant-time helpers for equality and selection.
- Ensure secret material is zeroized where existing types expect that behavior.
- Kernels (portable, SIMD, intrinsics, `asm!`) zeroize, once per call rather
  than per block, every working copy of key-, keystream-, or key-derived state
  whose address reaches memory in optimized code: storage passed by reference
  to a non-inlined function (`#[inline(never)]` loops, out-of-line helpers) or
  used as an `asm!` memory operand. Iterate secret `Copy` arrays by reference
  so no iterator-owned copy is made. Values that only flow through inlined
  helpers live in registers and spill slots, which Rust cannot reliably wipe;
  do not add wipes that force them into memory, and say so at the kernel.
- Treat nonce generation and reuse rules as part of the API contract; do not
  silently change them.
- Any new `unsafe` must be small, documented by surrounding invariants, and
  covered by tests. Prefer existing unsafe wrappers and allocation helpers.
- Detected `#[target_feature]` kernels are named `*_unchecked` and entered
  only through a safe `#[inline(always)]` wrapper beside them that takes the
  matching feature token (`src/x86_64.rs`, `src/aarch64.rs`) by value; that
  wrapper holds the kernel's one `unsafe` call. Tokens are only constructed
  by their detection functions (`new`, and the `avx512vl` refinements),
  which use `has_x86_feature!`/`has_aarch64_feature!`; dispatch enums hold
  them. Do not call those macros outside the token constructors. The
  WebAssembly `simd128` kernels are not detected: they are compiled only
  when the crate itself has the target feature, so they are ordinary safe
  functions without `#[target_feature]`, `*_unchecked` names or tokens.
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
- `src/aarch64.rs`: the AArch64 CPU feature tokens (`Neon`, `Sve2`, `Sha2`,
  `Sha3`); compiled for little-endian AArch64 targets, with `Neon` and
  `Sve2` also compiled out under Miri, like `neon.rs`.
- `src/neon.rs`: AArch64 NEON load/store/transpose/XOR helpers shared by the
  `*_neon.rs` kernels.
- `src/x86_64.rs`: the x86-64 CPU feature tokens (`Avx2`, `Avx512`,
  `Avx512Vl`, `Avx512Ifma`, `Bmi2`) and the AVX2/AVX-512
  load/store/transpose/XOR helpers shared by the `*_x86_64.rs` kernels.
- `src/wasm32.rs`: WebAssembly `simd128` load/store/transpose/XOR helpers
  shared by the `*_wasm32.rs` kernels. WebAssembly has no runtime feature
  detection, so these kernels are selected at compile time with
  `cfg(all(target_arch = "wasm32", target_feature = "simd128"))` (built with
  `RUSTFLAGS=-Ctarget-feature=+simd128`); other wasm builds use the portable
  code. Test both configurations (see the `wasm` CI job); the cross-backend
  test modules import `wasm_bindgen_test as test` on wasm so their `#[test]`
  functions run under `wasm-bindgen-test-runner`.
- `src/keccak/`: the Keccak sponge behind SHA-3 (`src/sha3.rs`) and the
  SHAKE/TurboSHAKE XOFs (`src/xof.rs`), and the multi-state `ParSponge`
  behind ML-KEM sampling; the permutation comes from the `keccak` crate,
  with a runtime-detected 4-way AVX2 kernel (`keccak_x86_64.rs`) for
  multi-state permutations. On AArch64 a single state runs the in-crate
  lazy-rotation scalar permutation (`keccak_soft.rs`), and with the SHA3
  extension a 2-way NEON kernel (`keccak_aarch64.rs`) and a 3-way kernel
  (`keccak3_aarch64.rs`, two NEON states beside one on the integer
  registers) run them; `keccak3_aarch64.rs` is generated by
  `keccak3_aarch64.py` (run it from the repository root after changing it,
  never edit the `.rs` by hand).
- `src/mlkem/`: ML-KEM-768 (FIPS 203) with runtime-selected polynomial
  arithmetic backends (`Arith`); `test-vectors/` holds the ML-KEM and X-Wing
  known answers. X-Wing is in `src/classic/crypto_kem_xwing.rs`; `src/kem.rs`
  is the Rustaceous API for both.
- `src/sha2_impl.rs`: the `sha2_hasher!` macro that generates the SHA-256 and
  SHA-512 hasher types; each `sha*/mod.rs` supplies its IV and `compress`.
- `src/classic/crypto_*_impl.rs`: shared bodies behind pairs of classic
  modules (HMAC, secretbox/box, ChaCha20-Poly1305 and XChaCha20-Poly1305).
- `src/classic/`: libsodium-compatible API modules.
- `src/blake2b/`, `src/poly1305/`, `src/argon2/`, `src/salsa20/`,
  `src/chacha20/`, `src/sha256/`, `src/sha512/`, `src/fe25519/`,
  `src/edwards25519/` (with the precomputed basepoint tables in
  `tables.rs`), `src/scalarmult_curve25519.rs`: primitive
  implementations and backend selection. An algorithm directory holds a
  `mod.rs` that selects the backend, plus one file per backend it has, named
  `<algo>_soft.rs` (portable Rust), `<algo>_simd.rs` (nightly portable SIMD),
  `<algo>_neon.rs` (runtime-detected AArch64 NEON/SVE2 intrinsics),
  `<algo>_x86_64.rs` (runtime-detected AVX2/AVX-512 intrinsics),
  `<algo>_wasm32.rs` (compile-time-selected WebAssembly `simd128`
  intrinsics), or `<algo>_aarch64.rs` (AArch64 `asm!` blocks: base integer
  instructions or the runtime-detected `sha2`/`sha3` extensions). Two
  AArch64 field files break the pattern: `fe25519/fe64_aarch64.rs` is a
  four-limb field (`Fe64`) for the X25519 ladder and the Edwards scalar
  multiplications, beside the five-limb `fe25519_aarch64.rs`, and
  `fe25519/safegcd.rs` is the constant-time Bernstein-Yang inversion used
  on AArch64.
- `BENCHMARKS.md` and `benchmarks/`: libsodium comparison results per machine
  (`results-<arch>.dat`) and the gnuplot script that renders the charts.
- `src/native_test_util.rs`: safe wrappers over the libsodium FFI calls
  (from the `libsodium-sys-stable` dev-dependency, currently libsodium
  1.0.22) shared by the `dryoc_native_tests` compatibility tests.
- `tests/integration_tests.rs`: public behavior and feature integration.
- `fuzz/`: cargo-fuzz target workspace.
- `python/`: PyPI package `dryoc`, built with PyO3 and maturin as one
  `abi3-py311` extension module (`dryoc._dryoc`). It is its own Cargo
  workspace (like `fuzz/`), so root `cargo package` and `cargo publish` never
  include it. `src/` holds the PyO3 code, `python/dryoc/` the pure-Python
  modules and `.pyi` stubs, and `tests/` the pytest suite, which reads the
  vectors in `src/mlkem/test-vectors/`. It uses only Rustaceous APIs (plus
  Classic functions internally where the Rustaceous API has no runtime-sized
  equivalent) and must stay free of `unsafe`. Rules:
  - Every pyclass is `frozen`. Mutable state (hashers, MACs, streams,
    `Ed25519ph`) goes behind `util::Locked`, which serializes calls without
    deadlocking with the GIL.
  - Inputs are extracted through `util::Buf`: `bytes` is borrowed, every other
    buffer is copied while attached into a zeroizing vector before use, in one
    copy. An exact `bytearray` is copied with `PyByteArray::to_vec`, which
    holds its critical section: it is a mutable exporter that other threads
    can write to while exported on free-threaded builds, and its methods write
    under that lock, so the copy cannot be torn (subclasses may override
    `__buffer__`, so they are not special-cased). Other buffers are copied
    through `PyBuffer<u8>` (byte formats at any strides; other formats once
    `memoryview.cast('B')` makes them bytes, which needs a C-contiguous
    buffer) without a lock; concurrent mutation of those (a `memoryview` of a
    `bytearray`, `array.array`, numpy) is the caller's race, as with `hashlib`.
    The one exception is a non-C-contiguous buffer of a non-byte format
    (`memoryview(array.array('I'))[::2]`), which goes through a `bytearray`
    temporary that is wiped afterwards: PyO3 0.29 has no safe C-order copy of
    an untyped buffer, and the bindings stay free of `unsafe`. Anything passed
    into `py.detach` (or `util::maybe_detach`) must be `bytes` or such a copy,
    never a view of a mutable Python buffer.
  - Secret classes keep constant-time `__eq__`, `__hash__ = None` and a
    redacted repr (`util::secret_key_class!` for single-key classes; hand-written
    classes such as key pairs and `kx.SessionKeys` do the same).
  - The module declares `gil_used = false`. Keep that valid: no global mutable
    state other than `PyOnceLock` caches.

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
