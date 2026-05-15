# Benchmarks

This page collects `dryoc` benchmark results by algorithm and implementation.
Results are meant to show relative performance for the same API surface on the
same machine; they are not portable guarantees.

## Environment

These results were collected on:

| Item | Value |
| --- | --- |
| Machine | MacBook M3 Max |
| Architecture | `aarch64-apple-darwin` |
| OS | Darwin `25.5.0` |
| Rust | `rustc 1.97.0-nightly (ff9a9ea07 2026-05-13)` |
| Cargo | `cargo 1.97.0-nightly (a343accce 2026-05-08)` |
| Target CPU | `native` (`apple-m3`) |

Commands used for the rows below:

```sh
RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+neon" cargo +nightly bench --features nightly blake2b_bench
RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+neon" cargo +nightly bench --features simd_backend,nightly blake2b_bench
RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly bench --features nightly poly1305
RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly bench --features simd_backend,nightly poly1305
RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+neon" cargo +nightly bench --features nightly crypto_secretbox_detached
RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+neon" cargo +nightly bench --features simd_backend,nightly crypto_secretbox_detached
```

`neon` is already reported by `rustc +nightly --print cfg` on this target.
Some commands include it explicitly along with `target-cpu=native`; adding
`-Ctarget-feature=+neon` is not expected to change native Apple Silicon
results.
Run `cargo +nightly bench` without a benchmark-name filter to collect the full
suite.

## Generic Hashing: BLAKE2b

Benchmark: hash a 694,200-byte buffer and produce a 64-byte output.

| Implementation | Feature set | Time | Relative |
| --- | --- | ---: | ---: |
| Software | `nightly` | `781,221.36 ns/iter` | `1.00x` |
| Portable SIMD | `simd_backend,nightly` | `592,678.12 ns/iter` | `1.32x faster` |

The portable SIMD backend is about 31.8% faster than the software backend for
this workload on this machine.

## One-Time Authentication: Poly1305

Benchmark: authenticate fixed-size messages with Poly1305. The scalar rows come
from the scalar/default build, and the SIMD rows come from the
`simd_backend,nightly` build.

| Message size | Software time | Software throughput | SIMD time | SIMD throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `26.81 ns/iter` | `2461 MB/s` | `52.38 ns/iter` | `1230 MB/s` | `1.95x slower` |
| 1 KiB | `384.91 ns/iter` | `2666 MB/s` | `399.52 ns/iter` | `2566 MB/s` | `1.04x slower` |
| 16 KiB | `5,980.91 ns/iter` | `2739 MB/s` | `5,906.60 ns/iter` | `2774 MB/s` | `1.01x faster` |
| 1 MiB | `385,375.05 ns/iter` | `2720 MB/s` | `376,518.75 ns/iter` | `2784 MB/s` | `1.02x faster` |

The portable SIMD backend uses a 4-way decimated Horner evaluation with 5x26-bit
limbs. On this Apple Silicon target it is close to scalar for large messages,
but the large-input edge is small enough to treat as benchmark noise rather than
a reliable production speedup. It remains intentionally opt-in.

External libsodium baseline from the scalar/default run:

| Message size | dryoc software time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `26.81 ns/iter` | `2461 MB/s` | `29.21 ns/iter` | `2206 MB/s` | `1.09x slower` |
| 1 KiB | `384.91 ns/iter` | `2666 MB/s` | `361.69 ns/iter` | `2836 MB/s` | `1.06x faster` |
| 16 KiB | `5,980.91 ns/iter` | `2739 MB/s` | `5,735.08 ns/iter` | `2856 MB/s` | `1.04x faster` |
| 1 MiB | `385,375.05 ns/iter` | `2720 MB/s` | `366,554.15 ns/iter` | `2860 MB/s` | `1.05x faster` |

The useful portable SIMD shape is narrower than it first appears:

- The direct RFC formulation is serial:
  `a = (r * (a + block)) % p` for every 16-byte block. SIMD implementations
  have to rewrite this as decimated Horner streams and fold those streams back
  together.
- Fast target-specific implementations use a 5x26-bit representation, precompute
  key powers such as `r^2` and `r^4`, and process multiple blocks per
  iteration.
- On AArch64, Rust portable SIMD cannot express the widening
  multiply-accumulate shape exposed by target-specific NEON intrinsics such as
  `vmull_u32`, `vmlal_u32`, and `vmlal_high_u32`.

References: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439),
[Improved SIMD Implementation of Poly1305, ePrint 2019/842](https://eprint.iacr.org/2019/842.pdf),
and [BoringSSL's Poly1305 NEON source](https://boringssl.googlesource.com/boringssl/+/8e5174b1186e/crypto/poly1305/poly1305_arm.cc).

## Secretbox: XSalsa20-Poly1305

Benchmark: `crypto_secretbox_detached` encrypts a fixed-size message into a
preallocated ciphertext buffer and computes the Poly1305 tag. This measures the
combined XSalsa20 stream and Poly1305 authentication path used by secretbox.

| Message size | Software time | Software throughput | SIMD time | SIMD throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `282.73 ns/iter` | `226 MB/s` | `327.27 ns/iter` | `195 MB/s` | `1.16x slower` |
| 1 KiB | `1,619.71 ns/iter` | `632 MB/s` | `1,505.93 ns/iter` | `680 MB/s` | `1.08x faster` |
| 16 KiB | `22,647.52 ns/iter` | `723 MB/s` | `18,721.46 ns/iter` | `875 MB/s` | `1.21x faster` |
| 1 MiB | `1,466,233.40 ns/iter` | `715 MB/s` | `1,183,574.90 ns/iter` | `885 MB/s` | `1.24x faster` |

The SIMD build uses portable SIMD for both Salsa20 and Poly1305. Larger
messages benefit from the Salsa20 path processing four independent counter
blocks in parallel. Small messages are slower in this run because fixed XSalsa20
setup plus Poly1305 SIMD overhead dominates the short payload.

## Benchmark Coverage

Current side-by-side software/SIMD benchmark coverage:

| Algorithm | Software implementation | SIMD implementation | Benchmarked |
| --- | --- | --- | --- |
| BLAKE2b | `blake2b_soft` | `blake2b_simd` | Yes |
| Poly1305 | `poly1305_soft` | `poly1305_simd` | Yes |
| XSalsa20-Poly1305 secretbox | RustCrypto `salsa20` + `poly1305_soft` | portable-SIMD Salsa20 + `poly1305_simd` | Yes |

Algorithms without side-by-side benchmark coverage should get their own section
when a second implementation is added or when performance work begins.
