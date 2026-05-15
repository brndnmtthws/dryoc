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
RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+neon" cargo +nightly bench --features nightly crypto_secretbox_detached
RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+neon" cargo +nightly bench --features simd_backend,nightly crypto_secretbox_detached
```

`neon` is already reported by `rustc +nightly --print cfg` on this target, but
the benchmark commands include it explicitly along with `target-cpu=native`.
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

## Secretbox: XSalsa20-Poly1305

Benchmark: `crypto_secretbox_detached` encrypts a fixed-size message into a
preallocated ciphertext buffer and computes the Poly1305 tag. This measures the
combined XSalsa20 stream and Poly1305 authentication path used by secretbox.

| Message size | Software time | Software throughput | SIMD time | SIMD throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `287.06 ns/iter` | `222 MB/s` | `300.90 ns/iter` | `213 MB/s` | `0.95x` |
| 1 KiB | `1,621.30 ns/iter` | `631 MB/s` | `1,491.99 ns/iter` | `686 MB/s` | `1.09x faster` |
| 16 KiB | `22,893.99 ns/iter` | `715 MB/s` | `18,996.15 ns/iter` | `862 MB/s` | `1.21x faster` |
| 1 MiB | `1,447,766.70 ns/iter` | `724 MB/s` | `1,200,971.88 ns/iter` | `873 MB/s` | `1.21x faster` |

The portable SIMD Salsa20 path helps larger messages by processing four
independent Salsa20 counter blocks in parallel. Very small messages mostly
measure fixed XSalsa20 setup plus Poly1305 overhead, so the 64-byte case can be
slightly slower while the SIMD advantage grows with payload size.

## Benchmark Coverage

Current side-by-side software/SIMD benchmark coverage:

| Algorithm | Software implementation | SIMD implementation | Benchmarked |
| --- | --- | --- | --- |
| BLAKE2b | `blake2b_soft` | `blake2b_simd` | Yes |
| XSalsa20-Poly1305 secretbox | RustCrypto `salsa20` + `poly1305_soft` | portable-SIMD Salsa20 + `poly1305_soft` | Yes |

Algorithms without side-by-side benchmark coverage should get their own section
when a second implementation is added or when performance work begins.
