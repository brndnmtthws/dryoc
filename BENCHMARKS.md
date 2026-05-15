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
export RUSTFLAGS="-Ctarget-cpu=native"

bench_pair() {
    cargo +nightly bench --features nightly "$1"
    cargo +nightly bench --features simd_backend,nightly "$1"
}

bench_pair blake2b_bench
bench_pair poly1305
bench_pair crypto_secretbox_detached
bench_pair argon2id_64kib_bench
bench_pair argon2id_1mib_bench
```

On Apple Silicon, `target-cpu=native` already enables NEON for this target.
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
| 64 B | `281.52 ns/iter` | `227 MB/s` | `327.97 ns/iter` | `195 MB/s` | `1.17x slower` |
| 1 KiB | `1,607.85 ns/iter` | `637 MB/s` | `1,516.26 ns/iter` | `675 MB/s` | `1.06x faster` |
| 16 KiB | `22,886.41 ns/iter` | `715 MB/s` | `18,726.82 ns/iter` | `874 MB/s` | `1.22x faster` |
| 1 MiB | `1,433,748.95 ns/iter` | `731 MB/s` | `1,175,895.90 ns/iter` | `891 MB/s` | `1.22x faster` |

The SIMD build uses portable SIMD for both Salsa20 and Poly1305. Larger
messages benefit from the Salsa20 path processing four independent counter
blocks in parallel. Small messages are slower in this run because fixed XSalsa20
setup plus Poly1305 SIMD overhead dominates the short payload.

## Password Hashing: Argon2id

Benchmark: `argon2_hash` with a fixed 32-byte password, 16-byte salt, 32-byte
output, `t=2`, and `p=1`.

| Memory cost | Software time | Software throughput | SIMD time | SIMD throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | `74,998.33 ns/iter` | `1,747 MB/s` | `48,813.80 ns/iter` | `2,685 MB/s` | `1.54x faster` |
| 1 MiB | `813,129.10 ns/iter` | `2,579 MB/s` | `587,006.25 ns/iter` | `3,572 MB/s` | `1.39x faster` |

The portable SIMD Argon2 path vectorizes the four independent BlaMka G
operations inside each block-mixing round. The surrounding memory indexing and
lane scheduling remain shared with the software path.

## Benchmark Coverage

Current side-by-side software/SIMD benchmark coverage:

| Algorithm | Software implementation | SIMD implementation | Benchmarked |
| --- | --- | --- | --- |
| BLAKE2b | `blake2b_soft` | `blake2b_simd` | Yes |
| Poly1305 | `poly1305_soft` | `poly1305_simd` | Yes |
| XSalsa20-Poly1305 secretbox | RustCrypto `salsa20` + `poly1305_soft` | portable-SIMD Salsa20 + `poly1305_simd` | Yes |
| Argon2id password hashing | scalar Argon2 block mixer | portable-SIMD Argon2 block mixer | Yes |

Algorithms without side-by-side benchmark coverage should get their own section
when a second implementation is added or when performance work begins.
