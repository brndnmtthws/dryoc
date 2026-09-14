# Benchmarks

This page collects `dryoc` benchmark results by algorithm and implementation,
measured against libsodium on the same machine, in the same process, on the
same buffers. Results were collected on two machines, an Intel Xeon 6975P-C
(Granite Rapids) with AVX-512 and AVX-512 IFMA and an Arm Neoverse V3 with
NEON, SVE2 and the SHA-2/SHA-3 extensions; see [Environment](#environment) for
the full setup. Results show relative performance for the same API surface on
those CPUs; they are not portable guarantees.

## Headline

On the Xeon 6975P-C, dryoc's runtime-detected AVX2/AVX-512 kernels beat
libsodium 1.0.18 on every workload with `-Ctarget-cpu=native`, and on all but
the memory-bound Argon2id 1 MiB row with no build flags at all:

| Workload | dryoc | libsodium | dryoc vs libsodium |
| --- | ---: | ---: | ---: |
| Poly1305, 1 MiB | `18,624 MB/s` | `3,181 MB/s` | `5.85x faster` |
| Poly1305, 16 KiB | `17,411 MB/s` | `3,111 MB/s` | `5.59x faster` |
| XSalsa20-Poly1305 secretbox, 1 MiB | `4,502 MB/s` | `1,465 MB/s` | `3.07x faster` |
| XSalsa20-Poly1305 secretbox, 1 KiB | `2,432 MB/s` | `768 MB/s` | `3.16x faster` |
| Argon2id, `t=2 m=64 KiB` | `4,281 MB/s` | `3,644 MB/s` | `1.17x faster` |
| Argon2id, `t=2 m=1 MiB` | `6,442 MB/s` | `5,855 MB/s` | `1.10x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `486,813 ns` | `627,232 ns` | `1.29x faster` |
| BLAKE2b, 694,200 B (default) | `527,130 ns` | `629,177 ns` | `1.19x faster` |

On the Neoverse V3 (rows below: `-Ctarget-cpu=native`, pinned to one core,
median of three runs), dryoc's NEON Poly1305 bulk path, SVE2 Salsa20 kernel
and `asm!` BLAKE2b rounds are ahead of libsodium 1.0.18 on every
default-backend row of 1 KiB and above; the separate no-flags table shows the
same ordering. The 64-byte rows are within measurement noise of libsodium,
and only the opt-in portable-SIMD backends are slower than it:

| Workload | dryoc | libsodium | dryoc vs libsodium |
| --- | ---: | ---: | ---: |
| Poly1305, 1 MiB | `6,480 MB/s` | `1,975 MB/s` | `3.28x faster` |
| Poly1305, 16 KiB | `6,211 MB/s` | `1,976 MB/s` | `3.14x faster` |
| XSalsa20-Poly1305 secretbox, 1 MiB | `1,910 MB/s` | `673 MB/s` | `2.84x faster` |
| XSalsa20-Poly1305 secretbox, 1 KiB | `1,262 MB/s` | `620 MB/s` | `2.04x faster` |
| Argon2id, `t=2 m=64 KiB` | `2,462 MB/s` | `2,067 MB/s` | `1.19x faster` |
| Argon2id, `t=2 m=1 MiB` | `2,816 MB/s` | `2,537 MB/s` | `1.11x faster` |
| BLAKE2b, 694,200 B (default) | `417,185 ns` | `595,169 ns` | `1.43x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `792,149 ns` | `593,916 ns` | `1.33x slower` |

![dryoc speedup over libsodium by workload on both machines](benchmarks/speedup.svg)

![Single-thread throughput on the Xeon, log scale](benchmarks/throughput-x86_64.svg)

![Single-thread throughput on the Neoverse V3, log scale](benchmarks/throughput-aarch64.svg)

On the Xeon, the Poly1305, Salsa20, Argon2 and BLAKE2b kernels are selected
at runtime by CPU feature detection; on the Neoverse V3 the Poly1305 bulk
path and the Salsa20 kernel are, while the BLAKE2b `asm!` rounds are selected
at compile time by target architecture and Argon2 has no AArch64 kernel. The
runtime-selected kernels do not require `-Ctarget-cpu=native` to be used;
what the flag changes on each machine is measured in
[Without `target-cpu=native`](#without-target-cpunative). Only the BLAKE2b
portable-SIMD rows need the `simd_backend,nightly` build; on the Xeon that
row also needs `target-cpu=native` to come out ahead. On the Neoverse V3 the
Argon2id rows are faster *without* `target-cpu=native` (`1.55x` and `1.51x`
over libsodium); the native rows are kept in the tables and charts above for
consistency with the Xeon, not as the crates.io default result. See
[Password Hashing: Argon2id](#password-hashing-argon2id).

## Environment

These results were collected on:

| Item | Intel Xeon 6975P-C | Arm Neoverse V3 |
| --- | --- | --- |
| Machine | Cloud VM, 32 vCPUs | Cloud VM, 192 vCPUs |
| CPU | Intel Xeon 6975P-C (Granite Rapids; AVX2, AVX-512F/VL, AVX-512 IFMA) | Arm Neoverse V3 r0p1 (NEON, SVE/SVE2, `sha2`, `sha3`, `sha512`) |
| Architecture | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| OS | Debian 13, Linux `6.12.74+deb13+1-cloud-amd64` | Debian 13, Linux `6.12.107+deb13-cloud-arm64` |
| Rust | `rustc 1.100.0-nightly (809936eac 2026-09-12)` | `rustc 1.100.0-nightly (0fc141305 2026-09-11)` |
| Cargo | `cargo 1.100.0-nightly (7941be6fb 2026-09-11)` | `cargo 1.100.0-nightly (3c0b53475 2026-09-04)` |
| Target CPU | `native` unless stated otherwise | `native` unless stated otherwise |
| libsodium | `1.0.18`, statically linked from the `libsodium-sys 0.2.7` bundled source | same |
| Sampling | one run per configuration | pinned to one core with `taskset -c 7`, median of three runs |

Commands used for the rows below:

```sh
export RUSTFLAGS="-Ctarget-cpu=native"

# Software backends, plus the libsodium baseline rows.
cargo +nightly bench --features nightly

# Portable-SIMD backends (BLAKE2b, and Argon2 block mixing on AArch64; on
# x86-64 the runtime-detected Argon2 kernel is used either way).
cargo +nightly bench --features simd_backend,nightly
```

On the Neoverse V3 the same commands were run under `taskset -c 7` three
times each, after the machine was otherwise idle, and the median `ns/iter` is
reported. Across the 102 rows measured, the run-to-run spread (max minus min
over the median) was below 1% on 95 rows and below 1.7% on all but one; the
noisiest row was the libsodium Argon2id 64 KiB baseline in the native build,
63,091–64,910 ns around a 63,410 ns median (2.9%). Ratios in the tables
that round to `1.00x`–`1.04x` are within that noise.

The charts are rendered from
[`benchmarks/results-x86_64.dat`](benchmarks/results-x86_64.dat) and
[`benchmarks/results-aarch64.dat`](benchmarks/results-aarch64.dat) (the
`ns/iter` figures from the tables) by
[`benchmarks/charts.gp`](benchmarks/charts.gp); regenerate them with
`gnuplot -c benchmarks/charts.gp` after updating a data file.

Each `*_bench` has a `libsodium_*_bench` (or `sodiumoxide_*_bench`) twin in
the same test module that runs the corresponding libsodium function on the
same input sizes after `sodium_init()`, so libsodium uses its own
runtime-selected implementation. `RUSTFLAGS` does not affect the C library;
its numbers were identical within noise across every build below.

Kernels selected at runtime on each CPU:

| Algorithm | dryoc kernel, Xeon 6975P-C | libsodium, Xeon | dryoc kernel, Neoverse V3 | libsodium, Neoverse V3 |
| --- | --- | --- | --- | --- |
| Poly1305 | AVX-512 IFMA, 3x44-bit limbs, two chains for long runs (`poly1305_x86_64`) | `sse2` (Poly1305-donna) | NEON 5x26-bit lanes plus two scalar 3x44-bit lanes, ten blocks per iteration (`poly1305_neon`) | `donna` (64-bit, 3x44-bit limbs) |
| Salsa20 (secretbox) | AVX-512F/VL 16-block lane set (`salsa20_x86_64`) | `xmm6int` AVX2 | SVE2 `xar` 4-block vector set plus one scalar block in the same `asm!` block (`salsa20_neon`) | `ref` (scalar) |
| Argon2 block mixing | AVX-512F (`argon2_x86_64`) | `avx512f` | portable scalar `argon2_soft` (no AArch64 kernel), or portable SIMD with `simd_backend,nightly` | `ref` (scalar) |
| BLAKE2b | AVX-512VL `vprorq` rotations on a 256-bit lane set (`blake2b_x86_64`), or portable SIMD with `simd_backend,nightly` | `avx2` | scalar `asm!` rounds (`blake2b_aarch64`), or portable SIMD with `simd_backend,nightly` | `ref` (scalar) |

libsodium 1.0.18 has no NEON code for any of these four algorithms, so on the
Neoverse V3 every libsodium row is its portable C implementation. This was
checked against the linked artifact, not just the source: `nm` on the
AArch64 bench binary lists only `crypto_onetimeauth_poly1305_donna_*`,
`crypto_stream_salsa20_ref_implementation`, `argon2_fill_segment_ref` and
`blake2b_compress_ref` behind the `*_pick_best_implementation` selectors;
that binary contains no other variant of these four algorithms.

## One-Time Authentication: Poly1305

Benchmark: authenticate fixed-size messages with Poly1305 (`Poly1305::new`,
`update`, `finalize_to_array`). The libsodium rows call
`crypto_onetimeauth_poly1305` through `sodiumoxide`.

### Intel Xeon 6975P-C

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `35.24 ns/iter` | `1,828 MB/s` | `54.97 ns/iter` | `1,185 MB/s` | `1.56x faster` |
| 1 KiB | `115.52 ns/iter` | `8,904 MB/s` | `356.93 ns/iter` | `2,876 MB/s` | `3.09x faster` |
| 16 KiB | `941.39 ns/iter` | `17,411 MB/s` | `5,265.10 ns/iter` | `3,111 MB/s` | `5.59x faster` |
| 1 MiB | `56,300.84 ns/iter` | `18,624 MB/s` | `329,632.25 ns/iter` | `3,181 MB/s` | `5.85x faster` |

The scalar backend keeps the accumulator in three 44-bit limbs and hands runs
of full blocks to a runtime-detected bulk path: AVX2 or AVX-512F lanes in
5x26-bit limbs, or, on CPUs with `avx512ifma`, 3x44-bit lanes multiplied
with `vpmadd52luq`/`vpmadd52huq`. Each bulk kernel processes a chunk of
consecutive blocks as independent Horner lanes and folds them with one power
of `r` per block, so the result is bit-identical to the serial evaluation.
Every iteration executes the same instructions regardless of data. libsodium
1.0.18 has no AVX2 or AVX-512 Poly1305 and tops out at its SSE2 donna path.

The 64-byte row has no bulk path on either side (the IFMA path needs at
least 256 bytes); the gap there is the scalar `u128` 3-limb multiply against
the 32-bit limbs of the `sse2` implementation libsodium selects on x86-64.
(Its 64-bit `donna` implementation, selected on AArch64, uses the same
44/44/42-bit `u128` limbs as dryoc; see the Neoverse V3 row below.)

### Arm Neoverse V3

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `39.85 ns/iter` | `1,606 MB/s` | `40.57 ns/iter` | `1,578 MB/s` | `1.02x faster` |
| 1 KiB | `270.70 ns/iter` | `3,783 MB/s` | `529.52 ns/iter` | `1,934 MB/s` | `1.96x faster` |
| 16 KiB | `2,637.90 ns/iter` | `6,211 MB/s` | `8,291.94 ns/iter` | `1,976 MB/s` | `3.14x faster` |
| 1 MiB | `161,823.55 ns/iter` | `6,480 MB/s` | `531,023.10 ns/iter` | `1,975 MB/s` | `3.28x faster` |

On AArch64 the same scalar backend hands messages of at least 480 bytes to
the NEON bulk path, which processes ten blocks per iteration: eight in NEON
as two chains of four 5x26-bit lanes (`vmlal_u32` widening multiplies), and
two more in scalar 3x44-bit lanes on the otherwise idle integer multipliers,
because the NEON part is bound by the two vector pipes that execute widening
multiplies. The 64-byte row is scalar on both sides and comes out even:
libsodium's 64-bit donna uses the same 3x44-bit `u128` limb multiplication as
dryoc's scalar backend.

The portable-SIMD Poly1305 backend (`poly1305_simd`) is compiled only for
tests on x86-64 and AArch64 because it is slower than the target-specific
kernels. For reference, with `simd_backend,nightly` and `target-cpu=native`
it measured `82.52 ns/iter` (64 B), `946.25 ns/iter` (1 KiB),
`14,638.02 ns/iter` (16 KiB) and `936,144.30 ns/iter` (1 MiB), about
`1,120 MB/s`, on the Xeon, and `76.22`, `458.40`, `6,622.47` and
`413,112.10 ns/iter`, about `2,538 MB/s`, on the Neoverse V3: ahead of
libsodium's scalar code there but 2.6x behind the NEON kernel. Rust portable
SIMD cannot express the widening multiply-accumulate shapes (`vpmuludq`,
`vpmadd52luq`, `vmlal_u32`) that make the target-specific kernels fast.

References: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439),
[Improved SIMD Implementation of Poly1305, ePrint 2019/842](https://eprint.iacr.org/2019/842.pdf),
and [BoringSSL's Poly1305 NEON source](https://boringssl.googlesource.com/boringssl/+/8e5174b1186e/crypto/poly1305/poly1305_arm.cc).

## Secretbox: XSalsa20-Poly1305

Benchmark: `crypto_secretbox_detached` encrypts a fixed-size message into a
preallocated ciphertext buffer and computes the Poly1305 tag. This measures the
combined XSalsa20 stream and Poly1305 authentication path used by secretbox
and `crypto_box`. The libsodium rows call `crypto_secretbox_detached` with the
same buffers.

### Intel Xeon 6975P-C

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `279.44 ns/iter` | `229 MB/s` | `376.71 ns/iter` | `170 MB/s` | `1.35x faster` |
| 1 KiB | `421.82 ns/iter` | `2,432 MB/s` | `1,332.88 ns/iter` | `768 MB/s` | `3.16x faster` |
| 16 KiB | `3,776.17 ns/iter` | `4,338 MB/s` | `11,833.44 ns/iter` | `1,384 MB/s` | `3.13x faster` |
| 1 MiB | `232,893.15 ns/iter` | `4,502 MB/s` | `715,590.00 ns/iter` | `1,465 MB/s` | `3.07x faster` |

The XSalsa20 keystream comes from a runtime-detected lane-set kernel: eight
blocks per `ymm` lane set under AVX2, sixteen per `zmm` lane set under
AVX-512F, with the AVX-512VL variant using `vprold` rotations and the 32 EVEX
registers for short tails. Lane `i` of every state vector belongs to block
`counter + i`, so the rounds are plain lane-wise arithmetic and the blocks are
transposed once before the XOR. The tag is then computed by the Poly1305
kernel above. The 64-byte row is dominated by the fixed HSalsa20 subkey
derivation and the first Salsa20 block on both sides.

On x86-64 the `simd_backend` feature does not change this path (the
portable-SIMD Salsa20 lane set is slower than the AVX2/AVX-512 kernels and is
compiled only for tests); the `simd_backend,nightly` build measured
`289.73`, `414.32`, `3,782.53` and `233,251.50 ns/iter`, identical within
noise.

### Arm Neoverse V3

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `225.70 ns/iter` | `284 MB/s` | `228.51 ns/iter` | `280 MB/s` | `1.01x faster` |
| 1 KiB | `811.37 ns/iter` | `1,262 MB/s` | `1,652.38 ns/iter` | `620 MB/s` | `2.04x faster` |
| 16 KiB | `8,845.02 ns/iter` | `1,852 MB/s` | `24,491.63 ns/iter` | `669 MB/s` | `2.77x faster` |
| 1 MiB | `548,902.50 ns/iter` | `1,910 MB/s` | `1,557,190.80 ns/iter` | `673 MB/s` | `2.84x faster` |

On this CPU the runtime detection picks the SVE2 kernel: one four-block
vector set whose quarter-round step is `add` + `xar` + `xar` (a two-deep
dependency chain against four for plain NEON), with a fifth block computed
from general-purpose registers in the same `asm!` block on the spare integer
pipes. The NEON and NEON+`sha3` (`eor3`) kernels are the fallbacks for cores
without SVE2. libsodium has only its scalar `ref` Salsa20 on AArch64, so the
gap here is vector versus scalar; it is smaller than on the Xeon because the
lane set is four blocks wide instead of sixteen. The 64-byte row is the same
fixed HSalsa20 plus one block on both sides.

As on x86-64, `simd_backend` does not change this path on AArch64; the
`simd_backend,nightly` build measured `225.83`, `811.14`, `8,845.40` and
`548,909.50 ns/iter`.

## Password Hashing: Argon2id

Benchmark: `argon2_hash` with a fixed 32-byte password, 16-byte salt, 32-byte
output, `t=2`, and `p=1`. Throughput is `t * m` bytes of block memory per
second. The libsodium rows call its `argon2_hash` with the same parameters.

### Intel Xeon 6975P-C

| Memory cost | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | `30,617.08 ns/iter` | `4,281 MB/s` | `35,967.61 ns/iter` | `3,644 MB/s` | `1.17x faster` |
| 1 MiB | `325,536.75 ns/iter` | `6,442 MB/s` | `358,176.60 ns/iter` | `5,855 MB/s` | `1.10x faster` |

Both sides run an AVX-512F block compression here. dryoc's kernel holds two
16-word states side by side in each 512-bit vector and rotates with `vprorq`;
the surrounding memory indexing and lane scheduling are the shared portable
code. The 1 MiB row is memory-bound and the noisiest in this suite: across
three native runs dryoc measured 314–327 µs and libsodium 352–361 µs.

With `simd_backend,nightly` the Argon2id rows are unchanged on x86-64
(`34,861.48` and `333,063.80 ns/iter`) because the runtime-detected AVX-512
kernel is preferred over the portable-SIMD block mixer.

### Arm Neoverse V3

| Memory cost | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | `53,236.46 ns/iter` | `2,462 MB/s` | `63,409.51 ns/iter` | `2,067 MB/s` | `1.19x faster` |
| 1 MiB | `744,782.00 ns/iter` | `2,816 MB/s` | `826,501.80 ns/iter` | `2,537 MB/s` | `1.11x faster` |

dryoc has no AArch64 Argon2 kernel, so both sides run a scalar block mixer:
dryoc's `argon2_soft` against libsodium's `ref`, two independent
implementations of the same fBlaMka rounds.

These are the native-flag rows for consistency with the rest of this page,
but on this CPU `-Ctarget-cpu=native` makes Argon2id *slower*: `53,236` /
`744,782 ns/iter` against the default build's `40,817` / `544,960 ns/iter`,
a 30–37% loss, reproducible across pinned runs. The disassembly shows what
changed: `-Ctarget-cpu=native` enables SVE, and the native build's
`argon2_soft::fill_block` contains 254 SVE instructions (917 in total) where
the default build's contains none (811 in total, 136 of them NEON), so LLVM
auto-vectorized the scalar rounds. An alternate build with
`-Ctarget-cpu=native -Ctarget-feature=-sve,-sve2` produces a `fill_block`
with no SVE and the default build's NEON count (825 instructions, 136 NEON)
and measured `42,374` / `574,046 ns/iter`, 4–6% slower than the default
build; that remaining difference is not attributed. Without `RUSTFLAGS`, which is
the crates.io default, dryoc is `1.55x` and `1.51x` faster than libsodium on
these rows; see [Without `target-cpu=native`](#without-target-cpunative).

With `simd_backend,nightly` the portable-SIMD block mixer is selected on
AArch64, and it is slower than the scalar one on this core: `75,885.73` and
`942,469.50 ns/iter` with `target-cpu=native` (`1.43x` and `1.27x` slower
than `argon2_soft`, and `1.20x` / `1.14x` slower than libsodium), and
`91,540.45` / `1,071,963.50 ns/iter` without flags. The default backend is the
right choice for Argon2 on AArch64.

## Generic Hashing: BLAKE2b

Benchmark: hash a 694,200-byte buffer and produce a 64-byte output
(`State::init`, `update`, `finalize`). The libsodium row calls
`crypto_generichash_blake2b` on the same buffer.

### Intel Xeon 6975P-C

| Implementation | Feature set | Time | vs libsodium | vs default |
| --- | --- | ---: | ---: | ---: |
| libsodium `avx2` | – | `629,177.30 ns/iter` | `1.00x` | `1.19x slower` |
| Default (AVX-512VL kernel) | `nightly` | `527,129.50 ns/iter` | `1.19x faster` | `1.00x` |
| Portable SIMD | `simd_backend,nightly` | `486,813.25 ns/iter` | `1.29x faster` | `1.08x faster` |
| Portable scalar (`compress_portable`) | `nightly`, before the kernel | `663,811.90 ns/iter` | `1.06x slower` | `1.26x slower` |

The default backend compresses each block through a runtime-detected x86-64
kernel: the 16-word state as four `ymm` rows so the four `G` mixings of a
step are one lane-wise `G`, with the message vectors assembled by the BLAKE2
reference AVX2 unpack/align/blend schedule. Its AVX2 variant has to rotate
lanes with shuffles (`vpshufd`, `vpshufb`), which compete with the message
shuffles for the shuffle port and leave it only 3–4% ahead of libsodium's
AVX2 code; the AVX-512VL variant, the same 256-bit lane set with one `vprorq`
per rotation, is what opens the gap on this CPU. The portable scalar row is
the same benchmark measured before the kernel was added, for reference.

The portable-SIMD backend vectorizes the same four-lane layout with
`Simd<u64, 4>` and, compiled with `-Ctarget-cpu=native`, is still 8% faster:
LLVM lowers its rotations to `vprolq` as well, and its compression is
inlined into the `update` loop, whereas the runtime-dispatched kernel is a
`#[target_feature]` function called once per 128-byte block. It remains
opt-in because it needs nightly Rust and its advantage depends on the
compile-time target: with the baseline x86-64 target the lane set is lowered
to SSE2 width and it is slower than the default backend.

### Arm Neoverse V3

| Implementation | Feature set | Time | vs libsodium | vs default |
| --- | --- | ---: | ---: | ---: |
| libsodium `ref` | – | `595,169.20 ns/iter` | `1.00x` | `1.43x slower` |
| Default (`asm!` rounds) | `nightly` | `417,184.65 ns/iter` | `1.43x faster` | `1.00x` |
| Portable SIMD | `simd_backend,nightly` | `792,149.20 ns/iter` | `1.33x slower` | `1.90x slower` |

The default backend on AArch64 is scalar: `blake2b_aarch64::rounds` emits
each `G` step `z = (z ^ x) >>> r` as `ror` followed by `eor` with a rotated
operand, so a step is two dependent instructions instead of three, and the
message words are loaded from the block with immediate offsets so the state
and temporaries stay in registers. That is enough to beat libsodium's scalar
`ref` by 43% with the 64-bit integer pipes alone.

The portable-SIMD backend is 1.9x slower than the scalar rounds with
`target-cpu=native` (`792,149.20 ns/iter`). Without flags it measures
`1,396,043.40 ns/iter`, 3.4x slower. With `target-cpu=native` LLVM lowers its `Simd<u64, 4>`
rotations to SVE2 `xar` and its diagonal shuffles to `ext` permutes; why that
loses to the scalar rounds on this core has not been profiled. On AArch64,
`simd_backend` should not be enabled for BLAKE2b performance.

## Without `target-cpu=native`

The same `cargo +nightly bench --features nightly` run with no `RUSTFLAGS`,
which is what a crates.io consumer gets by default. The runtime-detected
kernels are compiled with per-function `target_feature` attributes, so they
are used without any build flags on both machines; on the Xeon that covers
Poly1305, secretbox and Argon2id, on the Neoverse V3 Poly1305 and secretbox
(its Argon2id runs the portable code and changes with the flag, below).

### Intel Xeon 6975P-C

| Workload | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poly1305, 64 B | `36.37 ns/iter` | `1,777 MB/s` | `54.21 ns/iter` | `1,185 MB/s` | `1.49x faster` |
| Poly1305, 1 KiB | `121.97 ns/iter` | `8,462 MB/s` | `356.40 ns/iter` | `2,876 MB/s` | `2.92x faster` |
| Poly1305, 16 KiB | `971.96 ns/iter` | `16,873 MB/s` | `5,210.77 ns/iter` | `3,144 MB/s` | `5.36x faster` |
| Poly1305, 1 MiB | `57,588.91 ns/iter` | `18,208 MB/s` | `329,848.10 ns/iter` | `3,178 MB/s` | `5.73x faster` |
| Secretbox, 64 B | `286.11 ns/iter` | `223 MB/s` | `374.89 ns/iter` | `171 MB/s` | `1.31x faster` |
| Secretbox, 1 KiB | `428.84 ns/iter` | `2,392 MB/s` | `1,339.45 ns/iter` | `764 MB/s` | `3.12x faster` |
| Secretbox, 16 KiB | `3,805.65 ns/iter` | `4,305 MB/s` | `11,852.24 ns/iter` | `1,382 MB/s` | `3.11x faster` |
| Secretbox, 1 MiB | `233,474.60 ns/iter` | `4,491 MB/s` | `714,460.90 ns/iter` | `1,467 MB/s` | `3.06x faster` |
| Argon2id, 64 KiB | `32,217.03 ns/iter` | `4,068 MB/s` | `35,851.64 ns/iter` | `3,656 MB/s` | `1.11x faster` |
| Argon2id, 1 MiB | `374,579.78 ns/iter` | `5,598 MB/s` | `353,796.70 ns/iter` | `5,927 MB/s` | `1.06x slower` |
| BLAKE2b, 694,200 B (default) | `556,002.70 ns/iter` | – | `627,764.60 ns/iter` | – | `1.13x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `754,820.30 ns/iter` | – | `627,434.20 ns/iter` | – | `1.20x slower` |

The only rows that move are the ones whose hot loop is compiled for the
generic target: the Argon2id 1 MiB row loses its margin (the block mixing is
still AVX-512, but the portable indexing and `blake2b_long` code around it is
no longer tuned for this core; across three default-flag runs dryoc measured
364–375 µs against libsodium's 353–365 µs), and the portable-SIMD BLAKE2b
backend drops to SSE2 width.

### Arm Neoverse V3

| Workload | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poly1305, 64 B | `40.65 ns/iter` | `1,574 MB/s` | `40.72 ns/iter` | `1,572 MB/s` | `1.00x` |
| Poly1305, 1 KiB | `274.42 ns/iter` | `3,732 MB/s` | `525.96 ns/iter` | `1,947 MB/s` | `1.92x faster` |
| Poly1305, 16 KiB | `2,708.40 ns/iter` | `6,049 MB/s` | `8,291.20 ns/iter` | `1,976 MB/s` | `3.06x faster` |
| Poly1305, 1 MiB | `166,374.63 ns/iter` | `6,302 MB/s` | `530,265.20 ns/iter` | `1,977 MB/s` | `3.19x faster` |
| Secretbox, 64 B | `220.13 ns/iter` | `291 MB/s` | `228.59 ns/iter` | `280 MB/s` | `1.04x faster` |
| Secretbox, 1 KiB | `809.01 ns/iter` | `1,266 MB/s` | `1,651.33 ns/iter` | `620 MB/s` | `2.04x faster` |
| Secretbox, 16 KiB | `8,940.82 ns/iter` | `1,832 MB/s` | `24,460.84 ns/iter` | `670 MB/s` | `2.74x faster` |
| Secretbox, 1 MiB | `555,557.90 ns/iter` | `1,887 MB/s` | `1,557,761.00 ns/iter` | `673 MB/s` | `2.80x faster` |
| Argon2id, 64 KiB | `40,816.83 ns/iter` | `3,211 MB/s` | `63,411.44 ns/iter` | `2,067 MB/s` | `1.55x faster` |
| Argon2id, 1 MiB | `544,959.90 ns/iter` | `3,848 MB/s` | `825,552.80 ns/iter` | `2,540 MB/s` | `1.51x faster` |
| BLAKE2b, 694,200 B (default) | `415,627.35 ns/iter` | – | `595,196.10 ns/iter` | – | `1.43x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `1,396,043.40 ns/iter` | – | `595,235.30 ns/iter` | – | `2.35x slower` |

The baseline `aarch64-unknown-linux-gnu` target already includes NEON, the
SVE2 and `sha3` kernels are compiled with per-function `target_feature`
attributes, and the BLAKE2b rounds are `asm!`, so the Poly1305, secretbox
and BLAKE2b rows are within 3% of the native build. Argon2id is the exception
in the other direction: the generic target does not include SVE, the scalar
block mixer stays scalar, and the rows are 30–37% faster than with
`target-cpu=native` (see
[Password Hashing: Argon2id](#password-hashing-argon2id)). The portable-SIMD
BLAKE2b backend, which is already the slowest option on this core, is a
further 1.8x slower without `target-cpu=native`.

## Benchmark Coverage

Current benchmark coverage, with the implementation each build uses on each
machine:

| Algorithm | Xeon: software / default build | Xeon: `simd_backend,nightly` build | Neoverse V3: software / default build | Neoverse V3: `simd_backend,nightly` build | libsodium baseline |
| --- | --- | --- | --- | --- | --- |
| Poly1305 | `poly1305_soft` + runtime `poly1305_x86_64` (AVX2 / AVX-512F / AVX-512 IFMA) | same; `poly1305_simd` compiled for tests only | `poly1305_soft` + runtime `poly1305_neon` | same; `poly1305_simd` compiled for tests only | `sodiumoxide_poly1305_*_bench` |
| XSalsa20-Poly1305 secretbox | `salsa20_x86_64` (AVX2 / AVX-512) + Poly1305 above | same; `salsa20_simd` compiled for tests only | `salsa20_neon` (NEON / NEON+`sha3` / SVE2) + Poly1305 above | same; `salsa20_simd` compiled for tests only | `libsodium_secretbox_detached_*_bench` |
| Argon2id password hashing | runtime `argon2_x86_64` (AVX2 / AVX-512F), else `argon2_soft` | runtime `argon2_x86_64`, else `argon2_simd` | `argon2_soft` | `argon2_simd` | `libsodium_argon2id_*_bench` |
| BLAKE2b | `blake2b_soft` + runtime `blake2b_x86_64` (AVX2 / AVX-512VL) | `blake2b_simd` | `blake2b_soft` + `blake2b_aarch64` rounds | `blake2b_simd` | `libsodium_blake2b_bench` |

Algorithms without benchmark coverage should get their own section when a
second implementation is added or when performance work begins.
