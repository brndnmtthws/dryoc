# Benchmarks

dryoc measured against libsodium on the same machine, in the same process, on
the same buffers. Two machines: an Intel Xeon 6975P-C (Granite Rapids,
AVX-512/IFMA) and an Arm Neoverse V3 (NEON, SVE2, SHA-2/SHA-3 extensions), both
against libsodium 1.0.22 — Xeon rows at `f33b8f8` (#194), Neoverse V3 rows at
#194. See [Environment](#environment) for setup. Numbers are relative
performance on those CPUs, not portable guarantees.

## Headline

On the Xeon 6975P-C (at `f33b8f8`, same pinning/median), dryoc's runtime-detected AVX2/AVX-512
kernels beat libsodium 1.0.22 on every workload with `-Ctarget-cpu=native`,
and on everything but the memory-bound Argon2id 1 MiB row (plus the opt-in
portable-SIMD BLAKE2b row, which needs native to lead) with no build flags:

| Workload | dryoc | libsodium | dryoc vs libsodium |
| --- | ---: | ---: | ---: |
| Poly1305, 1 MiB | `19,087 MB/s` | `4,451 MB/s` | `4.29x faster` |
| Poly1305, 16 KiB | `17,842 MB/s` | `4,380 MB/s` | `4.07x faster` |
| XSalsa20-Poly1305 secretbox, 1 MiB | `4,533 MB/s` | `1,676 MB/s` | `2.71x faster` |
| XSalsa20-Poly1305 secretbox, 1 KiB | `2,678 MB/s` | `820 MB/s` | `3.27x faster` |
| Argon2id, `t=2 m=64 KiB` | `4,446 MB/s` | `3,628 MB/s` | `1.23x faster` |
| Argon2id, `t=2 m=1 MiB` | `6,396 MB/s` | `5,813 MB/s` | `1.10x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `486,884 ns` | `611,619 ns` | `1.26x faster` |
| BLAKE2b, 694,200 B (default) | `523,856 ns` | `611,391 ns` | `1.17x faster` |
On the Neoverse V3 (below: `-Ctarget-cpu=native`, pinned to one core, median
of three runs), dryoc leads on every default-backend row, including the
64-byte ones, and the no-flags build is within 2.4% on each of those rows.
Only the opt-in portable-SIMD BLAKE2b backend loses to libsodium:

| Workload | dryoc | libsodium | dryoc vs libsodium |
| --- | ---: | ---: | ---: |
| Poly1305, 1 MiB | `7,134 MB/s` | `1,976 MB/s` | `3.61x faster` |
| Poly1305, 16 KiB | `6,931 MB/s` | `1,975 MB/s` | `3.51x faster` |
| XSalsa20-Poly1305 secretbox, 1 MiB | `2,699 MB/s` | `674 MB/s` | `4.00x faster` |
| XSalsa20-Poly1305 secretbox, 1 KiB | `1,618 MB/s` | `621 MB/s` | `2.60x faster` |
| Argon2id, `t=2 m=64 KiB` | `4,000 MB/s` | `1,410 MB/s` | `2.84x faster` |
| Argon2id, `t=2 m=1 MiB` | `5,032 MB/s` | `1,637 MB/s` | `3.07x faster` |
| BLAKE2b, 694,200 B (default) | `417,771 ns` | `594,888 ns` | `1.42x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `792,951 ns` | `595,068 ns` | `1.33x slower` |
| ML-KEM-768 decapsulation | `6,952 ns` | `26,405 ns` | `3.80x faster` |
| X-Wing decapsulation | `40,556 ns` | `94,106 ns` | `2.32x faster` |

Part of the Argon2id margin is libsodium's: 1.0.22 always picks its NEON
block compression on AArch64, which is slower than 1.0.18's portable code on
this core; see [Password Hashing: Argon2id](#password-hashing-argon2id).

![dryoc speedup over libsodium by workload on both machines](benchmarks/speedup.svg)

![Single-thread throughput on the Xeon, log scale](benchmarks/throughput-x86_64.svg)

![Single-thread throughput on the Neoverse V3, log scale](benchmarks/throughput-aarch64.svg)

On the Xeon, the Poly1305, Salsa20, Argon2 and BLAKE2b kernels are picked at
runtime. On the Neoverse V3 the SVE2 Salsa20/Argon2 and the ML-KEM NEON and
SHA3-extension kernels are; the Poly1305 block loops and BLAKE2b rounds are
baseline `asm!`, picked at compile time. None of the runtime kernels needs
`-Ctarget-cpu=native`; see [Without `target-cpu=native`](#without-target-cpunative).
Only the BLAKE2b portable-SIMD rows need the `simd_backend,nightly` build, and
on the Xeon that row also needs `target-cpu=native` to lead.

## Environment

| Item | Intel Xeon 6975P-C | Arm Neoverse V3 |
| --- | --- | --- |
| Machine | Cloud VM (c8i.8xlarge), 32 vCPUs, pinned to one core with `taskset -c 7` | Cloud VM, 192 vCPUs |
| CPU | Intel Xeon 6975P-C (Granite Rapids; AVX2, AVX-512F/VL, AVX-512 IFMA) | Arm Neoverse V3 r0p1 (NEON, SVE/SVE2, `sha2`, `sha3`, `sha512`) |
| Architecture | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| OS | Debian 13, Linux `6.12.107+deb13-cloud-amd64` | Debian 13, Linux `6.12.107+deb13-cloud-arm64` |
| Rust | `rustc 1.100.0-nightly (5ceaf6608 2026-09-25)` | `rustc 1.100.0-nightly (6eeff9a52 2026-09-23)` |
| Cargo | `cargo 1.100.0-nightly (3d7cf6e93 2026-09-25)` | `cargo 1.100.0-nightly (98a09e7e7 2026-09-21)` |
| Target CPU | `native` unless stated otherwise | `native` unless stated otherwise |
| dryoc revision | `f33b8f8` (#194) | #194 |
| libsodium | `1.0.22`, statically linked from the `libsodium-sys-stable 1.24.0` bundled source, built with its default flags | `1.0.22`, statically linked from the `libsodium-sys-stable 1.24.0` bundled source, built with its default flags |
| Sampling | pinned to one core with `taskset -c 7`, median of three runs | pinned to one core with `taskset -c 7`, median of three runs |

```sh
export RUSTFLAGS="-Ctarget-cpu=native"

# Software backends, plus the libsodium baseline rows.
cargo +nightly bench --features nightly

# Portable-SIMD backends (BLAKE2b, and Argon2 block mixing on AArch64; on
# x86-64 the runtime-detected Argon2 kernel is used either way).
cargo +nightly bench --features simd_backend,nightly
```

Each command ran under `taskset -c 7` three times, with and without
`-Ctarget-cpu=native`, on an otherwise idle core; the median `ns/iter` is
reported. Across the 146 Neoverse V3 rows the run-to-run spread was below 1%
on 139 rows and below 1.7% on all but four; the noisiest was dryoc's
secretbox 16 KiB no-flags build at 3.0%. On the Xeon rerun every Poly1305,
secretbox, BLAKE2b and KEM row was within 0.6%; the noisiest fresh rows were
Poly1305 1 MiB (3.6%) and Argon2id 1 MiB (dryoc 2.5%, libsodium 1.3%).
Ratios rounding to `1.00x`–`1.03x` are within that noise.

Charts render from
[`benchmarks/results-x86_64.dat`](benchmarks/results-x86_64.dat) and
[`benchmarks/results-aarch64.dat`](benchmarks/results-aarch64.dat) via
[`benchmarks/charts.gp`](benchmarks/charts.gp); regenerate with
`gnuplot -c benchmarks/charts.gp`.

Each `*_bench` has a `libsodium_*_bench` twin in the same module running the
matching libsodium function on the same sizes after `sodium_init()`, so
libsodium uses its own runtime-selected code. `RUSTFLAGS` doesn't affect the C
library; its numbers matched within noise across builds.

Kernels picked at runtime on each CPU:

| Algorithm | dryoc kernel, Xeon 6975P-C | libsodium 1.0.22, Xeon | dryoc kernel, Neoverse V3 | libsodium, Neoverse V3 |
| --- | --- | --- | --- | --- |
| Poly1305 | AVX-512 IFMA, 3x44-bit limbs, two chains for long runs (`poly1305_x86_64`) | `sse2` (Poly1305-donna) | `asm!` radix-2^64 block loops on the integer multipliers, four Horner lanes for runs of at least 384 bytes (`poly1305_aarch64`) | `donna` (64-bit, 3x44-bit limbs) |
| Salsa20 (secretbox) | AVX-512F/VL 16-block lane set (`salsa20_x86_64`) | `xmm6int` AVX2 | SVE2 `xar` 4-block vector set plus scalar blocks in the same `asm!` block, with secretbox's Poly1305 in that block too (`salsa20_neon`) | `ref` (scalar) |
| Argon2 block mixing | AVX-512F (`argon2_x86_64`) | `avx512f` | SVE2 `asm!`, three states in vectors beside five on the integer registers (`argon2_neon`) | `neon` |
| BLAKE2b | AVX-512VL `vprorq` rotations on a 256-bit lane set (`blake2b_x86_64`), or portable SIMD with `simd_backend,nightly` | `avx2` | scalar `asm!` rounds (`blake2b_aarch64`), or portable SIMD with `simd_backend,nightly` | `ref` (scalar) |
| ML-KEM-768 and X-Wing | AVX2 NTT/multiply-add (`mlkem_x86_64`), 4-way AVX2 Keccak | reference C + reference Keccak | NEON NTT/multiply-add, 3-way (`keccak3_aarch64`) or 2-way SHA3-extension Keccak, X25519 on the `fe64_aarch64` field | reference C + reference Keccak |

libsodium 1.0.22 has AArch64 NEON code only for Argon2 here; its
Poly1305/Salsa20/BLAKE2b Neoverse V3 rows are portable C. Confirmed with `nm`
on the bench binary: donna Poly1305, `ref` Salsa20 and BLAKE2b behind the
pick-best selectors, plus `argon2_fill_segment_neon` — and nothing else for
these four. On the Xeon the same check finds donna/`sse2` Poly1305,
`ref`/`sse2`/`xmm6int_avx2` Salsa20, `ref`/`avx2`/`avx512f` Argon2 and
`ref`/`sse41`/`avx2` BLAKE2b. Its ML-KEM is reference C with reference Keccak;
the SHA3-extension Keccak in the 1.0.22 source isn't in the binary.

## One-Time Authentication: Poly1305

Authenticate fixed-size messages (`Poly1305::new`, `update`,
`finalize_to_array`); libsodium rows call `crypto_onetimeauth_poly1305`.

### Intel Xeon 6975P-C

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `31.28 ns/iter` | `2,046 MB/s` | `44.71 ns/iter` | `1,431 MB/s` | `1.43x faster` |
| 1 KiB | `111.75 ns/iter` | `9,163 MB/s` | `267.76 ns/iter` | `3,824 MB/s` | `2.40x faster` |
| 16 KiB | `918.26 ns/iter` | `17,842 MB/s` | `3,740.46 ns/iter` | `4,380 MB/s` | `4.07x faster` |
| 1 MiB | `54,935.39 ns/iter` | `19,087 MB/s` | `235,565.14 ns/iter` | `4,451 MB/s` | `4.29x faster` |

The scalar backend holds the accumulator in three 44-bit limbs and hands full
blocks to a runtime-detected bulk path: AVX2/AVX-512F lanes in 5x26-bit limbs,
or 3x44-bit lanes with `vpmadd52luq`/`vpmadd52huq` on `avx512ifma`. Each bulk
kernel runs a chunk as independent Horner lanes folded with one power of `r`
per block, bit-identical to serial evaluation, with data-independent
execution. libsodium 1.0.22 has no AVX2/AVX-512 Poly1305 and tops out at SSE2.

The 64-byte row uses no bulk path on either side (IFMA needs 256 bytes); the
gap is the scalar `u128` 3-limb multiply against the 32-bit limbs libsodium
picks on x86-64.

### Arm Neoverse V3

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `23.04 ns/iter` | `2,778 MB/s` | `39.80 ns/iter` | `1,608 MB/s` | `1.73x faster` |
| 1 KiB | `208.69 ns/iter` | `4,907 MB/s` | `525.07 ns/iter` | `1,950 MB/s` | `2.52x faster` |
| 16 KiB | `2,363.95 ns/iter` | `6,931 MB/s` | `8,294.04 ns/iter` | `1,975 MB/s` | `3.51x faster` |
| 1 MiB | `146,985.10 ns/iter` | `7,134 MB/s` | `530,544.90 ns/iter` | `1,976 MB/s` | `3.61x faster` |

Here the block loops are `asm!` on the integer multipliers in radix 2^64: ten
`mul`/`umulh` per block versus eighteen for 3x44-bit limbs. Runs of 384 bytes
or more split into four lanes that overlap to multiplier throughput, then join
with powers of `r`, bit-identical to serial; shorter runs take the one-lane
loop. Control flow and memory access depend only on length. This replaced the
NEON 5x26-bit kernel (`270.70` / `161,823.55 ns/iter` at 1 KiB / 1 MiB), whose
key-power setup cost more than the four-lane join.

The portable-SIMD backend (`poly1305_simd`) is test-only on x86-64/AArch64 —
slower than the target kernels. For reference with `simd_backend,nightly` and
`target-cpu=native`: ~`1,120 MB/s` on the Xeon, ~`2,537 MB/s` on the Neoverse
V3 — ahead of libsodium's scalar code from 1 KiB up, 2.8x behind the `asm!`
loops. Portable SIMD can't express the widening multiply-accumulates
(`vpmuludq`, `vpmadd52luq`) behind the x86-64 kernels, and vectors don't beat
this core's integer multipliers.

References: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439),
[Improved SIMD Implementation of Poly1305, ePrint 2019/842](https://eprint.iacr.org/2019/842.pdf),
and [poly1305-donna](https://github.com/floodyberry/poly1305-donna).

## Secretbox: XSalsa20-Poly1305

`crypto_secretbox_detached` into a preallocated buffer plus tag — the combined
XSalsa20 + Poly1305 path behind secretbox and `crypto_box`. libsodium rows
call `crypto_secretbox_detached` on the same buffers.

### Intel Xeon 6975P-C

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `256.60 ns/iter` | `249 MB/s` | `356.66 ns/iter` | `179 MB/s` | `1.39x faster` |
| 1 KiB | `382.36 ns/iter` | `2,678 MB/s` | `1,249.26 ns/iter` | `820 MB/s` | `3.27x faster` |
| 16 KiB | `3,754.75 ns/iter` | `4,364 MB/s` | `10,442.87 ns/iter` | `1,569 MB/s` | `2.78x faster` |
| 1 MiB | `231,302.05 ns/iter` | `4,533 MB/s` | `625,743.70 ns/iter` | `1,676 MB/s` | `2.71x faster` |

Keystream comes from a runtime-detected lane set: eight blocks per `ymm` set
(AVX2), sixteen per `zmm` set (AVX-512F), with a `vprold`/32-register AVX-512VL
variant for short tails. Lane `i` holds block `counter + i`, so rounds are
plain lane arithmetic transposed once before the XOR; the tag uses the
Poly1305 kernel above. The 64-byte row is mostly fixed HSalsa20 + first-block
cost on both sides.

`simd_backend` doesn't change this path (the portable-SIMD Salsa20 set is
slower and test-only): `256.68` / `383.78` / `3,782.47` / `232,404.25
ns/iter`, within noise.

### Arm Neoverse V3

| Message size | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 B | `181.26 ns/iter` | `353 MB/s` | `227.72 ns/iter` | `281 MB/s` | `1.26x faster` |
| 1 KiB | `633.00 ns/iter` | `1,618 MB/s` | `1,647.86 ns/iter` | `621 MB/s` | `2.60x faster` |
| 16 KiB | `6,907.57 ns/iter` | `2,372 MB/s` | `24,444.73 ns/iter` | `670 MB/s` | `3.54x faster` |
| 1 MiB | `388,473.70 ns/iter` | `2,699 MB/s` | `1,554,919.20 ns/iter` | `674 MB/s` | `4.00x faster` |

Detection picks the SVE2 kernel: a four-block vector set (`add`+`xar`+`xar`
per quarter round) with scalar blocks on the integer pipes in the same `asm!`
block. Secretbox's Poly1305 for each 320-byte chunk runs in that block too, on
the multipliers Salsa20 leaves idle — one pass for keystream, XOR and tag. The
NEON and NEON+`sha3` kernels cover cores without SVE2. libsodium has only
scalar `ref` Salsa20 + 64-bit donna here. The 64-byte row is fixed HSalsa20 +
two blocks; dryoc interleaves the two on the integer registers.

`simd_backend` doesn't change this path either: `180.08` / `629.32` /
`6,930.94` / `389,094.90 ns/iter`.

## Password Hashing: Argon2id

Fixed 32-byte password, 16-byte salt, 32-byte output, `t=2`, `p=1`.
Throughput is `t * m` block bytes per second; libsodium rows use the same
parameters.

### Intel Xeon 6975P-C

| Memory cost | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | `29,483.97 ns/iter` | `4,446 MB/s` | `36,131.62 ns/iter` | `3,628 MB/s` | `1.23x faster` |
| 1 MiB | `327,890.05 ns/iter` | `6,396 MB/s` | `360,764.35 ns/iter` | `5,813 MB/s` | `1.10x faster` |

Both run AVX-512F block compression. dryoc holds two 16-word states per vector
and rotates with `vprorq`; indexing and scheduling are shared portable code.
The 1 MiB row is memory-bound and the noisiest here: 327.9–328.3 µs vs
360.5–362.2 µs across three native runs.

With `simd_backend,nightly` these rows barely move (`33,843.92` /
`330,041.90 ns/iter`): the AVX-512 kernel wins over the portable-SIMD mixer.

### Arm Neoverse V3

| Memory cost | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | `32,768.21 ns/iter` | `4,000 MB/s` | `92,972.52 ns/iter` | `1,410 MB/s` | `2.84x faster` |
| 1 MiB | `416,792.90 ns/iter` | `5,032 MB/s` | `1,280,744.20 ns/iter` | `1,637 MB/s` | `3.07x faster` |

dryoc runs the SVE2 kernel: each pass (rows, then columns) is one `asm!` block
with three of eight 16-word states in vectors and five on the integer
registers, so both pipes stay busy. A vector `G` is `add`/`umullb`/`adr`/`xar`.

libsodium 1.0.22 runs NEON compression on every AArch64 build, which is slower
than 1.0.18's portable code on this core (`63,409.51` / `826,501.80 ns/iter`
then vs `92,972.52` / `1,280,744.20` now). Against 1.0.18 dryoc would be
`1.94x`/`1.98x` faster, so part of the table margin is libsodium's regression.
dryoc itself is `1.22x`/`1.30x` ahead of its previous scalar revision
(`40,817` / `544,960 ns/iter`, no-flags builds).

`-Ctarget-cpu=native` no longer matters here (within 2.4%): compression is
`asm!` once SVE2 is detected. Previously the flag made it 30–37% *slower* by
auto-vectorizing the scalar rounds with SVE.

With `simd_backend,nightly` these rows lose 11–12 µs native (18–19 µs without
flags) — the same at both memory costs, so it's the fixed per-hash BLAKE2b
outside the block fill, whose portable-SIMD backend is the slow option on this
core (next section). The default backend is the right Argon2 choice on
AArch64.

## Generic Hashing: BLAKE2b

Hash 694,200 bytes to 64 bytes (`State::init`, `update`, `finalize`);
libsodium rows call `crypto_generichash_blake2b` on the same buffer.

### Intel Xeon 6975P-C

| Implementation | Feature set | Time | vs libsodium | vs default |
| --- | --- | ---: | ---: | ---: |
| libsodium `avx2` | – | `611,391.20 ns/iter` | `1.00x` | `1.17x slower` |
| Default (AVX-512VL kernel) | `nightly` | `523,855.90 ns/iter` | `1.17x faster` | `1.00x` |
| Portable SIMD | `simd_backend,nightly` | `486,883.65 ns/iter` | `1.26x faster` | `1.08x faster` |
| Portable scalar (`compress_portable`) | `nightly`, before the kernel | `663,811.90 ns/iter` | `1.08x slower` | `1.27x slower` |

The default backend compresses through a runtime-detected kernel: the 16-word
state as four `ymm` rows, one lane-wise `G` per step, messages via the
reference AVX2 unpack/align/blend schedule. The AVX2 variant rotates with
shuffles that fight the message shuffles for the shuffle port (+3–4% over
libsodium); the AVX-512VL variant rotates with one `vprorq` each, which opens
the gap. The scalar row is the same bench from before the kernel.

Portable SIMD is still 7% faster with `target-cpu=native` (LLVM emits `vprolq`,
and compression inlines into `update` instead of a per-block
`#[target_feature]` call). It stays opt-in: it needs nightly, and on the
baseline target it lowers to SSE2 width and loses to the default.

### Arm Neoverse V3

| Implementation | Feature set | Time | vs libsodium | vs default |
| --- | --- | ---: | ---: | ---: |
| libsodium `ref` | – | `594,887.80 ns/iter` | `1.00x` | `1.42x slower` |
| Default (`asm!` rounds) | `nightly` | `417,771.30 ns/iter` | `1.42x faster` | `1.00x` |
| Portable SIMD | `simd_backend,nightly` | `792,951.20 ns/iter` | `1.33x slower` | `1.90x slower` |

The default here is scalar `asm!`: each `G` step is `ror`+`eor` with a rotated
operand (two dependent instructions, not three), message words loaded at
immediate offsets so state stays in registers — 42% past libsodium's scalar
`ref` on integer pipes alone.

Portable SIMD is 1.9x slower than that with native flags (`792,951.20
ns/iter`), 3.4x slower without (`1,396,414.70 ns/iter`). LLVM lowers it to
SVE2 `xar` + `ext` with native flags; why it loses hasn't been profiled. Don't
enable `simd_backend` for BLAKE2b on AArch64.

## Key Encapsulation: ML-KEM-768 and X-Wing

`classic::crypto_kem_mlkem768` / `crypto_kem_xwing`: seed keygen,
deterministic encapsulation, valid-ciphertext decapsulation, against
libsodium 1.0.22 (1.0.18 has no KEM). Same pinning/median method as above.

On the Xeon dryoc uses AVX2 polynomial arithmetic with 4-way AVX2 Keccak, and
portable five-limb X25519; libsodium is reference C + reference Keccak (the
1.0.22 SHA3-extension Keccak isn't in the binary). On the Neoverse V3 dryoc
uses NEON NTT/multiply-add/rejection/decompression/decoding with 3-way or
2-way SHA3-extension Keccak, X25519 on a four-limb `asm!` field. X-Wing adds
X25519 work (1 multiplication at keygen, 2 at encaps/decaps plus an ML-KEM
regen); on the Neoverse V3 the base-point multiply shares one inversion with
the exchange, so X-Wing speedups run smaller than ML-KEM's.

### Intel Xeon 6975P-C

| Operation | dryoc | libsodium | dryoc vs libsodium |
| --- | ---: | ---: | ---: |
| ML-KEM-768 key generation | `16,273 ns` | `26,127 ns` | `1.61x faster` |
| ML-KEM-768 encapsulation | `15,927 ns` | `30,715 ns` | `1.93x faster` |
| ML-KEM-768 decapsulation | `16,994 ns` | `36,593 ns` | `2.15x faster` |
| X-Wing key generation | `26,761 ns` | `39,761 ns` | `1.49x faster` |
| X-Wing encapsulation | `51,600 ns` | `76,903 ns` | `1.49x faster` |
| X-Wing decapsulation | `63,988 ns` | `109,610 ns` | `1.71x faster` |

With `simd_backend,nightly` the same kernels measured faster here (ML-KEM
`9,088` / `9,662` / `10,733 ns`, X-Wing `19,238` / `45,150` / `51,384 ns`).
There is no portable-SIMD ML-KEM/Keccak backend, so both builds run the same
kernels; why they differ hasn't been profiled.

### Arm Neoverse V3

| Operation | dryoc | libsodium | dryoc vs libsodium |
| --- | ---: | ---: | ---: |
| ML-KEM-768 key generation | `5,807 ns` | `17,360 ns` | `2.99x faster` |
| ML-KEM-768 encapsulation | `5,914 ns` | `20,138 ns` | `3.40x faster` |
| ML-KEM-768 decapsulation | `6,952 ns` | `26,405 ns` | `3.80x faster` |
| X-Wing key generation | `13,699 ns` | `31,113 ns` | `2.27x faster` |
| X-Wing encapsulation | `35,781 ns` | `69,871 ns` | `1.95x faster` |
| X-Wing decapsulation | `40,556 ns` | `94,106 ns` | `2.32x faster` |

libsodium is unchanged from the previous revision (within 0.4%); dryoc's rows
were `9,280` / `10,643` / `13,687` / `21,508` / `52,348` / `66,048 ns` before
#194.

## Without `target-cpu=native`

Same `cargo +nightly bench --features nightly` run with no `RUSTFLAGS` — what
a crates.io consumer gets. Runtime-detected kernels don't need flags
(per-function `target_feature`), so on the Xeon that still covers Poly1305,
secretbox, Argon2id and KEM; on the Neoverse V3 secretbox, Argon2id and KEM.

### Intel Xeon 6975P-C

| Workload | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poly1305, 64 B | `31.78 ns/iter` | `2,014 MB/s` | `44.70 ns/iter` | `1,432 MB/s` | `1.41x faster` |
| Poly1305, 1 KiB | `116.81 ns/iter` | `8,766 MB/s` | `267.89 ns/iter` | `3,822 MB/s` | `2.29x faster` |
| Poly1305, 16 KiB | `930.06 ns/iter` | `17,616 MB/s` | `3,740.71 ns/iter` | `4,380 MB/s` | `4.02x faster` |
| Poly1305, 1 MiB | `56,200.27 ns/iter` | `18,658 MB/s` | `235,266.88 ns/iter` | `4,457 MB/s` | `4.19x faster` |
| Secretbox, 64 B | `256.92 ns/iter` | `249 MB/s` | `357.57 ns/iter` | `179 MB/s` | `1.39x faster` |
| Secretbox, 1 KiB | `392.11 ns/iter` | `2,612 MB/s` | `1,246.97 ns/iter` | `821 MB/s` | `3.18x faster` |
| Secretbox, 16 KiB | `3,775.91 ns/iter` | `4,339 MB/s` | `10,429.47 ns/iter` | `1,571 MB/s` | `2.76x faster` |
| Secretbox, 1 MiB | `231,843.10 ns/iter` | `4,523 MB/s` | `626,616.80 ns/iter` | `1,673 MB/s` | `2.70x faster` |
| Argon2id, 64 KiB | `32,418.98 ns/iter` | `4,043 MB/s` | `36,021.00 ns/iter` | `3,639 MB/s` | `1.11x faster` |
| Argon2id, 1 MiB | `374,195.30 ns/iter` | `5,604 MB/s` | `360,096.50 ns/iter` | `5,824 MB/s` | `1.04x slower` |
| BLAKE2b, 694,200 B (default) | `514,435.00 ns/iter` | – | `611,076.90 ns/iter` | – | `1.19x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `754,223.40 ns/iter` | – | `611,076.90 ns/iter` | – | `1.23x slower` |
| ML-KEM-768 key generation | `12,611.70 ns/iter` | – | `26,212.36 ns/iter` | – | `2.08x faster` |
| ML-KEM-768 encapsulation | `12,986.30 ns/iter` | – | `30,715.30 ns/iter` | – | `2.36x faster` |
| ML-KEM-768 decapsulation | `14,538.37 ns/iter` | – | `36,656.90 ns/iter` | – | `2.52x faster` |
| X-Wing key generation | `22,784.53 ns/iter` | – | `40,279.42 ns/iter` | – | `1.77x faster` |
| X-Wing encapsulation | `47,242.61 ns/iter` | – | `77,383.90 ns/iter` | – | `1.64x faster` |
| X-Wing decapsulation | `55,340.72 ns/iter` | – | `110,562.79 ns/iter` | – | `2.00x faster` |

What moves without the flag is the generic-target surrounding code: Poly1305 /
secretbox at 1 KiB lose 3–5%, Argon2id drops from `1.23x` to `1.11x` at 64 KiB
and flips at 1 MiB (367–376 µs vs libsodium's 358–363 µs), and portable-SIMD
BLAKE2b falls back to SSE2 width. The KEM rows are faster without the flag
(ML-KEM decapsulation 14,538 vs 16,994 ns, not profiled); libsodium is within
noise either way.

### Arm Neoverse V3

| Workload | dryoc time | dryoc throughput | libsodium time | libsodium throughput | Relative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Poly1305, 64 B | `22.52 ns/iter` | `2,842 MB/s` | `39.80 ns/iter` | `1,608 MB/s` | `1.77x faster` |
| Poly1305, 1 KiB | `209.24 ns/iter` | `4,894 MB/s` | `525.15 ns/iter` | `1,950 MB/s` | `2.51x faster` |
| Poly1305, 16 KiB | `2,346.78 ns/iter` | `6,981 MB/s` | `8,294.27 ns/iter` | `1,975 MB/s` | `3.53x faster` |
| Poly1305, 1 MiB | `145,859.03 ns/iter` | `7,189 MB/s` | `530,500.30 ns/iter` | `1,977 MB/s` | `3.64x faster` |
| Secretbox, 64 B | `177.02 ns/iter` | `362 MB/s` | `227.72 ns/iter` | `281 MB/s` | `1.29x faster` |
| Secretbox, 1 KiB | `628.89 ns/iter` | `1,628 MB/s` | `1,648.61 ns/iter` | `621 MB/s` | `2.62x faster` |
| Secretbox, 16 KiB | `6,894.74 ns/iter` | `2,376 MB/s` | `24,469.43 ns/iter` | `670 MB/s` | `3.55x faster` |
| Secretbox, 1 MiB | `389,432.10 ns/iter` | `2,693 MB/s` | `1,553,692.60 ns/iter` | `675 MB/s` | `3.99x faster` |
| Argon2id, 64 KiB | `33,565.00 ns/iter` | `3,905 MB/s` | `92,988.13 ns/iter` | `1,410 MB/s` | `2.77x faster` |
| Argon2id, 1 MiB | `418,857.40 ns/iter` | `5,007 MB/s` | `1,280,757.60 ns/iter` | `1,637 MB/s` | `3.06x faster` |
| BLAKE2b, 694,200 B (default) | `416,176.15 ns/iter` | – | `595,433.70 ns/iter` | – | `1.43x faster` |
| BLAKE2b, 694,200 B (portable SIMD) | `1,396,414.70 ns/iter` | – | `595,304.30 ns/iter` | – | `2.35x slower` |
| ML-KEM-768 key generation | `5,847.78 ns/iter` | – | `17,374.14 ns/iter` | – | `2.97x faster` |
| ML-KEM-768 encapsulation | `5,877.16 ns/iter` | – | `20,134.39 ns/iter` | – | `3.43x faster` |
| ML-KEM-768 decapsulation | `6,822.12 ns/iter` | – | `26,407.69 ns/iter` | – | `3.87x faster` |
| X-Wing key generation | `13,734.76 ns/iter` | – | `31,096.76 ns/iter` | – | `2.26x faster` |
| X-Wing encapsulation | `35,302.57 ns/iter` | – | `69,826.22 ns/iter` | – | `1.98x faster` |
| X-Wing decapsulation | `40,131.50 ns/iter` | – | `94,104.02 ns/iter` | – | `2.34x faster` |

The baseline AArch64 target already has NEON, the SVE2/`sha3` kernels carry
their own `target_feature`s, and the Poly1305/BLAKE2b/field code is baseline
`asm!` — so every default row lands within 2.4% of native either way
(ML-KEM decapsulation is 1.9% faster without the flag). Only the already-slow
portable-SIMD BLAKE2b gets worse without native (another 1.8x).

## Benchmark Coverage

Which implementation each build uses on each machine:

| Algorithm | Xeon: software / default build | Xeon: `simd_backend,nightly` build | Neoverse V3: software / default build | Neoverse V3: `simd_backend,nightly` build | libsodium baseline |
| --- | --- | --- | --- | --- | --- |
| Poly1305 | `poly1305_soft` + runtime `poly1305_x86_64` (AVX2 / AVX-512F / AVX-512 IFMA) | same; `poly1305_simd` compiled for tests only | `poly1305_soft` + `poly1305_aarch64` `asm!` block loops | same; `poly1305_simd` compiled for tests only | `libsodium_poly1305_*_bench` |
| XSalsa20-Poly1305 secretbox | `salsa20_x86_64` (AVX2 / AVX-512) + Poly1305 above | same; `salsa20_simd` compiled for tests only | `salsa20_neon` (NEON / NEON+`sha3` / SVE2) + Poly1305 above | same; `salsa20_simd` compiled for tests only | `libsodium_secretbox_detached_*_bench` |
| Argon2id password hashing | runtime `argon2_x86_64` (AVX2 / AVX-512F), else `argon2_soft` | runtime `argon2_x86_64`, else `argon2_simd` | runtime `argon2_neon` (SVE2), else `argon2_soft` | runtime `argon2_neon`, else `argon2_simd` | `libsodium_argon2id_*_bench` |
| BLAKE2b | `blake2b_soft` + runtime `blake2b_x86_64` (AVX2 / AVX-512VL) | `blake2b_simd` | `blake2b_soft` + `blake2b_aarch64` rounds | `blake2b_simd` | `libsodium_blake2b_bench` |
| ML-KEM-768 and X-Wing | `mlkem_soft` + runtime `mlkem_x86_64` (AVX2), 4-way AVX2 Keccak | same kernels, yet 12–44% faster in this run (see above) | `mlkem_soft` + runtime `mlkem_neon`, 3-way (`keccak3_aarch64`) or 2-way SHA3-extension Keccak, X25519 on the `fe64_aarch64` field | same | `libsodium_mlkem768_*_bench`, `libsodium_xwing_*_bench` |

Add a section when a second implementation lands or performance work starts on
an uncovered algorithm.
