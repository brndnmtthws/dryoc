// On AArch64 and x86-64 the portable-SIMD backend is slower than the u128
// 3-limb implementation with its NEON or AVX2 bulk path, so the soft backend
// is used there even with `simd_backend`; the portable backend is still
// compiled for tests there so every backend is checked against the others.
#[cfg(all(
    feature = "simd_backend",
    feature = "nightly",
    any(test, not(any(target_arch = "aarch64", target_arch = "x86_64")))
))]
pub(crate) mod poly1305_simd;

#[cfg(any(
    test,
    target_arch = "aarch64",
    target_arch = "x86_64",
    not(all(feature = "simd_backend", feature = "nightly"))
))]
pub(crate) mod poly1305_soft;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
pub(crate) mod poly1305_neon;

#[cfg(target_arch = "x86_64")]
pub(crate) mod poly1305_x86_64;

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
const M26: u64 = (1 << 26) - 1;
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
const M44: u64 = (1 << 44) - 1;
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
const M42: u64 = (1 << 42) - 1;

/// Multiplies two 3x44-bit limb values modulo `2^130 - 5`, returning a
/// partially reduced result (limbs `< 2^44`, `< 2^44 + small`, `< 2^42 +
/// small`). Mirrors the scalar block multiplication in `poly1305_soft.rs`.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
fn mul_mod_p(a: &[u64; 3], b: &[u64; 3]) -> [u64; 3] {
    let mul = |x: u64, y: u64| u128::from(x) * u128::from(y);
    let s1 = b[1] * (5 << 2);
    let s2 = b[2] * (5 << 2);

    let d0 = mul(a[0], b[0]) + mul(a[1], s2) + mul(a[2], s1);
    let mut d1 = mul(a[0], b[1]) + mul(a[1], b[0]) + mul(a[2], s2);
    let mut d2 = mul(a[0], b[2]) + mul(a[1], b[1]) + mul(a[2], b[0]);

    let mut c = (d0 >> 44) as u64;
    let mut h0 = (d0 as u64) & M44;
    d1 += u128::from(c);
    c = (d1 >> 44) as u64;
    let mut h1 = (d1 as u64) & M44;
    d2 += u128::from(c);
    c = (d2 >> 42) as u64;
    let h2 = (d2 as u64) & M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;

    [h0, h1, h2]
}

/// Fully reduces a partially reduced 3x44-bit value to its canonical
/// representative below `2^130 - 5` (limbs exactly 44/44/42 bits).
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
fn canonical(h: &[u64; 3]) -> [u64; 3] {
    let (mut h0, mut h1, mut h2) = (h[0], h[1], h[2]);

    let mut c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    c = h2 >> 42;
    h2 &= M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    c = h2 >> 42;
    h2 &= M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;

    // Constant-time conditional subtraction of p.
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 44;
    g0 &= M44;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 44;
    g1 &= M44;
    let g2 = h2.wrapping_add(c).wrapping_sub(1u64 << 42);

    let mask = (g2 >> 63).wrapping_sub(1);
    [
        (h0 & !mask) | (g0 & mask),
        (h1 & !mask) | (g1 & mask),
        (h2 & !mask) | (g2 & mask),
    ]
}

/// Splits canonical 44/44/42-bit limbs into 5x26-bit limbs.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
fn limbs26(h: [u64; 3]) -> [u32; 5] {
    let [h0, h1, h2] = h;
    [
        (h0 & M26) as u32,
        (((h0 >> 26) | (h1 << 18)) & M26) as u32,
        ((h1 >> 8) & M26) as u32,
        (((h1 >> 34) | (h2 << 10)) & M26) as u32,
        (h2 >> 16) as u32,
    ]
}

/// Sums per-lane 5x26-bit limbs (each below `2^30`) into the scalar
/// backend's partially reduced 3x44-bit form: carries so `l1..l4 < 2^26` and
/// `l0 < 2^26 + 2^5`, repacks the 130-bit value (the low four limbs fit a
/// `u128`; the top limb is added to `h2` separately) and carries once more.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
fn pack_limbs26(mut l: [u64; 5]) -> [u64; 3] {
    let mut c = l[0] >> 26;
    l[0] &= M26;
    l[1] += c;
    c = l[1] >> 26;
    l[1] &= M26;
    l[2] += c;
    c = l[2] >> 26;
    l[2] &= M26;
    l[3] += c;
    c = l[3] >> 26;
    l[3] &= M26;
    l[4] += c;
    c = l[4] >> 26;
    l[4] &= M26;
    l[0] += c * 5;

    let v = u128::from(l[0])
        + (u128::from(l[1]) << 26)
        + (u128::from(l[2]) << 52)
        + (u128::from(l[3]) << 78);
    [
        (v as u64) & M44,
        ((v >> 44) as u64) & M44,
        ((v >> 88) as u64) + (l[4] << 16),
    ]
}

/// One more carry pass over 3x44-bit limbs whose sums may exceed the limb
/// widths, returning the scalar backend's partially reduced form.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
fn carry44(h: [u64; 3]) -> [u64; 3] {
    let [mut h0, mut h1, mut h2] = h;
    let mut c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    c = h2 >> 42;
    h2 &= M42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= M44;
    h1 += c;
    [h0, h1, h2]
}

const BLOCK_SIZE: usize = 16;

#[inline]
fn pad_partial_block(buffer: &[u8]) -> [u8; BLOCK_SIZE] {
    debug_assert!(buffer.len() < BLOCK_SIZE);

    let mut block = [0u8; BLOCK_SIZE];
    block[..buffer.len()].copy_from_slice(buffer);
    block[buffer.len()] = 1;
    block
}

#[cfg(all(test, feature = "nightly", not(tarpaulin)))]
mod bench_inputs {
    pub(super) const BYTES_64: usize = 64;
    pub(super) const KIB_1: usize = 1024;
    pub(super) const KIB_16: usize = 16 * 1024;
    pub(super) const MIB_1: usize = 1024 * 1024;
}

#[cfg(all(
    feature = "simd_backend",
    feature = "nightly",
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
pub(crate) use poly1305_simd::*;
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "x86_64",
    not(all(feature = "simd_backend", feature = "nightly"))
))]
pub(crate) use poly1305_soft::*;
