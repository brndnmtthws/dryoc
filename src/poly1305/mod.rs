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

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
pub(crate) mod poly1305_neon;

#[cfg(target_arch = "x86_64")]
pub(crate) mod poly1305_x86_64;

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    target_arch = "x86_64"
))]
const M26: u64 = (1 << 26) - 1;
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    target_arch = "x86_64"
))]
const M44: u64 = (1 << 44) - 1;
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
    target_arch = "x86_64"
))]
const M42: u64 = (1 << 42) - 1;

/// Multiplies two 3x44-bit limb values modulo `2^130 - 5`, returning a
/// partially reduced result (limbs `< 2^44`, `< 2^44 + small`, `< 2^42 +
/// small`). Mirrors the scalar block multiplication in `poly1305_soft.rs`.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
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
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
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
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
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
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
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
    all(target_arch = "aarch64", target_endian = "little", not(miri)),
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

/// Tests of the production `Poly1305` type, whichever backend it resolves to
/// on this target; the backend modules test their own internals.
#[cfg(test)]
mod tests {
    use super::{BLOCK_SIZE, Key, Poly1305};

    fn mac(key: &[u8; 32], chunks: &[&[u8]]) -> [u8; BLOCK_SIZE] {
        let mut mac = Poly1305::new(&Key::from(key));
        for chunk in chunks {
            mac.update(chunk);
        }
        mac.finalize_to_array()
    }

    /// RFC 8439 appendix A.3 test vectors #5 to #11 (#1 to #4 are in the
    /// backend tests): the final-reduction edge cases, where `h` lands on
    /// `2^130 - 5` or `2^130 - 6`, the pad addition overflows `2^128`, a
    /// partially reduced `h` is not yet canonical, and the `5 * high` carry
    /// produces a 131-bit intermediate or final result.
    #[test]
    fn rfc8439_a3_final_reduction_vectors() {
        const R2: &str = "02000000000000000000000000000000";
        const R1: &str = "01000000000000000000000000000000";
        const R1_4: &str = "01000000000000000400000000000000";
        const S0: &str = "00000000000000000000000000000000";
        const SFF: &str = "ffffffffffffffffffffffffffffffff";
        const FF: &str = "ffffffffffffffffffffffffffffffff";
        // (r, s, message, tag)
        let vectors: [(&str, &str, &str, &str); 7] = [
            (R2, S0, FF, "03000000000000000000000000000000"),
            (
                R2,
                SFF,
                "02000000000000000000000000000000",
                "03000000000000000000000000000000",
            ),
            (
                R1,
                S0,
                concat!(
                    "ffffffffffffffffffffffffffffffff",
                    "f0ffffffffffffffffffffffffffffff",
                    "11000000000000000000000000000000",
                ),
                "05000000000000000000000000000000",
            ),
            (
                R1,
                S0,
                concat!(
                    "ffffffffffffffffffffffffffffffff",
                    "fbfefefefefefefefefefefefefefefe",
                    "01010101010101010101010101010101",
                ),
                "00000000000000000000000000000000",
            ),
            (
                R2,
                S0,
                "fdffffffffffffffffffffffffffffff",
                "faffffffffffffffffffffffffffffff",
            ),
            (
                R1_4,
                S0,
                concat!(
                    "e33594d7505e43b90000000000000000",
                    "3394d7505e4379cd0100000000000000",
                    "00000000000000000000000000000000",
                    "01000000000000000000000000000000",
                ),
                "14000000000000005500000000000000",
            ),
            (
                R1_4,
                S0,
                concat!(
                    "e33594d7505e43b90000000000000000",
                    "3394d7505e4379cd0100000000000000",
                    "00000000000000000000000000000000",
                ),
                "13000000000000000000000000000000",
            ),
        ];
        for (index, (r, s, message, tag)) in vectors.iter().enumerate() {
            let key: [u8; 32] = hex::decode(format!("{r}{s}")).unwrap().try_into().unwrap();
            let message = hex::decode(message).unwrap();
            let tag: [u8; 16] = hex::decode(tag).unwrap().try_into().unwrap();
            assert_eq!(mac(&key, &[&message]), tag, "vector #{}", index + 5);
            // Split inside every block, so the buffered path reaches the
            // same final reduction.
            let (head, rest) = message.split_at(message.len().min(7));
            assert_eq!(mac(&key, &[head, rest]), tag, "vector #{} split", index + 5);
        }
    }

    /// `r` with only its clamped bits set (top four bits of bytes 3, 7, 11
    /// and 15, low two bits of bytes 4, 8 and 12): clamps to zero, so the
    /// tag is exactly `s` whatever the message.
    fn clamped_bits_only() -> [u8; 16] {
        let mut r = [0u8; 16];
        for i in [3, 7, 11, 15] {
            r[i] = 0xf0;
        }
        for i in [4, 8, 12] {
            r[i] = 0x03;
        }
        r
    }

    /// A key whose `r` clamps to zero authenticates every message to its
    /// pad `s`, here `2^128 - 1`, one-shot and split; lengths reach past the
    /// bulk-path thresholds so every route clamps.
    #[test]
    fn clamped_r_yields_the_pad() {
        let mut key = [0xffu8; 32];
        key[..16].copy_from_slice(&clamped_bits_only());
        for len in [0usize, 1, 16, 17, 480, 481, 2048, 2049] {
            let message = vec![0xa5u8; len];
            assert_eq!(mac(&key, &[&message]), [0xff; 16], "len {len}");
            if len > 1 {
                assert_eq!(
                    mac(&key, &[&message[..1], &message[1..]]),
                    [0xff; 16],
                    "len {len}"
                );
            }
        }
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;
        use crate::utils::test_util::XorShift64;

        fn sodium_mac(key: &[u8; 32], message: &[u8]) -> [u8; BLOCK_SIZE] {
            let mut tag = [0u8; BLOCK_SIZE];
            // SAFETY: `tag` is `crypto_onetimeauth_BYTES` long, `message` is
            // valid for its length and `key` is `crypto_onetimeauth_KEYBYTES`.
            let rc = unsafe {
                libsodium_sys::crypto_onetimeauth(
                    tag.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            tag
        }

        /// Keys stressing clamping, the limb carries and the pad addition:
        /// all-ones, all-zero, the clamped bits alone, the clamped bits alone
        /// inverted (the largest `r`) with `s = 2^128 - 5`, and two
        /// deterministic random keys.
        fn keys() -> Vec<([u8; 32], &'static str)> {
            let mut rng = XorShift64::new(0x9e37_79b9_7f4a_7c15);
            let mut clamp_only = [0xffu8; 32];
            clamp_only[..16].copy_from_slice(&clamped_bits_only());
            let mut max_r = [0u8; 32];
            for (byte, clamped) in max_r.iter_mut().zip(clamped_bits_only()) {
                *byte = !clamped;
            }
            max_r[16..].fill(0xff);
            max_r[16] = 0xfb;
            vec![
                ([0xffu8; 32], "all-ones"),
                ([0u8; 32], "all-zero"),
                (clamp_only, "clamped bits only, s = 2^128 - 1"),
                (max_r, "largest r, s = 2^128 - 5"),
                (rng.next_bytes32(), "random 1"),
                (rng.next_bytes32(), "random 2"),
            ]
        }

        /// The bulk-path thresholds and chunk sizes of this target's driver.
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        const THRESHOLDS: &[usize] = &[480];
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        const CHUNKS: &[usize] = &[160];
        #[cfg(target_arch = "x86_64")]
        const THRESHOLDS: &[usize] = &[256, 512, 1024, 2048];
        #[cfg(target_arch = "x86_64")]
        const CHUNKS: &[usize] = &[128, 256];
        #[cfg(not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86_64"
        )))]
        const THRESHOLDS: &[usize] = &[];
        #[cfg(not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86_64"
        )))]
        const CHUNKS: &[usize] = &[64];

        /// Block boundaries, the 160-byte lane-set boundary, and every bulk
        /// threshold with a whole and a partial block before and after it.
        fn lens() -> Vec<usize> {
            let mut lens = vec![0, 1, 15, 16, 17, 31, 32, 33, 159, 160, 161];
            for &threshold in THRESHOLDS {
                lens.extend([
                    threshold - 17,
                    threshold - 16,
                    threshold - 1,
                    threshold,
                    threshold + 1,
                    threshold + 16,
                    threshold + 17,
                ]);
                for &chunk in CHUNKS {
                    lens.extend([
                        threshold + chunk - 1,
                        threshold + chunk,
                        threshold + chunk + 1,
                    ]);
                }
            }
            lens.sort_unstable();
            lens.dedup();
            lens
        }

        /// Update boundaries for a message of `len` bytes: inside the first
        /// block, at every block edge, and at every chunk boundary and one
        /// byte either side of it, so partial blocks are pending both before
        /// and after the bulk run.
        fn splits(len: usize) -> Vec<usize> {
            let mut splits = vec![1, 15, 16, 17];
            for &chunk in CHUNKS {
                for boundary in (chunk..len).step_by(chunk) {
                    splits.extend([boundary - 1, boundary, boundary + 1]);
                }
            }
            splits.retain(|&split| split < len);
            splits.sort_unstable();
            splits.dedup();
            splits
        }

        /// The production driver against libsodium for every key, message
        /// pattern and length around the bulk-path thresholds, one-shot and
        /// split at every chunk boundary and one byte either side.
        #[test]
        fn matches_libsodium_around_bulk_thresholds() {
            let max_len = *lens().last().unwrap();
            let mut rng = XorShift64::new(0xd1b5_4a32_d192_ed03);
            let random: Vec<u8> = (0..max_len.div_ceil(8))
                .flat_map(|_| rng.next_u64().to_le_bytes())
                .collect();
            let messages: [(&[u8], &str); 3] = [
                (&vec![0xffu8; max_len], "all-ones"),
                (&vec![0u8; max_len], "all-zero"),
                (&random, "random"),
            ];
            for (key, key_name) in keys() {
                for (data, message_name) in messages {
                    for len in lens() {
                        let message = &data[..len];
                        let expected = sodium_mac(&key, message);
                        assert_eq!(
                            mac(&key, &[message]),
                            expected,
                            "{key_name}, {message_name} message, len {len}"
                        );
                        for split in splits(len) {
                            assert_eq!(
                                mac(&key, &[&message[..split], &message[split..]]),
                                expected,
                                "{key_name}, {message_name} message, len {len}, split {split}"
                            );
                        }
                    }
                }
            }
        }
    }
}
