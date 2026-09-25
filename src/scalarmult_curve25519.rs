//! X25519 scalar multiplication.
//!
//! The fixed-base function multiplies the Ed25519 basepoint through the
//! in-crate precomputed table ([`crate::edwards25519`]) and maps the result to
//! its Montgomery u coordinate, which is far faster than a ladder; the scalar
//! is first reduced modulo the group order, as libsodium does. The
//! variable-base function is the RFC 7748 Montgomery ladder over the in-crate
//! field [`crate::fe25519::Fe`]; inlining the whole ladder step is what dalek's
//! out-of-line field multiply prevents.

use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_SCALARMULT_CURVE25519_BYTES, CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES,
};
use crate::edwards25519::mul_base;
use crate::fe25519::Fe;

/// Clamps `s` in place into a valid X25519 scalar: clears the low three bits
/// (cofactor), clears the top bit, and sets bit 254 (fixed leading bit).
#[inline]
pub(crate) fn clamp_scalar(s: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

fn clamp(
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
) -> [u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES] {
    let mut s = *n;
    clamp_scalar(&mut s);
    s
}

pub(crate) fn crypto_scalarmult_curve25519_base(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
) {
    let mut clamped = clamp(n);
    *q = mul_base(&clamped).to_montgomery();
    clamped.zeroize();
}

/// On x86-64 with BMI2 the ladder runs in a copy compiled for `mulx` (see
/// [`crate::x86_64::has_bmi2`]); the arithmetic is the same code.
pub(crate) fn crypto_scalarmult_curve25519(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    #[cfg(target_arch = "x86_64")]
    if crate::x86_64::has_bmi2() {
        // SAFETY: `ladder_bmi2` requires the `bmi2` target feature, which
        // the feature check above confirmed is present.
        return unsafe { ladder_bmi2(q, n, p) };
    }
    ladder(q, n, p)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
fn ladder_bmi2(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    ladder(q, n, p)
}

/// The RFC 7748 Montgomery ladder; see [`crypto_scalarmult_curve25519`].
#[inline(always)]
fn ladder(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    let mut clamped = clamp(n);
    // RFC 7748 requires X25519 implementations to ignore the most significant
    // bit of the final input byte for compatibility with existing point
    // formats; `Fe::from_bytes` drops it.
    let x1 = Fe::from_bytes(p);

    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;

    // RFC 7748 section 5 ladder. Every step performs the same operations on
    // the same registers; the secret scalar only selects `cswap` masks.
    for t in (0..255).rev() {
        let bit = u64::from((clamped[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let b = x2.sub(&z2);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let aa = a.square();
        let bb = b.square();
        let da = d.mul(&a);
        let cb = c.mul(&b);
        // Products that need only AA and BB come first so they fill the
        // multiplier while the DA/CB-dependent chain below is still carrying.
        let e = aa.sub(&bb);
        x2 = aa.mul(&bb);
        // z2 = E * (BB + (A + 2) / 4 * E), with (A + 2) / 4 = 121666.
        z2 = e.mul(&bb.add(&e.mul_121666()));
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);

    let mut shared = x2.mul(&z2.invert());
    *q = shared.to_bytes();

    clamped.zeroize();
    shared.zeroize();
    x2.zeroize();
    z2.zeroize();
    x3.zeroize();
    z3.zeroize();
}

/// Inputs shared by the X25519 unit tests and the `crypto_core`, `crypto_kx`
/// and `crypto_box` tests.
#[cfg(test)]
pub(crate) mod test_vectors {
    /// The seven `u` encodings whose X25519 output is all zero: libsodium's
    /// `has_small_order` blacklist, in its order (0, 1, the two order-8
    /// points, `p - 1`, `p` and `p + 1`). X25519 ignores bit 255, so each
    /// also stands for the encoding with that bit set.
    pub(crate) const LOW_ORDER_U: [[u8; 32]; 7] = [
        [0; 32],
        {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        },
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        field_prime_plus(-1),
        field_prime_plus(0),
        field_prime_plus(1),
    ];

    /// Little-endian `2^255 - 19 + offset` for small `offset`, with bit 255
    /// clear.
    pub(crate) const fn field_prime_plus(offset: i8) -> [u8; 32] {
        let mut bytes = [0xff; 32];
        bytes[0] = (0xed + offset as i16) as u8;
        bytes[31] = 0x7f;
        bytes
    }

    /// [`LOW_ORDER_U`] with bit 255 clear and set: fourteen encodings.
    pub(crate) fn low_order_u_encodings() -> [[u8; 32]; 14] {
        let mut all = [[0u8; 32]; 14];
        for (i, u) in LOW_ORDER_U.iter().enumerate() {
            all[2 * i] = *u;
            all[2 * i + 1] = *u;
            all[2 * i + 1][31] |= 0x80;
        }
        all
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::montgomery::MontgomeryPoint;

    use super::test_vectors::{field_prime_plus, low_order_u_encodings};
    use super::*;
    use crate::utils::test_util::{XorShift64, hex32 as hex};

    fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        let mut q = [0u8; 32];
        crypto_scalarmult_curve25519(&mut q, k, u);
        q
    }

    /// RFC 7748 section 5.2 vectors, including the non-canonical `u`
    /// (>= p) in the second one.
    #[test]
    fn test_rfc7748_vectors() {
        assert_eq!(
            x25519(
                &hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                &hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            ),
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
        assert_eq!(
            x25519(
                &hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                &hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            ),
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    /// RFC 7748 section 5.2 iterated vector (1 and 1,000 iterations) and the
    /// section 6.1 Diffie-Hellman exchange.
    #[test]
    fn test_rfc7748_iterated_and_dh() {
        let base = {
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        };
        let mut k = base;
        let mut u = base;
        // Keep the single-iteration vector and DH exchange under Miri; the
        // 1,000-iteration stress vector runs in the native suite.
        for i in 1..=if cfg!(miri) { 1 } else { 1000 } {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k,
                    hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        #[cfg(not(miri))]
        assert_eq!(
            k,
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );

        let a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = x25519(&a, &base);
        let b_pub = x25519(&b, &base);
        assert_eq!(
            a_pub,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b_pub,
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &b_pub), shared);
        assert_eq!(x25519(&b, &a_pub), shared);
        let mut q = [0u8; 32];
        crypto_scalarmult_curve25519_base(&mut q, &a);
        assert_eq!(q, a_pub);
    }

    /// The ladder agrees with `curve25519-dalek` on random inputs and on
    /// encodings around the field boundary: values near `p` and `2^255`,
    /// small values (including the low-order points 0 and 1), and inputs with
    /// the ignored top bit set.
    #[test]
    fn test_matches_dalek_on_random_and_boundary_inputs() {
        let mut rng = XorShift64::new(0x9e37_79b9_7f4a_7c15);
        for i in 0..if cfg!(miri) { 12 } else { 2000 } {
            let k = rng.next_bytes32();
            let mut u = rng.next_bytes32();
            match i % 4 {
                1 => {
                    u = [0xff; 32];
                    u[0] = rng.next_u64() as u8;
                }
                2 => {
                    u = [0; 32];
                    u[0] = (rng.next_u64() as u8) & 0x1f;
                }
                _ => {}
            }
            if i % 3 == 0 {
                u[31] |= 0x80;
            }
            let mut masked = u;
            masked[31] &= 0x7f;
            let expected = MontgomeryPoint(masked).mul_clamped(k).0;
            assert_eq!(x25519(&k, &u), expected, "input {i}");
        }
    }

    /// Every low-order `u` (libsodium's blacklist, with and without bit 255)
    /// multiplies to the all-zero output for any clamped scalar, which is
    /// what `crypto_scalarmult` turns into an error; dalek's ladder agrees.
    #[test]
    fn test_low_order_inputs_yield_zero() {
        let mut rng = XorShift64::new(0x6a09_e667_f3bc_c908);
        let scalars = [[0u8; 32], [0xff; 32], [0x42; 32], rng.next_bytes32()];
        for u in low_order_u_encodings() {
            let mut masked = u;
            masked[31] &= 0x7f;
            for k in scalars {
                assert_eq!(x25519(&k, &u), [0u8; 32], "u {u:02x?}");
                assert_eq!(MontgomeryPoint(masked).mul_clamped(k).0, [0u8; 32]);
            }
        }
    }

    /// `p + j` and `2^255 + p + j` decode to the same field element as `j`
    /// (RFC 7748 section 5: the top bit is ignored, the value reduced), so
    /// the four encodings of every `j` in `0..=18` (up to `2^256 - 1`) give
    /// the same output as dalek does for the canonical `j`.
    #[test]
    fn test_noncanonical_u_matches_reduced_u() {
        let mut rng = XorShift64::new(0xbb67_ae85_84ca_a73b);
        for j in 0..=18u8 {
            let mut canonical = [0u8; 32];
            canonical[0] = j;
            let mut canonical_high = canonical;
            canonical_high[31] |= 0x80;
            let unreduced = field_prime_plus(j as i8);
            let mut unreduced_high = unreduced;
            unreduced_high[31] |= 0x80;
            assert_eq!(unreduced_high[31], 0xff);

            let k = rng.next_bytes32();
            let expected = MontgomeryPoint(canonical).mul_clamped(k).0;
            for u in [canonical, canonical_high, unreduced, unreduced_high] {
                assert_eq!(x25519(&k, &u), expected, "j {j}, u {u:02x?}");
            }
        }
    }
}
