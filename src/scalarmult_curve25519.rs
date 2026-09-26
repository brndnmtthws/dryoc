//! X25519 scalar multiplication.
//!
//! The fixed-base function multiplies the Ed25519 basepoint through the
//! in-crate precomputed table ([`crate::edwards25519`]) and maps the result to
//! its Montgomery u coordinate, which is far faster than a ladder; the scalar
//! is first reduced modulo the group order, as libsodium does. The
//! variable-base function is the RFC 7748 Montgomery ladder over the in-crate
//! field [`crate::fe25519::Fe`] (its four-limb `Fe64` on AArch64); inlining
//! the whole ladder step is what dalek's out-of-line field multiply prevents.

use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_SCALARMULT_CURVE25519_BYTES, CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES,
};
use crate::edwards25519::mul_base;
use crate::fe25519::Fe;
#[cfg(all(target_arch = "aarch64", not(miri)))]
use crate::fe25519::Fe64;

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

/// `Point::to_montgomery` may stay out of line (it does at opt-level `z`,
/// `s` and `2`), which adds no copy: it only gets `&point`, wiped here, and
/// wipes its own `Z - Y` and inverse. The `zeroize` calls only get `&mut`
/// to the storage they wipe.
pub(crate) fn crypto_scalarmult_curve25519_base(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
) {
    let mut clamped = clamp(n);
    let mut point = mul_base(&clamped);
    *q = point.to_montgomery();
    clamped.zeroize();
    point.zeroize();
}

/// `shared = X25519(n, p)` and `public = X25519(n, 9)` (the base point),
/// as [`crypto_scalarmult_curve25519`] and
/// [`crypto_scalarmult_curve25519_base`] give them, with one field inversion
/// for both quotients (Montgomery's trick): `1 / (Z_s W_b)` times `W_b` and
/// `Z_s`. The base point's denominator `Z - Y` is never zero (a clamped
/// scalar is not a multiple of the group order), so `public` is right
/// whenever `shared` is not all zero; for a low-order `p`, where `shared`
/// is all zero, `public` is zero too, and callers reject that case.
///
/// On AArch64 with NEON the base-point multiplication runs as
/// [`BaseSteps`](crate::edwards25519::BaseSteps), one table addition after
/// each of the ladder's first steps: the two are independent, and the
/// ladder's carry chains leave the multipliers idle often enough that the
/// additions mostly fit in its gaps (measured 0.9 us of `mul_base`'s 5.9
/// saved on Neoverse V3). The `steps` local is wiped by its `finish`.
pub(crate) fn crypto_scalarmult_curve25519_and_base(
    shared: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    public: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    let mut clamped = clamp(n);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))]
    let ((mut x, mut z), mut point) = {
        let mut steps = crate::edwards25519::BaseSteps::new(&clamped);
        let xz = ladder_xz_with(n, p, &mut steps);
        (xz, steps.finish())
    };
    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon", not(miri))))]
    let ((mut x, mut z), mut point) = {
        #[cfg(target_arch = "x86_64")]
        let xz = match crate::x86_64::Bmi2::new() {
            Some(bmi2) => ladder_xz_bmi2(bmi2, n, p),
            None => ladder_xz(n, p),
        };
        #[cfg(not(target_arch = "x86_64"))]
        let xz = ladder_xz(n, p);
        (xz, mul_base(&clamped))
    };
    let (mut u, mut w) = point.montgomery_ratio();
    let mut zw = z.mul(&w);
    let mut inv = zw.invert();
    let mut s = x.mul(&w).mul(&inv);
    let mut b = u.mul(&z).mul(&inv);
    *shared = s.to_bytes_inline();
    *public = b.to_bytes_inline();

    clamped.zeroize();
    point.zeroize();
    for fe in [
        &mut x, &mut z, &mut u, &mut w, &mut zw, &mut inv, &mut s, &mut b,
    ] {
        fe.zeroize();
    }
}

/// On x86-64 with BMI2 the ladder runs in a copy compiled for `mulx` (see
/// [`crate::x86_64::Bmi2`]); the arithmetic is the same code.
pub(crate) fn crypto_scalarmult_curve25519(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    #[cfg(target_arch = "x86_64")]
    if let Some(bmi2) = crate::x86_64::Bmi2::new() {
        return ladder_bmi2(bmi2, q, n, p);
    }
    ladder(q, n, p)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
fn ladder_bmi2_unchecked(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    ladder(q, n, p)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
fn ladder_xz_bmi2_unchecked(
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) -> (Fe, Fe) {
    ladder_xz(n, p)
}

/// [`ladder_xz_bmi2_unchecked`], safe to call with a
/// [`crate::x86_64::Bmi2`] token.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn ladder_xz_bmi2(
    _: crate::x86_64::Bmi2,
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) -> (Fe, Fe) {
    // SAFETY: a `Bmi2` token exists only after detection of `bmi2`,
    // the feature the ladder copy is compiled for.
    unsafe { ladder_xz_bmi2_unchecked(n, p) }
}

/// [`ladder_bmi2_unchecked`], safe to call with a [`crate::x86_64::Bmi2`]
/// token.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn ladder_bmi2(
    _: crate::x86_64::Bmi2,
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    // SAFETY: a `Bmi2` token exists only after detection of `bmi2`,
    // the feature the ladder copy is compiled for.
    unsafe { ladder_bmi2_unchecked(q, n, p) }
}

/// The RFC 7748 Montgomery ladder; see [`crypto_scalarmult_curve25519`].
///
/// On AArch64 the ladder runs on the four-limb [`Fe64`] (see
/// `fe64_aarch64.rs`), whose products take a quarter fewer multiplies, and
/// converts the result to [`Fe`] for the inversion and encoding.
///
/// The `zeroize` calls (out of line at opt-level `z` and `s`) only get
/// `&mut` to the storage they wipe.
#[inline(always)]
fn ladder(
    q: &mut [u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) {
    let (mut x, mut z) = ladder_xz(n, p);
    let mut zinv = z.invert();
    let mut shared = x.mul(&zinv);
    *q = shared.to_bytes_inline();

    x.zeroize();
    z.zeroize();
    zinv.zeroize();
    shared.zeroize();
}

/// Independent work run after each of the first [`LadderExtra::STEPS`]
/// ladder steps.
trait LadderExtra {
    const STEPS: usize;
    fn step(&mut self, j: usize);
}

/// No extra work.
impl LadderExtra for () {
    const STEPS: usize = 0;

    #[inline(always)]
    fn step(&mut self, _: usize) {}
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))]
impl LadderExtra for crate::edwards25519::BaseSteps {
    const STEPS: usize = Self::STEPS;

    #[inline(always)]
    fn step(&mut self, j: usize) {
        Self::step(self, j)
    }
}

/// The ladder's projective result `(X, Z)`, `u = X / Z`, before the
/// inversion. The caller wipes both.
#[inline(always)]
fn ladder_xz(
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
) -> (Fe, Fe) {
    ladder_xz_with(n, p, &mut ())
}

/// [`ladder_xz`], running `extra`'s steps after the first ladder steps.
#[inline(always)]
fn ladder_xz_with<E: LadderExtra>(
    n: &[u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_CURVE25519_BYTES],
    extra: &mut E,
) -> (Fe, Fe) {
    let mut clamped = clamp(n);
    // RFC 7748 requires X25519 implementations to ignore the most significant
    // bit of the final input byte for compatibility with existing point
    // formats; `from_bytes` drops it.
    let x1 = Field::from_bytes(p);

    let mut x2 = Field::ONE;
    let mut z2 = Field::ZERO;
    let mut x3 = x1;
    let mut z3 = Field::ONE;
    let mut swap = 0u64;

    // RFC 7748 section 5 ladder. Every step performs the same operations on
    // the same registers; the secret scalar only selects `cswap` masks.
    // Clamping clears bits 0 to 2 of every scalar, so the last three steps
    // are unrolled below as the doublings they reduce to.
    for t in (3..255).rev() {
        let bit = u64::from((clamped[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        Field::cswap(&mut x2, &mut x3, swap);
        Field::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let b = x2.sub(&z2);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        // Independent products are adjacent, so the out-of-order window
        // holds two or three at a time while each one's carry chain runs.
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let aa = a.square();
        let bb = b.square();
        let sum = da.add(&cb);
        let diff = da.sub(&cb);
        let e = aa.sub(&bb);
        x3 = sum.square();
        let diff2 = diff.square();
        x2 = aa.mul(&bb);
        // z2 = E * (BB + (A + 2) / 4 * E), with (A + 2) / 4 = 121666.
        let bb_e = e.mul_121666_add(&bb);
        z3 = x1.mul(&diff2);
        z2 = e.mul(&bb_e);
        let j = 254 - t;
        if j < E::STEPS {
            extra.step(j);
        }
    }
    Field::cswap(&mut x2, &mut x3, swap);
    Field::cswap(&mut z2, &mut z3, swap);
    // Steps 2, 1 and 0: with a zero bit a step's `cswap`s are no-ops after
    // the one above, and of its outputs only the doubling `(x2, z2)` is used
    // afterwards; these are that step's own `x2` and `z2` formulas.
    for _ in 0..3 {
        let aa = x2.add(&z2).square();
        let bb = x2.sub(&z2).square();
        let e = aa.sub(&bb);
        x2 = aa.mul(&bb);
        z2 = e.mul(&e.mul_121666_add(&bb));
    }

    let xz = (to_fe(x2), to_fe(z2));

    clamped.zeroize();
    x2.zeroize();
    z2.zeroize();
    x3.zeroize();
    z3.zeroize();
    xz
}

/// The ladder's field: [`Fe64`] on AArch64, [`Fe`] elsewhere.
#[cfg(all(target_arch = "aarch64", not(miri)))]
type Field = Fe64;
#[cfg(not(all(target_arch = "aarch64", not(miri))))]
type Field = Fe;

#[cfg(all(target_arch = "aarch64", not(miri)))]
#[inline(always)]
fn to_fe(x: Fe64) -> Fe {
    x.to_fe()
}

#[cfg(not(all(target_arch = "aarch64", not(miri))))]
#[inline(always)]
fn to_fe(x: Fe) -> Fe {
    x
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

    /// The shared-inversion pair equals the separate ladder and base-point
    /// multiplications on random, near-`p` and small `u` and on scalars
    /// with the bits clamping touches set; for a low-order `u` (all-zero
    /// shared secret, which callers reject, including `p` and `p + 1` among
    /// the near-`p` inputs) both outputs are zero.
    #[test]
    fn test_and_base_matches_separate_calls() {
        let mut rng = XorShift64::new(0x3c6e_f372_fe94_f82b);
        for i in 0..if cfg!(miri) { 6 } else { 500 } {
            let mut k = rng.next_bytes32();
            if i % 5 == 0 {
                k = [0xff; 32];
                k[1] = rng.next_u64() as u8;
            }
            let u = match i % 3 {
                0 => rng.next_bytes32(),
                1 => field_prime_plus((rng.next_u64() % 19) as i8 - 1),
                _ => {
                    let mut u = [0u8; 32];
                    u[0] = 2 + (rng.next_u64() as u8) % 32;
                    u
                }
            };
            let (mut shared, mut public, mut base) = ([0u8; 32], [0u8; 32], [0u8; 32]);
            crypto_scalarmult_curve25519_and_base(&mut shared, &mut public, &k, &u);
            crypto_scalarmult_curve25519_base(&mut base, &k);
            assert_eq!(shared, x25519(&k, &u), "shared {i}");
            // `p` and `p + 1` are the low-order 0 and 1.
            let expected = if shared == [0u8; 32] { [0u8; 32] } else { base };
            assert_eq!(public, expected, "public {i}");
        }
        for u in low_order_u_encodings() {
            let (mut shared, mut public) = ([1u8; 32], [1u8; 32]);
            crypto_scalarmult_curve25519_and_base(&mut shared, &mut public, &[0x42; 32], &u);
            assert_eq!((shared, public), ([0u8; 32], [0u8; 32]), "u {u:02x?}");
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
