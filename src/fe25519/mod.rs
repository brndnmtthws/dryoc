//! Arithmetic in GF(2^255 - 19), the Curve25519 field.
//!
//! Elements use five radix-2^51 limbs, the representation of dalek's
//! `FieldElement51` and libsodium's `fe51`. On AArch64 the multiply, square and
//! multiply-by-121666 are the register-only `asm!` blocks of `fe25519_aarch64`;
//! elsewhere they are the equivalent `u128` schoolbook products of
//! `fe25519_soft`. Every operation is branch-free and
//! its memory access pattern is independent of the values.

use zeroize::Zeroize;

#[cfg(target_arch = "aarch64")]
mod fe25519_aarch64;
#[cfg(target_arch = "aarch64")]
use fe25519_aarch64 as backend;

#[cfg(any(not(target_arch = "aarch64"), test))]
mod fe25519_soft;
#[cfg(not(target_arch = "aarch64"))]
use fe25519_soft as backend;

const MASK51: u64 = (1u64 << 51) - 1;
/// The curve constant `d = -121665 / 121666`.
pub(crate) const EDWARDS_D: Fe = Fe([
    0x0003_4dca_1359_78a3,
    0x0001_a828_3b15_6ebd,
    0x0005_e7a2_6001_c029,
    0x0007_39c6_63a0_3cbb,
    0x0005_2036_cee2_b6ff,
]);

/// `sqrt(-1) = 2^((p - 1) / 4)`, the nonnegative root.
pub(crate) const SQRT_M1: Fe = Fe([
    0x0006_1b27_4a0e_a0b0,
    0x0000_d5a5_fc8f_189d,
    0x0007_ef5e_9cbd_0c60,
    0x0007_8595_a680_4c9e,
    0x0002_b832_4804_fc1d,
]);

/// Element of GF(2^255 - 19) as five little-endian radix-2^51 limbs.
///
/// Multiply and square results are weakly reduced (each limb below
/// `2^51 + 2^13`); [`Fe::add`] and [`Fe::sub`] outputs are the limb sums (below
/// `2^53`), so inputs to [`Fe::mul`] and [`Fe::square`] stay below the `2^54`
/// per limb their column sums are sized for. The ladder never adds or
/// subtracts an unreduced value. Every operation is branch-free and touches
/// memory independently of the values.
#[derive(Clone, Copy, Zeroize)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);
    pub(crate) const ZERO: Fe = Fe([0; 5]);

    /// Decodes a little-endian 255-bit value, ignoring the top bit of `b`.
    #[inline(always)]
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    /// Canonical little-endian encoding of the fully reduced value.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut l = self.reduce().0;
        // `l` is below 2^255 but may still be in [p, 2^255): compute q = 1 in
        // that case by propagating the carry of (l + 19) and subtract q * p
        // by adding 19 * q and dropping bit 255.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK51;
        l[2] += l[1] >> 51;
        l[1] &= MASK51;
        l[3] += l[2] >> 51;
        l[2] &= MASK51;
        l[4] += l[3] >> 51;
        l[3] &= MASK51;
        l[4] &= MASK51;

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&(l[0] | (l[1] << 51)).to_le_bytes());
        out[8..16].copy_from_slice(&((l[1] >> 13) | (l[2] << 38)).to_le_bytes());
        out[16..24].copy_from_slice(&((l[2] >> 26) | (l[3] << 25)).to_le_bytes());
        out[24..32].copy_from_slice(&((l[3] >> 39) | (l[4] << 12)).to_le_bytes());
        out
    }

    /// Carries every limb once; limbs below 2^64 - 2^59 come out below
    /// `2^51 + 19 * 2^13`.
    #[inline(always)]
    fn reduce(self) -> Fe {
        let l = self.0;
        Fe([
            (l[0] & MASK51) + (l[4] >> 51) * 19,
            (l[1] & MASK51) + (l[0] >> 51),
            (l[2] & MASK51) + (l[1] >> 51),
            (l[3] & MASK51) + (l[2] >> 51),
            (l[4] & MASK51) + (l[3] >> 51),
        ])
    }

    #[inline(always)]
    pub(crate) fn add(&self, b: &Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        Fe([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    /// `self - b`, adding `2p` limb-wise first so nothing underflows for
    /// reduced `b`; the result (limbs below 2^53) is not reduced, which the
    /// multiply and square bounds allow.
    #[inline(always)]
    pub(crate) fn sub(&self, b: &Fe) -> Fe {
        debug_assert!(b.is_reduced(), "sub needs a reduced subtrahend");
        let a = self.0;
        let b = b.0;
        Fe([
            (a[0] + 0xF_FFFF_FFFF_FFDA) - b[0],
            (a[1] + 0xF_FFFF_FFFF_FFFE) - b[1],
            (a[2] + 0xF_FFFF_FFFF_FFFE) - b[2],
            (a[3] + 0xF_FFFF_FFFF_FFFE) - b[3],
            (a[4] + 0xF_FFFF_FFFF_FFFE) - b[4],
        ])
    }

    #[inline(always)]
    pub(crate) fn mul(&self, b: &Fe) -> Fe {
        debug_assert!(self.fits_mul_input() && b.fits_mul_input());
        Fe(backend::mul(&self.0, &b.0))
    }

    #[inline(always)]
    pub(crate) fn square(&self) -> Fe {
        debug_assert!(self.fits_mul_input());
        Fe(backend::square(&self.0))
    }

    /// Multiplies by the curve constant `(A + 2) / 4 = 121666`.
    #[inline(always)]
    pub(crate) fn mul_121666(&self) -> Fe {
        Fe(backend::mul_121666(&self.0))
    }

    #[inline(always)]
    pub(crate) fn pow2k(&self, k: u32) -> Fe {
        let mut r = *self;
        for _ in 0..k {
            r = r.square_chain();
        }
        r
    }

    /// Square for long dependent chains ([`Fe::pow2k`]): both backends
    /// reduce with two parallel carry passes, which shortens the critical
    /// path of a chain of squarings but needs a bounded input. Chain inputs
    /// are always multiply or square outputs (limbs below `2^51 + 2^13`), and
    /// each backend's output satisfies its own input bound again:
    /// `fe25519_soft::square_chain` takes limbs below `2^51 + 2^13` and
    /// returns limbs below `2^51 + 2^12`; `fe25519_aarch64::square_chain`
    /// takes limbs below `2^52` and returns limbs below `2^51 + 2^16`.
    #[inline(always)]
    fn square_chain(&self) -> Fe {
        Fe(backend::square_chain(&self.0))
    }

    /// `(self^(2^250 - 1), self^11)`, the shared prefix of the inversion and
    /// square-root exponentiations.
    #[inline(always)]
    fn pow22501(&self) -> (Fe, Fe) {
        let t0 = self.square(); // 2
        let t1 = t0.square().square(); // 8
        let t2 = self.mul(&t1); // 9
        let t3 = t0.mul(&t2); // 11
        let t4 = t3.square(); // 22
        let t5 = t2.mul(&t4); // 2^5 - 1
        let t6 = t5.pow2k(5).mul(&t5); // 2^10 - 1
        let t7 = t6.pow2k(10).mul(&t6); // 2^20 - 1
        let t8 = t7.pow2k(20).mul(&t7); // 2^40 - 1
        let t9 = t8.pow2k(10).mul(&t6); // 2^50 - 1
        let t10 = t9.pow2k(50).mul(&t9); // 2^100 - 1
        let t11 = t10.pow2k(100).mul(&t10); // 2^200 - 1
        (t11.pow2k(50).mul(&t9), t3) // 2^250 - 1
    }

    /// `self^(p - 2)` by the standard 254-squaring, 11-multiply chain.
    ///
    /// On x86-64 with BMI2 the chain runs in a copy compiled for `mulx`
    /// (see [`crate::x86_64::has_bmi2`]); the arithmetic is the same code.
    pub(crate) fn invert(&self) -> Fe {
        #[cfg(target_arch = "x86_64")]
        if crate::x86_64::has_bmi2() {
            // SAFETY: `invert_bmi2` requires the `bmi2` target feature, which
            // the runtime check above confirmed is present.
            return unsafe { self.invert_bmi2() };
        }
        self.invert_impl()
    }

    #[inline(always)]
    fn invert_impl(&self) -> Fe {
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(&t3) // 2^255 - 21
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi2")]
    fn invert_bmi2(&self) -> Fe {
        self.invert_impl()
    }

    /// `self^((p - 5) / 8) = self^(2^252 - 3)`.
    #[inline(always)]
    fn pow_p58(&self) -> Fe {
        let (t19, _) = self.pow22501();
        t19.pow2k(2).mul(self)
    }

    /// Square root of `u / v` when it exists (dalek's `sqrt_ratio_i`).
    ///
    /// Returns `(true, sqrt(u / v))` when `u / v` is a nonzero square,
    /// `(true, 0)` when `u` is zero, `(false, sqrt(i * u / v))` when `u / v`
    /// is a nonsquare and `(false, 0)` when `v` is zero. The root is the
    /// nonnegative one. Selection is by masks, so timing does not depend on
    /// the values.
    ///
    /// On x86-64 with BMI2 the exponentiation runs in a copy compiled for
    /// `mulx`, as in [`Fe::invert`].
    pub(crate) fn sqrt_ratio_i(u: &Fe, v: &Fe) -> (bool, Fe) {
        #[cfg(target_arch = "x86_64")]
        if crate::x86_64::has_bmi2() {
            // SAFETY: `sqrt_ratio_i_bmi2` requires the `bmi2` target feature,
            // which the runtime check above confirmed is present.
            return unsafe { Self::sqrt_ratio_i_bmi2(u, v) };
        }
        Self::sqrt_ratio_i_impl(u, v)
    }

    #[inline(always)]
    fn sqrt_ratio_i_impl(u: &Fe, v: &Fe) -> (bool, Fe) {
        // Accept sum/difference inputs: `neg` and `ct_eq` below need reduced
        // operands.
        let (u, v) = (&u.reduce(), &v.reduce());
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut r = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let check = v.mul(&r.square());

        let neg_u = u.neg();
        let correct_sign = check.ct_eq(u);
        let flipped_sign = check.ct_eq(&neg_u);
        let flipped_sign_i = check.ct_eq(&neg_u.mul(&SQRT_M1));

        let r_prime = r.mul(&SQRT_M1);
        r.conditional_assign(&r_prime, flipped_sign | flipped_sign_i);
        let neg_r = r.neg();
        r.conditional_assign(&neg_r, 0u64.wrapping_sub(u64::from(r.is_negative())));

        ((correct_sign | flipped_sign) != 0, r)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi2")]
    fn sqrt_ratio_i_bmi2(u: &Fe, v: &Fe) -> (bool, Fe) {
        Self::sqrt_ratio_i_impl(u, v)
    }

    /// All-ones when `self == other`, zero otherwise, from the canonical
    /// encodings.
    pub(crate) fn ct_eq(&self, other: &Fe) -> u64 {
        use subtle::ConstantTimeEq;
        0u64.wrapping_sub(u64::from(
            self.to_bytes().ct_eq(&other.to_bytes()).unwrap_u8(),
        ))
    }

    /// Whether every limb is below 2^54, the multiply and square input bound.
    fn fits_mul_input(&self) -> bool {
        self.0.iter().all(|&l| l < 1 << 54)
    }

    /// Whether every limb is below 2^52, the bound that makes the `2p` bias in
    /// [`Fe::sub`] sufficient (weakly reduced values are far below it).
    fn is_reduced(&self) -> bool {
        self.0.iter().all(|&l| l < 1 << 52)
    }

    /// `-self` for reduced `self`, as `2p - self` limb-wise (limbs below 2^52,
    /// valid as a multiply or add input).
    #[inline(always)]
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// Replaces `self` with `other` when `mask` is all ones and leaves it when
    /// `mask` is zero, with the same operations either way.
    #[inline(always)]
    pub(crate) fn conditional_assign(&mut self, other: &Fe, mask: u64) {
        for (x, y) in self.0.iter_mut().zip(other.0) {
            *x ^= mask & (*x ^ y);
        }
    }

    /// Whether the canonical encoding is odd (the Ed25519 sign bit).
    pub(crate) fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Swaps `a` and `b` when `swap` is 1 and leaves them when it is 0, using
    /// the same loads, stores and masks either way.
    #[inline(always)]
    pub(crate) fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::utils::test_util::{XorShift64, hex32 as hex};

    /// The field prime `2^255 - 19`.
    pub(super) fn prime() -> BigUint {
        (BigUint::from(1u8) << 255) - 19u8
    }

    /// The integer the (possibly unreduced) limbs represent.
    pub(super) fn limbs_to_int(limbs: &[u64; 5]) -> BigUint {
        limbs
            .iter()
            .rev()
            .fold(BigUint::ZERO, |acc, &l| (acc << 51) + l)
    }

    /// Canonical little-endian encoding of `v mod p`.
    pub(super) fn encode(v: &BigUint) -> [u8; 32] {
        let bytes = (v % prime()).to_bytes_le();
        let mut out = [0u8; 32];
        out[..bytes.len()].copy_from_slice(&bytes);
        out
    }

    fn int(fe: &Fe) -> BigUint {
        limbs_to_int(&fe.0)
    }

    fn bytes_to_int(bytes: &[u8; 32]) -> BigUint {
        BigUint::from_bytes_le(bytes)
    }

    /// Structured operands: 0, 1, 2, p - 1, p, p + 1, 2^255 - 1 and limb
    /// vectors at the reduced (2^51), sub-bias (2^52) and multiply-input
    /// (2^54) bounds.
    fn edge_operands() -> Vec<Fe> {
        let p_minus_1 = hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let mut two = [0u8; 32];
        two[0] = 2;
        vec![
            Fe::ZERO,
            Fe::ONE,
            Fe::from_bytes(&two),
            Fe::from_bytes(&p_minus_1),
            Fe([MASK51 - 18, MASK51, MASK51, MASK51, MASK51]),
            Fe([MASK51 - 17, MASK51, MASK51, MASK51, MASK51]),
            Fe([MASK51; 5]),
            Fe([
                (1 << 52) - 19 - 1,
                (1 << 52) - 1,
                (1 << 52) - 1,
                (1 << 52) - 1,
                (1 << 52) - 1,
            ]),
            Fe([(1 << 54) - 1; 5]),
            Fe([(1 << 54) - 1, 0, 0, 0, (1 << 54) - 1]),
            Fe([0, 0, 0, 0, (1 << 54) - 1]),
            Fe([0, (1 << 54) - 1, 0, 0, 0]),
        ]
    }

    /// Multiply, square, multiply-by-121666, add, subtract, negate, `pow2k`
    /// and invert equal the big-integer results modulo `p` on structured edge
    /// operands and random limb vectors at the 2^51 and 2^54 bounds, `square`
    /// equals `mul` of an element with itself, and `0^-1 = 0`.
    #[test]
    fn test_field_ops_against_bigint() {
        let p = prime();
        let mut rng = XorShift64::new(0x9b05_688c_2b3e_6c1f);
        let mut operands = edge_operands();
        for i in 0..96 {
            let mask = (1u64 << if i % 2 == 0 { 54 } else { 51 }) - 1;
            operands.push(Fe(std::array::from_fn(|_| rng.next_u64() & mask)));
            operands.push(Fe::from_bytes(&rng.next_bytes32()));
        }
        // Subtrahends must be reduced; production only ever subtracts
        // multiply outputs and decoded bytes (limbs below 2^51 + 2^13).
        let weakly_reduced = |fe: &Fe| fe.0.iter().all(|&l| l < (1 << 51) + (1 << 13));
        let reduced: Vec<Fe> = operands.iter().copied().filter(weakly_reduced).collect();
        assert!(reduced.len() > operands.len() / 2);

        let m121666 = BigUint::from(121666u32);
        for (i, a) in operands.iter().enumerate() {
            let ia = int(a);
            let square = a.square();
            assert_eq!(square.to_bytes(), encode(&(&ia * &ia)), "square {i}");
            assert_eq!(square.to_bytes(), a.mul(a).to_bytes(), "square vs mul {i}");
            assert_eq!(
                a.mul_121666().to_bytes(),
                encode(&(&ia * &m121666)),
                "mul_121666 {i}"
            );
            // `pow2k` chains `square_chain`, which takes multiply outputs.
            let ia2 = &ia * &ia;
            for k in [1u32, 5, 50] {
                let exponent = BigUint::from(1u8) << k;
                assert_eq!(
                    square.pow2k(k).to_bytes(),
                    encode(&ia2.modpow(&exponent, &p)),
                    "pow2k {i} {k}"
                );
            }
            let inverse = if ia.clone() % &p == BigUint::ZERO {
                BigUint::ZERO
            } else {
                ia.modpow(&(&p - 2u8), &p)
            };
            assert_eq!(a.invert().to_bytes(), encode(&inverse), "invert {i}");

            for (j, b) in operands.iter().enumerate().step_by(7) {
                let ib = int(b);
                assert_eq!(a.mul(b).to_bytes(), encode(&(&ia * &ib)), "mul {i} {j}");
                assert_eq!(a.add(b).to_bytes(), encode(&(&ia + &ib)), "add {i} {j}");
            }
            for (j, b) in reduced.iter().enumerate() {
                let ib = int(b);
                // a - b = a + (p - b mod p).
                let minus_b = &p - (&ib % &p);
                assert_eq!(
                    a.sub(b).to_bytes(),
                    encode(&(&ia + &minus_b)),
                    "sub {i} {j}"
                );
                assert_eq!(b.neg().to_bytes(), encode(&minus_b), "neg {j}");
            }
        }
        assert_eq!(Fe::ZERO.invert().to_bytes(), [0u8; 32]);
        assert_eq!(
            Fe([MASK51 - 18, MASK51, MASK51, MASK51, MASK51])
                .invert()
                .to_bytes(),
            [0u8; 32],
            "p^-1 = 0^-1 = 0"
        );
    }

    /// Decoding reads exactly the low 255 bits and encoding fully reduces:
    /// `p - 1`, `p`, `p + 1` and `2^255 - 1`, each with bit 255 clear and
    /// set, decode to the integer below bit 255 and encode to that integer
    /// modulo `p`; unreduced limb vectors of the same values encode the same
    /// way.
    #[test]
    fn test_canonical_encoding_at_field_boundary() {
        let p = prime();
        for (low_byte, reduced) in [
            (0xecu8, &p - 1u8),
            (0xed, BigUint::ZERO),
            (0xee, BigUint::from(1u8)),
            (0xff, BigUint::from(18u8)),
        ] {
            let mut encoding = [0xff; 32];
            encoding[0] = low_byte;
            encoding[31] = 0x7f;
            let mut high_bit = encoding;
            high_bit[31] = 0xff;
            let value = bytes_to_int(&encoding);
            assert_eq!(&value % &p, reduced);
            for bytes in [encoding, high_bit] {
                let fe = Fe::from_bytes(&bytes);
                assert_eq!(int(&fe), value, "from_bytes {bytes:02x?}");
                assert!(fe.is_reduced());
                assert_eq!(fe.to_bytes(), encode(&value), "to_bytes {bytes:02x?}");
                assert_eq!(Fe::from_bytes(&fe.to_bytes()).to_bytes(), fe.to_bytes());
            }
        }

        // Unreduced representations: 2p, 2p + 1, 2^255 - 1 as all-ones limbs,
        // and limbs at the multiply-input bound.
        let two_p = Fe([
            (1 << 52) - 38,
            (1 << 52) - 2,
            (1 << 52) - 2,
            (1 << 52) - 2,
            (1 << 52) - 2,
        ]);
        assert_eq!(int(&two_p), &p * 2u8);
        let mut two_p_plus_1 = two_p;
        two_p_plus_1.0[0] += 1;
        for fe in [
            two_p,
            two_p_plus_1,
            Fe([MASK51; 5]),
            Fe([(1 << 54) - 1; 5]),
            Fe([0, 0, 0, 0, (1 << 54) - 1]),
        ] {
            assert_eq!(fe.to_bytes(), encode(&int(&fe)), "{:x?}", fe.0);
        }
    }

    /// `sqrt_ratio_i` returns exactly what its contract says for every
    /// small `u / v` (including zero `u` and zero `v`), random ratios and
    /// ratios built to be squares or non-squares: the flag is Euler's
    /// criterion, the root is the unique nonnegative (even) `r` with
    /// `v r^2 = u` or, for a non-square, `v r^2 = i u`.
    #[test]
    fn test_sqrt_ratio_against_bigint() {
        let p = prime();
        let i = int(&SQRT_M1);
        assert_eq!(BigUint::from(2u8).modpow(&((&p - 1u8) >> 2), &p), i);
        let euler = (&p - 1u8) >> 1;

        let mut rng = XorShift64::new(0x1f83_d9ab_5be0_cd19);
        let mut cases: Vec<(Fe, Fe)> = Vec::new();
        for u in 0..=12u64 {
            for v in 0..=12u64 {
                cases.push((Fe([u, 0, 0, 0, 0]), Fe([v, 0, 0, 0, 0])));
            }
        }
        for _ in 0..32 {
            let u = Fe::from_bytes(&rng.next_bytes32());
            let v = Fe::from_bytes(&rng.next_bytes32());
            cases.push((u, v));
            // v r^2 / v = r^2 is a square; i r^2 is not, as i is a non-square
            // (p = 5 mod 8).
            let r = Fe::from_bytes(&rng.next_bytes32());
            let vr2 = v.mul(&r.square());
            cases.push((vr2, v));
            cases.push((vr2.mul(&SQRT_M1), v));
            // Sum/difference inputs, as decompression passes them.
            cases.push((
                u.square().sub(&Fe::ONE),
                u.square().mul(&EDWARDS_D).add(&Fe::ONE),
            ));
        }

        let mut squares = 0;
        for (u, v) in cases {
            let (iu, iv) = (int(&u) % &p, int(&v) % &p);
            let (is_square, r) = Fe::sqrt_ratio_i(&u, &v);
            let ir = int(&r) % &p;
            assert!(r.is_reduced());
            // A zero numerator is a square with root zero even when `v` is
            // zero too (dalek's `sqrt_ratio_i` order of precedence).
            if iu == BigUint::ZERO {
                assert!(is_square, "u = 0: {:x?}", v.0);
                assert_eq!(ir, BigUint::ZERO, "u = 0: {:x?}", v.0);
                continue;
            }
            if iv == BigUint::ZERO {
                assert!(!is_square, "v = 0: {:x?}", u.0);
                assert_eq!(ir, BigUint::ZERO, "v = 0: {:x?}", u.0);
                continue;
            }
            let ratio = &iu * iv.modpow(&(&p - 2u8), &p) % &p;
            let expected_square = ratio.modpow(&euler, &p) == BigUint::from(1u8);
            assert_eq!(is_square, expected_square, "{:x?} / {:x?}", u.0, v.0);
            squares += usize::from(is_square);
            assert!(!r.is_negative(), "{:x?} / {:x?}", u.0, v.0);
            assert_eq!(r.to_bytes()[0] & 1, 0);
            let r2 = &ir * &ir % &p;
            let target = if is_square { ratio } else { &ratio * &i % &p };
            assert_eq!(r2, target, "{:x?} / {:x?}", u.0, v.0);
        }
        assert!(squares > 40);
    }

    /// The register-only operations agree with the portable u128 versions,
    /// and their outputs are weakly reduced (every limb below 2^51 + 2^13,
    /// so they are valid inputs to the next operation), on random operands
    /// at the top of the allowed input range (limbs up to 2^54), on reduced
    /// ones, and on structured edge values.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_asm_operations_match_portable() {
        const WEAK_BOUND: u64 = (1 << 51) + (1 << 13);
        const CHAIN_BOUND: u64 = (1 << 51) + (1 << 16);

        let mut rng = crate::utils::test_util::XorShift64::new(0x2545_f491_4f6c_dd1d);
        let mut operands: Vec<(Fe, Fe)> = (0..5000)
            .map(|i| {
                let bits = if i % 2 == 0 { 54 } else { 51 };
                let mask = (1u64 << bits) - 1;
                let mut limbs = || Fe(std::array::from_fn(|_| rng.next_u64() & mask));
                (limbs(), limbs())
            })
            .collect();
        // Zero, one, p - 1, 2^255 - 1 (p + 18), p itself, 2p - 1 and all
        // limbs at their maxima, against one another.
        let p_minus_1 = Fe::from_bytes(&hex(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ));
        let edges = [
            Fe::ZERO,
            Fe::ONE,
            p_minus_1,
            Fe([MASK51; 5]),
            Fe([MASK51 - 18, MASK51, MASK51, MASK51, MASK51]),
            Fe([
                (1 << 52) - 19 - 1,
                (1 << 52) - 1,
                (1 << 52) - 1,
                (1 << 52) - 1,
                (1 << 52) - 1,
            ]),
            Fe([(1 << 54) - 1; 5]),
            Fe([(1 << 54) - 1, 0, 0, 0, (1 << 54) - 1]),
            Fe([0, 0, 0, 0, (1 << 54) - 1]),
        ];
        operands.extend(
            edges
                .iter()
                .flat_map(|a| edges.iter().map(move |b| (*a, *b))),
        );

        let weakly_reduced = |v: &Fe| v.0.iter().all(|&l| l < WEAK_BOUND);
        let chain_reduced = |v: &Fe| v.0.iter().all(|&l| l < CHAIN_BOUND);
        for (i, (a, b)) in operands.iter().enumerate() {
            let product = a.mul(b);
            assert_eq!(
                product.to_bytes(),
                Fe(fe25519_soft::mul(&a.0, &b.0)).to_bytes(),
                "mul {i}"
            );
            assert!(weakly_reduced(&product), "mul {i} bound: {:x?}", product.0);

            let square = a.square();
            assert_eq!(
                square.to_bytes(),
                Fe(fe25519_soft::square(&a.0)).to_bytes(),
                "square {i}"
            );
            assert!(weakly_reduced(&square), "square {i} bound: {:x?}", square.0);

            let scaled = a.mul_121666();
            assert_eq!(
                scaled.to_bytes(),
                Fe(fe25519_soft::mul_121666(&a.0)).to_bytes(),
                "mul_121666 {i}"
            );
            assert!(
                weakly_reduced(&scaled),
                "mul_121666 {i} bound: {:x?}",
                scaled.0
            );

            // `square_chain` takes reduced inputs (the asm form limbs below
            // 2^52, the portable form below 2^51 + 2^13); feed both the
            // weakly reduced square, as the exponentiation chains do. The asm
            // output bound is 2^51 + 2^16 (the portable one, checked in
            // `fe25519_soft::tests`, is 2^51 + 2^12); both are valid inputs
            // to their own backend again.
            let chained = square.square_chain();
            assert_eq!(
                chained.to_bytes(),
                Fe(fe25519_soft::square_chain(&square.0)).to_bytes(),
                "square_chain {i}"
            );
            assert!(
                chain_reduced(&chained),
                "square_chain {i} bound: {:x?}",
                chained.0
            );
        }

        // A long dependent chain, as in the inversion: 254 chained squarings
        // stay within the chain bound and agree with the portable squarings.
        // The seed is a square output, as every chain input is (the portable
        // form does not accept the wider `add` outputs).
        let mut asm = p_minus_1.add(&Fe([MASK51; 5])).square();
        let mut soft = asm.0;
        for k in 0..254 {
            asm = asm.square_chain();
            soft = fe25519_soft::square_chain(&soft);
            assert!(chain_reduced(&asm), "chain {k} bound: {:x?}", asm.0);
            assert_eq!(asm.to_bytes(), Fe(soft).to_bytes(), "chain {k}");
        }
    }

    /// `d` and `sqrt(-1)` are the values they claim to be, and the square
    /// root finds roots exactly when they exist.
    #[test]
    fn test_constants_and_sqrt_ratio() {
        let m121666 = Fe([121666, 0, 0, 0, 0]);
        let m121665 = Fe([121665, 0, 0, 0, 0]);
        assert_eq!(EDWARDS_D.mul(&m121666).to_bytes(), m121665.neg().to_bytes());
        assert_eq!(SQRT_M1.square().to_bytes(), Fe::ONE.neg().to_bytes());
        assert!(!SQRT_M1.is_negative());

        // 4 / 1 has root 2; 2 is a nonsquare mod p (p = 5 mod 8).
        let four = Fe([4, 0, 0, 0, 0]);
        let two = Fe([2, 0, 0, 0, 0]);
        let (ok, r) = Fe::sqrt_ratio_i(&four, &Fe::ONE);
        assert!(ok);
        assert_eq!(r.to_bytes(), two.to_bytes());
        let (ok, r) = Fe::sqrt_ratio_i(&two, &Fe::ONE);
        assert!(!ok);
        // The returned value is sqrt(i * 2).
        assert_eq!(r.square().to_bytes(), two.mul(&SQRT_M1).to_bytes());
        // 9 / 4 has root 3/2 = 3 * 2^-1.
        let nine = Fe([9, 0, 0, 0, 0]);
        let (ok, r) = Fe::sqrt_ratio_i(&nine, &four);
        assert!(ok);
        assert_eq!(r.square().mul(&four).to_bytes(), nine.to_bytes());
        // u = 0 is a square with root 0; v = 0 is rejected.
        let (ok, r) = Fe::sqrt_ratio_i(&Fe::ZERO, &four);
        assert!(ok);
        assert_eq!(r.to_bytes(), Fe::ZERO.to_bytes());
        let (ok, _) = Fe::sqrt_ratio_i(&four, &Fe::ZERO);
        assert!(!ok);
    }
}
