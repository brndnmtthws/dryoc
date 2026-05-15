use std::ops::{Deref, DerefMut, Mul};
use std::simd::{simd_swizzle, Simd, SimdUint};

use zeroize::Zeroize;

use crate::utils::load_u32_le;

#[derive(Clone, Copy, Zeroize)]
pub struct U130<State: U130State> {
    s: State,
}

#[derive(Clone, Copy, Zeroize)]
pub struct Reduced {
    #[zeroize(skip)]
    v: Simd<u32, 8>,
}
#[derive(Clone, Copy, Zeroize)]
pub struct Unreduced {
    #[zeroize(skip)]
    v: Simd<u64, 8>,
}
pub trait U130State {
    type Output;
    fn v(&self) -> &Self::Output;
}
impl U130State for Reduced {
    type Output = Simd<u32, 8>;

    fn v(&self) -> &Self::Output {
        &self.v
    }
}
impl U130State for Unreduced {
    type Output = Simd<u64, 8>;

    fn v(&self) -> &Self::Output {
        &self.v
    }
}

impl U130<Reduced> {
    pub fn to_u32_digits(&self) -> Vec<u32> {
        let mut v = *self.s.v();

        let lsb_mask = Simd::splat(0x3ffffff);
        let carry_shift = Simd::splat(26);
        let mut v_shift = Simd::from([6, 6, 6, 6, 0, 0, 0, 0]);

        for _ in 0..4 {
            let carry = (v & lsb_mask).rotate_lanes_right::<1>() << carry_shift;

            v >>= v_shift;
            v |= carry;

            v_shift = v_shift.rotate_lanes_right::<1>();
        }
        Vec::from(&v.to_array()[3..8])
    }

    pub fn from_u32_digits(v: &[u32]) -> Self {
        assert_eq!(v.len(), 5);
        let v = Simd::from([0, 0, 0, v[0], v[1], v[2], v[3], v[4]]);

        Self::u32x8_to_u130(v)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let v = Simd::from([
            0,
            0,
            0,
            0,
            load_u32_le(&bytes[0..4]),
            load_u32_le(&bytes[4..8]),
            load_u32_le(&bytes[8..12]),
            load_u32_le(&bytes[12..16]),
        ]);

        Self::u32x8_to_u130(v)
    }

    #[inline]
    pub fn u32x8_to_u130(mut v: Simd<u32, 8>) -> Self {
        let lsb_mask = Simd::splat(0x3ffffff);
        let msb_mask = Simd::splat(0xfc000000);
        let carry_shift = Simd::splat(26);
        let mut v_shift = Simd::from([0, 0, 0, 6, 6, 6, 6, 0]);

        for _ in 0..4 {
            let carry = (v & msb_mask).rotate_lanes_left::<1>() >> carry_shift;

            v &= lsb_mask;
            v <<= v_shift;
            v |= carry;

            v_shift = v_shift.rotate_lanes_left::<1>();
        }

        Self { s: Reduced { v } }
    }

    fn reduce_sum(&self) -> u32 {
        self.s.v.reduce_sum()
    }
}

impl U130<Unreduced> {
    pub fn from_bytes(bytes: &[u8], hibit: u64) -> Self {
        let v = Simd::from([
            0,
            0,
            0,
            hibit,
            load_u32_le(&bytes[0..4]) as u64,
            load_u32_le(&bytes[4..8]) as u64,
            load_u32_le(&bytes[8..12]) as u64,
            load_u32_le(&bytes[12..16]) as u64,
        ]);

        Self { s: Unreduced { v } }
    }

    fn reduce_sum(&self) -> u64 {
        self.s.v.reduce_sum()
    }
}

impl From<Simd<u32, 8>> for U130<Reduced> {
    fn from(v: Simd<u32, 8>) -> Self {
        Self { s: Reduced { v } }
    }
}

impl From<Simd<u64, 8>> for U130<Unreduced> {
    fn from(v: Simd<u64, 8>) -> Self {
        Self { s: Unreduced { v } }
    }
}

impl U130<Unreduced> {
    #[inline]
    pub fn reduce(self) -> U130<Reduced> {
        let mask = Simd::from([
            0, 0, 0, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff,
        ]);
        self.reduce_with(mask)
    }

    #[inline]
    pub fn reduce_with(self, mask: Simd<u32, 8>) -> U130<Reduced> {
        let mut v = self.s.v;
        let lsb_mask = Simd::splat(0x3ffffff);
        let msb_mask = Simd::splat(0xfffffffffc000000);
        let carry_shift = Simd::splat(26);
        let carry_mask = Simd::from([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0,
        ]);

        for _ in 0..4 {
            let carry = (v & msb_mask).rotate_lanes_left::<1>() >> carry_shift;
            let carry = carry & carry_mask;

            v &= lsb_mask;
            v += carry;
        }

        let v = v.cast::<u32>() & mask;

        U130 { s: Reduced { v } }
    }
}

impl<'a, State: U130State> Mul for &'a U130<State>
where
    &'a State: Mul<Output = Unreduced>,
{
    type Output = U130<Unreduced>;

    /// Multiplies 2 u130s using base 26 grid multiplication with u64s.
    fn mul(self, rhs: Self) -> Self::Output {
        Self::Output {
            s: &self.s * &rhs.s,
        }
    }
}

impl<'a, 'b> Mul<&'b U130<Unreduced>> for &'a U130<Reduced> {
    type Output = U130<Unreduced>;

    /// Multiplies 2 u130s using base 26 grid multiplication with u64s.
    fn mul(self, rhs: &'b U130<Unreduced>) -> Self::Output {
        Self::Output {
            s: &self.s.upcast() * &rhs.s,
        }
    }
}

impl<'a, 'b> Mul<&'b U130<Reduced>> for &'a U130<Unreduced> {
    type Output = U130<Unreduced>;

    /// Multiplies 2 u130s using base 26 grid multiplication with u64s.
    fn mul(self, rhs: &'b U130<Reduced>) -> Self::Output {
        Self::Output {
            s: &self.s * &rhs.s.upcast(),
        }
    }
}

impl<State: U130State + Mul<Output = Unreduced>> Mul for U130<State> {
    type Output = U130<Unreduced>;

    /// Multiplies 2 u130s using base 26 grid multiplication with u64s.
    fn mul(self, rhs: Self) -> Self::Output {
        Self::Output { s: self.s * rhs.s }
    }
}

impl Mul<U130<Reduced>> for U130<Unreduced> {
    type Output = U130<Unreduced>;

    /// Multiplies 2 u130s using base 26 grid multiplication with u64s.
    fn mul(self, rhs: U130<Reduced>) -> Self::Output {
        Self::Output {
            s: self.s * rhs.s.upcast(),
        }
    }
}

impl Mul<U130<Unreduced>> for U130<Reduced> {
    type Output = U130<Unreduced>;

    /// Multiplies 2 u130s using base 26 grid multiplication with u64s.
    fn mul(self, rhs: U130<Unreduced>) -> Self::Output {
        Self::Output {
            s: self.s.upcast() * rhs.s,
        }
    }
}

impl Reduced {
    fn upcast(self) -> Unreduced {
        Unreduced { v: self.v.cast() }
    }
}

fn mul_unreduced(lhs: &Unreduced, rhs: &Unreduced) -> Simd<u64, 8> {
    let mul = lhs.v * rhs.v;
    //   100000000   1000000   10000    100      1
    // [         3,        4,      5,     6,     7]
    let acc = simd_swizzle!(mul, [0, 4, 0, 5, 0, 6, 0, 7]);

    //       10000  10000000  100000   1000     10
    // [         3,        4,      5,     6,     7]
    let mul = lhs.v * simd_swizzle!(rhs.v, [0, 1, 2, 7, 3, 4, 5, 6]);
    let acc = acc + simd_swizzle!(mul, [4, 0, 5, 3, 6, 0, 7, 0]);

    //      100000      1000 1000000  10000    100
    // [         3,        4,      5,     6,     7]
    let mul = lhs.v * simd_swizzle!(rhs.v, [0, 1, 2, 6, 7, 3, 4, 5]);
    let acc = acc + simd_swizzle!(mul, [0, 5, 3, 6, 4, 7, 0, 0]);

    //     1000000     10000     100 100000   1000
    // [         3,        4,      5,     6,     7]
    let mul = lhs.v * simd_swizzle!(rhs.v, [0, 1, 2, 5, 6, 7, 3, 4]);
    let acc = acc + simd_swizzle!(mul, [0, 3, 6, 4, 7, 5, 0, 0]);

    //    10000000    100000    1000     10  10000
    // [         3,        4,      5,     6,     7]
    let mul = lhs.v * simd_swizzle!(rhs.v, [0, 1, 2, 4, 5, 6, 7, 3]);
    let acc = acc + simd_swizzle!(mul, [3, 0, 4, 7, 5, 0, 6, 0]);

    acc
}

impl<'a> Mul for &'a Reduced {
    type Output = Unreduced;

    fn mul(self, rhs: Self) -> Self::Output {
        // upcast u32x8 to u64x8

        let acc = mul_unreduced(&self.upcast(), &rhs.upcast());

        Unreduced { v: acc }
    }
}

impl Mul for Reduced {
    type Output = Unreduced;

    fn mul(self, rhs: Self) -> Self::Output {
        let acc = mul_unreduced(&self.upcast(), &rhs.upcast());

        Unreduced { v: acc }
    }
}

impl<'a> Mul for &'a Unreduced {
    type Output = Unreduced;

    fn mul(self, rhs: Self) -> Self::Output {
        let acc = mul_unreduced(self, rhs);

        Unreduced { v: acc }
    }
}

impl Mul for Unreduced {
    type Output = Unreduced;

    fn mul(self, rhs: Self) -> Self::Output {
        let acc = mul_unreduced(&self, &rhs);

        Unreduced { v: acc }
    }
}

impl Deref for U130<Reduced> {
    type Target = Simd<u32, 8>;

    fn deref(&self) -> &Self::Target {
        &self.s.v
    }
}

impl DerefMut for U130<Reduced> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s.v
    }
}

impl Deref for U130<Unreduced> {
    type Target = Simd<u64, 8>;

    fn deref(&self) -> &Self::Target {
        &self.s.v
    }
}

impl DerefMut for U130<Unreduced> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s.v
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;

    #[test]
    fn test_u130_digits() {
        use num_bigint::RandBigInt;

        let mut rng = rand::thread_rng();
        let a = rng.gen_biguint(130);

        let mut u32_digits: Vec<_> = a.iter_u32_digits().collect();
        u32_digits.resize(5, 0);
        u32_digits.reverse();

        let u130 = U130::from_u32_digits(u32_digits.as_slice());

        let blap = u130.to_u32_digits();

        assert_eq!(u32_digits, blap);
    }

    #[test]
    fn test_u130_mul() {
        use num_bigint::RandBigInt;

        let mut rng = rand::thread_rng();
        let a = rng.gen_biguint(130);

        let mut u32_digits: Vec<_> = a.iter_u32_digits().collect();
        u32_digits.resize(5, 0);
        u32_digits.reverse();

        let u130 = U130::from_u32_digits(u32_digits.as_slice());

        // check multiplication
        let u130_squared = u130 * u130;

        let mut clamp_u130 = BigUint::from_slice(&[]);
        for i in 0..130 {
            clamp_u130.set_bit(i, true);
        }
        let a_squared = (&a * &a) & &clamp_u130;

        let mut u32_digits: Vec<_> = a_squared.iter_u32_digits().collect();
        u32_digits.resize(5, 0);
        u32_digits.reverse();

        let blap = u130_squared.reduce().to_u32_digits();

        assert_eq!(u32_digits, blap);
    }

    #[test]
    fn test_u130_mul_simple() {
        let u130_1 = U130::from_u32_digits(&[0, 0, 3, 4, 5]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 0, 0, 0]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[0, 0, 0, 0, 0], blap.as_slice());

        let u130_1 = U130::from_u32_digits(&[0, 0, 3, 4, 5]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 0, 0, 1]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[0, 0, 3, 4, 5], blap.as_slice());

        let u130_1 = U130::from_u32_digits(&[0, 0, 3, 4, 5]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 0, 0, 2]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[0, 0, 6, 8, 10], blap.as_slice());

        let u130_1 = U130::from_u32_digits(&[0, 0, 0, 1, 0]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 0, 1, 0]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[0, 0, 1, 0, 0], blap.as_slice());

        let u130_1 = U130::from_u32_digits(&[0, 0, 0, 1, 0]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 1, 0, 0]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[0, 1, 0, 0, 0], blap.as_slice());

        let u130_1 = U130::from_u32_digits(&[0, 0, 0, 1, 0]);
        let u130_2 = U130::from_u32_digits(&[0, 1, 0, 0, 0]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[1, 0, 0, 0, 0], blap.as_slice());

        let u130_1 = U130::from_u32_digits(&[1, 1, 1, 1, 1]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 0, 0, 2]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(&[2, 2, 2, 2, 2], blap.as_slice());
        let u130_1 = U130::from_u32_digits(&[u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
        let u130_2 = U130::from_u32_digits(&[0, 0, 0, 0, 1]);

        let u130_mul = u130_1 * u130_2;

        let blap = u130_mul.reduce().to_u32_digits();

        assert_eq!(
            &[3, u32::MAX, u32::MAX, u32::MAX, u32::MAX],
            blap.as_slice()
        );
    }
}
