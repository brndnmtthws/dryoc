//! Group arithmetic on edwards25519 for Ed25519 and `crypto_core`.
//!
//! Points use extended twisted Edwards coordinates over
//! [`crate::fe25519::Fe`]. Two scalar multiplications are provided:
//!
//! - [`mul_base`]: `[s]B` for a *secret* scalar `s`, through a precomputed
//!   table of basepoint multiples in affine Niels form (the layout of
//!   libsodium's `ge25519_scalarmult_base` and dalek's basepoint table). The
//!   scalar is consumed as 64 signed radix-16 digits; every digit selects a
//!   table entry with constant-time compares and conditional moves, so the
//!   sequence of operations and memory accesses does not depend on the scalar.
//! - [`Point::double_scalar_mul_basepoint_vartime`]: `[a]A + [b]B` for *public*
//!   scalars (signature verification, subgroup checks) by Straus's method over
//!   width-5 / width-8 non-adjacent forms, with branches on the digits.
//!
//! Both tables are precomputed constants in [`tables`].

use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::fe25519::{EDWARDS_D, Fe};

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod edwards25519_neon;
#[cfg(target_arch = "x86_64")]
mod edwards25519_x86_64;
mod tables;

use tables::TABLES;

/// `2 * d`, where `d = -121665 / 121666` is the curve constant.
const EDWARDS_D2: Fe = Fe([
    0x0006_9b94_26b2_f159,
    0x0003_5050_762a_dd7a,
    0x0003_cf44_c003_8052,
    0x0006_738c_c740_7977,
    0x0002_406d_9dc5_6dff,
]);

/// The basepoint order `L = 2^252 + 27742317777372353535851937790883648493`.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Point in extended coordinates: `x = X / Z`, `y = Y / Z`, `x * y = T / Z`.
///
/// Coordinates are always weakly reduced multiply outputs.
#[derive(Clone, Copy, Zeroize)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// Affine point cached for mixed addition: `(y + x, y - x, 2 d x y)`, each
/// canonically reduced.
#[derive(Clone, Copy, Zeroize)]
struct Niels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

/// Point in projective coordinates `(X : Y : Z)`, an extended point with its
/// `T` dropped. Used between consecutive doublings in the variable-time
/// double-scalar multiplication, where `T` is only needed by an addition.
#[derive(Clone, Copy)]
struct Projective {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// Extended point cached for repeated variable-base mixed addition:
/// `(Y + X, Y - X, 2 Z, 2 d T)` (dalek's `ProjectiveNielsPoint` with `Z`
/// pre-doubled). The sums are add/sub outputs (below 2^53), `t2d` a weakly
/// reduced multiply output (below 2^51 + 2^13); every field is a valid
/// `mul` operand (below 2^54) but not canonical.
#[derive(Clone, Copy)]
struct ProjectiveNiels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z2: Fe,
    t2d: Fe,
}

impl ProjectiveNiels {
    /// `-self`: swap the sums and negate `2 d T`.
    ///
    /// Only used by the variable-time verification ladder on public points,
    /// so it may stay out of line.
    fn neg(&self) -> ProjectiveNiels {
        ProjectiveNiels {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            z2: self.z2,
            t2d: self.t2d.neg(),
        }
    }
}

impl Projective {
    const IDENTITY: Projective = Projective {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    /// `E, F, G, H` of dbl-2008-hwcd with `a = -1`, all negated (the same
    /// projective point): `X3 = E F`, `Y3 = G H`, `Z3 = F G`, `T3 = E H`.
    /// Subtrahends are reduced squares and every multiply input is below
    /// 2^54 per limb.
    #[inline(always)]
    fn double_parts(&self) -> (Fe, Fe, Fe, Fe) {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(&zz);
        let s = self.x.add(&self.y).square();
        let h = a.add(&b);
        let e = h.sub(&s);
        let g = a.sub(&b);
        let f = c.add(&g);
        (e, f, g, h)
    }

    /// `2 * self` without `T` (3M + 4S).
    #[inline(always)]
    fn double(&self) -> Projective {
        let (e, f, g, h) = self.double_parts();
        Projective {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
        }
    }

    /// `2 * self` in extended coordinates (4M + 4S).
    #[inline(always)]
    fn double_extended(&self) -> Point {
        let (e, f, g, h) = self.double_parts();
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }
}

impl ConditionallySelectable for Niels {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        let mask = 0u64.wrapping_sub(u64::from(choice.unwrap_u8()));
        let mut out = *a;
        out.y_plus_x.conditional_assign(&b.y_plus_x, mask);
        out.y_minus_x.conditional_assign(&b.y_minus_x, mask);
        out.xy2d.conditional_assign(&b.xy2d, mask);
        out
    }
}

impl Niels {
    const IDENTITY: Niels = Niels {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ZERO,
    };

    /// Negates in place when `mask` is all ones.
    ///
    /// `#[inline(always)]`: [`select`] applies it to the secret-selected
    /// entry, and at opt-level `z` and `s` LLVM kept it out of line, taking
    /// `next` (which stays in registers with NEON) and the negated copy
    /// through memory.
    #[inline(always)]
    fn conditional_negate(&mut self, mask: u64) {
        let swapped = Niels {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            xy2d: self.xy2d.neg(),
        };
        self.y_plus_x.conditional_assign(&swapped.y_plus_x, mask);
        self.y_minus_x.conditional_assign(&swapped.y_minus_x, mask);
        self.xy2d.conditional_assign(&swapped.xy2d, mask);
    }
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// `self + n` (add-2008-hwcd-3 with the cached Niels operand). Every
    /// subtrahend is reduced and every multiply input is below 2^54 per limb.
    #[inline(always)]
    fn add_niels(&self, n: &Niels) -> Point {
        let pp = self.y.add(&self.x).mul(&n.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&n.y_minus_x);
        let tt = self.t.mul(&n.xy2d);
        let zz = self.z.add(&self.z);
        let e = pp.sub(&mm);
        let h = pp.add(&mm);
        let f = zz.sub(&tt);
        let g = zz.add(&tt);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// `self + n` for a cached extended operand (add-2008-hwcd-3, 8M): the
    /// `2 d T` and `2 Z` of the operand are precomputed. Subtrahends are
    /// reduced multiply outputs and every multiply input is below 2^54.
    #[inline(always)]
    fn add_projective_niels(&self, n: &ProjectiveNiels) -> Point {
        let pp = self.y.add(&self.x).mul(&n.y_plus_x);
        let mm = self.y.sub(&self.x).mul(&n.y_minus_x);
        let tt = self.t.mul(&n.t2d);
        let zz = self.z.mul(&n.z2);
        let e = pp.sub(&mm);
        let h = pp.add(&mm);
        let f = zz.sub(&tt);
        let g = zz.add(&tt);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// `2 * self` (dbl-2008-hwcd with `a = -1`, 4M + 4S).
    #[inline(always)]
    fn double(&self) -> Point {
        self.to_projective().double_extended()
    }

    /// Drops `T`.
    #[inline(always)]
    fn to_projective(self) -> Projective {
        Projective {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    /// `-self`.
    ///
    /// Only used on public points (`-A` in signature verification), so it
    /// may stay out of line.
    pub(crate) fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Cached form for repeated mixed additions of this point.
    #[inline(always)]
    fn to_projective_niels(self) -> ProjectiveNiels {
        ProjectiveNiels {
            y_plus_x: self.y.add(&self.x),
            y_minus_x: self.y.sub(&self.x),
            z2: self.z.add(&self.z),
            t2d: self.t.mul(&EDWARDS_D2),
        }
    }

    /// Whether two points are equal, by cross-multiplying the projective
    /// coordinates (no inversion). Not constant time; for public points.
    pub(crate) fn eq_vartime(&self, other: &Point) -> bool {
        self.x.mul(&other.z).to_bytes() == other.x.mul(&self.z).to_bytes()
            && self.y.mul(&other.z).to_bytes() == other.y.mul(&self.z).to_bytes()
    }

    /// Whether this is the neutral element: `x = 0` and `y = z`. Not constant
    /// time; used on public points only.
    pub(crate) fn is_identity(&self) -> bool {
        self.x.to_bytes() == Fe::ZERO.to_bytes() && self.y.to_bytes() == self.z.to_bytes()
    }

    /// Whether the point has order dividing 8 (`[8]P` is the identity).
    pub(crate) fn is_small_order(&self) -> bool {
        self.double().double().double().is_identity()
    }

    /// Whether the point lies in the prime-order subgroup: `[L]P` is the
    /// identity for the basepoint order `L`. Variable time: `L` is public.
    pub(crate) fn is_torsion_free_vartime(&self) -> bool {
        self.double_scalar_mul_basepoint_vartime(&GROUP_ORDER, &[0u8; 32])
            .is_identity()
    }

    /// Decodes an Ed25519 point encoding (RFC 8032 section 5.1.3): `y` from
    /// the low 255 bits, `x = sqrt((y^2 - 1) / (d y^2 + 1))` with the sign
    /// bit choosing the root. Returns `None` when there is no such `x`. The
    /// encoding is not required to be canonical here; callers check that.
    /// Not constant time in the sign handling; used on public encodings.
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let y = Fe::from_bytes(bytes);
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&EDWARDS_D).add(&Fe::ONE);
        let (is_square, root) = Fe::sqrt_ratio_i(&u, &v);
        if !is_square {
            return None;
        }
        // The root is nonnegative; negate it when the sign bit is set.
        let x = if bytes[31] >> 7 == 1 {
            root.neg()
        } else {
            root
        };
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }

    /// `[a]self + [b]B` for public little-endian scalars below 2^255, by
    /// Straus's method over width-5 (for `self`) and width-8 (for `B`)
    /// non-adjacent forms. Variable time in the scalars and the point.
    ///
    /// Between additions the accumulator is kept projective (`T` dropped) so
    /// a doubling that is followed only by another doubling costs 3M + 4S
    /// instead of 4M + 4S; `T` is produced only by the doubling ahead of a
    /// nonzero digit.
    ///
    /// On x86-64 with BMI2 the loop runs in a copy compiled for `mulx` (see
    /// [`crate::x86_64::Bmi2`]); the arithmetic is the same code.
    pub(crate) fn double_scalar_mul_basepoint_vartime(&self, a: &[u8; 32], b: &[u8; 32]) -> Point {
        #[cfg(target_arch = "x86_64")]
        if let Some(bmi2) = crate::x86_64::Bmi2::new() {
            return self.double_scalar_mul_basepoint_vartime_bmi2(bmi2, a, b);
        }
        self.double_scalar_mul_basepoint_vartime_impl(a, b)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi2")]
    fn double_scalar_mul_basepoint_vartime_bmi2_unchecked(
        &self,
        a: &[u8; 32],
        b: &[u8; 32],
    ) -> Point {
        self.double_scalar_mul_basepoint_vartime_impl(a, b)
    }

    /// [`Point::double_scalar_mul_basepoint_vartime_bmi2_unchecked`], safe to
    /// call with a [`crate::x86_64::Bmi2`] token.
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn double_scalar_mul_basepoint_vartime_bmi2(
        &self,
        _: crate::x86_64::Bmi2,
        a: &[u8; 32],
        b: &[u8; 32],
    ) -> Point {
        // SAFETY: a `Bmi2` token exists only after detection of
        // `bmi2`, the feature the loop copy is compiled for.
        unsafe { self.double_scalar_mul_basepoint_vartime_bmi2_unchecked(a, b) }
    }

    /// Odd multiples `self, 3 self, ..., 15 self`, cached for mixed addition.
    ///
    /// Not `#[inline(always)]` in unoptimized builds: always-inlining these
    /// point operations into the caller merges them into one wasm function
    /// with more than the 50,000 locals that wasm engines allow. In a debug
    /// build (`debug_assertions`) this is a real call boundary; release
    /// builds force the inline as before.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn odd_multiples_niels(self) -> [ProjectiveNiels; 8] {
        let double = self.double().to_projective_niels();
        let mut odd = [self.to_projective_niels(); 8];
        let mut multiple = self;
        for entry in odd.iter_mut().skip(1) {
            multiple = multiple.add_projective_niels(&double);
            *entry = multiple.to_projective_niels();
        }
        odd
    }

    #[inline(always)]
    fn double_scalar_mul_basepoint_vartime_impl(&self, a: &[u8; 32], b: &[u8; 32]) -> Point {
        let a_naf = naf::<5>(a);
        let b_naf = naf::<8>(b);

        let odd = self.odd_multiples_niels();
        let top = (0..256).rev().find(|&i| a_naf[i] != 0 || b_naf[i] != 0);
        let Some(top) = top else {
            return Point::IDENTITY;
        };
        let mut r = Projective::IDENTITY;
        for i in (1..=top).rev() {
            let da = a_naf[i];
            let db = b_naf[i];
            if da == 0 && db == 0 {
                r = r.double();
                continue;
            }
            r = Self::add_digits(r.double_extended(), &odd, da, db).to_projective();
        }
        // The final doubling always yields the extended result. When `top`
        // is 0 this is `double(identity) + digits[0]`, which is also correct.
        Self::add_digits(r.double_extended(), &odd, a_naf[0], b_naf[0])
    }

    /// `p + da * A + db * B` for NAF digits `da`, `db` (odd or zero) and the
    /// odd multiples `odd[j] = (2 j + 1) A`.
    ///
    /// Not `#[inline(always)]` in unoptimized builds, like
    /// [`Point::odd_multiples_niels`]: the debug build must not merge its
    /// point operations into the ladder function (wasm caps functions at
    /// 50,000 locals). Release builds force the inline so the BMI2 copy of
    /// the ladder keeps `mulx` codegen for these additions.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn add_digits(mut p: Point, odd: &[ProjectiveNiels; 8], da: i8, db: i8) -> Point {
        if da > 0 {
            p = p.add_projective_niels(&odd[da as usize / 2]);
        } else if da < 0 {
            p = p.add_projective_niels(&odd[(-da) as usize / 2].neg());
        }
        let basepoint_odd = &TABLES.odd;
        if db > 0 {
            p = p.add_niels(&basepoint_odd[db as usize / 2]);
        } else if db < 0 {
            let mut n = basepoint_odd[(-db) as usize / 2];
            n.conditional_negate(u64::MAX);
            p = p.add_niels(&n);
        }
        p
    }

    /// Ed25519 encoding: the y coordinate with the sign of x in the top bit.
    ///
    /// `Fe::invert` is not inlined, so `1 / Z` reaches memory as its return
    /// slot and is wiped; `x` and `y` come from inlined multiplies and stay
    /// in registers.
    pub(crate) fn compress(&self) -> [u8; 32] {
        let mut zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        zinv.zeroize();
        let mut out = y.to_bytes();
        out[31] |= u8::from(x.is_negative()) << 7;
        out
    }

    /// The Montgomery u coordinate `(1 + y) / (1 - y) = (Z + Y) / (Z - Y)`;
    /// zero for the identity, as `0^-1 = 0`.
    ///
    /// `Z - Y` is passed to the non-inlined `Fe::invert` and its inverse is
    /// returned through memory, so both are wiped; `Z + Y` stays in
    /// registers. Takes `&self` although `Point` is `Copy`: by value, callers
    /// that wipe their point afterwards would pass an unwiped copy.
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_montgomery(&self) -> [u8; 32] {
        let u = self.z.add(&self.y);
        let mut w = self.z.sub(&self.y);
        let mut winv = w.invert();
        let out = u.mul(&winv).to_bytes();
        w.zeroize();
        winv.zeroize();
        out
    }
}

/// `base[k][j - 1] = [j * 256^k] B` for `k` in `0..32`, `j` in `1..=8`, and
/// `odd[j] = [2 j + 1] B` for `j` in `0..64`.
struct Tables {
    base: [[Niels; 8]; 32],
    odd: [Niels; 64],
}

/// Constant-time table row lookup into `out`: entry `magnitude - 1` for
/// `magnitude` in `1..=8`, the identity for `0` (the only values [`select`]
/// passes). Every entry is read and merged under a mask that is all ones
/// only for the matching one.
///
/// The result goes to caller-owned storage rather than a return value, so
/// where this dispatcher is out of line (x86-64, whose AVX-512 kernel never
/// inlines, and targets without NEON) the one copy that reaches memory is
/// the caller's, which [`mul_base`] wipes. With NEON the dispatcher and the
/// kernel are always inlined and `out` stays in registers.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline(always)]
fn select_row(row: &[Niels; 8], magnitude: u8, out: &mut Niels) {
    edwards25519_neon::select_row(row, magnitude, out)
}

/// [`select_row`] without NEON: the AVX-512 kernel where available, else
/// [`select_row_scalar`].
#[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
fn select_row(row: &[Niels; 8], magnitude: u8, out: &mut Niels) {
    #[cfg(target_arch = "x86_64")]
    if let Some(avx512) = crate::x86_64::Avx512::new() {
        return edwards25519_x86_64::select_row(avx512, row, magnitude, out);
    }
    select_row_scalar(row, magnitude, out)
}

/// [`select_row`] with scalar masking, one limb at a time.
#[cfg_attr(
    all(target_arch = "aarch64", target_feature = "neon"),
    allow(dead_code)
)]
fn select_row_scalar(row: &[Niels; 8], magnitude: u8, out: &mut Niels) {
    let mut acc = Niels::IDENTITY;
    for (j, entry) in row.iter().enumerate() {
        acc = Niels::conditional_select(&acc, entry, magnitude.ct_eq(&(j as u8 + 1)));
    }
    *out = acc;
}

/// Selects `[digit * 256^k] B` for `digit` in `-8..=8` into `out` without
/// revealing the digit through timing or memory access.
#[inline(always)]
fn select(row: &[Niels; 8], digit: i8, out: &mut Niels) {
    let negative = ((digit as i16) >> 8) as u8 & 1;
    // |digit| via the two's complement identity (d ^ m) - m for m in {0, -1}.
    let sign_mask = 0u8.wrapping_sub(negative);
    let magnitude = ((digit as u8) ^ sign_mask).wrapping_sub(sign_mask);

    select_row(row, magnitude, out);
    out.conditional_negate(0u64.wrapping_sub(u64::from(negative)));
}

/// Signed radix-16 digits of a little-endian scalar below 2^255, each in
/// `-8..=8`, with `sum(d[i] * 16^i)` equal to the scalar.
fn radix16(scalar: &[u8; 32]) -> [i8; 64] {
    let mut digits = [0i8; 64];
    for (i, byte) in scalar.iter().enumerate() {
        digits[2 * i] = (byte & 15) as i8;
        digits[2 * i + 1] = (byte >> 4) as i8;
    }
    for i in 0..63 {
        let carry = (digits[i] + 8) >> 4;
        digits[i] -= carry << 4;
        digits[i + 1] += carry;
    }
    digits
}

/// Width-`W` non-adjacent form of a little-endian scalar below 2^255: digits
/// are odd and in `-2^(W-1)..2^(W-1)`, with at least `W - 1` zeros after each
/// nonzero digit. Variable time; for public scalars.
fn naf<const W: usize>(scalar: &[u8; 32]) -> [i8; 256] {
    let mut words = [0u64; 5];
    for (word, chunk) in words.iter_mut().zip(scalar.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    let width = 1u64 << W;
    let window_mask = width - 1;

    let mut digits = [0i8; 256];
    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 256 {
        let idx = pos / 64;
        let bit = pos % 64;
        let bits = if bit < 64 - W {
            words[idx] >> bit
        } else {
            (words[idx] >> bit) | (words[idx + 1] << (64 - bit))
        };
        let window = carry + (bits & window_mask);
        if window & 1 == 0 {
            pos += 1;
            continue;
        }
        if window < width / 2 {
            carry = 0;
            digits[pos] = window as i8;
        } else {
            carry = 1;
            digits[pos] = (window as i8).wrapping_sub(width as i8);
        }
        pos += W;
    }
    digits
}

/// `[scalar] B` for a little-endian `scalar` below 2^255: either a value
/// reduced modulo the group order or a clamped X25519/Ed25519 secret scalar.
///
/// On x86-64 with BMI2 the loop runs in a copy compiled for `mulx` (see
/// [`crate::x86_64::Bmi2`]); the arithmetic is the same code.
pub(crate) fn mul_base(scalar: &[u8; 32]) -> Point {
    #[cfg(target_arch = "x86_64")]
    if let Some(bmi2) = crate::x86_64::Bmi2::new() {
        return mul_base_bmi2(bmi2, scalar);
    }
    mul_base_impl(scalar)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
fn mul_base_bmi2_unchecked(scalar: &[u8; 32]) -> Point {
    mul_base_impl(scalar)
}

/// [`mul_base_bmi2_unchecked`], safe to call with a [`crate::x86_64::Bmi2`]
/// token.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn mul_base_bmi2(_: crate::x86_64::Bmi2, scalar: &[u8; 32]) -> Point {
    // SAFETY: a `Bmi2` token exists only after detection of `bmi2`,
    // the feature the loop copy is compiled for.
    unsafe { mul_base_bmi2_unchecked(scalar) }
}

#[inline(always)]
fn mul_base_impl(scalar: &[u8; 32]) -> Point {
    let mut digits = radix16(scalar);
    let table = &TABLES.base;

    // sum over odd digits, times 16, plus the sum over even digits. Each
    // lookup is issued one addition ahead of its use: the lookup runs on the
    // vector unit and the addition on the scalar multipliers, and the
    // addition's ~800 instructions would otherwise keep the next lookup
    // outside the out-of-order window. The digit sequence is fixed, so this
    // changes no data-dependent behaviour.
    //
    // Without NEON, `next` is the only lookup storage whose address reaches
    // memory: it is passed to the out-of-line `select_row`, so it is wiped
    // once at the end. With NEON the lookup is always inlined and `next`
    // stays in registers and spill slots like `entry`, the point and the
    // field temporaries, which cannot be reliably wiped; wiping them would
    // only force them into memory.
    let mut p = Point::IDENTITY;
    let mut next = Niels::IDENTITY;
    select(&table[0], digits[1], &mut next);
    for k in 0..32 {
        let entry = next;
        if k + 1 < 32 {
            select(&table[k + 1], digits[2 * (k + 1) + 1], &mut next);
        } else {
            select(&table[0], digits[0], &mut next);
        }
        p = p.add_niels(&entry);
    }
    p = p.double().double().double().double();
    for k in 0..32 {
        let entry = next;
        if k + 1 < 32 {
            select(&table[k + 1], digits[2 * (k + 1)], &mut next);
        }
        p = p.add_niels(&entry);
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
    next.zeroize();
    digits.zeroize();
    p
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    use super::*;
    use crate::test_prelude::*;
    use crate::utils::test_util::{XorShift64, hex32 as hex};

    /// `2d` really is twice `-121665 / 121666`.
    #[test]
    fn test_curve_constant() {
        // d * 121666 = -121665.
        let d = EDWARDS_D2.mul(&Fe::from_bytes(&{
            // 2^-1 = (p + 1) / 2.
            let mut half = [0u8; 32];
            half[0] = 0xf7;
            half[1..31].fill(0xff);
            half[31] = 0x3f;
            half
        }));
        let m121666 = Fe([121666, 0, 0, 0, 0]);
        let m121665 = Fe([121665, 0, 0, 0, 0]);
        assert_eq!(d.mul(&m121666).to_bytes(), m121665.neg().to_bytes());
    }

    /// The affine point a Niels entry encodes: `y = (P + M) / 2`,
    /// `x = (P - M) / 2` for `P = y + x`, `M = y - x`; also checks that
    /// `xy2d` is `2 d x y` for that `(x, y)`.
    fn niels_to_point(entry: &Niels) -> Point {
        // 2^-1 = (p + 1) / 2.
        let two_inv = Fe::from_bytes(&{
            let mut half = [0u8; 32];
            half[0] = 0xf7;
            half[1..31].fill(0xff);
            half[31] = 0x3f;
            half
        });
        let y = entry.y_plus_x.add(&entry.y_minus_x).mul(&two_inv);
        let x = entry.y_plus_x.sub(&entry.y_minus_x).mul(&two_inv);
        assert_eq!(
            entry.xy2d.to_bytes(),
            x.mul(&y).mul(&EDWARDS_D2).to_bytes(),
            "xy2d"
        );
        Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        }
    }

    /// The canonical affine Niels form of a curve25519-dalek point, derived
    /// independently of [`TABLES`]: the point is decoded from dalek's
    /// encoding and each coordinate reduced to canonical limbs.
    fn niels_from_dalek(point: curve25519_dalek::EdwardsPoint) -> Niels {
        let p = Point::decompress(&point.compress().to_bytes()).expect("valid dalek point");
        let zinv = p.z.invert();
        let x = p.x.mul(&zinv);
        let y = p.y.mul(&zinv);
        let canonical = |v: Fe| Fe::from_bytes(&v.to_bytes());
        Niels {
            y_plus_x: canonical(y.add(&x)),
            y_minus_x: canonical(y.sub(&x)),
            xy2d: canonical(x.mul(&y).mul(&EDWARDS_D2)),
        }
    }

    /// Every limb of every fixed-base table entry equals the canonical Niels
    /// form of the basepoint multiple it claims to be, as computed by dalek.
    #[test]
    fn test_table_matches_dalek() {
        let limbs = |n: &Niels| [n.y_plus_x.0, n.y_minus_x.0, n.xy2d.0];
        let mut scale = Scalar::ONE;
        for (k, row) in TABLES.base.iter().enumerate() {
            for (j, entry) in row.iter().enumerate() {
                let multiple = ED25519_BASEPOINT_TABLE * &(scale * Scalar::from(j as u64 + 1));
                assert_eq!(
                    limbs(entry),
                    limbs(&niels_from_dalek(multiple)),
                    "base[{k}][{j}]"
                );
                assert_eq!(
                    niels_to_point(entry).compress(),
                    multiple.compress().to_bytes(),
                    "base[{k}][{j}]"
                );
            }
            scale *= Scalar::from(256u64);
        }
    }

    /// Every limb of every odd-multiple entry used by the double-scalar
    /// multiplication equals the canonical Niels form of `[2 j + 1] B`.
    #[test]
    fn test_odd_table_matches_dalek() {
        let limbs = |n: &Niels| [n.y_plus_x.0, n.y_minus_x.0, n.xy2d.0];
        for (j, entry) in TABLES.odd.iter().enumerate() {
            let multiple = ED25519_BASEPOINT_TABLE * &Scalar::from(2 * j as u64 + 1);
            assert_eq!(limbs(entry), limbs(&niels_from_dalek(multiple)), "odd {j}");
            assert_eq!(
                niels_to_point(entry).compress(),
                multiple.compress().to_bytes(),
                "odd {j}"
            );
        }
        assert_eq!(limbs(&TABLES.odd[0]), limbs(&TABLES.base[0][0]));
    }

    /// `[s]B` agrees with dalek for random reduced scalars, clamped-style
    /// scalars and the edges of the scalar range, in both encodings.
    #[test]
    fn test_mul_base_matches_dalek() {
        let mut rng = XorShift64::new(0x1234_5678_9abc_def1);
        let mut scalars: Vec<[u8; 32]> = vec![
            [0; 32],
            {
                let mut one = [0u8; 32];
                one[0] = 1;
                one
            },
            (Scalar::ZERO - Scalar::ONE).to_bytes(),
            hex("0000000000000000000000000000000000000000000000000000000000000010"),
        ];
        for i in 0..if cfg!(miri) { 4 } else { 1000 } {
            let mut k = rng.next_bytes32();
            if i % 2 == 0 {
                // Clamped secret scalars are passed unreduced (2^254 <= k <
                // 2^255).
                k[0] &= 248;
                k[31] &= 127;
                k[31] |= 64;
                scalars.push(k);
            } else {
                scalars.push(Scalar::from_bytes_mod_order(k).to_bytes());
            }
        }
        for k in scalars {
            let expected = ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(k);
            let p = mul_base(&k);
            assert_eq!(p.compress(), expected.compress().to_bytes(), "{k:02x?}");
            assert_eq!(
                p.to_montgomery(),
                expected.to_montgomery().to_bytes(),
                "{k:02x?}"
            );
        }
    }

    /// RFC 8032 section 7.1 test 1: the public key of the all-zero-ish seed.
    #[test]
    #[cfg(feature = "alloc")]
    fn test_rfc8032_public_key() {
        // Secret scalar a for seed 9d61b19d...; a = clamp(SHA-512(seed)[..32]).
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let mut h = crate::sha512::Sha512::compute_to_vec(&seed);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;
        let a = Scalar::from_bytes_mod_order(h[..32].try_into().unwrap()).to_bytes();
        assert_eq!(
            mul_base(&a).compress(),
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
    }

    /// Unreduced scalars at the top of the `< 2^255` range and radix-16
    /// carry patterns (every digit 8, alternating carries, a carry into the
    /// top nibble): `2^255 - 1`, `p`, `L - 1`, `L`, `L + 1`, `2^254` and the
    /// repeated-byte patterns, against dalek's reduction modulo `L`.
    #[test]
    fn test_mul_base_scalar_boundaries() {
        let mut scalars: Vec<[u8; 32]> = vec![
            hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
            GROUP_ORDER,
            hex("eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
            hex("0000000000000000000000000000000000000000000000000000000000000040"),
            hex("0800000000000000000000000000000000000000000000000000000000000000"),
            hex("0000000000000000000000000000000000000000000000000000000000000008"),
        ];
        for (fill, top) in [
            (0x88u8, 0x78u8),
            (0x78, 0x78),
            (0xf8, 0x7f),
            (0x08, 0x08),
            (0x80, 0x78),
            (0x87, 0x78),
            (0xff, 0x0f),
            (0x00, 0x7f),
        ] {
            let mut k = [fill; 32];
            k[31] = top;
            scalars.push(k);
        }
        for k in scalars {
            assert!(k[31] < 0x80);
            let expected = ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(k);
            let p = mul_base(&k);
            assert_eq!(p.compress(), expected.compress().to_bytes(), "{k:02x?}");
            assert_eq!(
                p.to_montgomery(),
                expected.to_montgomery().to_bytes(),
                "{k:02x?}"
            );
        }
    }

    /// `add_digits` adds `da * A + db * B` for every NAF digit pair the
    /// double-scalar multiplication can produce (odd `da` in `-15..=15`, odd
    /// `db` in `-127..=127`, and zeros), checking the odd-multiple cache, the
    /// negation branches and every `TABLES.odd` entry in use.
    #[test]
    fn test_add_digits_matches_dalek() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use curve25519_dalek::edwards::EdwardsPoint;

        let mut rng = XorShift64::new(0x7137_4491_23ef_65cd);
        let a_scalar = Scalar::from_bytes_mod_order(rng.next_bytes32());
        let q_scalar = Scalar::from_bytes_mod_order(rng.next_bytes32());
        let dalek_a: EdwardsPoint = ED25519_BASEPOINT_TABLE * &a_scalar;
        let dalek_q: EdwardsPoint = ED25519_BASEPOINT_TABLE * &q_scalar;
        let a = Point::decompress(&dalek_a.compress().to_bytes()).unwrap();
        let q = Point::decompress(&dalek_q.compress().to_bytes()).unwrap();
        let odd = a.odd_multiples_niels();

        let scale = |d: i8| {
            let magnitude = Scalar::from(d.unsigned_abs());
            if d < 0 { -magnitude } else { magnitude }
        };
        // Miri covers zero, both signs and the extrema; native tests cover
        // every digit pair.
        let digits = |width: i8| {
            (-width..=width)
                .filter(move |d| d % 2 != 0 && (!cfg!(miri) || d.abs() == 1 || d.abs() == width))
                .chain([0])
        };
        for da in digits(15) {
            for db in digits(127) {
                let expected = dalek_q + dalek_a * scale(da) + ED25519_BASEPOINT_POINT * scale(db);
                let actual = Point::add_digits(q, &odd, da, db);
                assert_eq!(
                    actual.compress(),
                    expected.compress().to_bytes(),
                    "da {da}, db {db}"
                );
            }
        }
    }

    /// Doubling, negation, cached and fixed-base addition and the
    /// double-scalar multiplication agree with dalek on every eight-torsion
    /// point and on mixed-order points, including the scalar pair `(0, 0)`
    /// and scalars at the top of the range on a prime-order point.
    #[test]
    fn test_torsion_and_mixed_order_operations_match_dalek() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
        use curve25519_dalek::edwards::EdwardsPoint;
        use curve25519_dalek::traits::IsIdentity;

        let mut rng = XorShift64::new(0x2b8c_5fa1_9d4e_7301);
        let mut rnd_scalar = || Scalar::from_bytes_mod_order(rng.next_bytes32());
        let prime_order: EdwardsPoint = ED25519_BASEPOINT_TABLE * &rnd_scalar();
        let mut cases: Vec<EdwardsPoint> = EIGHT_TORSION.to_vec();
        cases.extend(EIGHT_TORSION.iter().map(|t| prime_order + t));
        let ours = |p: &EdwardsPoint| Point::decompress(&p.compress().to_bytes()).unwrap();
        let encoded = |p: &EdwardsPoint| p.compress().to_bytes();

        let scalar_pairs: Vec<(Scalar, Scalar)> = {
            let mut pairs = vec![
                (Scalar::ZERO, Scalar::ZERO),
                (Scalar::ONE, Scalar::ZERO),
                (Scalar::ZERO, Scalar::ONE),
                (Scalar::from(7u64), Scalar::from(3u64)),
                (Scalar::from(8u64), Scalar::ZERO),
                (Scalar::ZERO - Scalar::ONE, Scalar::ZERO - Scalar::ONE),
            ];
            pairs.push((rnd_scalar(), rnd_scalar()));
            pairs
        };

        for dalek_point in &cases {
            let point = ours(dalek_point);
            let label = encoded(dalek_point);
            assert_eq!(point.compress(), label);
            assert_eq!(
                point.neg().compress(),
                encoded(&-dalek_point),
                "neg {label:02x?}"
            );
            assert_eq!(
                point.double().compress(),
                encoded(&(dalek_point + dalek_point)),
                "double {label:02x?}"
            );
            assert_eq!(
                point.add_niels(&TABLES.odd[0]).compress(),
                encoded(&(dalek_point + ED25519_BASEPOINT_POINT)),
                "add B {label:02x?}"
            );
            for other in &cases {
                assert_eq!(
                    point
                        .add_projective_niels(&ours(other).to_projective_niels())
                        .compress(),
                    encoded(&(dalek_point + other)),
                    "add {label:02x?} + {:02x?}",
                    encoded(other)
                );
            }
            for (a, b) in &scalar_pairs {
                let expected = EdwardsPoint::vartime_double_scalar_mul_basepoint(a, dalek_point, b);
                let actual =
                    point.double_scalar_mul_basepoint_vartime(&a.to_bytes(), &b.to_bytes());
                assert_eq!(
                    actual.compress(),
                    expected.compress().to_bytes(),
                    "straus {label:02x?}, a {:02x?}, b {:02x?}",
                    a.to_bytes(),
                    b.to_bytes()
                );
                assert_eq!(actual.is_identity(), expected.is_identity());
            }
        }

        // Scalars at the top of the accepted range on a prime-order point,
        // where reduction modulo L does not change the result: 2^255 - 1,
        // L, L - 1, and the (0, 0) pair.
        let point = ours(&prime_order);
        let top = hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let l_minus_1 = (Scalar::ZERO - Scalar::ONE).to_bytes();
        for (a, b) in [
            (top, top),
            (GROUP_ORDER, GROUP_ORDER),
            (top, [0; 32]),
            ([0; 32], top),
            (l_minus_1, GROUP_ORDER),
            ([0; 32], [0; 32]),
        ] {
            let expected = EdwardsPoint::vartime_double_scalar_mul_basepoint(
                &Scalar::from_bytes_mod_order(a),
                &prime_order,
                &Scalar::from_bytes_mod_order(b),
            );
            let actual = point.double_scalar_mul_basepoint_vartime(&a, &b);
            assert_eq!(
                actual.compress(),
                expected.compress().to_bytes(),
                "a {a:02x?}, b {b:02x?}"
            );
        }
        assert!(
            point
                .double_scalar_mul_basepoint_vartime(&[0; 32], &[0; 32])
                .is_identity()
        );
        assert!(
            point
                .double_scalar_mul_basepoint_vartime(&GROUP_ORDER, &GROUP_ORDER)
                .is_identity()
        );
    }

    /// Decompression, negation, full addition and the double-base
    /// multiplication agree with dalek on random points and scalars, and the
    /// subgroup check classifies prime-order, small-order and mixed-order
    /// points like dalek's `is_torsion_free`.
    #[test]
    fn test_vartime_operations_match_dalek() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
        use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
        use curve25519_dalek::traits::IsIdentity;

        let mut rng = XorShift64::new(0x0f1e_2d3c_4b5a_6978);
        let mut rnd_scalar = || Scalar::from_bytes_mod_order(rng.next_bytes32());

        for i in 0..if cfg!(miri) { 4 } else { 200 } {
            let a = rnd_scalar();
            let b = rnd_scalar();
            let point_scalar = rnd_scalar();
            let dalek_point: EdwardsPoint = ED25519_BASEPOINT_TABLE * &point_scalar;
            let encoded = dalek_point.compress().to_bytes();
            let point = Point::decompress(&encoded).expect("valid point");
            assert_eq!(point.compress(), encoded, "decompress {i}");

            let expected = EdwardsPoint::vartime_double_scalar_mul_basepoint(&a, &dalek_point, &b);
            let actual = point.double_scalar_mul_basepoint_vartime(&a.to_bytes(), &b.to_bytes());
            assert_eq!(
                actual.compress(),
                expected.compress().to_bytes(),
                "straus {i}"
            );

            let negated = point.add_projective_niels(&point.neg().to_projective_niels());
            assert!(negated.is_identity(), "neg/add {i}");
            assert!(
                point
                    .add_projective_niels(&point.to_projective_niels().neg())
                    .is_identity(),
                "cached neg {i}"
            );
            assert_eq!(
                point
                    .add_projective_niels(&point.to_projective_niels())
                    .compress(),
                (dalek_point + dalek_point).compress().to_bytes(),
                "cached add {i}"
            );
            assert_eq!(
                point.to_projective().double().double_extended().compress(),
                (dalek_point + dalek_point + dalek_point + dalek_point)
                    .compress()
                    .to_bytes(),
                "projective double {i}"
            );
            // Scalars whose only nonzero NAF digit is at index 0 (the loop
            // body never runs; the final step alone produces the result).
            for (sa, sb) in [(1u64, 0u64), (0, 1), (1, 1)] {
                let sa = Scalar::from(sa);
                let sb = Scalar::from(sb);
                assert_eq!(
                    point
                        .double_scalar_mul_basepoint_vartime(&sa.to_bytes(), &sb.to_bytes())
                        .compress(),
                    EdwardsPoint::vartime_double_scalar_mul_basepoint(&sa, &dalek_point, &sb)
                        .compress()
                        .to_bytes(),
                    "digit-0-only {i}"
                );
            }
            // Only the basepoint part.
            assert_eq!(
                Point::IDENTITY
                    .double_scalar_mul_basepoint_vartime(&[0; 32], &b.to_bytes())
                    .compress(),
                (ED25519_BASEPOINT_TABLE * &b).compress().to_bytes(),
                "basepoint only {i}"
            );
        }

        // Subgroup membership on prime-order, torsion and mixed points.
        let mut cases: Vec<EdwardsPoint> = vec![ED25519_BASEPOINT_POINT];
        for _ in 0..if cfg!(miri) { 2 } else { 16 } {
            cases.push(ED25519_BASEPOINT_TABLE * &rnd_scalar());
        }
        let prime_order = cases.clone();
        for torsion in EIGHT_TORSION {
            cases.push(torsion);
            for p in &prime_order {
                cases.push(p + torsion);
            }
        }
        for dalek_point in cases {
            let encoded = dalek_point.compress().to_bytes();
            let point = Point::decompress(&encoded).expect("valid point");
            assert_eq!(
                point.is_identity(),
                dalek_point.is_identity(),
                "{encoded:02x?}"
            );
            assert_eq!(
                point.is_small_order(),
                dalek_point.is_small_order(),
                "{encoded:02x?}"
            );
            assert_eq!(
                point.is_torsion_free_vartime(),
                dalek_point.is_torsion_free(),
                "{encoded:02x?}"
            );
        }

        // Non-square encodings are rejected exactly when dalek rejects them.
        for _ in 0..if cfg!(miri) { 8 } else { 200 } {
            let bytes = rng.next_bytes32();
            let ours = Point::decompress(&bytes);
            let theirs = CompressedEdwardsY(bytes).decompress();
            assert_eq!(ours.is_some(), theirs.is_some(), "{bytes:02x?}");
            if let (Some(p), Some(d)) = (ours, theirs) {
                assert_eq!(p.compress(), d.compress().to_bytes());
            }
        }
    }

    /// Runs a table lookup into storage that starts as garbage, so a lookup
    /// that leaves part of its output unwritten is caught.
    fn lookup(f: impl FnOnce(&mut Niels)) -> [[u64; 5]; 3] {
        let garbage = Fe([u64::MAX; 5]);
        let mut out = Niels {
            y_plus_x: garbage,
            y_minus_x: garbage,
            xy2d: garbage,
        };
        f(&mut out);
        [out.y_plus_x.0, out.y_minus_x.0, out.xy2d.0]
    }

    /// The AVX-512 lookup equals the scalar one for every table row and
    /// every digit magnitude `0..=8`, including the identity for 0, and the
    /// production dispatch agrees with both.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_avx512_select_row_matches_scalar() {
        let Some(avx512) = crate::x86_64::Avx512::new() else {
            return;
        };
        let limbs = |n: &Niels| [n.y_plus_x.0, n.y_minus_x.0, n.xy2d.0];
        for (k, row) in TABLES.base.iter().enumerate() {
            for magnitude in 0..=8u8 {
                let expected = lookup(|out| select_row_scalar(row, magnitude, out));
                let selected =
                    lookup(|out| edwards25519_x86_64::select_row(avx512, row, magnitude, out));
                assert_eq!(selected, expected, "row {k}, magnitude {magnitude}");
                assert_eq!(
                    lookup(|out| select_row(row, magnitude, out)),
                    expected,
                    "row {k}, magnitude {magnitude}"
                );
                if magnitude == 0 {
                    assert_eq!(expected, limbs(&Niels::IDENTITY));
                } else {
                    assert_eq!(expected, limbs(&row[usize::from(magnitude) - 1]));
                }
            }
        }
    }

    /// The NEON row lookup returns exactly the limbs the scalar one does
    /// for every table row and every digit magnitude `0..=8`, including the
    /// identity for 0, and the production dispatch agrees with both.
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[test]
    fn test_neon_select_row_matches_scalar() {
        let limbs = |n: &Niels| [n.y_plus_x.0, n.y_minus_x.0, n.xy2d.0];
        for (k, row) in TABLES.base.iter().enumerate() {
            for magnitude in 0..=8u8 {
                let expected = lookup(|out| select_row_scalar(row, magnitude, out));
                let neon = lookup(|out| edwards25519_neon::select_row(row, magnitude, out));
                assert_eq!(neon, expected, "row {k}, magnitude {magnitude}");
                assert_eq!(
                    lookup(|out| select_row(row, magnitude, out)),
                    expected,
                    "row {k}, magnitude {magnitude}"
                );
                if magnitude == 0 {
                    assert_eq!(expected, limbs(&Niels::IDENTITY));
                } else {
                    assert_eq!(expected, limbs(&row[usize::from(magnitude) - 1]));
                }
            }
        }
    }
}
