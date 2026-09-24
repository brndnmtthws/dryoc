//! Portable ML-KEM polynomial arithmetic.
//!
//! These are the reference algorithms for the kernel operations in
//! [`super`]: the forward and inverse NTT and the NTT-domain multiply-add.
//! The vector backends compute exactly the same values lane by lane, so
//! every intermediate coefficient, not just the final result, agrees with
//! this file. Arithmetic is on signed 16-bit coefficients modulo `q = 3329`
//! with Montgomery multiplication (`R = 2^16`) and a flooring Barrett
//! reduction; both are branch-free.

use super::{N, Poly, Q};

/// `q^-1 mod 2^16`, as a signed 16-bit value.
pub(super) const QINV: i16 = -3327;
/// `round(2^26 / q)`, the Barrett multiplier.
pub(super) const BARRETT_V: i16 = 20159;
/// `R^2 / 128 mod q`: the inverse NTT's final scale, leaving results
/// multiplied by `R` so the next Montgomery product cancels it.
pub(super) const INVNTT_F: i16 = 1441;
/// `R^2 mod q`, which converts to the Montgomery domain.
pub(super) const R2: i16 = 1353;

/// `zeta^bitrev7(i) * R mod q` for the primitive 256th root `zeta = 17`,
/// centered into `(-q/2, q/2]`: the twiddle factors for the NTT layers
/// (`ZETAS[1..128]`) and the base multiplication (`ZETAS[64..128]`).
pub(super) const ZETAS: [i16; 128] = zetas();

const fn zetas() -> [i16; 128] {
    let q = Q as i64;
    let mut table = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        // zeta^bitrev7(i) mod q by square-and-multiply.
        let mut exp = (i as u8).reverse_bits() >> 1;
        let mut base = 17i64;
        let mut power = 1i64;
        while exp > 0 {
            if exp & 1 == 1 {
                power = power * base % q;
            }
            base = base * base % q;
            exp >>= 1;
        }
        let mont = power * 65536 % q;
        table[i] = if mont > q / 2 { mont - q } else { mont } as i16;
        i += 1;
    }
    table
}

/// Montgomery reduction: `a * R^-1 mod q` in `(-q, q)` for `|a| < q * 2^15`.
///
/// Written as the vector backends compute it, `hi(a) - hi(t * q)` with `t =
/// lo(a) * q^-1`; the low halves of `a` and `t * q` are equal, so this is
/// exactly `(a - t * q) >> 16`.
#[inline(always)]
pub(super) fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - i32::from(t) * i32::from(Q)) >> 16) as i16
}

/// `a * b * R^-1 mod q`.
#[inline(always)]
pub(super) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

/// Flooring Barrett reduction: a representative of `a mod q` in `[0, q]`
/// for any 16-bit `a`.
///
/// `t = floor(a * v / 2^26)` is what a 16-bit high multiply followed by an
/// arithmetic shift of 10 gives on every backend.
#[inline(always)]
pub(super) fn barrett_reduce(a: i16) -> i16 {
    let t = ((i32::from(a) * i32::from(BARRETT_V)) >> 26) as i16;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// In-place forward NTT: natural order in, bit-reversed NTT order out.
/// Coefficients must be in `(-q, q)`; outputs are Barrett-reduced.
pub(super) fn ntt(r: &mut Poly) {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
            }
        }
        len >>= 1;
    }
    for c in r.iter_mut() {
        *c = barrett_reduce(*c);
    }
}

/// In-place inverse NTT, also multiplying by `R`: bit-reversed NTT order in,
/// natural order out, with outputs in `(-q, q)`.
pub(super) fn invntt_tomont(r: &mut Poly) {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t.wrapping_add(r[j + len]));
                r[j + len] = fqmul(zeta, r[j + len].wrapping_sub(t));
            }
        }
        len <<= 1;
    }
    for c in r.iter_mut() {
        *c = fqmul(*c, INVNTT_F);
    }
}

/// Products of degree-one residues `(a0 + a1 X)(b0 + b1 X) mod (X^2 - zeta)`,
/// times `R^-1`, as `(c0, c1)`.
#[inline(always)]
fn basemul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let c0 = fqmul(fqmul(a1, b1), zeta).wrapping_add(fqmul(a0, b0));
    let c1 = fqmul(a0, b1).wrapping_add(fqmul(a1, b0));
    (c0, c1)
}

/// `r = sum(a[i] * b[i]) * R^-1` in the NTT domain, Barrett-reduced.
///
/// Each product is reduced separately and the sum of `K` products is
/// reduced once, so the inputs need only be 16-bit values below `2^12` in
/// magnitude (the size of a decoded coefficient).
pub(super) fn basemul_acc<const K: usize>(r: &mut Poly, a: &[Poly; K], b: &[Poly; K]) {
    *r = [0; N];
    for (a, b) in a.iter().zip(b) {
        for i in 0..N / 4 {
            let zeta = ZETAS[64 + i];
            let j = 4 * i;
            let (c0, c1) = basemul(a[j], a[j + 1], b[j], b[j + 1], zeta);
            let (c2, c3) = basemul(a[j + 2], a[j + 3], b[j + 2], b[j + 3], -zeta);
            r[j] = r[j].wrapping_add(c0);
            r[j + 1] = r[j + 1].wrapping_add(c1);
            r[j + 2] = r[j + 2].wrapping_add(c2);
            r[j + 3] = r[j + 3].wrapping_add(c3);
        }
    }
    for c in r.iter_mut() {
        *c = barrett_reduce(*c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        let q = i64::from(Q);
        assert_eq!((i64::from(Q) * i64::from(QINV)).rem_euclid(1 << 16), 1);
        assert_eq!(i64::from(BARRETT_V), ((1 << 26) + q / 2) / q);
        assert_eq!(i64::from(R2), (1i64 << 32) % q);
        assert_eq!((i64::from(INVNTT_F) * 128).rem_euclid(q), (1i64 << 32) % q);
        // zeta = 17 has order 256: 17^128 = -1.
        assert_eq!(ZETAS[0], 2285 - 3329);
        assert_eq!(ZETAS[1], -758);
        assert_eq!(ZETAS[127], 1628);
    }

    /// Exhaustive over every 16-bit input: the reductions are congruent and
    /// land in their documented ranges.
    #[test]
    fn test_reductions_exhaustive() {
        let q = i32::from(Q);
        for a in i16::MIN..=i16::MAX {
            let r = barrett_reduce(a);
            assert!((0..=Q).contains(&r), "barrett {a} -> {r}");
            assert_eq!((i32::from(a) - i32::from(r)).rem_euclid(q), 0);
        }
        // Montgomery reduction over the products the kernels form.
        for a in (-(q << 15) + 1..(q << 15)).step_by(9973) {
            let r = i32::from(montgomery_reduce(a));
            assert!(r.abs() < q, "montgomery {a} -> {r}");
            assert_eq!((r * 65536 - a).rem_euclid(q), 0);
        }
    }

    /// Schoolbook multiplication in `Z_q[X]/(X^256 + 1)`.
    fn schoolbook(a: &Poly, b: &Poly) -> [i64; N] {
        let q = i64::from(Q);
        let mut c = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = i64::from(a[i]) * i64::from(b[j]);
                if i + j < N {
                    c[i + j] += p;
                } else {
                    c[i + j - N] -= p;
                }
            }
        }
        c.map(|x| x.rem_euclid(q))
    }

    /// `invntt_tomont(basemul_acc(ntt(a), ntt(b)))` is the negacyclic
    /// product: the three operations and their Montgomery factors compose
    /// to exactly polynomial multiplication, with coefficients at the input
    /// extremes.
    #[test]
    fn test_ntt_multiply_matches_schoolbook() {
        let q = i64::from(Q);
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..8 {
            let mut a: Poly = std::array::from_fn(|_| (next() % 6657) as i16 - 3328);
            let mut b: Poly = std::array::from_fn(|_| (next() % 6657) as i16 - 3328);
            if round == 0 {
                a = [3328; N];
                b = [-3328; N];
            }
            let expected = schoolbook(&a, &b);
            ntt(&mut a);
            ntt(&mut b);
            let mut c = [0; N];
            basemul_acc(&mut c, &[a], &[b]);
            invntt_tomont(&mut c);
            let c = c.map(|x| i64::from(x).rem_euclid(q));
            assert_eq!(c, expected, "round {round}");
        }
    }
}
