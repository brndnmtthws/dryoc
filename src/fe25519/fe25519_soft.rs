//! Portable `u128` schoolbook products for the Curve25519 field.
//!
//! Each product forms the five 128-bit column sums of a radix-2^51
//! multiplication and carries them once, leaving every limb weakly reduced
//! (below `2^51 + 2^13`). Inputs may have limbs up to `2^54`.

use super::MASK51;

/// Reduces the five 128-bit column sums of a schoolbook product.
#[inline(always)]
fn carry(c0: u128, mut c1: u128, mut c2: u128, mut c3: u128, mut c4: u128) -> [u64; 5] {
    c1 += c0 >> 51;
    let mut l0 = (c0 as u64) & MASK51;
    c2 += c1 >> 51;
    let l1 = (c1 as u64) & MASK51;
    c3 += c2 >> 51;
    let l2 = (c2 as u64) & MASK51;
    c4 += c3 >> 51;
    let l3 = (c3 as u64) & MASK51;
    let l4 = (c4 as u64) & MASK51;
    l0 += ((c4 >> 51) as u64) * 19;
    let l1 = l1 + (l0 >> 51);
    l0 &= MASK51;
    [l0, l1, l2, l3, l4]
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

/// Schoolbook product of two elements with limbs below 2^54, weakly reduced.
#[inline(always)]
pub(super) fn mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let b1_19 = b[1] * 19;
    let b2_19 = b[2] * 19;
    let b3_19 = b[3] * 19;
    let b4_19 = b[4] * 19;
    carry(
        m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19),
        m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19),
        m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19),
        m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19),
        m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]),
    )
}

/// Square of an element with limbs below 2^54, weakly reduced.
#[inline(always)]
pub(super) fn square(a: &[u64; 5]) -> [u64; 5] {
    let a0_2 = a[0] * 2;
    let a1_2 = a[1] * 2;
    let a3_19 = a[3] * 19;
    let a4_19 = a[4] * 19;
    let a3_38 = a3_19 * 2;
    let a4_38 = a4_19 * 2;
    carry(
        m(a[0], a[0]) + m(a1_2, a4_19) + m(a[2], a3_38),
        m(a0_2, a[1]) + m(a[2], a4_38) + m(a[3], a3_19),
        m(a0_2, a[2]) + m(a[1], a[1]) + m(a[3], a4_38),
        m(a0_2, a[3]) + m(a1_2, a[2]) + m(a[4], a4_19),
        m(a0_2, a[4]) + m(a1_2, a[3]) + m(a[2], a[2]),
    )
}

/// Reduces the five column sums of a squaring of a *reduced* element (limbs
/// below `2^51 + 2^13`) with two short parallel passes instead of the serial
/// chain of [`carry`]: every limb is masked and receives its lower
/// neighbour's carry at once (the top carry times 19 wraps to limb 0), then
/// once more for the small carries that leaves. Column sums of such a
/// squaring are below `2^110`, so the first carries are below `2^59` (times
/// 19 still fits a `u64`), the second below `2^8`, and the result's limbs are
/// below `2^51 + 2^12` (limb 0 takes 19 times its carry). The dependency
/// chain is about half of [`carry`]'s,
/// which is what bounds a long chain of dependent squarings.
#[cfg(any(not(target_arch = "aarch64"), miri, test))]
#[inline(always)]
fn carry_reduced(c0: u128, c1: u128, c2: u128, c3: u128, c4: u128) -> [u64; 5] {
    let low = |c: u128| (c as u64) & MASK51;
    let high = |c: u128| (c >> 51) as u64;
    let l0 = low(c0) + high(c4) * 19;
    let l1 = low(c1) + high(c0);
    let l2 = low(c2) + high(c1);
    let l3 = low(c3) + high(c2);
    let l4 = low(c4) + high(c3);
    [
        (l0 & MASK51) + (l4 >> 51) * 19,
        (l1 & MASK51) + (l0 >> 51),
        (l2 & MASK51) + (l1 >> 51),
        (l3 & MASK51) + (l2 >> 51),
        (l4 & MASK51) + (l3 >> 51),
    ]
}

/// Square of a reduced element (limbs below `2^51 + 2^13`, a multiply or
/// square output) for long dependent chains: the same products as
/// [`square`] with the latency-shorter [`carry_reduced`], whose bounds those
/// inputs satisfy. In a chain of dependent squarings the carry is on the
/// critical path, and this form runs about a third faster than [`square`].
#[cfg(any(not(target_arch = "aarch64"), miri, test))]
#[inline(always)]
pub(super) fn square_chain(a: &[u64; 5]) -> [u64; 5] {
    debug_assert!(a.iter().all(|&l| l < (1 << 51) + (1 << 13)));
    let a0_2 = a[0] * 2;
    let a1_2 = a[1] * 2;
    let a3_19 = a[3] * 19;
    let a4_19 = a[4] * 19;
    let a3_38 = a[3] * 38;
    let a4_38 = a[4] * 38;
    carry_reduced(
        m(a[0], a[0]) + m(a1_2, a4_19) + m(a[2], a3_38),
        m(a0_2, a[1]) + m(a[2], a4_38) + m(a[3], a3_19),
        m(a0_2, a[2]) + m(a[1], a[1]) + m(a[3], a4_38),
        m(a0_2, a[3]) + m(a1_2, a[2]) + m(a[4], a4_19),
        m(a0_2, a[4]) + m(a1_2, a[3]) + m(a[2], a[2]),
    )
}

/// `121666 * a`, weakly reduced.
#[inline(always)]
#[cfg(not(all(target_arch = "aarch64", not(miri))))]
pub(super) fn mul_121666(a: &[u64; 5]) -> [u64; 5] {
    let m = |x: u64| u128::from(x) * 121666u128;
    carry(m(a[0]), m(a[1]), m(a[2]), m(a[3]), m(a[4]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_prelude::*;

    /// The chain squaring equals the plain squaring and the big-integer
    /// square modulo `p` on reduced inputs with limbs at and around their
    /// bound, and its output limbs stay below `2^51 + 2^12`.
    #[test]
    fn test_square_chain_matches_square() {
        use super::super::tests::{encode, limbs_to_int};

        let mut rng = crate::utils::test_util::XorShift64::new(0x5151_5151_2024);
        let bound = (1u64 << 51) + (1 << 13) - 1;
        let edges = [0u64, 1, MASK51, MASK51 + 1, bound];
        let mut cases: Vec<[u64; 5]> = Vec::new();
        for i in 0..edges.len().pow(2) {
            let mut a = [edges[i % edges.len()]; 5];
            a[i / edges.len() % 5] = edges[(i + 1) % edges.len()];
            cases.push(a);
        }
        for _ in 0..500 {
            cases.push(core::array::from_fn(|_| rng.next_u64() % (bound + 1)));
        }
        for a in cases {
            let chained = square_chain(&a);
            let expected = limbs_to_int(&a);
            assert_eq!(
                super::super::Fe(chained).to_bytes(),
                encode(&(&expected * &expected)),
                "{a:x?}"
            );
            assert_eq!(
                super::super::Fe(chained).to_bytes(),
                super::super::Fe(square(&a)).to_bytes(),
                "{a:x?}"
            );
            for limb in chained {
                assert!(limb < (1 << 51) + (1 << 12), "{a:x?} -> {limb:#x}");
            }
        }
    }
}
