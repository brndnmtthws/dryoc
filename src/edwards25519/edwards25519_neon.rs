//! NEON constant-time lookup in a row of the edwards25519 basepoint table:
//! `select_row64` on the four-limb copy of the table that [`super::mul_base`]
//! uses, and `select_row` on the radix-2^51 table (under Miri, and in the
//! tests).
//!
//! The 15 limbs of every entry are masked and merged two at a time, so a
//! lookup is 8 * 8 vector `and`/`orr` pairs instead of 8 * 15 scalar mask
//! steps. Memory access is the same for every digit: all eight entries are
//! always read.

use core::arch::aarch64::*;

use super::Niels;
#[cfg(any(miri, test))]
use crate::fe25519::Fe;
#[cfg(not(miri))]
use crate::fe25519::Fe64;

/// Constant-time table row lookup into `out`: entry `magnitude - 1` for
/// `magnitude` in `1..=8`, the identity for `0`.
///
/// Compiled only when NEON is a build-time target feature, so it needs no
/// `#[target_feature]` and can be `#[inline(always)]`: inlined into
/// `mul_base` together with the dispatcher, `out` never has its address
/// taken and the selected entry stays in registers and spill slots, which
/// cannot be reliably wiped. Wiping `out` would only force them into memory.
///
/// The nine digit masks are vector compares of the broadcast magnitude, all
/// computed before the merges, which are spelled out: `acc` then never has
/// to survive a call, and nothing is indexed by a loop counter. At
/// opt-level `z` and `s` the former `zip` over `acc` was not unrolled,
/// which kept it in a stack array nothing wipes. The compares replace
/// subtle's `Choice` barrier, an out-of-line call per mask that took 7% of
/// a basepoint multiplication and stored the secret magnitude to the stack
/// each time; like the sign mask in `select`, the masks are plain
/// arithmetic with no branch or secret-dependent address.
#[cfg(any(miri, test))]
#[inline(always)]
pub(super) fn select_row(row: &[Niels; 8], magnitude: u8, out: &mut Niels) {
    // SAFETY: this module is compiled only when `neon` is a build-time
    // target feature, so every NEON intrinsic's feature requirement holds
    // wherever this code runs; they operate on values only.
    unsafe {
        let pair = |a: u64, b: u64| vcombine_u64(vcreate_u64(a), vcreate_u64(b));
        let magnitude = vdupq_n_u64(u64::from(magnitude));
        // All ones when `magnitude == $j`, otherwise zero (`cmeq`).
        macro_rules! hit {
            ($j:literal) => {
                vceqq_u64(magnitude, vdupq_n_u64($j))
            };
        }
        let masks = [
            hit!(1),
            hit!(2),
            hit!(3),
            hit!(4),
            hit!(5),
            hit!(6),
            hit!(7),
            hit!(8),
        ];
        let identity = hit!(0);
        // `acc` is never passed by reference either.
        let mut acc = [vdupq_n_u64(0); 8];
        // Merges entry `$j` under `masks[$j]`.
        macro_rules! merge {
            ($j:literal) => {{
                let mask = masks[$j];
                let p = &row[$j].y_plus_x.0;
                let m = &row[$j].y_minus_x.0;
                let d = &row[$j].xy2d.0;
                acc[0] = vorrq_u64(acc[0], vandq_u64(pair(p[0], p[1]), mask));
                acc[1] = vorrq_u64(acc[1], vandq_u64(pair(p[2], p[3]), mask));
                acc[2] = vorrq_u64(acc[2], vandq_u64(pair(m[0], m[1]), mask));
                acc[3] = vorrq_u64(acc[3], vandq_u64(pair(m[2], m[3]), mask));
                acc[4] = vorrq_u64(acc[4], vandq_u64(pair(d[0], d[1]), mask));
                acc[5] = vorrq_u64(acc[5], vandq_u64(pair(d[2], d[3]), mask));
                acc[6] = vorrq_u64(acc[6], vandq_u64(pair(p[4], m[4]), mask));
                acc[7] = vorrq_u64(acc[7], vandq_u64(pair(d[4], 0), mask));
            }};
        }
        merge!(0);
        merge!(1);
        merge!(2);
        merge!(3);
        merge!(4);
        merge!(5);
        merge!(6);
        merge!(7);
        // Digit 0 selects the identity (1, 1, 0): limb 0 of y_plus_x and of
        // y_minus_x are the low halves of acc[0] and acc[2].
        let one = vandq_u64(identity, pair(1, 0));
        acc[0] = vorrq_u64(acc[0], one);
        acc[2] = vorrq_u64(acc[2], one);
        let lo = |v: uint64x2_t| vgetq_lane_u64::<0>(v);
        let hi = |v: uint64x2_t| vgetq_lane_u64::<1>(v);
        *out = Niels {
            y_plus_x: Fe([lo(acc[0]), hi(acc[0]), lo(acc[1]), hi(acc[1]), lo(acc[6])]),
            y_minus_x: Fe([lo(acc[2]), hi(acc[2]), lo(acc[3]), hi(acc[3]), hi(acc[6])]),
            xy2d: Fe([lo(acc[4]), hi(acc[4]), lo(acc[5]), hi(acc[5]), lo(acc[7])]),
        };
    }
}

/// [`select_row`] of a four-limb row ([`super::tables::BASE64`]): each
/// coordinate is two whole vectors, so an entry is six loads and six
/// `and`/`orr` pairs with no lane inserts, and the result needs no
/// conversion. Returned by value: inlined, it stays in registers.
#[cfg(not(miri))]
#[inline(always)]
pub(super) fn select_row64(row: &[Niels<Fe64>; 8], magnitude: u8) -> Niels<Fe64> {
    // SAFETY: as for `select_row`; each `vld1q_u64` reads the two `u64`s of
    // a two-element subslice of a table limb array, in bounds and aligned
    // for `u64`, which is all the instruction requires.
    unsafe {
        let pair = |a: u64, b: u64| vcombine_u64(vcreate_u64(a), vcreate_u64(b));
        let magnitude = vdupq_n_u64(u64::from(magnitude));
        macro_rules! hit {
            ($j:expr) => {
                vceqq_u64(magnitude, vdupq_n_u64($j))
            };
        }
        let mut acc = [vdupq_n_u64(0); 6];
        macro_rules! merge {
            ($j:literal) => {{
                let mask = hit!($j + 1);
                let p = &row[$j].y_plus_x.0;
                let m = &row[$j].y_minus_x.0;
                let d = &row[$j].xy2d.0;
                acc[0] = vorrq_u64(acc[0], vandq_u64(vld1q_u64(p[..2].as_ptr()), mask));
                acc[1] = vorrq_u64(acc[1], vandq_u64(vld1q_u64(p[2..].as_ptr()), mask));
                acc[2] = vorrq_u64(acc[2], vandq_u64(vld1q_u64(m[..2].as_ptr()), mask));
                acc[3] = vorrq_u64(acc[3], vandq_u64(vld1q_u64(m[2..].as_ptr()), mask));
                acc[4] = vorrq_u64(acc[4], vandq_u64(vld1q_u64(d[..2].as_ptr()), mask));
                acc[5] = vorrq_u64(acc[5], vandq_u64(vld1q_u64(d[2..].as_ptr()), mask));
            }};
        }
        merge!(0);
        merge!(1);
        merge!(2);
        merge!(3);
        merge!(4);
        merge!(5);
        merge!(6);
        merge!(7);
        // Digit 0 selects the identity (1, 1, 0).
        let one = vandq_u64(hit!(0), pair(1, 0));
        acc[0] = vorrq_u64(acc[0], one);
        acc[2] = vorrq_u64(acc[2], one);
        let lo = |v: uint64x2_t| vgetq_lane_u64::<0>(v);
        let hi = |v: uint64x2_t| vgetq_lane_u64::<1>(v);
        Niels {
            y_plus_x: Fe64([lo(acc[0]), hi(acc[0]), lo(acc[1]), hi(acc[1])]),
            y_minus_x: Fe64([lo(acc[2]), hi(acc[2]), lo(acc[3]), hi(acc[3])]),
            xy2d: Fe64([lo(acc[4]), hi(acc[4]), lo(acc[5]), hi(acc[5])]),
        }
    }
}
