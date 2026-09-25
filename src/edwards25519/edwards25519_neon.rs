//! NEON constant-time lookup in a row of the edwards25519 basepoint table.
//!
//! The 15 limbs of every entry are masked and merged two at a time, so a
//! lookup is 8 * 8 vector `and`/`orr` pairs instead of 8 * 15 scalar mask
//! steps. Memory access is the same for every digit: all eight entries are
//! always read.

use core::arch::aarch64::*;

use super::{Niels, ct_eq_u8};
use crate::fe25519::Fe;

/// Constant-time table row lookup into `out`: entry `magnitude - 1` for
/// `magnitude` in `1..=8`, the identity for `0`.
///
/// Compiled only when NEON is a build-time target feature, so it needs no
/// `#[target_feature]` and can be `#[inline(always)]`: inlined into
/// `mul_base` together with the dispatcher, `out` never has its address
/// taken and the selected entry stays in registers and spill slots, which
/// cannot be reliably wiped. Wiping `out` would only force them into memory.
///
/// The nine digit compares (subtle's out-of-line `Choice` barrier, through
/// [`ct_eq_u8`]) all run before the merges, which are spelled out: `acc`
/// then never has to survive a call, and nothing is indexed by a loop
/// counter. At opt-level `z` and `s` the former `zip` over `acc` was not
/// unrolled, which kept it in a stack array nothing wipes, and `u8::ct_eq`
/// was out of line with a reference to the secret magnitude.
#[inline(always)]
pub(super) fn select_row(row: &[Niels; 8], magnitude: u8, out: &mut Niels) {
    // SAFETY: this module is compiled only when `neon` is a build-time
    // target feature, so every NEON intrinsic's feature requirement holds
    // wherever this code runs; they operate on values only.
    unsafe {
        let pair = |a: u64, b: u64| vcombine_u64(vcreate_u64(a), vcreate_u64(b));
        // All ones when `magnitude == $j`, otherwise zero.
        macro_rules! hit {
            ($j:literal) => {
                vdupq_n_u64(0u64.wrapping_sub(u64::from(ct_eq_u8(magnitude, $j).unwrap_u8())))
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
