//! NEON constant-time lookup in a row of the edwards25519 basepoint table.
//!
//! The 15 limbs of every entry are masked and merged two at a time, so a
//! lookup is 8 * 8 vector `and`/`orr` pairs instead of 8 * 15 scalar mask
//! steps. Memory access is the same for every digit: all eight entries are
//! always read.

use core::arch::aarch64::*;

use subtle::ConstantTimeEq;

use super::Niels;
use crate::fe25519::Fe;

/// Constant-time table row lookup into `out`: entry `magnitude - 1` for
/// `magnitude` in `1..=8`, the identity for `0`.
///
/// Compiled only when NEON is a build-time target feature, so it needs no
/// `#[target_feature]` and can be `#[inline(always)]`: inlined into
/// `mul_base` together with the dispatcher, `out` never has its address
/// taken and the selected entry stays in registers and spill slots, which
/// cannot be reliably wiped. Wiping `out` would only force it into memory.
#[inline(always)]
pub(super) fn select_row(row: &[Niels; 8], magnitude: u8, out: &mut Niels) {
    // SAFETY: this module is compiled only when `neon` is a build-time
    // target feature, so every NEON intrinsic's feature requirement holds
    // wherever this code runs; they operate on values only.
    unsafe {
        let pair = |a: u64, b: u64| vcombine_u64(vcreate_u64(a), vcreate_u64(b));
        // `acc` is never passed by reference either; around the out-of-line
        // `subtle` barrier calls it lives in spill slots.
        let mut acc = [vdupq_n_u64(0); 8];
        for (j, entry) in row.iter().enumerate() {
            let mask = vdupq_n_u64(
                0u64.wrapping_sub(u64::from(magnitude.ct_eq(&(j as u8 + 1)).unwrap_u8())),
            );
            let p = &entry.y_plus_x.0;
            let m = &entry.y_minus_x.0;
            let d = &entry.xy2d.0;
            let limbs = [
                pair(p[0], p[1]),
                pair(p[2], p[3]),
                pair(m[0], m[1]),
                pair(m[2], m[3]),
                pair(d[0], d[1]),
                pair(d[2], d[3]),
                pair(p[4], m[4]),
                pair(d[4], 0),
            ];
            for (a, l) in acc.iter_mut().zip(limbs) {
                *a = vorrq_u64(*a, vandq_u64(l, mask));
            }
        }
        // Digit 0 selects the identity (1, 1, 0): limb 0 of y_plus_x and of
        // y_minus_x are the low halves of acc[0] and acc[2].
        let identity = vdupq_n_u64(0u64.wrapping_sub(u64::from(magnitude.ct_eq(&0).unwrap_u8())));
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
