//! AVX-512 constant-time lookup in a row of the edwards25519 basepoint table.
//!
//! The 15 limbs of every entry are held in two `zmm` registers and merged
//! with two masked blends, so a lookup is 8 * (2 loads + 2 blends) instead of
//! 8 * 15 scalar mask steps. Memory access is the same for every digit: all
//! eight entries are always read, and the blend mask comes from a vector
//! compare of the digit.

use core::arch::x86_64::{
    _mm512_cmpeq_epi64_mask, _mm512_mask_blend_epi64, _mm512_set1_epi64, _mm512_setr_epi64,
};

use super::Niels;
use crate::fe25519::Fe;
use crate::x86_64::store_words512;

/// Constant-time table row lookup: entry `magnitude - 1` for `magnitude` in
/// `1..=8`, the identity for `0`.
#[target_feature(enable = "avx512f")]
pub(super) fn select_row(row: &[Niels; 8], magnitude: u8) -> Niels {
    // Limbs 0..8 and 8..15 of an entry (y_plus_x, y_minus_x, xy2d), the
    // second word padded with a zero lane.
    let words = |n: &Niels| {
        let p = &n.y_plus_x.0;
        let m = &n.y_minus_x.0;
        let d = &n.xy2d.0;
        [
            _mm512_setr_epi64(
                p[0] as i64,
                p[1] as i64,
                p[2] as i64,
                p[3] as i64,
                p[4] as i64,
                m[0] as i64,
                m[1] as i64,
                m[2] as i64,
            ),
            _mm512_setr_epi64(
                m[3] as i64,
                m[4] as i64,
                d[0] as i64,
                d[1] as i64,
                d[2] as i64,
                d[3] as i64,
                d[4] as i64,
                0,
            ),
        ]
    };
    let digit = _mm512_set1_epi64(i64::from(magnitude));
    let mut acc = words(&Niels::IDENTITY);
    for (j, entry) in row.iter().enumerate() {
        // All ones when `magnitude == j + 1`, otherwise zero; the compare
        // and the blends run in the same time whatever the digit.
        let hit = _mm512_cmpeq_epi64_mask(digit, _mm512_set1_epi64(j as i64 + 1));
        let [lo, hi] = words(entry);
        acc[0] = _mm512_mask_blend_epi64(hit, acc[0], lo);
        acc[1] = _mm512_mask_blend_epi64(hit, acc[1], hi);
    }
    let mut lo = [0u64; 8];
    let mut hi = [0u64; 8];
    store_words512(&mut lo, acc[0]);
    store_words512(&mut hi, acc[1]);
    Niels {
        y_plus_x: Fe([lo[0], lo[1], lo[2], lo[3], lo[4]]),
        y_minus_x: Fe([lo[5], lo[6], lo[7], hi[0], hi[1]]),
        xy2d: Fe([hi[2], hi[3], hi[4], hi[5], hi[6]]),
    }
}
