//! GF(2^255 - 19) in four 64-bit limbs, for the AArch64 X25519 ladder and
//! the basepoint multiplication's accumulators.
//!
//! An element is any value below `2^256` congruent to the field element, so
//! results are only reduced modulo `2^256 - 38` (`2^256 = 38 mod p`): a
//! product is 16 `mul`/`umulh` pairs plus 4 for the fold of its high half,
//! against 25 pairs and 4 scaling multiplies in the radix-2^51
//! [`super::Fe`], so the multiplier-bound ladder step and basepoint
//! additions need about a quarter fewer multiplies. Sums and differences carry
//! across the limbs and fold the carry (or borrow) back in as `38`, twice at
//! most, with conditional selects. Every block is register-only base A64
//! arithmetic with no branch and no memory access; the ladder and the basepoint
//! multiplication convert their results to [`super::Fe`].
//!
//! Zeroization: the limbs flow only through registers, `asm!` operands and
//! the callers' locals: the ladder wipes its locals, and the basepoint
//! multiplication's stay in registers and spill slots (see its comments).

use zeroize::Zeroize;

use super::{Fe, MASK51};

/// Field element as four little-endian 64-bit limbs of a value below `2^256`.
#[derive(Clone, Copy, Zeroize)]
pub(crate) struct Fe64(pub(crate) [u64; 4]);

/// Folds the carry limb `$c` (small) of `$t0..$t3` back in as `38 * $c`,
/// then a possible carry out of that as one more `38`; `$k` holds 38.
macro_rules! fold_carry {
    ($t0:literal, $t1:literal, $t2:literal, $t3:literal, $c:literal, $k:literal) => {
        concat!(
            "mul {",
            $c,
            "}, {",
            $c,
            "}, {",
            $k,
            "}\n",
            "adds {",
            $t0,
            "}, {",
            $t0,
            "}, {",
            $c,
            "}\n",
            "adcs {",
            $t1,
            "}, {",
            $t1,
            "}, xzr\n",
            "adcs {",
            $t2,
            "}, {",
            $t2,
            "}, xzr\n",
            "adcs {",
            $t3,
            "}, {",
            $t3,
            "}, xzr\n",
            "csel {",
            $c,
            "}, {",
            $k,
            "}, xzr, cs\n",
            "add {",
            $t0,
            "}, {",
            $t0,
            "}, {",
            $c,
            "}\n",
        )
    };
}

/// Reduces the eight-limb `t0..t7` to four limbs `t0..t3`: `t4..t7 * 38`
/// added to `t0..t3`, then the carry folded; uses `l0..l3`, `h0..h3`, `k`.
macro_rules! reduce512 {
    () => {
        concat!(
            "mul {l0}, {t4}, {k}\n",
            "umulh {h0}, {t4}, {k}\n",
            "mul {l1}, {t5}, {k}\n",
            "umulh {h1}, {t5}, {k}\n",
            "mul {l2}, {t6}, {k}\n",
            "umulh {h2}, {t6}, {k}\n",
            "mul {l3}, {t7}, {k}\n",
            "umulh {h3}, {t7}, {k}\n",
            "adds {t0}, {t0}, {l0}\n",
            "adcs {t1}, {t1}, {l1}\n",
            "adcs {t2}, {t2}, {l2}\n",
            "adcs {t3}, {t3}, {l3}\n",
            "adc {t4}, xzr, xzr\n",
            "adds {t1}, {t1}, {h0}\n",
            "adcs {t2}, {t2}, {h1}\n",
            "adcs {t3}, {t3}, {h2}\n",
            // Each `h` is below 38, so the carry limb is below 40.
            "adc {t4}, {t4}, {h3}\n",
            fold_carry!("t0", "t1", "t2", "t3", "t4", "k"),
        )
    };
}

impl Fe64 {
    pub(crate) const ONE: Fe64 = Fe64([1, 0, 0, 0]);
    pub(crate) const ZERO: Fe64 = Fe64([0; 4]);

    /// Decodes a little-endian 255-bit value, ignoring the top bit of `b`.
    #[inline(always)]
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe64 {
        let w = b.as_chunks::<8>().0;
        Fe64([
            u64::from_le_bytes(w[0]),
            u64::from_le_bytes(w[1]),
            u64::from_le_bytes(w[2]),
            u64::from_le_bytes(w[3]) & (u64::MAX >> 1),
        ])
    }

    /// The same element from radix-2^51 limbs each below `2^51` (a
    /// canonical or reduced [`Fe`], such as a basepoint table entry).
    #[inline(always)]
    pub(crate) fn from_fe(f: &Fe) -> Fe64 {
        let [l0, l1, l2, l3, l4] = f.0;
        debug_assert!(f.0.iter().all(|&l| l <= MASK51));
        Fe64([
            l0 | (l1 << 51),
            (l1 >> 13) | (l2 << 38),
            (l2 >> 26) | (l3 << 25),
            (l3 >> 39) | (l4 << 12),
        ])
    }

    /// `b` when `mask` is all ones and `self` when it is zero, with the
    /// same operations either way.
    #[inline(always)]
    pub(crate) fn select(&self, b: &Fe64, mask: u64) -> Fe64 {
        Fe64(core::array::from_fn(|i| {
            self.0[i] ^ ((self.0[i] ^ b.0[i]) & mask)
        }))
    }

    /// The same element in radix 2^51, weakly reduced like a multiply
    /// output (limbs below `2^51 + 2^13`): bit 255 and up fold into the low
    /// limb as `19`.
    #[inline(always)]
    pub(crate) fn to_fe(self) -> Fe {
        let [v0, v1, v2, v3] = self.0;
        let top = v3 >> 12;
        Fe([
            (v0 & MASK51) + 19 * (top >> 51),
            ((v0 >> 51) | (v1 << 13)) & MASK51,
            ((v1 >> 38) | (v2 << 26)) & MASK51,
            ((v2 >> 25) | (v3 << 39)) & MASK51,
            top & MASK51,
        ])
    }

    /// `self + b`.
    #[inline(always)]
    pub(crate) fn add(&self, b: &Fe64) -> Fe64 {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = b.0;
        let (t0, t1, t2, t3): (u64, u64, u64, u64);
        // SAFETY: register-only arithmetic on the declared operands; no
        // memory or stack access.
        unsafe {
            core::arch::asm!(
                "adds {t0}, {a0}, {b0}",
                "adcs {t1}, {a1}, {b1}",
                "adcs {t2}, {a2}, {b2}",
                "adcs {t3}, {a3}, {b3}",
                "csel {c}, {k}, xzr, cs",
                "adds {t0}, {t0}, {c}",
                "adcs {t1}, {t1}, xzr",
                "adcs {t2}, {t2}, xzr",
                "adcs {t3}, {t3}, xzr",
                "csel {c}, {k}, xzr, cs",
                "add {t0}, {t0}, {c}",
                a0 = in(reg) a0, a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3,
                b0 = in(reg) b0, b1 = in(reg) b1, b2 = in(reg) b2, b3 = in(reg) b3,
                k = in(reg) 38u64, c = out(reg) _,
                t0 = out(reg) t0, t1 = out(reg) t1, t2 = out(reg) t2, t3 = out(reg) t3,
                options(pure, nomem, nostack),
            );
        }
        Fe64([t0, t1, t2, t3])
    }

    /// `self - b`.
    #[inline(always)]
    pub(crate) fn sub(&self, b: &Fe64) -> Fe64 {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = b.0;
        let (t0, t1, t2, t3): (u64, u64, u64, u64);
        // SAFETY: as for `add`.
        unsafe {
            core::arch::asm!(
                "subs {t0}, {a0}, {b0}",
                "sbcs {t1}, {a1}, {b1}",
                "sbcs {t2}, {a2}, {b2}",
                "sbcs {t3}, {a3}, {b3}",
                // A borrow wrapped the value by 2^256 = 38: take 38 off.
                "csel {c}, {k}, xzr, cc",
                "subs {t0}, {t0}, {c}",
                "sbcs {t1}, {t1}, xzr",
                "sbcs {t2}, {t2}, xzr",
                "sbcs {t3}, {t3}, xzr",
                "csel {c}, {k}, xzr, cc",
                "sub {t0}, {t0}, {c}",
                a0 = in(reg) a0, a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3,
                b0 = in(reg) b0, b1 = in(reg) b1, b2 = in(reg) b2, b3 = in(reg) b3,
                k = in(reg) 38u64, c = out(reg) _,
                t0 = out(reg) t0, t1 = out(reg) t1, t2 = out(reg) t2, t3 = out(reg) t3,
                options(pure, nomem, nostack),
            );
        }
        Fe64([t0, t1, t2, t3])
    }

    /// `self * b`: a four-by-four schoolbook product as two independent
    /// halves, rows 0-1 into `t0..t5` and rows 2-3 into `u2..u7`, each with
    /// one carry chain for the low and one for the high product halves, then
    /// their sum and the 512-bit fold. Splitting the rows halves the
    /// dependent carry chain, which bounds the ladder step's latency.
    #[inline(always)]
    pub(crate) fn mul(&self, b: &Fe64) -> Fe64 {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = b.0;
        let (t0, t1, t2, t3): (u64, u64, u64, u64);
        // SAFETY: as for `add`.
        unsafe {
            core::arch::asm!(
                // Rows 0 and 1: t0..t5 = (a0 + a1 * 2^64) * b.
                "mul {t0}, {a0}, {b0}",
                "umulh {y}, {a0}, {b0}",
                "mul {x}, {a0}, {b1}",
                "adds {t1}, {x}, {y}",
                "umulh {y}, {a0}, {b1}",
                "mul {x}, {a0}, {b2}",
                "adcs {t2}, {x}, {y}",
                "umulh {y}, {a0}, {b2}",
                "mul {x}, {a0}, {b3}",
                "adcs {t3}, {x}, {y}",
                "umulh {y}, {a0}, {b3}",
                "adc {t4}, {y}, xzr",
                "mul {x}, {a1}, {b0}",
                "adds {t1}, {t1}, {x}",
                "mul {x}, {a1}, {b1}",
                "adcs {t2}, {t2}, {x}",
                "mul {x}, {a1}, {b2}",
                "adcs {t3}, {t3}, {x}",
                "mul {x}, {a1}, {b3}",
                "adcs {t4}, {t4}, {x}",
                "adc {t5}, xzr, xzr",
                "umulh {x}, {a1}, {b0}",
                "adds {t2}, {t2}, {x}",
                "umulh {x}, {a1}, {b1}",
                "adcs {t3}, {t3}, {x}",
                "umulh {x}, {a1}, {b2}",
                "adcs {t4}, {t4}, {x}",
                "umulh {x}, {a1}, {b3}",
                "adc {t5}, {t5}, {x}",
                // Rows 2 and 3: u2..u7 = (a2 + a3 * 2^64) * b, from 2^128.
                "mul {u2}, {a2}, {b0}",
                "umulh {w}, {a2}, {b0}",
                "mul {v}, {a2}, {b1}",
                "adds {u3}, {v}, {w}",
                "umulh {w}, {a2}, {b1}",
                "mul {v}, {a2}, {b2}",
                "adcs {u4}, {v}, {w}",
                "umulh {w}, {a2}, {b2}",
                "mul {v}, {a2}, {b3}",
                "adcs {u5}, {v}, {w}",
                "umulh {w}, {a2}, {b3}",
                "adc {u6}, {w}, xzr",
                "mul {v}, {a3}, {b0}",
                "adds {u3}, {u3}, {v}",
                "mul {v}, {a3}, {b1}",
                "adcs {u4}, {u4}, {v}",
                "mul {v}, {a3}, {b2}",
                "adcs {u5}, {u5}, {v}",
                "mul {v}, {a3}, {b3}",
                "adcs {u6}, {u6}, {v}",
                "adc {u7}, xzr, xzr",
                "umulh {v}, {a3}, {b0}",
                "adds {u4}, {u4}, {v}",
                "umulh {v}, {a3}, {b1}",
                "adcs {u5}, {u5}, {v}",
                "umulh {v}, {a3}, {b2}",
                "adcs {u6}, {u6}, {v}",
                "umulh {v}, {a3}, {b3}",
                "adc {u7}, {u7}, {v}",
                // t2..t7 = t2..t5 + u2..u7.
                "adds {t2}, {t2}, {u2}",
                "adcs {t3}, {t3}, {u3}",
                "adcs {t4}, {t4}, {u4}",
                "adcs {t5}, {t5}, {u5}",
                "adcs {u6}, {u6}, xzr",
                "adc {u7}, {u7}, xzr",
                // Fold: t0..t3 += (t4, t5, u6, u7) * 38, then the carry.
                "mul {x}, {t4}, {k}",
                "adds {t0}, {t0}, {x}",
                "mul {x}, {t5}, {k}",
                "adcs {t1}, {t1}, {x}",
                "mul {x}, {u6}, {k}",
                "adcs {t2}, {t2}, {x}",
                "mul {x}, {u7}, {k}",
                "adcs {t3}, {t3}, {x}",
                "adc {v}, xzr, xzr",
                "umulh {x}, {t4}, {k}",
                "adds {t1}, {t1}, {x}",
                "umulh {x}, {t5}, {k}",
                "adcs {t2}, {t2}, {x}",
                "umulh {x}, {u6}, {k}",
                "adcs {t3}, {t3}, {x}",
                "umulh {x}, {u7}, {k}",
                // Each high half is below 38, so the carry limb is below 40.
                "adc {v}, {v}, {x}",
                fold_carry!("t0", "t1", "t2", "t3", "v", "k"),
                a0 = in(reg) a0, a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3,
                b0 = in(reg) b0, b1 = in(reg) b1, b2 = in(reg) b2, b3 = in(reg) b3,
                k = in(reg) 38u64,
                x = out(reg) _, y = out(reg) _, v = out(reg) _, w = out(reg) _,
                t4 = out(reg) _, t5 = out(reg) _,
                u2 = out(reg) _, u3 = out(reg) _, u4 = out(reg) _, u5 = out(reg) _,
                u6 = out(reg) _, u7 = out(reg) _,
                t0 = out(reg) t0, t1 = out(reg) t1, t2 = out(reg) t2, t3 = out(reg) t3,
                options(pure, nomem, nostack),
            );
        }
        Fe64([t0, t1, t2, t3])
    }

    /// `self^2`: the six cross products once, doubled, plus the four
    /// squares, then the 512-bit fold.
    #[inline(always)]
    pub(crate) fn square(&self) -> Fe64 {
        let [a0, a1, a2, a3] = self.0;
        let (t0, t1, t2, t3): (u64, u64, u64, u64);
        // SAFETY: as for `add`.
        unsafe {
            core::arch::asm!(
                // Cross products a_i * a_j (i < j) into t1..t6.
                "mul {t1}, {a0}, {a1}",
                "umulh {h0}, {a0}, {a1}",
                "mul {l1}, {a0}, {a2}",
                "umulh {h1}, {a0}, {a2}",
                "mul {l2}, {a0}, {a3}",
                "umulh {t4}, {a0}, {a3}",
                "adds {t2}, {h0}, {l1}",
                "adcs {t3}, {h1}, {l2}",
                "adc {t4}, {t4}, xzr",
                "mul {l0}, {a1}, {a2}",
                "umulh {h0}, {a1}, {a2}",
                "mul {l1}, {a1}, {a3}",
                "umulh {h1}, {a1}, {a3}",
                "adds {t3}, {t3}, {l0}",
                "adcs {t4}, {t4}, {l1}",
                "adc {t5}, xzr, xzr",
                "adds {t4}, {t4}, {h0}",
                "adc {t5}, {t5}, {h1}",
                "mul {l0}, {a2}, {a3}",
                "umulh {h0}, {a2}, {a3}",
                "adds {t5}, {t5}, {l0}",
                "adc {t6}, {h0}, xzr",
                // Doubled into t1..t7.
                "adds {t1}, {t1}, {t1}",
                "adcs {t2}, {t2}, {t2}",
                "adcs {t3}, {t3}, {t3}",
                "adcs {t4}, {t4}, {t4}",
                "adcs {t5}, {t5}, {t5}",
                "adcs {t6}, {t6}, {t6}",
                "adc {t7}, xzr, xzr",
                // Plus the squares a_i^2 at limbs 2i, 2i + 1.
                "mul {t0}, {a0}, {a0}",
                "umulh {h0}, {a0}, {a0}",
                "mul {l1}, {a1}, {a1}",
                "umulh {h1}, {a1}, {a1}",
                "mul {l2}, {a2}, {a2}",
                "umulh {h2}, {a2}, {a2}",
                "mul {l3}, {a3}, {a3}",
                "umulh {h3}, {a3}, {a3}",
                "adds {t1}, {t1}, {h0}",
                "adcs {t2}, {t2}, {l1}",
                "adcs {t3}, {t3}, {h1}",
                "adcs {t4}, {t4}, {l2}",
                "adcs {t5}, {t5}, {h2}",
                "adcs {t6}, {t6}, {l3}",
                "adc {t7}, {t7}, {h3}",
                reduce512!(),
                a0 = in(reg) a0, a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3,
                k = in(reg) 38u64,
                l0 = out(reg) _, l1 = out(reg) _, l2 = out(reg) _, l3 = out(reg) _,
                h0 = out(reg) _, h1 = out(reg) _, h2 = out(reg) _, h3 = out(reg) _,
                t4 = out(reg) _, t5 = out(reg) _, t6 = out(reg) _, t7 = out(reg) _,
                t0 = out(reg) t0, t1 = out(reg) t1, t2 = out(reg) t2, t3 = out(reg) t3,
                options(pure, nomem, nostack),
            );
        }
        Fe64([t0, t1, t2, t3])
    }

    /// `self * 121666 + b`, the ladder's `BB + (A + 2) / 4 * E` in one fold
    /// instead of the product's and the sum's.
    #[inline(always)]
    pub(crate) fn mul_121666_add(&self, b: &Fe64) -> Fe64 {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = b.0;
        let (t0, t1, t2, t3): (u64, u64, u64, u64);
        // SAFETY: as for `add`.
        unsafe {
            core::arch::asm!(
                "mul {t0}, {a0}, {m}",
                "umulh {h0}, {a0}, {m}",
                "mul {l1}, {a1}, {m}",
                "umulh {h1}, {a1}, {m}",
                "mul {l2}, {a2}, {m}",
                "umulh {h2}, {a2}, {m}",
                "mul {l3}, {a3}, {m}",
                "umulh {t4}, {a3}, {m}",
                "adds {t1}, {l1}, {h0}",
                "adcs {t2}, {l2}, {h1}",
                "adcs {t3}, {l3}, {h2}",
                "adc {t4}, {t4}, xzr",
                "adds {t0}, {t0}, {b0}",
                "adcs {t1}, {t1}, {b1}",
                "adcs {t2}, {t2}, {b2}",
                "adcs {t3}, {t3}, {b3}",
                // Below 121667.
                "adc {t4}, {t4}, xzr",
                fold_carry!("t0", "t1", "t2", "t3", "t4", "k"),
                a0 = in(reg) a0, a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3,
                b0 = in(reg) b0, b1 = in(reg) b1, b2 = in(reg) b2, b3 = in(reg) b3,
                m = in(reg) 121_666u64, k = in(reg) 38u64,
                l1 = out(reg) _, l2 = out(reg) _, l3 = out(reg) _,
                h0 = out(reg) _, h1 = out(reg) _, h2 = out(reg) _, t4 = out(reg) _,
                t0 = out(reg) t0, t1 = out(reg) t1, t2 = out(reg) t2, t3 = out(reg) t3,
                options(pure, nomem, nostack),
            );
        }
        Fe64([t0, t1, t2, t3])
    }

    /// Swaps `a` and `b` when `swap` is 1 and leaves them when it is 0,
    /// with the same operations either way.
    #[inline(always)]
    pub(crate) fn cswap(a: &mut Fe64, b: &mut Fe64, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        let [x0, x1, x2, x3] = &mut a.0;
        let [y0, y1, y2, y3] = &mut b.0;
        macro_rules! swap_limb {
            ($x:ident, $y:ident) => {
                let t = mask & (*$x ^ *$y);
                *$x ^= t;
                *$y ^= t;
            };
        }
        swap_limb!(x0, y0);
        swap_limb!(x1, y1);
        swap_limb!(x2, y2);
        swap_limb!(x3, y3);
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::test_prelude::*;
    use crate::utils::test_util::XorShift64;

    fn prime() -> BigUint {
        (BigUint::from(1u8) << 255u32) - 19u8
    }

    fn int(x: &Fe64) -> BigUint {
        x.0.iter()
            .rev()
            .fold(BigUint::ZERO, |acc, &limb| (acc << 64u32) + limb)
    }

    /// Every operation agrees with integer arithmetic modulo `p` on random
    /// values and on the edges of the four-limb range (0, 1, `p - 1`, `p`,
    /// `2^255 - 1`, `2p`, `2^256 - 39`, `2^256 - 38` and `2^256 - 1`, where
    /// the carry and borrow folds run once or twice), and `to_fe` keeps the
    /// value.
    #[test]
    fn test_ops_match_bigint() {
        let p = prime();
        let top = (BigUint::from(1u8) << 256u32) - 1u8;
        let from_int = |v: &BigUint| {
            let digits = v.to_u64_digits();
            Fe64(core::array::from_fn(|i| {
                digits.get(i).copied().unwrap_or(0)
            }))
        };
        let mut values: Vec<Fe64> = [
            BigUint::ZERO,
            BigUint::from(1u8),
            &p - 1u8,
            p.clone(),
            (BigUint::from(1u8) << 255u32) - 1u8,
            &p * 2u8,
            &top - 38u8,
            &top - 37u8,
            top.clone(),
            &top - (BigUint::from(1u8) << 64u32),
        ]
        .iter()
        .map(from_int)
        .collect();
        let mut rng = XorShift64::new(0x6a09_e667_f3bc_c908);
        for _ in 0..300 {
            values.push(Fe64(core::array::from_fn(|_| rng.next_u64())));
        }
        let modp = |v: BigUint| v % &p;
        for (i, a) in values.iter().enumerate() {
            let ia = int(a);
            assert_eq!(modp(int(&a.square())), modp(&ia * &ia), "square {i}");
            let fe = a.to_fe();
            assert!(
                fe.0.iter().all(|&l| l < (1 << 51) + (1 << 13)),
                "to_fe {i} bound"
            );
            let limbs =
                fe.0.iter()
                    .rev()
                    .fold(BigUint::ZERO, |acc, &l| (acc << 51u32) + l);
            assert_eq!(modp(limbs), modp(ia.clone()), "to_fe {i}");
            for (j, b) in values.iter().enumerate() {
                let ib = int(b);
                assert_eq!(modp(int(&a.mul(b))), modp(&ia * &ib), "mul {i} {j}");
                assert_eq!(modp(int(&a.add(b))), modp(&ia + &ib), "add {i} {j}");
                assert_eq!(
                    modp(int(&a.mul_121666_add(b))),
                    modp(&ia * 121_666u32 + &ib),
                    "mul_121666_add {i} {j}"
                );
                assert_eq!(
                    modp(int(&a.sub(b))),
                    modp(&ia + &p * 4u8 - &ib),
                    "sub {i} {j}"
                );
            }
            let (mut x, mut y) = (*a, values[(i + 1) % values.len()]);
            let (x0, y0) = (x.0, y.0);
            Fe64::cswap(&mut x, &mut y, 0);
            assert_eq!((x.0, y.0), (x0, y0), "cswap 0 {i}");
            Fe64::cswap(&mut x, &mut y, 1);
            assert_eq!((x.0, y.0), (y0, x0), "cswap 1 {i}");
        }
        // Bit 255 is ignored: all ones with low byte 0xed decode to p.
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xed;
        assert_eq!(int(&Fe64::from_bytes(&bytes)), p);
    }
}
