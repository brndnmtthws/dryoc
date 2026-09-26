//! Register-only `asm!` bodies for the field multiply and square (the
//! ladder's multiply by the curve constant is in `fe64_aarch64`).
//!
//! LLVM interleaves the 25 (15) `mul`/`umulh` pairs of the portable versions
//! with the surrounding ladder arithmetic and spills a third of the ladder
//! step to the stack; keeping each product in one opaque block removes the
//! spills and runs the ladder ~10% faster. The blocks use only base A64
//! integer instructions, so no feature detection is needed.

use super::MASK51;

/// Schoolbook product of two elements with limbs below 2^54, weakly
/// reduced. Column `j` collects `a[i] * b[j - i]` plus `19 * a[i] *
/// b[j - i + 5]` as a 128-bit `l:h` pair; each product is below 2^113 and
/// each column below 2^116, so `extr #51` recovers the full carry.
#[inline(always)]
pub(super) fn mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let (l0, l1, l2, l3, l4): (u64, u64, u64, u64, u64);
    // SAFETY: pure register arithmetic on the ten input limbs; every
    // written register is declared as an output or scratch operand and
    // the block touches neither memory nor the stack.
    unsafe {
        core::arch::asm!(
            // 19 * b[1..4], folded into the columns that wrap past 2^255.
            "mul {s1}, {b1}, {n19}",
            "mul {s2}, {b2}, {n19}",
            "mul {s3}, {b3}, {n19}",
            "mul {s4}, {b4}, {n19}",
            // column 0: {l0}:{h0} = a0*b0 + a4*s1 + a3*s2 + a2*s3 + a1*s4
            "mul {l0}, {a0}, {b0}",
            "umulh {h0}, {a0}, {b0}",
            "mul {t0}, {a4}, {s1}",
            "umulh {t1}, {a4}, {s1}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            "mul {t0}, {a3}, {s2}",
            "umulh {t1}, {a3}, {s2}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            "mul {t0}, {a2}, {s3}",
            "umulh {t1}, {a2}, {s3}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            "mul {t0}, {a1}, {s4}",
            "umulh {t1}, {a1}, {s4}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            // column 1: {l1}:{h1} = a1*b0 + a0*b1 + a4*s2 + a3*s3 + a2*s4
            "mul {l1}, {a1}, {b0}",
            "umulh {h1}, {a1}, {b0}",
            "mul {t0}, {a0}, {b1}",
            "umulh {t1}, {a0}, {b1}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            "mul {t0}, {a4}, {s2}",
            "umulh {t1}, {a4}, {s2}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            "mul {t0}, {a3}, {s3}",
            "umulh {t1}, {a3}, {s3}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            "mul {t0}, {a2}, {s4}",
            "umulh {t1}, {a2}, {s4}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            // column 2: {l2}:{h2} = a2*b0 + a1*b1 + a0*b2 + a4*s3 + a3*s4
            "mul {l2}, {a2}, {b0}",
            "umulh {h2}, {a2}, {b0}",
            "mul {t0}, {a1}, {b1}",
            "umulh {t1}, {a1}, {b1}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            "mul {t0}, {a0}, {b2}",
            "umulh {t1}, {a0}, {b2}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            "mul {t0}, {a4}, {s3}",
            "umulh {t1}, {a4}, {s3}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            "mul {t0}, {a3}, {s4}",
            "umulh {t1}, {a3}, {s4}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            // column 3: {l3}:{h3} = a3*b0 + a2*b1 + a1*b2 + a0*b3 + a4*s4
            "mul {l3}, {a3}, {b0}",
            "umulh {h3}, {a3}, {b0}",
            "mul {t0}, {a2}, {b1}",
            "umulh {t1}, {a2}, {b1}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            "mul {t0}, {a1}, {b2}",
            "umulh {t1}, {a1}, {b2}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            "mul {t0}, {a0}, {b3}",
            "umulh {t1}, {a0}, {b3}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            "mul {t0}, {a4}, {s4}",
            "umulh {t1}, {a4}, {s4}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            // column 4: {l4}:{h4} = a4*b0 + a3*b1 + a2*b2 + a1*b3 + a0*b4
            "mul {l4}, {a4}, {b0}",
            "umulh {h4}, {a4}, {b0}",
            "mul {t0}, {a3}, {b1}",
            "umulh {t1}, {a3}, {b1}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            "mul {t0}, {a2}, {b2}",
            "umulh {t1}, {a2}, {b2}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            "mul {t0}, {a1}, {b3}",
            "umulh {t1}, {a1}, {b3}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            "mul {t0}, {a0}, {b4}",
            "umulh {t1}, {a0}, {b4}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            // Carry each column's bits above 51 into the next; the top carry
            // wraps to column 0 as 19 * carry, and one more carry from column
            // 0 to 1 leaves every limb below 2^51 + 2^13.
            "extr {t0}, {h0}, {l0}, #51",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, xzr",
            "and {l0}, {l0}, {mask}",
            "extr {t0}, {h1}, {l1}, #51",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, xzr",
            "and {l1}, {l1}, {mask}",
            "extr {t0}, {h2}, {l2}, #51",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, xzr",
            "and {l2}, {l2}, {mask}",
            "extr {t0}, {h3}, {l3}, #51",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, xzr",
            "and {l3}, {l3}, {mask}",
            "extr {t0}, {h4}, {l4}, #51",
            "and {l4}, {l4}, {mask}",
            "madd {l0}, {t0}, {n19}, {l0}",
            "add {l1}, {l1}, {l0}, lsr #51",
            "and {l0}, {l0}, {mask}",
            a0 = in(reg) a[0], a1 = in(reg) a[1], a2 = in(reg) a[2],
            a3 = in(reg) a[3], a4 = in(reg) a[4],
            b0 = in(reg) b[0], b1 = in(reg) b[1], b2 = in(reg) b[2],
            b3 = in(reg) b[3], b4 = in(reg) b[4],
            n19 = in(reg) 19u64, mask = in(reg) MASK51,
            s1 = out(reg) _, s2 = out(reg) _, s3 = out(reg) _, s4 = out(reg) _,
            t0 = out(reg) _, t1 = out(reg) _,
            h0 = out(reg) _, h1 = out(reg) _, h2 = out(reg) _, h3 = out(reg) _,
            h4 = out(reg) _,
            l0 = out(reg) l0, l1 = out(reg) l1, l2 = out(reg) l2, l3 = out(reg) l3,
            l4 = out(reg) l4,
            options(pure, nomem, nostack),
        );
    }
    [l0, l1, l2, l3, l4]
}

/// Square of an element with limbs below 2^54, weakly reduced; the
/// symmetric cross terms are formed once from doubled limbs.
#[inline(always)]
pub(super) fn square(a: &[u64; 5]) -> [u64; 5] {
    let (l0, l1, l2, l3, l4): (u64, u64, u64, u64, u64);
    // SAFETY: as for `mul`: register-only arithmetic with every written
    // register declared, no memory or stack access.
    unsafe {
        core::arch::asm!(
            // Doubled and 19-scaled limbs shared by the symmetric products.
            "lsl {d0}, {a0}, #1",
            "lsl {d1}, {a1}, #1",
            // 19 * a3 and 19 * a4 as 17x + 2x: two single-cycle adds
            // instead of a multiply at the head of the chain.
            "add {s3}, {a3}, {a3}, lsl #4",
            "add {s4}, {a4}, {a4}, lsl #4",
            "add {s3}, {s3}, {a3}, lsl #1",
            "add {s4}, {s4}, {a4}, lsl #1",
            "lsl {w3}, {s3}, #1",
            "lsl {w4}, {s4}, #1",
            // column 0: a0*a0 + d1*s4 + a2*w3
            "mul {l0}, {a0}, {a0}",
            "umulh {h0}, {a0}, {a0}",
            "mul {t0}, {d1}, {s4}",
            "umulh {t1}, {d1}, {s4}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            "mul {t0}, {a2}, {w3}",
            "umulh {t1}, {a2}, {w3}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            // column 1: d0*a1 + a2*w4 + a3*s3
            "mul {l1}, {d0}, {a1}",
            "umulh {h1}, {d0}, {a1}",
            "mul {t0}, {a2}, {w4}",
            "umulh {t1}, {a2}, {w4}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            "mul {t0}, {a3}, {s3}",
            "umulh {t1}, {a3}, {s3}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            // column 2: d0*a2 + a1*a1 + a3*w4
            "mul {l2}, {d0}, {a2}",
            "umulh {h2}, {d0}, {a2}",
            "mul {t0}, {a1}, {a1}",
            "umulh {t1}, {a1}, {a1}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            "mul {t0}, {a3}, {w4}",
            "umulh {t1}, {a3}, {w4}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            // column 3: d0*a3 + d1*a2 + a4*s4
            "mul {l3}, {d0}, {a3}",
            "umulh {h3}, {d0}, {a3}",
            "mul {t0}, {d1}, {a2}",
            "umulh {t1}, {d1}, {a2}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            "mul {t0}, {a4}, {s4}",
            "umulh {t1}, {a4}, {s4}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            // column 4: d0*a4 + d1*a3 + a2*a2
            "mul {l4}, {d0}, {a4}",
            "umulh {h4}, {d0}, {a4}",
            "mul {t0}, {d1}, {a3}",
            "umulh {t1}, {d1}, {a3}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            "mul {t0}, {a2}, {a2}",
            "umulh {t1}, {a2}, {a2}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            // Carry each column's bits above 51 into the next; the top carry
            // wraps to column 0 as 19 * carry, and one more carry from column
            // 0 to 1 leaves every limb below 2^51 + 2^13.
            "extr {t0}, {h0}, {l0}, #51",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, xzr",
            "and {l0}, {l0}, {mask}",
            "extr {t0}, {h1}, {l1}, #51",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, xzr",
            "and {l1}, {l1}, {mask}",
            "extr {t0}, {h2}, {l2}, #51",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, xzr",
            "and {l2}, {l2}, {mask}",
            "extr {t0}, {h3}, {l3}, #51",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, xzr",
            "and {l3}, {l3}, {mask}",
            "extr {t0}, {h4}, {l4}, #51",
            "and {l4}, {l4}, {mask}",
            "madd {l0}, {t0}, {n19}, {l0}",
            "add {l1}, {l1}, {l0}, lsr #51",
            "and {l0}, {l0}, {mask}",
            a0 = in(reg) a[0], a1 = in(reg) a[1], a2 = in(reg) a[2],
            a3 = in(reg) a[3], a4 = in(reg) a[4],
            n19 = in(reg) 19u64, mask = in(reg) MASK51,
            d0 = out(reg) _, d1 = out(reg) _, s3 = out(reg) _, s4 = out(reg) _,
            w3 = out(reg) _, w4 = out(reg) _,
            t0 = out(reg) _, t1 = out(reg) _,
            h0 = out(reg) _, h1 = out(reg) _, h2 = out(reg) _, h3 = out(reg) _,
            h4 = out(reg) _,
            l0 = out(reg) l0, l1 = out(reg) l1, l2 = out(reg) l2, l3 = out(reg) l3,
            l4 = out(reg) l4,
            options(pure, nomem, nostack),
        );
    }
    [l0, l1, l2, l3, l4]
}

/// Square of a *reduced* element (limbs below 2^52), weakly reduced, with
/// a shorter dependency chain than [`square`]: its two carry passes run
/// in parallel across the limbs, which matters for the 254 dependent
/// squarings of an inversion.
#[inline(always)]
pub(super) fn square_chain(a: &[u64; 5]) -> [u64; 5] {
    let (l0, l1, l2, l3, l4): (u64, u64, u64, u64, u64);
    // SAFETY: as for `mul`: register-only arithmetic with every written
    // register declared, no memory or stack access.
    unsafe {
        core::arch::asm!(
            // Doubled and 19-scaled limbs shared by the symmetric products.
            "lsl {d0}, {a0}, #1",
            "lsl {d1}, {a1}, #1",
            // 19 * a3 and 19 * a4 as 17x + 2x: two single-cycle adds
            // instead of a multiply at the head of the chain.
            "add {s3}, {a3}, {a3}, lsl #4",
            "add {s4}, {a4}, {a4}, lsl #4",
            "add {s3}, {s3}, {a3}, lsl #1",
            "add {s4}, {s4}, {a4}, lsl #1",
            "lsl {w3}, {s3}, #1",
            "lsl {w4}, {s4}, #1",
            // column 0: a0*a0 + d1*s4 + a2*w3
            "mul {l0}, {a0}, {a0}",
            "umulh {h0}, {a0}, {a0}",
            "mul {t0}, {d1}, {s4}",
            "umulh {t1}, {d1}, {s4}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            "mul {t0}, {a2}, {w3}",
            "umulh {t1}, {a2}, {w3}",
            "adds {l0}, {l0}, {t0}",
            "adc {h0}, {h0}, {t1}",
            // column 1: d0*a1 + a2*w4 + a3*s3
            "mul {l1}, {d0}, {a1}",
            "umulh {h1}, {d0}, {a1}",
            "mul {t0}, {a2}, {w4}",
            "umulh {t1}, {a2}, {w4}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            "mul {t0}, {a3}, {s3}",
            "umulh {t1}, {a3}, {s3}",
            "adds {l1}, {l1}, {t0}",
            "adc {h1}, {h1}, {t1}",
            // column 2: d0*a2 + a1*a1 + a3*w4
            "mul {l2}, {d0}, {a2}",
            "umulh {h2}, {d0}, {a2}",
            "mul {t0}, {a1}, {a1}",
            "umulh {t1}, {a1}, {a1}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            "mul {t0}, {a3}, {w4}",
            "umulh {t1}, {a3}, {w4}",
            "adds {l2}, {l2}, {t0}",
            "adc {h2}, {h2}, {t1}",
            // column 3: d0*a3 + d1*a2 + a4*s4
            "mul {l3}, {d0}, {a3}",
            "umulh {h3}, {d0}, {a3}",
            "mul {t0}, {d1}, {a2}",
            "umulh {t1}, {d1}, {a2}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            "mul {t0}, {a4}, {s4}",
            "umulh {t1}, {a4}, {s4}",
            "adds {l3}, {l3}, {t0}",
            "adc {h3}, {h3}, {t1}",
            // column 4: d0*a4 + d1*a3 + a2*a2
            "mul {l4}, {d0}, {a4}",
            "umulh {h4}, {d0}, {a4}",
            "mul {t0}, {d1}, {a3}",
            "umulh {t1}, {d1}, {a3}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            "mul {t0}, {a2}, {a2}",
            "umulh {t1}, {a2}, {a2}",
            "adds {l4}, {l4}, {t0}",
            "adc {h4}, {h4}, {t1}",
            // Two parallel carry passes instead of one serial chain: the
            // inputs are reduced, so every column is below 2^112 and its
            // carry fits in 64 bits; after the first pass each limb is
            // below 2^62 and the second pass brings it below 2^51 + 2^16.
            "extr {h0}, {h0}, {l0}, #51",
            "extr {h1}, {h1}, {l1}, #51",
            "extr {h2}, {h2}, {l2}, #51",
            "extr {h3}, {h3}, {l3}, #51",
            "extr {h4}, {h4}, {l4}, #51",
            "and {l0}, {l0}, {mask}",
            "and {l1}, {l1}, {mask}",
            "and {l2}, {l2}, {mask}",
            "and {l3}, {l3}, {mask}",
            "and {l4}, {l4}, {mask}",
            "add {l1}, {l1}, {h0}",
            "add {l2}, {l2}, {h1}",
            "add {l3}, {l3}, {h2}",
            "add {l4}, {l4}, {h3}",
            "madd {l0}, {h4}, {n19}, {l0}",
            "lsr {h0}, {l0}, #51",
            "lsr {h1}, {l1}, #51",
            "lsr {h2}, {l2}, #51",
            "lsr {h3}, {l3}, #51",
            "lsr {h4}, {l4}, #51",
            "and {l0}, {l0}, {mask}",
            "and {l1}, {l1}, {mask}",
            "and {l2}, {l2}, {mask}",
            "and {l3}, {l3}, {mask}",
            "and {l4}, {l4}, {mask}",
            "add {l1}, {l1}, {h0}",
            "add {l2}, {l2}, {h1}",
            "add {l3}, {l3}, {h2}",
            "add {l4}, {l4}, {h3}",
            "madd {l0}, {h4}, {n19}, {l0}",
            a0 = in(reg) a[0], a1 = in(reg) a[1], a2 = in(reg) a[2],
            a3 = in(reg) a[3], a4 = in(reg) a[4],
            n19 = in(reg) 19u64, mask = in(reg) MASK51,
            d0 = out(reg) _, d1 = out(reg) _, s3 = out(reg) _, s4 = out(reg) _,
            w3 = out(reg) _, w4 = out(reg) _,
            t0 = out(reg) _, t1 = out(reg) _,
            h0 = out(reg) _, h1 = out(reg) _, h2 = out(reg) _, h3 = out(reg) _,
            h4 = out(reg) _,
            l0 = out(reg) l0, l1 = out(reg) l1, l2 = out(reg) l2, l3 = out(reg) l3,
            l4 = out(reg) l4,
            options(pure, nomem, nostack),
        );
    }
    [l0, l1, l2, l3, l4]
}
