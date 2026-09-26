//! AArch64 Poly1305 block loops on the integer multipliers, in radix 2^64
//! (Poly1305-donna-64, the `asm!` text of [`crate::poly1305::poly_block`]):
//! [`blocks`], four Horner lanes each over a contiguous quarter of the
//! input, joined at the end as `L0 p^3 + L1 p^2 + L2 p + L3` with `p = r^n`
//! for `n` blocks per lane, and [`blocks1`], one lane for short inputs.
//!
//! Each lane multiplies by the clamped `r` itself, whose low two bits of
//! `r1` are clear, so a block is ten `mul`/`umulh` and about twenty additions
//! (a 3x44-bit block takes eighteen multiplies). One lane is bound by its
//! Horner step's latency (about fifteen cycles on Neoverse V3); four overlap
//! to the multipliers' throughput, about 7.5 cycles per block, which the
//! NEON kernel's 5x26-bit lanes only match with a key-power setup that
//! costs more than the join here.
//!
//! The lanes, the radix-2^64 key and the join power are locals: they live
//! only in registers and compiler spill slots, which Rust cannot reliably
//! wipe; wiping them would only force them into memory. Control flow and
//! memory access depend only on the input length.

use super::{carry44, limbs44, limbs64, mul_mod_p, sq_mod_p};

/// Horner lanes of [`blocks`].
const LANES: usize = 4;
/// `blocks` takes a non-empty multiple of this: one block per lane.
pub(super) const CHUNK: usize = 16 * LANES;

/// The clamped 3x44-bit `r` in radix 2^64 with the folded `s1 = r1 + r1 /
/// 4`, as `poly_block` takes it.
#[inline(always)]
fn radix64_key(r: &[u64; 3]) -> [u64; 3] {
    // `r` is clamped below 2^124, with the low two bits of `r1` clear.
    let r0 = r[0] | (r[1] << 44);
    let r1 = (r[1] >> 20) | (r[2] << 24);
    [r0, r1, r1 + (r1 >> 2)]
}

/// The scalar block loop over whole 16-byte blocks of `input`: `h` (the
/// state in radix 2^64, `h[2]` below 8) absorbs each block with the `2^128`
/// bit when `hibit` is 1 (full blocks) or without it when 0 (the padded
/// final block), and is multiplied by `r` (the clamped 3x44-bit key limbs). One
/// radix-2^64 Horner step is about fifteen cycles on Neoverse V3 against about
/// 27 for the 3x44-bit step, which is latency-bound too.
#[inline]
pub(super) fn blocks1(h: &mut [u64; 3], r: &[u64; 3], input: &[u8], hibit: u64) {
    debug_assert!(input.len().is_multiple_of(16) && hibit <= 1);
    let n = input.len() / 16;
    if n == 0 {
        return;
    }
    let [r0, r1, s1] = radix64_key(r);
    // SAFETY: the loop runs `n` times and each iteration's `poly_block`
    // reads the 16 bytes at the pointer and advances it, so it reads exactly
    // `input`. Apart from those loads the block is register-only
    // arithmetic: every written register is a declared operand, the flags
    // are clobbered and it uses no stack.
    unsafe {
        core::arch::asm!(
            "2:",
            crate::poly1305::poly_block!("a"),
            "subs {n}, {n}, #1",
            "b.ne 2b",
            h0a = inout(reg) h[0], h1a = inout(reg) h[1], h2a = inout(reg) h[2],
            pa = inout(reg) input.as_ptr() => _,
            n = inout(reg) n => _,
            r0 = in(reg) r0, r1 = in(reg) r1, s1 = in(reg) s1, one = in(reg) hibit,
            t0a = out(reg) _, t1a = out(reg) _,
            d0a = out(reg) _, d1a = out(reg) _, d2a = out(reg) _,
            options(nostack, readonly),
        );
    }
}

/// `r^e` for `e >= 1` by left-to-right square-and-multiply. `e` is a
/// public length, so the loop's shape may depend on it.
#[inline(always)]
fn pow_mod_p(r: &[u64; 3], e: usize) -> [u64; 3] {
    debug_assert!(e >= 1);
    let mut acc = *r;
    for bit in (0..usize::BITS - 1 - e.leading_zeros()).rev() {
        acc = sq_mod_p(&acc);
        if (e >> bit) & 1 == 1 {
            acc = mul_mod_p(&acc, r);
        }
    }
    acc
}

/// Processes `input` (a non-empty multiple of `CHUNK` bytes) into `h`, the
/// state in radix 2^64 (`h[2]` below 8), with the clamped 3x44-bit key limbs
/// `r`.
#[inline]
pub(super) fn blocks(h: &mut [u64; 3], r: &[u64; 3], input: &[u8]) {
    debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK));
    let n = input.len() / CHUNK;
    // The join powers `p = r^n`, `p^2`, `p^3`: independent of the lanes, and
    // formed first so the core overlaps their chain with the loop.
    let p = pow_mod_p(r, n);
    let p2 = sq_mod_p(&p);
    let p3 = mul_mod_p(&p2, &p);
    blocks_with_powers(h, r, input, &[p, p2, p3]);
}

/// [`blocks`] with the join powers `[r^n, r^2n, r^3n]` (3x44-bit limbs) for
/// `n = input.len() / CHUNK` given, as the stitched ChaCha20 key already holds
/// them for its chunks. `#[inline(always)]`: out of line (opt-level `z`) it
/// took [`blocks`]' powers by reference from an unwiped stack array.
#[inline(always)]
pub(super) fn blocks_with_powers(
    h: &mut [u64; 3],
    r: &[u64; 3],
    input: &[u8],
    [p, p2, p3]: &[[u64; 3]; 3],
) {
    debug_assert!(!input.is_empty() && input.len().is_multiple_of(CHUNK));
    let n = input.len() / CHUNK;
    let quarter = n * 16;
    let (a, rest) = input.split_at(quarter);
    let (b, rest) = rest.split_at(quarter);
    let (c, d) = rest.split_at(quarter);
    let [r0, r1, s1] = radix64_key(r);
    let mut lanes = [*h, [0; 3], [0; 3], [0; 3]];
    // SAFETY: the loop runs `n` times and each iteration's `poly_block`s
    // read 16 bytes at each lane's pointer and advance it, so lane `k`
    // reads exactly its `n * 16`-byte quarter of `input`. Apart from those
    // loads the block is register-only arithmetic: every written register
    // is a declared operand, the flags are clobbered and it uses no stack.
    unsafe {
        core::arch::asm!(
            "2:",
            crate::poly1305::poly_block!("a", ""),
            crate::poly1305::poly_block!("b", ""),
            crate::poly1305::poly_block!("c", ""),
            crate::poly1305::poly_block!("d", ""),
            "subs {n}, {n}, #1",
            "b.ne 2b",
            h0a = inout(reg) lanes[0][0], h1a = inout(reg) lanes[0][1], h2a = inout(reg) lanes[0][2],
            h0b = inout(reg) lanes[1][0], h1b = inout(reg) lanes[1][1], h2b = inout(reg) lanes[1][2],
            h0c = inout(reg) lanes[2][0], h1c = inout(reg) lanes[2][1], h2c = inout(reg) lanes[2][2],
            h0d = inout(reg) lanes[3][0], h1d = inout(reg) lanes[3][1], h2d = inout(reg) lanes[3][2],
            pa = inout(reg) a.as_ptr() => _, pb = inout(reg) b.as_ptr() => _,
            pc = inout(reg) c.as_ptr() => _, pd = inout(reg) d.as_ptr() => _,
            n = inout(reg) n => _,
            r0 = in(reg) r0, r1 = in(reg) r1, s1 = in(reg) s1, one = in(reg) 1u64,
            t0 = out(reg) _, t1 = out(reg) _,
            d0 = out(reg) _, d1 = out(reg) _, d2 = out(reg) _,
            options(nostack, readonly),
        );
    }
    // Each lane follows `n` blocks after the previous one:
    // `L0 p^3 + L1 p^2 + L2 p + L3`, three independent products.
    let a = mul_mod_p(&limbs44(&lanes[0]), p3);
    let b = mul_mod_p(&limbs44(&lanes[1]), p2);
    let c = mul_mod_p(&limbs44(&lanes[2]), p);
    let d = limbs44(&lanes[3]);
    *h = limbs64(&carry44([
        a[0] + b[0] + c[0] + d[0],
        a[1] + b[1] + c[1] + d[1],
        a[2] + b[2] + c[2] + d[2],
    ]));
}
