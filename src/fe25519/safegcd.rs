//! Constant-time inversion in GF(2^255 - 19) by Bernstein-Yang divsteps
//! ("Fast constant-time gcd computation and modular inversion", 2019), in
//! the form of libsecp256k1's `modinv64` (Wuille's variant: `zeta = -(delta
//! + 1/2)`, 59 divsteps per batch on the low 64 bits of `f` and `g`, ten
//! batches for inputs below `2^256`).
//!
//! Integers are five signed 62-bit limbs (`v[0] + v[1] 2^62 + ...`). The
//! modulus is sparse in that form, `p = -19 + 128 * 2^248`, so its middle
//! limbs drop out of the products. Every step is branch-free and indexes
//! memory by constants only: the divsteps select on `zeta` and the low bit
//! of `g` (conditional selects in a register-only `asm!` loop on AArch64,
//! masks in the portable form), the batch updates are fixed sequences of
//! products, and the final normalization adds and negates with masks.
//!
//! Zeroization: the working values are locals of [`invert`] and of the
//! always-inlined helpers, so they only live in registers and compiler
//! spill slots, which Rust cannot reliably wipe; wiping them would only
//! force them into memory.

use super::Fe;

const M62: u64 = u64::MAX >> 2;

/// `p` in signed 62-bit limbs.
const MODULUS: [i64; 5] = [-19, 0, 0, 0, 128];

/// `p^-1 mod 2^62`, by Newton's iteration on the odd low limb.
const MODULUS_INV62: u64 = {
    let n = (MODULUS[0] as u64) & M62;
    // Each step doubles the number of correct low bits, from 3.
    let mut x = n;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
        i += 1;
    }
    x & M62
};

/// The transition matrix of a batch of divsteps, scaled by `2^62`.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 59 divsteps on the low bits `f0`, `g0` of `f` and `g`, starting from
/// `zeta`; returns the new `zeta` and the matrix taking `(f, g)` to `2^62`
/// times their values after the steps.
///
/// On AArch64 the loop is one register-only `asm!` block with conditional
/// selects: when `g` is odd and `zeta < 0`, `(f, g, u, v, q, r)` become
/// `(g, g - f, q, r, q - u, r - v)`; when `g` is odd otherwise, `f`, `u`, `v`
/// are added to `g`, `q`, `r`; then `g` is halved, `u` and `v` doubled and
/// `zeta` updated. That is [`divsteps_59_portable`]'s step (libsecp256k1's),
/// arranged so that the next `g` is two selects after its test: `g` is
/// never halved but kept scaled by `2^(k + 1)` at step `k` (so step `k`
/// tests bit `k + 1`, marked by `bit`, which is bit 0 of the true `g`, and
/// the low `63 - k` bits of the true `g` are all exact), and `f`, scaled
/// alike, is held as `h = f / 2`, so `g + f` and `g - f` are one
/// shifted-operand instruction each, formed beside the test.
#[cfg(all(target_arch = "aarch64", not(miri)))]
#[inline(always)]
fn divsteps_59(zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    let mut zeta = zeta;
    // The identity times 8: the loop's 59 doublings bring it to 2^62.
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    // SAFETY: register-only arithmetic: every written register is a declared
    // output or scratch operand, the flags are clobbered (no
    // `preserves_flags`), and the block reads and writes no memory and
    // uses no stack. `csel`, `csneg` and `ccmp` take the same time whatever
    // the condition, so the step is branch-free in the secret values; the
    // only branch is the fixed 59-iteration loop.
    unsafe {
        core::arch::asm!(
            "2:",
            "add {sp}, {g}, {h}, lsl #1",
            "sub {sm}, {g}, {h}, lsl #1",
            "lsl {f}, {h}, #1",
            "sub {zm}, {zeta}, #1",
            "add {zp}, {zeta}, #2",
            // `ne` iff `g` is odd.
            "tst {g}, {bit}",
            "csel {t1}, {u}, xzr, ne",
            "csel {t2}, {v}, xzr, ne",
            "csel {sp}, {sp}, {g}, ne",
            // `lt` iff `g` is odd and `zeta < 0` (flags cleared when even).
            "ccmp {zeta}, #0, #0, ne",
            // The swap: `f` takes `g` (halved: `h`), and `g` becomes `g - f`
            // rather than `g + f` (or `g`, when even).
            "csel {h}, {g}, {f}, lt",
            "csel {g}, {sm}, {sp}, lt",
            // `-zeta - 2` when `lt`, else `zeta - 1`.
            "csneg {zeta}, {zm}, {zp}, ge",
            // Negated when `lt`: the terms added to `q`, `r`.
            "csneg {t1}, {t1}, {u}, ge",
            "csneg {t2}, {t2}, {v}, ge",
            // The swap: `u`, `v` take `q`, `r` when `lt`.
            "csel {u}, {q}, {u}, lt",
            "csel {v}, {r}, {v}, lt",
            "add {q}, {q}, {t1}",
            "add {r}, {r}, {t2}",
            "lsl {u}, {u}, #1",
            "lsl {v}, {v}, #1",
            "lsl {bit}, {bit}, #1",
            "subs {i}, {i}, #1",
            "b.ne 2b",
            zeta = inout(reg) zeta,
            h = inout(reg) f0 => _,
            f = out(reg) _,
            sp = out(reg) _,
            sm = out(reg) _,
            zm = out(reg) _,
            zp = out(reg) _,
            g = inout(reg) g0 << 1 => _,
            u = inout(reg) u,
            v = inout(reg) v,
            q = inout(reg) q,
            r = inout(reg) r,
            i = inout(reg) 59u64 => _,
            bit = inout(reg) 2u64 => _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    (
        zeta,
        Trans {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// The portable [`divsteps_59`] (libsecp256k1's `divsteps_59`).
#[cfg_attr(all(target_arch = "aarch64", not(miri)), cfg(test))]
#[inline(always)]
fn divsteps_59_portable(mut zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    // The identity times 8: the loop's 59 doublings bring it to 2^62.
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        debug_assert_eq!(f & 1, 1);
        // Masks for `zeta < 0`, for `g` odd, and for both.
        let c1 = (zeta >> 63) as u64;
        let c2 = (g & 1).wrapping_neg();
        let c3 = c1 & c2;
        // `f`, `u`, `v`, negated when `zeta < 0`, are added to `g`, `q`,
        // `r` when `g` is odd. When both, `f`, `u`, `v` take the old `g`,
        // `q`, `r` (the sum libsecp256k1 forms, `f + (g - f)`, selected
        // directly so the new `f` does not wait for the new `g`), and
        // `zeta` becomes `-zeta - 2`; otherwise `zeta - 1`.
        let x = (f ^ c1).wrapping_sub(c1);
        let y = (u ^ c1).wrapping_sub(c1);
        let z = (v ^ c1).wrapping_sub(c1);
        f ^= (f ^ g) & c3;
        u ^= (u ^ q) & c3;
        v ^= (v ^ r) & c3;
        g = g.wrapping_add(x & c2) >> 1;
        q = q.wrapping_add(y & c2);
        r = r.wrapping_add(z & c2);
        u <<= 1;
        v <<= 1;
        zeta = (zeta ^ c3 as i64).wrapping_sub(1);
    }
    (
        zeta,
        Trans {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// [`divsteps_59_portable`] under Miri, which cannot run `asm!`.
#[cfg(not(all(target_arch = "aarch64", not(miri))))]
#[inline(always)]
fn divsteps_59(zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    divsteps_59_portable(zeta, f0, g0)
}

#[inline(always)]
fn mul(a: i64, b: i64) -> i128 {
    i128::from(a) * i128::from(b)
}

/// `(t [d, e] + p [md, me]) / 2^62`, with `md` and `me` chosen so the
/// division is exact and the results stay in `(-2p, p)`.
#[inline(always)]
fn update_de(d: &mut [i64; 5], e: &mut [i64; 5], t: &Trans) {
    let Trans { u, v, q, r } = *t;
    // Start from `[u, q]` if `d` is negative, plus `[v, r]` if `e` is.
    let sd = d[4] >> 63;
    let se = e[4] >> 63;
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);
    let mut cd = mul(u, d[0]) + mul(v, e[0]);
    let mut ce = mul(q, d[0]) + mul(r, e[0]);
    // Make the low 62 bits of `t [d, e] + p [md, me]` zero.
    md = md.wrapping_sub(
        (MODULUS_INV62
            .wrapping_mul(cd as u64)
            .wrapping_add(md as u64)
            & M62) as i64,
    );
    me = me.wrapping_sub(
        (MODULUS_INV62
            .wrapping_mul(ce as u64)
            .wrapping_add(me as u64)
            & M62) as i64,
    );
    cd += mul(MODULUS[0], md);
    ce += mul(MODULUS[0], me);
    debug_assert_eq!(cd as u64 & M62, 0);
    debug_assert_eq!(ce as u64 & M62, 0);
    cd >>= 62;
    ce >>= 62;
    // Limbs 1 to 3 of `p` are zero.
    for i in 1..4 {
        cd += mul(u, d[i]) + mul(v, e[i]);
        ce += mul(q, d[i]) + mul(r, e[i]);
        d[i - 1] = (cd as u64 & M62) as i64;
        e[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    cd += mul(u, d[4]) + mul(v, e[4]) + mul(MODULUS[4], md);
    ce += mul(q, d[4]) + mul(r, e[4]) + mul(MODULUS[4], me);
    d[3] = (cd as u64 & M62) as i64;
    e[3] = (ce as u64 & M62) as i64;
    d[4] = (cd >> 62) as i64;
    e[4] = (ce >> 62) as i64;
}

/// `t [f, g] / 2^62`, which is exact.
#[inline(always)]
fn update_fg(f: &mut [i64; 5], g: &mut [i64; 5], t: &Trans) {
    let Trans { u, v, q, r } = *t;
    let mut cf = mul(u, f[0]) + mul(v, g[0]);
    let mut cg = mul(q, f[0]) + mul(r, g[0]);
    debug_assert_eq!(cf as u64 & M62, 0);
    debug_assert_eq!(cg as u64 & M62, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf += mul(u, f[i]) + mul(v, g[i]);
        cg += mul(q, f[i]) + mul(r, g[i]);
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[4] = cf as i64;
    g[4] = cg as i64;
}

/// Brings `x` from `(-2p, p)` to `[0, p)`, negated first when `sign` is
/// negative, with limbs in `[0, 2^62)`.
#[inline(always)]
fn normalize(x: &mut [i64; 5], sign: i64) {
    let add_p = |x: &mut [i64; 5]| {
        let mask = x[4] >> 63;
        for (limb, &m) in x.iter_mut().zip(&MODULUS) {
            *limb += m & mask;
        }
    };
    let carry = |x: &mut [i64; 5]| {
        for i in 0..4 {
            x[i + 1] += x[i] >> 62;
            x[i] &= M62 as i64;
        }
    };
    add_p(x);
    let negate = sign >> 63;
    for limb in x.iter_mut() {
        *limb = (*limb ^ negate) - negate;
    }
    carry(x);
    add_p(x);
    carry(x);
}

/// `a^-1`, and zero for zero.
#[inline(always)]
pub(super) fn invert(a: &Fe) -> Fe {
    let w = a.canonical_words();
    let mut g = [
        (w[0] & M62) as i64,
        ((w[0] >> 62 | w[1] << 2) & M62) as i64,
        ((w[1] >> 60 | w[2] << 4) & M62) as i64,
        ((w[2] >> 58 | w[3] << 6) & M62) as i64,
        (w[3] >> 56) as i64,
    ];
    let mut f = MODULUS;
    let mut d = [0i64; 5];
    let mut e = [1i64, 0, 0, 0, 0];
    let mut zeta = -1i64;
    for _ in 0..10 {
        let (next, t) = divsteps_59(zeta, f[0] as u64, g[0] as u64);
        zeta = next;
        update_de(&mut d, &mut e, &t);
        update_fg(&mut f, &mut g, &t);
    }
    // `g` is zero and `f` is `+-1` (or `+-p` for a zero input, when `d` is
    // zero), with `d = f / a`.
    debug_assert!(g == [0; 5]);
    normalize(&mut d, f[4]);
    let l = d.map(|limb| limb as u64);
    let words = [
        l[0] | l[1] << 62,
        l[1] >> 2 | l[2] << 60,
        l[2] >> 4 | l[3] << 58,
        l[3] >> 6 | l[4] << 56,
    ];
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    Fe::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_util::XorShift64;

    /// The `asm!` divsteps give exactly the portable transition matrix and
    /// `zeta`, for random odd `f`, any `g` and `zeta` in the range the
    /// inversion reaches.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    #[test]
    fn test_divsteps_asm_matches_portable() {
        let mut rng = XorShift64::new(0x1f83_d9ab_5be0_cd19);
        for i in 0..20000 {
            let f = rng.next_u64() | 1;
            let g = match i % 4 {
                0 => 0,
                1 => rng.next_u64() & 0xff,
                _ => rng.next_u64(),
            };
            let zeta = (rng.next_u64() % 1183) as i64 - 591;
            let (za, ta) = divsteps_59(zeta, f, g);
            let (zp, tp) = divsteps_59_portable(zeta, f, g);
            assert_eq!(
                (za, ta.u, ta.v, ta.q, ta.r),
                (zp, tp.u, tp.v, tp.q, tp.r),
                "{f:x} {g:x} {zeta}"
            );
        }
    }

    /// The divsteps inversion equals the exponentiation on zero, one, `p`
    /// and `p - 1` (weakly reduced inputs included), values next to powers
    /// of two, and random elements and limb vectors up to the `2^54` limb
    /// bound; the product with the input is one.
    #[test]
    fn test_invert_matches_exponentiation() {
        const MASK51: u64 = (1 << 51) - 1;
        let mut inputs = vec![
            Fe::ZERO,
            Fe::ONE,
            Fe([MASK51 - 18, MASK51, MASK51, MASK51, MASK51]),
            Fe([MASK51 - 19, MASK51, MASK51, MASK51, MASK51]),
            Fe([MASK51; 5]),
            Fe([(1 << 54) - 1; 5]),
        ];
        for k in 0..255 {
            let mut bytes = [0u8; 32];
            bytes[k / 8] = 1 << (k % 8);
            inputs.push(Fe::from_bytes(&bytes));
            inputs.push(Fe::from_bytes(&bytes).neg());
        }
        let mut rng = XorShift64::new(0x243f_6a88_85a3_08d3);
        for i in 0..if cfg!(miri) { 8 } else { 4000 } {
            inputs.push(Fe::from_bytes(&rng.next_bytes32()));
            let mask = (1u64 << if i % 2 == 0 { 54 } else { 51 }) - 1;
            inputs.push(Fe(core::array::from_fn(|_| rng.next_u64() & mask)));
        }
        for (i, a) in inputs.iter().enumerate() {
            let inverse = invert(a);
            assert_eq!(inverse.to_bytes(), a.invert_impl().to_bytes(), "input {i}");
            let product = a.mul(&inverse).to_bytes();
            let expected = if a.to_bytes() == [0; 32] {
                Fe::ZERO
            } else {
                Fe::ONE
            };
            assert_eq!(product, expected.to_bytes(), "product {i}");
        }
    }
}
