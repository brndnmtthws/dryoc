//! AArch64 Keccak-p[1600] on the SHA3 extension (`EOR3`, `RAX1`, `XAR`,
//! `BCAX`), one or two states per call.
//!
//! Vector `i` holds lane `i` (`x + 5 * y`) of both states, one state per
//! 64-bit half; a single state runs with a zero second half, as the `keccak`
//! crate's AArch64 backend does. The round is that backend's (after XKCP's
//! `KeccakP-1600-ARMv8Asha3.S`): `theta` with `EOR3` and `RAX1`, `rho` and
//! `pi` with `XAR`, `chi` with `BCAX`.
//!
//! This replaces the crate backend for dryoc's sponges on CPUs with the SHA3
//! extension. That backend's single-state entry point copies the state into
//! a local `[state, zero]` array, passes it by reference to the out-of-line
//! two-state function and never wipes it, at every opt-level. Here the lanes
//! are loaded straight from, and stored straight back to, the caller's
//! state, and the whole permutation is one macro on 25 named locals, so the
//! working state lives only in registers and compiler spill slots (which are
//! not wiped: a wipe would only force them into memory) and no copy reaches
//! memory through a call. Control flow and memory access are independent of
//! the state.

use core::arch::aarch64::{
    uint64x2_t, vbcaxq_u64, vcombine_u64, vcreate_u64, vdupq_n_u64, veor3q_u64, veorq_u64,
    vgetq_lane_u64, vrax1q_u64, vxarq_u64,
};

use super::RC;

/// A kernel the running CPU has been verified to support.
///
/// Values are only created by [`detect`] after `has_aarch64_feature!("sha3")`
/// succeeds, which is what makes the permutation methods safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kernel {
    /// The SHA3 extension (`FEAT_SHA3`).
    Sha3,
}

/// The kernel the running CPU supports, if any.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    if has_aarch64_feature!("sha3") {
        Some(Kernel::Sha3)
    } else {
        None
    }
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> alloc::vec::Vec<Kernel> {
        detect().into_iter().collect()
    }

    /// Keccak-p[1600, `ROUNDS`] on one state, in place.
    #[inline]
    pub(super) fn permute1<const ROUNDS: usize>(self, state: &mut [u64; 25]) {
        match self {
            // SAFETY: `Kernel::Sha3` is only constructed after
            // `has_aarch64_feature!("sha3")` succeeded.
            Kernel::Sha3 => unsafe { permute1_sha3::<ROUNDS>(state) },
        }
    }

    /// Keccak-p[1600, `ROUNDS`] on two states, in place.
    #[inline]
    pub(super) fn permute2<const ROUNDS: usize>(self, a: &mut [u64; 25], b: &mut [u64; 25]) {
        match self {
            // SAFETY: as for `permute1`.
            Kernel::Sha3 => unsafe { permute2_sha3::<ROUNDS>(a, b) },
        }
    }

    /// Applies Keccak-p[1600, `ROUNDS`] to every state in `selected`, two
    /// at a time in lane order (the last one alone when their number is
    /// odd), and clears their flags.
    pub(super) fn permute_selected<const ROUNDS: usize, const N: usize>(
        self,
        states: &mut [[u64; 25]; N],
        selected: &mut [bool; N],
    ) {
        let mut lanes = [0; N];
        let mut count = 0;
        for (lane, _) in selected.iter().enumerate().filter(|(_, s)| **s) {
            lanes[count] = lane;
            count += 1;
        }
        let (pairs, rest) = lanes[..count].as_chunks::<2>();
        for &pair in pairs {
            let [a, b] = states
                .get_disjoint_mut(pair)
                .expect("selected lanes are distinct and in bounds");
            self.permute2::<ROUNDS>(a, b);
        }
        if let &[lane] = rest {
            self.permute1::<ROUNDS>(&mut states[lane]);
        }
        for flag in selected.iter_mut() {
            *flag = false;
        }
    }
}

/// Keccak-p[1600, `$rounds`] on 25 lane vectors that `$load!(i)` yields for
/// lane `i`, handing each result to `$store!(i, v)`. The lanes are 25 named
/// locals rather than an array, so keeping them in registers needs no
/// array scalarization at any opt-level; the round is the crate backend's
/// `theta`, `rho_pi` and `chi_iota`.
macro_rules! permute {
    ($rounds:expr, $load:ident, $store:ident) => {{
        let mut s0: uint64x2_t = $load!(0);
        let mut s1: uint64x2_t = $load!(1);
        let mut s2: uint64x2_t = $load!(2);
        let mut s3: uint64x2_t = $load!(3);
        let mut s4: uint64x2_t = $load!(4);
        let mut s5: uint64x2_t = $load!(5);
        let mut s6: uint64x2_t = $load!(6);
        let mut s7: uint64x2_t = $load!(7);
        let mut s8: uint64x2_t = $load!(8);
        let mut s9: uint64x2_t = $load!(9);
        let mut s10: uint64x2_t = $load!(10);
        let mut s11: uint64x2_t = $load!(11);
        let mut s12: uint64x2_t = $load!(12);
        let mut s13: uint64x2_t = $load!(13);
        let mut s14: uint64x2_t = $load!(14);
        let mut s15: uint64x2_t = $load!(15);
        let mut s16: uint64x2_t = $load!(16);
        let mut s17: uint64x2_t = $load!(17);
        let mut s18: uint64x2_t = $load!(18);
        let mut s19: uint64x2_t = $load!(19);
        let mut s20: uint64x2_t = $load!(20);
        let mut s21: uint64x2_t = $load!(21);
        let mut s22: uint64x2_t = $load!(22);
        let mut s23: uint64x2_t = $load!(23);
        let mut s24: uint64x2_t = $load!(24);
        let mut round = 24 - $rounds;
        while round < 24 {
            let rc = RC[round];
            // theta
            let c0 = veor3q_u64(s0, s5, veor3q_u64(s10, s15, s20));
            let c1 = veor3q_u64(s1, s6, veor3q_u64(s11, s16, s21));
            let c2 = veor3q_u64(s2, s7, veor3q_u64(s12, s17, s22));
            let c3 = veor3q_u64(s3, s8, veor3q_u64(s13, s18, s23));
            let c4 = veor3q_u64(s4, s9, veor3q_u64(s14, s19, s24));
            let d0 = vrax1q_u64(c4, c1);
            let d1 = vrax1q_u64(c0, c2);
            let d2 = vrax1q_u64(c1, c3);
            let d3 = vrax1q_u64(c2, c4);
            let d4 = vrax1q_u64(c3, c0);
            // rho and pi
            let v0 = veorq_u64(s0, d0);
            let v25 = vxarq_u64::<63>(s1, d1);
            let v1 = vxarq_u64::<20>(s6, d1);
            let v6 = vxarq_u64::<44>(s9, d4);
            let v9 = vxarq_u64::<3>(s22, d2);
            let v22 = vxarq_u64::<25>(s14, d4);
            let v14 = vxarq_u64::<46>(s20, d0);
            let v26 = vxarq_u64::<2>(s2, d2);
            let v2 = vxarq_u64::<21>(s12, d2);
            let v12 = vxarq_u64::<39>(s13, d3);
            let v13 = vxarq_u64::<56>(s19, d4);
            let v19 = vxarq_u64::<8>(s23, d3);
            let v23 = vxarq_u64::<23>(s15, d0);
            let v15 = vxarq_u64::<37>(s4, d4);
            let v28 = vxarq_u64::<50>(s24, d4);
            let v24 = vxarq_u64::<62>(s21, d1);
            let v8 = vxarq_u64::<9>(s8, d3);
            let v4 = vxarq_u64::<19>(s16, d1);
            let v16 = vxarq_u64::<28>(s5, d0);
            let v5 = vxarq_u64::<36>(s3, d3);
            let v27 = vxarq_u64::<43>(s18, d3);
            let v3 = vxarq_u64::<49>(s17, d2);
            let v30 = vxarq_u64::<54>(s11, d1);
            let v31 = vxarq_u64::<58>(s7, d2);
            let v29 = vxarq_u64::<61>(s10, d0);
            // chi and iota
            let rc_v = vdupq_n_u64(rc);
            s0 = veorq_u64(vbcaxq_u64(v0, v2, v1), rc_v);
            s1 = vbcaxq_u64(v1, v27, v2);
            s2 = vbcaxq_u64(v2, v28, v27);
            s3 = vbcaxq_u64(v27, v0, v28);
            s4 = vbcaxq_u64(v28, v1, v0);
            s5 = vbcaxq_u64(v5, v29, v6);
            s6 = vbcaxq_u64(v6, v4, v29);
            s7 = vbcaxq_u64(v29, v9, v4);
            s8 = vbcaxq_u64(v4, v5, v9);
            s9 = vbcaxq_u64(v9, v6, v5);
            s10 = vbcaxq_u64(v25, v12, v31);
            s11 = vbcaxq_u64(v31, v13, v12);
            s12 = vbcaxq_u64(v12, v14, v13);
            s13 = vbcaxq_u64(v13, v25, v14);
            s14 = vbcaxq_u64(v14, v31, v25);
            s15 = vbcaxq_u64(v15, v30, v16);
            s16 = vbcaxq_u64(v16, v3, v30);
            s17 = vbcaxq_u64(v30, v19, v3);
            s18 = vbcaxq_u64(v3, v15, v19);
            s19 = vbcaxq_u64(v19, v16, v15);
            s20 = vbcaxq_u64(v26, v22, v8);
            s21 = vbcaxq_u64(v8, v23, v22);
            s22 = vbcaxq_u64(v22, v24, v23);
            s23 = vbcaxq_u64(v23, v26, v24);
            s24 = vbcaxq_u64(v24, v8, v26);
            round += 1;
        }
        $store!(0, s0);
        $store!(1, s1);
        $store!(2, s2);
        $store!(3, s3);
        $store!(4, s4);
        $store!(5, s5);
        $store!(6, s6);
        $store!(7, s7);
        $store!(8, s8);
        $store!(9, s9);
        $store!(10, s10);
        $store!(11, s11);
        $store!(12, s12);
        $store!(13, s13);
        $store!(14, s14);
        $store!(15, s15);
        $store!(16, s16);
        $store!(17, s17);
        $store!(18, s18);
        $store!(19, s19);
        $store!(20, s20);
        $store!(21, s21);
        $store!(22, s22);
        $store!(23, s23);
        $store!(24, s24);
    }};
}

/// Keccak-p[1600, `ROUNDS`] on one state, with a zero second half.
#[target_feature(enable = "neon,sha3")]
fn permute1_sha3<const ROUNDS: usize>(state: &mut [u64; 25]) {
    const { assert!(ROUNDS <= 24) };
    macro_rules! load {
        ($i:literal) => {
            vcombine_u64(vcreate_u64(state[$i]), vcreate_u64(0))
        };
    }
    macro_rules! store {
        ($i:literal, $v:ident) => {
            state[$i] = vgetq_lane_u64::<0>($v)
        };
    }
    permute!(ROUNDS, load, store);
}

/// Keccak-p[1600, `ROUNDS`] on two states, `a` in the low halves and `b` in
/// the high halves.
#[target_feature(enable = "neon,sha3")]
fn permute2_sha3<const ROUNDS: usize>(a: &mut [u64; 25], b: &mut [u64; 25]) {
    const { assert!(ROUNDS <= 24) };
    macro_rules! load {
        ($i:literal) => {
            vcombine_u64(vcreate_u64(a[$i]), vcreate_u64(b[$i]))
        };
    }
    macro_rules! store {
        ($i:literal, $v:ident) => {{
            a[$i] = vgetq_lane_u64::<0>($v);
            b[$i] = vgetq_lane_u64::<1>($v);
        }};
    }
    permute!(ROUNDS, load, store);
}
