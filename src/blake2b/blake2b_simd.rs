use core::simd::{Simd, simd_swizzle};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    BLOCKBYTES, IV, KEYBYTES, OUTBYTES, PERSONALBYTES, Params, SALTBYTES, blake2b_longhash,
    increment_counter,
};
use crate::error::Error;
use crate::utils::load_u64_le;

#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct State {
    t: [u64; 2],
    f: [u64; 2],
    // Keep the persistent chaining state in scalar arrays so zeroize can wipe
    // it with volatile writes. Compression converts these values to SIMD only
    // for the duration of a block operation.
    a: [u64; 4],
    b: [u64; 4],
    last_node: u8,
    buf: [u8; BLOCKBYTES],
    buflen: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            t: [0u64; 2],
            f: [0u64; 2],
            a: [0; 4],
            b: [0; 4],
            last_node: 0,
            buf: [0u8; BLOCKBYTES],
            buflen: 0,
        }
    }
}

#[inline(always)]
fn loadm(block: &[u8; BLOCKBYTES]) -> [Simd<u64, 4>; 8] {
    macro_rules! load_pair {
        ($start:expr) => {{
            let m0 = load_u64_le(&block[$start..$start + 8]);
            let m1 = load_u64_le(&block[$start + 8..$start + 16]);
            Simd::from_array([m0, m1, m0, m1])
        }};
    }

    [
        load_pair!(0),
        load_pair!(16),
        load_pair!(32),
        load_pair!(48),
        load_pair!(64),
        load_pair!(80),
        load_pair!(96),
        load_pair!(112),
    ]
}

#[inline(always)]
fn rotru64<const N: u64>(v: Simd<u64, 4>) -> Simd<u64, 4> {
    (v >> Simd::splat(N)) | (v << Simd::splat(64 - N))
}

#[inline(always)]
fn g1(
    a: &mut Simd<u64, 4>,
    b: &mut Simd<u64, 4>,
    c: &mut Simd<u64, 4>,
    d: &mut Simd<u64, 4>,
    m: &Simd<u64, 4>,
) {
    *a = *a + *b + *m;
    *d = rotru64::<32>(*d ^ *a);
    *c += *d;
    *b = rotru64::<24>(*b ^ *c);
}

#[inline(always)]
fn g2(
    a: &mut Simd<u64, 4>,
    b: &mut Simd<u64, 4>,
    c: &mut Simd<u64, 4>,
    d: &mut Simd<u64, 4>,
    m: &Simd<u64, 4>,
) {
    *a = *a + *b + *m;
    *d = rotru64::<16>(*d ^ *a);
    *c += *d;
    *b = rotru64::<63>(*b ^ *c);
}

#[inline(always)]
fn permute(a: &mut Simd<u64, 4>, c: &mut Simd<u64, 4>, d: &mut Simd<u64, 4>) {
    *a = simd_swizzle!(*a, [3, 0, 1, 2]);
    *d = simd_swizzle!(*d, [2, 3, 0, 1]);
    *c = simd_swizzle!(*c, [1, 2, 3, 0]);
}

#[inline(always)]
fn unpermute(a: &mut Simd<u64, 4>, c: &mut Simd<u64, 4>, d: &mut Simd<u64, 4>) {
    *a = simd_swizzle!(*a, [1, 2, 3, 0]);
    *d = simd_swizzle!(*d, [2, 3, 0, 1]);
    *c = simd_swizzle!(*c, [3, 0, 1, 2]);
}

#[inline(always)]
fn compress_simd(
    a: &mut Simd<u64, 4>,
    b: &mut Simd<u64, 4>,
    st: &[u64; 2],
    sf: &[u64; 2],
    block: &[u8; BLOCKBYTES],
) {
    let mut c = Simd::<u64, 4>::from_array([IV[0], IV[1], IV[2], IV[3]]);
    let mut d =
        Simd::<u64, 4>::from_array([IV[4] ^ st[0], IV[5] ^ st[1], IV[6] ^ sf[0], IV[7] ^ sf[1]]);

    let m = loadm(block);

    let iv0 = *a;
    let iv1 = *b;
    let mut t0;
    let mut t1;
    let mut b0;

    // round 1
    t0 = simd_swizzle!(m[0], m[1], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[2], m[3], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[0], m[1], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[2], m[3], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[7], m[4], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[5], m[6], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[7], m[4], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[5], m[6], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 2
    t0 = simd_swizzle!(m[7], m[2], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[4], m[6], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[5], m[4], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[3], m[7], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[2], m[0], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[5], m[0], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[6], m[1], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[3], m[1], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 3
    t0 = simd_swizzle!(m[6], m[5], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[2], m[7], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[4], m[0], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[6], m[1], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[5], m[4], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[1], m[3], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[2], m[7], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[0], m[3], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 4
    t0 = simd_swizzle!(m[3], m[1], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[6], m[5], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[4], m[0], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[6], m[7], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[1], m[7], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[2], [1, 0, 3, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[4], m[3], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[5], m[0], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 5
    t0 = simd_swizzle!(m[4], m[2], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[1], m[5], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[3], m[0], [4, 1, 6, 3]);
    t1 = simd_swizzle!(m[7], m[2], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[7], m[1], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[3], m[5], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[6], m[0], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[6], m[4], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 6
    t0 = simd_swizzle!(m[1], m[3], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[0], m[4], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[6], m[5], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[5], m[1], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[2], m[0], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[3], m[7], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[4], m[6], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[7], m[2], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 7
    t0 = simd_swizzle!(m[0], m[6], [4, 1, 6, 3]);
    t1 = simd_swizzle!(m[7], m[2], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[2], m[7], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[5], m[6], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[4], m[0], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[4], m[3], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[5], m[3], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[1], [1, 0, 3, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 8
    t0 = simd_swizzle!(m[6], m[3], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[1], m[6], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[7], m[5], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[0], m[4], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[2], m[1], [4, 1, 6, 3]);
    t1 = simd_swizzle!(m[4], m[7], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[5], m[0], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[2], m[3], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 9
    t0 = simd_swizzle!(m[3], m[7], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[0], m[5], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[7], m[4], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[4], m[1], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[5], m[6], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[6], m[0], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[1], m[2], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[2], m[3], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 10
    t0 = simd_swizzle!(m[5], m[4], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[3], m[0], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[1], m[2], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[2], m[3], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[6], m[7], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[4], m[1], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[5], m[0], [4, 1, 6, 3]);
    t1 = simd_swizzle!(m[7], m[6], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 11
    t0 = simd_swizzle!(m[0], m[1], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[2], m[3], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[0], m[1], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[2], m[3], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[7], m[4], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[5], m[6], [0, 4, 2, 6]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[7], m[4], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[5], m[6], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    // round 12
    t0 = simd_swizzle!(m[7], m[2], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[4], m[6], [1, 5, 3, 7]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[5], m[4], [0, 4, 2, 6]);
    t1 = simd_swizzle!(m[3], m[7], [5, 0, 7, 2]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    permute(a, &mut c, &mut d);
    t0 = simd_swizzle!(m[2], m[0], [1, 5, 3, 7]);
    t1 = simd_swizzle!(m[5], m[0], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g1(a, b, &mut c, &mut d, &b0);
    t0 = simd_swizzle!(m[6], m[1], [5, 0, 7, 2]);
    t1 = simd_swizzle!(m[3], m[1], [4, 1, 6, 3]);
    b0 = simd_swizzle!(t0, t1, [0, 1, 6, 7]);
    g2(a, b, &mut c, &mut d, &b0);
    unpermute(a, &mut c, &mut d);

    *a ^= c;
    *b ^= d;
    *a ^= iv0;
    *b ^= iv1;
}

#[inline(always)]
fn compress(
    a: &mut [u64; 4],
    b: &mut [u64; 4],
    st: &[u64; 2],
    sf: &[u64; 2],
    block: &[u8; BLOCKBYTES],
) {
    let mut simd_a = Simd::from_array(*a);
    let mut simd_b = Simd::from_array(*b);
    compress_simd(&mut simd_a, &mut simd_b, st, sf, block);
    *a = simd_a.to_array();
    *b = simd_b.to_array();
}

impl State {
    fn init_param(params: &Params) -> Self {
        let mut state = Self::default();
        state.init0();

        let pslice = params.as_bytes();

        let param_a = [
            load_u64_le(&pslice[0..8]),
            load_u64_le(&pslice[8..16]),
            load_u64_le(&pslice[16..24]),
            load_u64_le(&pslice[24..32]),
        ];
        let param_b = [
            load_u64_le(&pslice[32..40]),
            load_u64_le(&pslice[40..48]),
            load_u64_le(&pslice[48..56]),
            load_u64_le(&pslice[56..64]),
        ];
        for (state_word, parameter_word) in state.a.iter_mut().zip(param_a) {
            *state_word ^= parameter_word;
        }
        for (state_word, parameter_word) in state.b.iter_mut().zip(param_b) {
            *state_word ^= parameter_word;
        }

        state
    }

    fn init0(&mut self) {
        self.a.copy_from_slice(&IV[..4]);
        self.b.copy_from_slice(&IV[4..]);
    }

    pub(crate) fn init(
        outlen: u8,
        key: Option<&[u8]>,
        salt: Option<&[u8; SALTBYTES]>,
        personal: Option<&[u8; PERSONALBYTES]>,
    ) -> Result<State, Error> {
        let params = Params::new(outlen, key, salt, personal)?;
        let mut state = Self::init_param(&params);

        if let Some(key) = key {
            let mut block = [0u8; BLOCKBYTES];
            block[..key.len()].copy_from_slice(key);
            state.update(&block);
            block.zeroize();
        }

        Ok(state)
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            // return early if the input is empty
            return;
        }

        if self.buflen != 0 {
            let fill = BLOCKBYTES - self.buflen;
            if input.len() <= fill {
                self.buf[self.buflen..self.buflen + input.len()].copy_from_slice(input);
                self.buflen += input.len();
                return;
            }

            self.buf[self.buflen..].copy_from_slice(&input[..fill]);
            self.buflen = 0;
            increment_counter(&mut self.t, BLOCKBYTES);
            compress(&mut self.a, &mut self.b, &self.t, &self.f, &self.buf);
            self.buf.zeroize();
            input = &input[fill..];
        }

        while input.len() > BLOCKBYTES {
            let block = input[..BLOCKBYTES]
                .try_into()
                .expect("input block should be exactly BLOCKBYTES");
            increment_counter(&mut self.t, BLOCKBYTES);
            compress(&mut self.a, &mut self.b, &self.t, &self.f, block);
            input = &input[BLOCKBYTES..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buflen = input.len();
    }

    pub(crate) fn finalize(mut self, output: &mut [u8]) -> Result<(), Error> {
        validate_length!(
            1,
            OUTBYTES,
            output.len(),
            crate::ErrorContext::Blake2bOutput
        );

        if self.is_lastblock() {
            return Err(Error::invalid_state(crate::ErrorContext::Blake2b));
        }

        increment_counter(&mut self.t, self.buflen);
        self.set_lastblock();

        self.buf[self.buflen..].fill(0);
        compress(&mut self.a, &mut self.b, &self.t, &self.f, &self.buf);

        let mut buffer = [0u8; OUTBYTES];
        buffer[0..8].copy_from_slice(&self.a[0].to_le_bytes());
        buffer[8..16].copy_from_slice(&self.a[1].to_le_bytes());
        buffer[16..24].copy_from_slice(&self.a[2].to_le_bytes());
        buffer[24..32].copy_from_slice(&self.a[3].to_le_bytes());
        buffer[32..40].copy_from_slice(&self.b[0].to_le_bytes());
        buffer[40..48].copy_from_slice(&self.b[1].to_le_bytes());
        buffer[48..56].copy_from_slice(&self.b[2].to_le_bytes());
        buffer[56..64].copy_from_slice(&self.b[3].to_le_bytes());
        output.copy_from_slice(&buffer[..output.len()]);

        buffer.zeroize();
        self.zeroize();

        Ok(())
    }

    fn set_lastnode(&mut self) {
        self.f[1] = -1i64 as u64;
    }

    fn is_lastblock(&self) -> bool {
        self.f[0] != 0
    }

    fn set_lastblock(&mut self) {
        if self.last_node != 0 {
            self.set_lastnode();
        }
        self.f[0] = -1i64 as u64;
    }
}

pub fn hash(output: &mut [u8], input: &[u8], key: Option<&[u8]>) -> Result<(), Error> {
    validate_length!(max OUTBYTES, output.len(), crate::ErrorContext::Blake2bOutput);

    let mut state = State::init(output.len() as u8, key, None, None)?;

    state.update(input);
    state.finalize(output)
}

/// Keyed BLAKE2b of the empty message with `salt` and `personal` (the
/// `crypto_kdf` construction).
pub(crate) fn hash_key_only(
    output: &mut [u8],
    key: &[u8],
    salt: &[u8; SALTBYTES],
    personal: &[u8; PERSONALBYTES],
) -> Result<(), Error> {
    validate_length!(
        1,
        OUTBYTES,
        output.len(),
        crate::ErrorContext::Blake2bOutput
    );
    validate_length!(1, KEYBYTES, key.len(), crate::ErrorContext::Blake2bKey);
    State::init(output.len() as u8, Some(key), Some(salt), Some(personal))?.finalize(output)
}

blake2b_longhash!();

#[cfg(test)]
mod tests {
    use crate::test_prelude::*;

    #[cfg(feature = "nightly")]
    extern crate test;
    use std::sync::LazyLock;

    #[cfg(dryoc_native_tests)]
    use libc::*;
    use serde::{Deserialize, Serialize};

    use super::*;

    static_assertions::assert_impl_all!(State: zeroize::ZeroizeOnDrop);
    const _: () = assert!(core::mem::needs_drop::<State>());

    #[cfg(dryoc_native_tests)]
    #[repr(C)]
    #[derive(Debug)]
    struct B2state {
        h: [u64; 8],
        t: [u64; 2],
        f: [u64; 2],
        buf: [c_uchar; 256],
        buflen: size_t,
        last_node: u8,
    }

    #[cfg(dryoc_native_tests)]
    unsafe extern "C" {
        fn blake2b_init(S: *mut B2state, outlen: c_uchar);
        fn blake2b_init_key(S: *mut B2state, outlen: c_uchar, key: *const u8, keylen: c_uchar);
        fn blake2b_update(S: *mut B2state, input: *const u8, inlen: u64);
        fn blake2b_final(S: *mut B2state, output: *mut u8, outlen: u64);
        fn blake2b_long(pout: *mut u8, outlen: u64, input: *const u8, inlen: u64);
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestVector {
        hash: String,
        #[serde(rename = "in")]
        in_: String,
        key: String,
        out: String,
    }

    static TEST_VECTORS: LazyLock<Vec<TestVector>> = LazyLock::new(|| {
        serde_json::from_str(include_str!("test-vectors/blake2b-test-vectors.json")).unwrap()
    });

    #[test]
    fn test_vectors() {
        for vector in TEST_VECTORS.iter() {
            let key = if vector.key.is_empty() {
                None
            } else {
                Some(hex::decode(&vector.key).unwrap())
            };
            let mut state = State::init(64, key.as_deref(), None, None).expect("init");
            state.update(hex::decode(&vector.in_).unwrap().as_slice());
            let mut output = [0u8; 64];

            state.finalize(&mut output).ok();

            assert_eq!(vector.out, hex::encode(output));
        }
    }

    #[test]
    fn rejects_key_lengths_that_do_not_fit_in_u8() {
        let key = [0u8; 256];
        let error = State::init(64, Some(&key), None, None).expect_err("key should be rejected");

        assert!(matches!(
            error,
            Error::InvalidLength {
                context: crate::ErrorContext::Blake2bKey,
                actual: 256,
                constraint: crate::LengthConstraint::AtMost(KEYBYTES),
            }
        ));
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn blake2b_bench(b: &mut test::Bencher) {
        use crate::rng::copy_randombytes;
        let mut input = vec![0u8; 694200];
        copy_randombytes(&mut input);

        b.iter(|| {
            let mut state = State::init(64, None, None, None).expect("init");
            state.update(test::black_box(&input));

            let mut output = [0u8; 64];
            state.finalize(&mut output).expect("finalize");
            test::black_box(&output);
        });
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_b2_simd() {
        crate::native_test_util::init();
        use crate::rng::copy_randombytes;

        let mut s = B2state {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            buf: [0u8; 256],
            buflen: 0,
            last_node: 0,
        };

        for i in 0..512 {
            unsafe { blake2b_init(&mut s, 64) };

            let mut state = State::init(64, None, None, None).expect("init");

            let mut block = vec![0u8; i];
            copy_randombytes(&mut block);

            unsafe { blake2b_update(&mut s, block.as_ptr(), block.len() as u64) };

            state.update(&block);

            unsafe { blake2b_update(&mut s, block.as_ptr(), block.len() as u64) };

            state.update(&block);

            let mut output = [0u8; 64];
            let mut so_output = [0u8; 64];

            unsafe { blake2b_final(&mut s, so_output.as_mut_ptr(), so_output.len() as u64) };

            state.finalize(&mut output).ok();

            assert_eq!(output, so_output);
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_b2_key_simd() {
        crate::native_test_util::init();
        use crate::rng::copy_randombytes;

        let mut s = B2state {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            buf: [0u8; 256],
            buflen: 0,
            last_node: 0,
        };

        let mut key = [0u8; 32];
        copy_randombytes(&mut key);
        let mut block = [0u8; 256];
        copy_randombytes(&mut block);

        unsafe { blake2b_init_key(&mut s, 64, &key as *const u8, key.len() as u8) };

        let mut state = State::init(64, Some(&key), None, None).expect("init");

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        state.update(&block);

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        state.update(&block);

        let mut output = [0u8; 64];
        let mut so_output = [0u8; 64];

        unsafe { blake2b_final(&mut s, so_output.as_mut_ptr(), so_output.len() as u64) };

        state.finalize(&mut output).ok();

        assert_eq!(output, so_output);
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_blake2b_long_simd() {
        crate::native_test_util::init();
        use crate::rng::copy_randombytes;

        for i in 5..320 {
            let mut input = vec![0u8; i - 5_usize];
            let mut output = vec![0u8; i];
            let mut so_output = output.clone();
            copy_randombytes(&mut input);

            longhash(&mut output, &input).expect("longhash failed");

            unsafe {
                blake2b_long(
                    so_output.as_mut_ptr(),
                    so_output.len() as u64,
                    input.as_ptr(),
                    input.len() as u64,
                )
            };

            assert_eq!(output, so_output);
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_blake2b_long_rand_length_simd() {
        crate::native_test_util::init();
        use crate::rng::copy_randombytes;

        let random_u32 = || {
            let mut bytes = [0u8; 4];
            copy_randombytes(&mut bytes);
            u32::from_le_bytes(bytes)
        };

        for _ in 0..25 {
            let mut input = vec![0u8; (random_u32() % 1000) as usize];
            let mut output = vec![0u8; (random_u32() % 1000 + 64) as usize];
            let mut so_output = output.clone();
            copy_randombytes(&mut input);

            longhash(&mut output, &input).expect("longhash failed");

            unsafe {
                blake2b_long(
                    so_output.as_mut_ptr(),
                    so_output.len() as u64,
                    input.as_ptr(),
                    input.len() as u64,
                )
            };

            assert_eq!(output, so_output);
        }
    }
}
