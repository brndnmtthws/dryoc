use std::simd::{simd_swizzle, Simd};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::utils::load_u64_le;

const BLOCKBYTES: usize = 128;
const OUTBYTES: usize = 64;
const HALFOUTBYTES: usize = OUTBYTES / 2;
const KEYBYTES: usize = 64;
const SALTBYTES: usize = 16;
const PERSONALBYTES: usize = 16;

#[repr(packed)]
#[allow(dead_code)]
struct Params {
    digest_length: u8,
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: [u8; 4],
    node_offset: [u8; 8],
    node_depth: u8,
    inner_length: u8,
    reserved: [u8; 14],
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
}

impl Default for Params {
    fn default() -> Self {
        Self {
            digest_length: 0,
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: [0u8; 4],
            node_offset: [0u8; 8],
            node_depth: 0,
            inner_length: 0,
            reserved: [0u8; 14],
            salt: [0u8; SALTBYTES],
            personal: [0u8; PERSONALBYTES],
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Default)]
pub struct State {
    t: [u64; 2],
    f: [u64; 2],
    #[zeroize(skip)]
    a: Simd<u64, 4>,
    #[zeroize(skip)]
    b: Simd<u64, 4>,
    last_node: u8,
    buf: Vec<u8>,
}

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[inline]
fn loadm(block: &[u8]) -> [Simd<u64, 4>; 8] {
    macro_rules! swizzle_my_jizzle {
        ($arr:expr, $start:expr, $mid:expr, $end:expr) => {{
            {
                simd_swizzle!(
                    Simd::<u64, 2>::from([
                        load_u64_le(&$arr[$start..$mid]),
                        load_u64_le(&block[$mid..$end])
                    ]),
                    [0, 1, 0, 1]
                )
            }
        }};
    }

    [
        swizzle_my_jizzle!(block, 0, 8, 16),
        swizzle_my_jizzle!(block, 16, 24, 32),
        swizzle_my_jizzle!(block, 32, 40, 48),
        swizzle_my_jizzle!(block, 48, 56, 64),
        swizzle_my_jizzle!(block, 64, 72, 80),
        swizzle_my_jizzle!(block, 80, 88, 96),
        swizzle_my_jizzle!(block, 96, 104, 112),
        swizzle_my_jizzle!(block, 112, 120, 128),
    ]
}

#[inline]
fn rotru64(v: Simd<u64, 4>, n: u64) -> Simd<u64, 4> {
    v >> Simd::from([n, n, n, n]) | v << Simd::from([64 - n, 64 - n, 64 - n, 64 - n])
}

#[inline]
fn g1(
    a: &mut Simd<u64, 4>,
    b: &mut Simd<u64, 4>,
    c: &mut Simd<u64, 4>,
    d: &mut Simd<u64, 4>,
    m: &Simd<u64, 4>,
) {
    *a = *a + *b + *m;
    *d = rotru64(*d ^ *a, 32);
    *c += *d;
    *b = rotru64(*b ^ *c, 24);
}

#[inline]
fn g2(
    a: &mut Simd<u64, 4>,
    b: &mut Simd<u64, 4>,
    c: &mut Simd<u64, 4>,
    d: &mut Simd<u64, 4>,
    m: &Simd<u64, 4>,
) {
    *a = *a + *b + *m;
    *d = rotru64(*d ^ *a, 16);
    *c += *d;
    *b = rotru64(*b ^ *c, 63);
}

#[inline]
fn permute(a: &mut Simd<u64, 4>, c: &mut Simd<u64, 4>, d: &mut Simd<u64, 4>) {
    *a = simd_swizzle!(*a, [3, 0, 1, 2]);
    *d = simd_swizzle!(*d, [2, 3, 0, 1]);
    *c = simd_swizzle!(*c, [1, 2, 3, 0]);
}

#[inline]
fn unpermute(a: &mut Simd<u64, 4>, c: &mut Simd<u64, 4>, d: &mut Simd<u64, 4>) {
    *a = simd_swizzle!(*a, [1, 2, 3, 0]);
    *d = simd_swizzle!(*d, [2, 3, 0, 1]);
    *c = simd_swizzle!(*c, [3, 0, 1, 2]);
}

#[inline]
fn compress(
    a: &mut Simd<u64, 4>,
    b: &mut Simd<u64, 4>,
    st: &[u64; 2],
    sf: &[u64; 2],
    block: &[u8],
) {
    let mut c = Simd::<u64, 4>::from_slice(&IV[..4]);
    let flags = Simd::<u64, 4>::from([st[0], st[1], sf[0], sf[1]]);
    let mut d = Simd::<u64, 4>::from_slice(&IV[4..]) ^ flags;

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

fn increment_counter(t: &mut [u64; 2], inc: usize) {
    let mut c: u128 = ((t[1] as u128) << 64) | t[0] as u128;
    c += inc as u128;
    t[0] = c as u64;
    t[1] = (c >> 64) as u64;
}

impl State {
    fn init_param(params: &Params) -> Self {
        let mut state = Self::default();
        state.init0();

        let pslice = unsafe {
            std::slice::from_raw_parts(
                (params as *const Params) as *const u8,
                std::mem::size_of::<Params>(),
            )
        };

        state.a ^= Simd::<u64, 4>::from([
            load_u64_le(&pslice[0..8]),
            load_u64_le(&pslice[8..16]),
            load_u64_le(&pslice[16..24]),
            load_u64_le(&pslice[24..32]),
        ]);
        state.b ^= Simd::<u64, 4>::from([
            load_u64_le(&pslice[32..40]),
            load_u64_le(&pslice[40..48]),
            load_u64_le(&pslice[48..56]),
            load_u64_le(&pslice[56..64]),
        ]);

        state
    }

    fn init0(&mut self) {
        self.a = Simd::from_slice(&IV[..4]);
        self.b = Simd::from_slice(&IV[4..8]);
    }

    pub(crate) fn init(
        outlen: u8,
        key: Option<&[u8]>,
        salt: Option<&[u8; SALTBYTES]>,
        personal: Option<&[u8; PERSONALBYTES]>,
    ) -> Result<State, Error> {
        if outlen == 0 || outlen as usize > OUTBYTES {
            return Err(dryoc_error!(format!("invalid blake2b outlen: {}", outlen)));
        }

        let key_length: u8 = match key {
            Some(key) => key.len() as u8,
            None => 0,
        };

        if key_length > KEYBYTES as u8 {
            return Err(dryoc_error!(format!(
                "invalid blake2b key length: {} max: {}",
                key_length, KEYBYTES
            )));
        }

        let salt = match salt {
            Some(salt) => *salt,
            None => [0u8; SALTBYTES],
        };

        let personal = match personal {
            Some(personal) => *personal,
            None => [0u8; PERSONALBYTES],
        };

        let params = Params {
            digest_length: outlen,
            key_length,
            salt,
            personal,
            ..Default::default()
        };

        let mut state = Self::init_param(&params);

        if let Some(key) = key {
            let mut block = [0u8; BLOCKBYTES];
            block[..key.len()].copy_from_slice(key);
            state.update(&block);
            block.zeroize();
        }

        Ok(state)
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        if input.is_empty() {
            // return early if the input is empty
            return;
        }
        if input.len() + self.buf.len() <= BLOCKBYTES {
            // do nothing, not enough data to make a block, just append input to buf
            self.buf.extend_from_slice(input);
        } else {
            let start = if !self.buf.is_empty() && self.buf.len() < BLOCKBYTES {
                let start = BLOCKBYTES - self.buf.len();
                self.buf.extend_from_slice(&input[..start]);
                start
            } else {
                0
            };
            let remaining = input.len() - start;
            let end = if remaining > BLOCKBYTES && remaining % BLOCKBYTES == 0 {
                input.len() - BLOCKBYTES
            } else if remaining > BLOCKBYTES {
                input.len() - remaining % BLOCKBYTES
            } else {
                start
            };

            let t = &mut self.t;
            let f = &mut self.f;

            let a = &mut self.a;
            let b = &mut self.b;

            for chunk in self.buf.chunks_exact(BLOCKBYTES) {
                increment_counter(t, BLOCKBYTES);
                compress(a, b, t, f, chunk);
            }
            for chunk in input[start..end].chunks_exact(BLOCKBYTES) {
                increment_counter(t, BLOCKBYTES);
                compress(a, b, t, f, chunk);
            }

            // finally, copy whatever's leftover from the input into buf
            self.buf.resize(input[end..].len(), 0);
            self.buf.copy_from_slice(&input[end..]);
        }
    }

    pub(crate) fn finalize(mut self, output: &mut [u8]) -> Result<(), Error> {
        if output.is_empty() || output.len() > OUTBYTES {
            return Err(dryoc_error!(format!(
                "invalid output length {}, should be <= {}",
                output.len(),
                OUTBYTES
            )));
        }

        if self.is_lastblock() {
            return Err(dryoc_error!("already on last block"));
        }

        if self.buf.len() > BLOCKBYTES {
            increment_counter(&mut self.t, BLOCKBYTES);
            compress(
                &mut self.a,
                &mut self.b,
                &self.t,
                &self.f,
                &self.buf[..BLOCKBYTES],
            );

            increment_counter(&mut self.t, self.buf.len() - BLOCKBYTES);
            self.set_lastblock();

            // fill last block with zero padding
            self.buf.resize(2 * BLOCKBYTES, 0);

            compress(
                &mut self.a,
                &mut self.b,
                &self.t,
                &self.f,
                &self.buf[BLOCKBYTES..],
            );
        } else {
            increment_counter(&mut self.t, self.buf.len());
            self.set_lastblock();

            // fill last block with zero padding
            self.buf.resize(BLOCKBYTES, 0);

            compress(&mut self.a, &mut self.b, &self.t, &self.f, &self.buf);
        }

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

        self.a = Simd::splat(0);
        self.b = Simd::splat(0);
        self.buf.zeroize();

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
    if output.len() > OUTBYTES {
        return Err(dryoc_error!(format!(
            "output length {} greater than max {}",
            output.len(),
            OUTBYTES
        )));
    }

    let mut state = State::init(output.len() as u8, key, None, None)?;

    state.update(input);
    state.finalize(output)
}

pub fn longhash(output: &mut [u8], input: &[u8]) -> Result<(), Error> {
    // long variant of blake2b, used by argon2
    // fills output with bytes from blake2b based on input

    assert!(output.len() > 4);
    assert!(output.len() < u32::MAX as usize);

    let outlen = output.len() as u32;
    let outlen_bytes = outlen.to_le_bytes();

    let mut state = State::init(
        std::cmp::min(outlen, OUTBYTES as u32) as u8,
        None,
        None,
        None,
    )?;
    state.update(&outlen_bytes);
    state.update(input);

    if outlen as usize <= OUTBYTES {
        state.finalize(output)
    } else {
        let mut in_buffer = [0u8; OUTBYTES];

        state.finalize(&mut output[..OUTBYTES])?;
        in_buffer.copy_from_slice(&output[..OUTBYTES]);

        let outlen = output.len() - HALFOUTBYTES;
        let chunk_count = if outlen % HALFOUTBYTES == 0 {
            outlen / HALFOUTBYTES - 2
        } else {
            outlen / HALFOUTBYTES - 1
        };
        let end = chunk_count * HALFOUTBYTES;
        let (start, end) = output[HALFOUTBYTES..].split_at_mut(end);

        for chunk in start.chunks_exact_mut(HALFOUTBYTES) {
            let mut out_buffer = [0u8; OUTBYTES];

            hash(&mut out_buffer, &in_buffer, None)?;

            chunk.copy_from_slice(&out_buffer[..HALFOUTBYTES]);
            in_buffer.copy_from_slice(&out_buffer);
        }
        hash(end, &in_buffer, None)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "nightly")]
    extern crate test;
    use lazy_static::lazy_static;
    use libc::*;
    use serde::{Deserialize, Serialize};

    use super::*;

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

    extern "C" {
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

    lazy_static! {
        static ref TEST_VECTORS: Vec<TestVector> =
            serde_json::from_str(include_str!("test-vectors/blake2b-test-vectors.json")).unwrap();
    }

    #[test]
    fn test_vectors() {
        for vector in TEST_VECTORS.iter() {
            println!("input {:?}, key {:?}", vector.in_, vector.key);
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

    #[cfg(feature = "nightly")]
    #[bench]
    fn blake2b_bench(b: &mut test::Bencher) {
        use crate::rng::copy_randombytes;
        let mut input = vec![0u8; 694200];
        copy_randombytes(&mut input);

        b.iter(|| {
            let mut state = State::init(64, None, None, None).expect("init");
            state.update(&input);

            let mut output = [0u8; 64];
            state.finalize(&mut output).ok();
        });
    }

    #[test]
    fn test_b2_simd() {
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

    #[test]
    fn test_b2_key_simd() {
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

    #[test]
    fn test_blake2b_long_simd() {
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

    #[test]
    fn test_blake2b_long_rand_length_simd() {
        use rand_core::{OsRng, RngCore};

        use crate::rng::copy_randombytes;

        for _ in 0..25 {
            let mut input = vec![0u8; (OsRng.next_u32() % 1000) as usize];
            let mut output = vec![0u8; (OsRng.next_u32() % 1000 + 64) as usize];
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
