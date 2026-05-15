use std::simd::{Simd, simd_swizzle};

use super::{Block, finalize_block, prepare_block};

#[inline]
pub(super) fn fill_block(
    prev_block: &Block,
    ref_block: &Block,
    next_block: Option<&Block>,
) -> Block {
    let (mut block_r, block_tmp) = prepare_block(prev_block, ref_block, next_block);
    apply_block_rounds!(&mut block_r, blake2_round_nomsg_simd);
    finalize_block(block_tmp, &block_r)
}

#[inline(always)]
fn rotr64x4<const N: u64>(v: Simd<u64, 4>) -> Simd<u64, 4> {
    (v >> Simd::splat(N)) | (v << Simd::splat(64 - N))
}

#[inline(always)]
fn fblamka_x4(x: Simd<u64, 4>, y: Simd<u64, 4>) -> Simd<u64, 4> {
    let m = Simd::splat(0xFFFFFFFFu64);
    let xy = (x & m) * (y & m);
    x + y + xy + xy
}

#[inline(always)]
fn g_simd(a: &mut Simd<u64, 4>, b: &mut Simd<u64, 4>, c: &mut Simd<u64, 4>, d: &mut Simd<u64, 4>) {
    *a = fblamka_x4(*a, *b);
    *d = rotr64x4::<32>(*d ^ *a);
    *c = fblamka_x4(*c, *d);
    *b = rotr64x4::<24>(*b ^ *c);
    *a = fblamka_x4(*a, *b);
    *d = rotr64x4::<16>(*d ^ *a);
    *c = fblamka_x4(*c, *d);
    *b = rotr64x4::<63>(*b ^ *c);
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn blake2_round_nomsg_simd(
    block: &mut Block,
    v0: usize,
    v1: usize,
    v2: usize,
    v3: usize,
    v4: usize,
    v5: usize,
    v6: usize,
    v7: usize,
    v8: usize,
    v9: usize,
    v10: usize,
    v11: usize,
    v12: usize,
    v13: usize,
    v14: usize,
    v15: usize,
) {
    let mut a = Simd::from_array([block.v[v0], block.v[v1], block.v[v2], block.v[v3]]);
    let mut b = Simd::from_array([block.v[v4], block.v[v5], block.v[v6], block.v[v7]]);
    let mut c = Simd::from_array([block.v[v8], block.v[v9], block.v[v10], block.v[v11]]);
    let mut d = Simd::from_array([block.v[v12], block.v[v13], block.v[v14], block.v[v15]]);

    g_simd(&mut a, &mut b, &mut c, &mut d);

    b = simd_swizzle!(b, [1, 2, 3, 0]);
    c = simd_swizzle!(c, [2, 3, 0, 1]);
    d = simd_swizzle!(d, [3, 0, 1, 2]);

    g_simd(&mut a, &mut b, &mut c, &mut d);

    b = simd_swizzle!(b, [3, 0, 1, 2]);
    c = simd_swizzle!(c, [2, 3, 0, 1]);
    d = simd_swizzle!(d, [1, 2, 3, 0]);

    [block.v[v0], block.v[v1], block.v[v2], block.v[v3]] = a.to_array();
    [block.v[v4], block.v[v5], block.v[v6], block.v[v7]] = b.to_array();
    [block.v[v8], block.v[v9], block.v[v10], block.v[v11]] = c.to_array();
    [block.v[v12], block.v[v13], block.v[v14], block.v[v15]] = d.to_array();
}
