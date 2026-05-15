use super::{Block, finalize_block, prepare_block};
use crate::utils::rotr64;

#[inline]
pub(super) fn fill_block(
    prev_block: &Block,
    ref_block: &Block,
    next_block: Option<&Block>,
) -> Block {
    let (mut block_r, block_tmp) = prepare_block(prev_block, ref_block, next_block);
    apply_block_rounds!(&mut block_r, blake2_round_nomsg);
    finalize_block(block_tmp, &block_r)
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn blake2_round_nomsg(
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
    let g = |block: &mut Block, a, b, c, d| {
        block.v[a] = fblamka(block.v[a], block.v[b]);
        block.v[d] = rotr64(block.v[d] ^ block.v[a], 32);
        block.v[c] = fblamka(block.v[c], block.v[d]);
        block.v[b] = rotr64(block.v[b] ^ block.v[c], 24);
        block.v[a] = fblamka(block.v[a], block.v[b]);
        block.v[d] = rotr64(block.v[d] ^ block.v[a], 16);
        block.v[c] = fblamka(block.v[c], block.v[d]);
        block.v[b] = rotr64(block.v[b] ^ block.v[c], 63);
    };

    g(block, v0, v4, v8, v12);
    g(block, v1, v5, v9, v13);
    g(block, v2, v6, v10, v14);
    g(block, v3, v7, v11, v15);
    g(block, v0, v5, v10, v15);
    g(block, v1, v6, v11, v12);
    g(block, v2, v7, v8, v13);
    g(block, v3, v4, v9, v14);
}

#[inline]
fn fblamka(x: u64, y: u64) -> u64 {
    let m = 0xFFFFFFFFu64;
    let xy = (x & m) * (y & m);
    x.wrapping_add(y).wrapping_add(2u64.wrapping_mul(xy))
}
