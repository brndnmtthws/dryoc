use super::{Block, finish_in_place, prepare_in_place};

/// Overwrites `dst` with `P(R) ^ R [^ old dst]` for `R = prev_block ^
/// ref_block`; see [`super::fill_block`].
#[inline]
pub(super) fn fill_block(
    dst: &mut Block,
    prev_block: &Block,
    ref_block: &Block,
    xor_old: bool,
    scratch: &mut Block,
) {
    prepare_in_place(dst, prev_block, ref_block, xor_old, scratch);
    apply_block_rounds!(dst, blake2_round_nomsg);
    finish_in_place(dst, prev_block, ref_block, xor_old, scratch);
}

/// One fBlaMka `G` step on four register-resident words.
macro_rules! g {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $a = fblamka($a, $b);
        $d = ($d ^ $a).rotate_right(32);
        $c = fblamka($c, $d);
        $b = ($b ^ $c).rotate_right(24);
        $a = fblamka($a, $b);
        $d = ($d ^ $a).rotate_right(16);
        $c = fblamka($c, $d);
        $b = ($b ^ $c).rotate_right(63);
    };
}

/// BLAKE2b round without message words (Argon2 permutation `P`) over the 16
/// block words selected by `i0..i15`. The words are loaded into locals so the
/// eight `G` steps run entirely in registers, then stored back.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn blake2_round_nomsg(
    block: &mut Block,
    i0: usize,
    i1: usize,
    i2: usize,
    i3: usize,
    i4: usize,
    i5: usize,
    i6: usize,
    i7: usize,
    i8: usize,
    i9: usize,
    i10: usize,
    i11: usize,
    i12: usize,
    i13: usize,
    i14: usize,
    i15: usize,
) {
    let v = &mut block.v;
    let (mut v0, mut v1, mut v2, mut v3) = (v[i0], v[i1], v[i2], v[i3]);
    let (mut v4, mut v5, mut v6, mut v7) = (v[i4], v[i5], v[i6], v[i7]);
    let (mut v8, mut v9, mut v10, mut v11) = (v[i8], v[i9], v[i10], v[i11]);
    let (mut v12, mut v13, mut v14, mut v15) = (v[i12], v[i13], v[i14], v[i15]);

    g!(v0, v4, v8, v12);
    g!(v1, v5, v9, v13);
    g!(v2, v6, v10, v14);
    g!(v3, v7, v11, v15);
    g!(v0, v5, v10, v15);
    g!(v1, v6, v11, v12);
    g!(v2, v7, v8, v13);
    g!(v3, v4, v9, v14);

    v[i0] = v0;
    v[i1] = v1;
    v[i2] = v2;
    v[i3] = v3;
    v[i4] = v4;
    v[i5] = v5;
    v[i6] = v6;
    v[i7] = v7;
    v[i8] = v8;
    v[i9] = v9;
    v[i10] = v10;
    v[i11] = v11;
    v[i12] = v12;
    v[i13] = v13;
    v[i14] = v14;
    v[i15] = v15;
}

/// `x + y + 2 * lo32(x) * lo32(y)`, the Argon2 fBlaMka mixing function.
#[inline(always)]
fn fblamka(x: u64, y: u64) -> u64 {
    let xy = (x as u32 as u64) * (y as u32 as u64);
    x.wrapping_add(y).wrapping_add(xy << 1)
}
